package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/gofrs/flock"
	"github.com/rs/zerolog/log"
)

type persistedCertificateState struct {
	Version     int              `json:"version"`
	Fingerprint string           `json:"fingerprint"`
	State       CertificateState `json:"state"`
}

func validPersistedCertificateState(saved persistedCertificateState) bool {
	if saved.Version != 1 || saved.Fingerprint == "" {
		return false
	}
	switch saved.State.Status {
	case "active":
		return saved.State.CertificateID != "" && saved.State.CertificateRequestID == ""
	case "pending_issuance", "renewing":
		return saved.State.CertificateRequestID != ""
	case "failed":
		return saved.State.CertificateID != "" || saved.State.CertificateRequestID != "" || (saved.State.LastError != "" && !saved.State.LastRetry.IsZero())
	case "requesting_issuance", "requesting_renewal", "pending":
		return true
	default:
		return false
	}
}

func restoreRejectedCertificateRequest(certificate *AgentCertificateConfig, state *CertificateState, previous CertificateState, requestErr error) error {
	var apiErr *api.APIError
	// A timeout, transport error, or server error can occur after the CA has accepted the request.
	if errors.As(requestErr, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 && apiErr.StatusCode != 408 {
		*state = previous
		if state.CertificateID == "" && state.CertificateRequestID == "" {
			state.Status = "pending"
		}
		return errors.Join(requestErr, persistCertificateState(certificate, state))
	}
	return requestErr
}

func canonicalCertificatePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if info, statErr := os.Lstat(absolute); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(absolute)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(absolute), target)
		}
		return canonicalCertificatePath(target)
	}
	parent := filepath.Dir(absolute)
	if parent == absolute {
		return "", err
	}
	resolvedParent, err := canonicalCertificatePath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(absolute)), nil
}

func validateCertificateStatePaths(certificates []AgentCertificateConfig) error {
	outputs := make(map[string]bool)
	for _, certificate := range certificates {
		for _, output := range []string{certificate.FileConfig.Certificate.Path, certificate.FileConfig.PrivateKey.Path, certificate.FileConfig.Chain.Path} {
			if output == "" {
				continue
			}
			absolute, err := canonicalCertificatePath(output)
			if err != nil {
				return err
			}
			outputs[absolute] = true
		}
	}
	states := make(map[string]bool)
	for _, certificate := range certificates {
		if certificate.HasCertificateID() {
			if certificate.Lifecycle.StatePath != "" {
				return fmt.Errorf("lifecycle.state-path is only supported for profile-based issuance")
			}
			continue
		}
		if certificate.FileConfig.Certificate.Path == "" && certificate.Lifecycle.StatePath == "" {
			continue
		}
		for _, statePath := range []string{certificateStatePath(&certificate), certificateStatePath(&certificate) + ".lock"} {
			absolute, err := canonicalCertificatePath(statePath)
			if err != nil {
				return err
			}
			if outputs[absolute] || states[absolute] {
				return fmt.Errorf("certificate state or lock path %s overlaps an output or another certificate's state", statePath)
			}
			states[absolute] = true
		}
	}
	return nil
}

func certificateStatePath(certificate *AgentCertificateConfig) string {
	if certificate.Lifecycle.StatePath != "" {
		return certificate.Lifecycle.StatePath
	}
	return certificate.FileConfig.Certificate.Path + ".infisical-state.json"
}

func preflightCertificateOutputs(certificate *AgentCertificateConfig) error {
	if certificate.FileConfig.Certificate.Path == "" {
		return fmt.Errorf("certificate.path is required in file-output configuration")
	}
	for _, output := range []string{certificate.FileConfig.Certificate.Path, certificate.FileConfig.PrivateKey.Path, certificate.FileConfig.Chain.Path} {
		if output == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
			return fmt.Errorf("cannot prepare certificate output %s: %w", output, err)
		}
		file, err := os.OpenFile(output, os.O_WRONLY, 0)
		if err == nil {
			_ = file.Close()
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("cannot write certificate output %s: %w", output, err)
		}
		probe, err := os.CreateTemp(filepath.Dir(output), ".infisical-output-*")
		if err != nil {
			return fmt.Errorf("cannot write certificate output directory for %s: %w", output, err)
		}
		_ = probe.Close()
		_ = os.Remove(probe.Name())
	}
	return nil
}

func certificateChainOutput(certificate *AgentCertificateConfig, chain string) (string, string, error) {
	if certificate.FileConfig.Chain.Path != "" && strings.TrimSpace(chain) == "" {
		return "", "", fmt.Errorf("configured certificate chain is missing from the remote bundle")
	}
	return formatCertificateChain(chain, chainOmitRoot(certificate))
}

func formatCertificateChain(chain string, omitRoot bool) (string, string, error) {
	var output []byte
	var der []byte
	rest := []byte(chain)
	for len(bytes.TrimSpace(rest)) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return "", "", fmt.Errorf("certificate chain contains invalid PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", "", err
		}
		rest = remaining
		if omitRoot && cert.IsCA && bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil {
			continue
		}
		output = append(output, pem.EncodeToMemory(block)...)
		der = append(der, cert.Raw...)
	}
	hash := sha256.Sum256(der)
	return string(output), hex.EncodeToString(hash[:]), nil
}

func chainOmitRoot(certificate *AgentCertificateConfig) bool {
	return certificate.FileConfig.Chain.OmitRoot == nil || *certificate.FileConfig.Chain.OmitRoot
}

func certificateFingerprint(certificate *AgentCertificateConfig) (string, error) {
	attributes := buildCertificateAttributes(certificate)
	if attributes != nil {
		attributes.AltNames = slices.Clone(attributes.AltNames)
		slices.SortFunc(attributes.AltNames, func(a, b api.AltName) int { return strings.Compare(a.Value, b.Value) })
		attributes.RemoveRootsFromChain = false
		attributes.KeyUsages = slices.Clone(attributes.KeyUsages)
		slices.Sort(attributes.KeyUsages)
		attributes.ExtendedKeyUsages = slices.Clone(attributes.ExtendedKeyUsages)
		slices.Sort(attributes.ExtendedKeyUsages)
	}
	data, err := json.Marshal(struct {
		Address       string
		ProfileID     string
		ApplicationID string
		CSR           string
		Attributes    *api.CertificateAttributes
	}{config.INFISICAL_URL, certificate.ProfileID, certificate.ApplicationID, certificate.CSR, attributes})
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func lockCertificateState(certificate *AgentCertificateConfig) (func(), error) {
	if err := validateCertificateStatePaths([]AgentCertificateConfig{*certificate}); err != nil {
		return nil, err
	}
	if certificate.FileConfig.Certificate.Path == "" {
		return nil, fmt.Errorf("certificate.path is required in file-output configuration")
	}
	statePath, err := canonicalCertificatePath(certificateStatePath(certificate))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0755); err != nil {
		return nil, fmt.Errorf("cannot create certificate state directory: %w", err)
	}
	lockFile, err := os.OpenFile(statePath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot create certificate state lock: %w", err)
	}
	_ = lockFile.Close()
	lock := flock.New(statePath + ".lock")
	locked, err := lock.TryLock()
	if err != nil {
		return nil, fmt.Errorf("cannot lock certificate state: %w", err)
	}
	if !locked {
		return nil, fmt.Errorf("another Agent is managing certificate state at %s", statePath)
	}
	return func() { _ = lock.Unlock() }, nil
}

func persistCertificateState(certificate *AgentCertificateConfig, state *CertificateState) error {
	if err := validateCertificateStatePaths([]AgentCertificateConfig{*certificate}); err != nil {
		return err
	}
	fingerprint, err := certificateFingerprint(certificate)
	if err != nil {
		return err
	}
	data, err := json.Marshal(persistedCertificateState{Version: 1, Fingerprint: fingerprint, State: *state})
	if err != nil {
		return err
	}
	statePath, err := canonicalCertificatePath(certificateStatePath(certificate))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0755); err != nil {
		return fmt.Errorf("cannot create certificate state directory: %w", err)
	}
	if err := util.WriteFileAtomic(statePath, data, 0600); err != nil {
		return fmt.Errorf("cannot persist certificate state at %s: %w", statePath, err)
	}
	file, err := os.Open(statePath)
	if err != nil {
		return err
	}
	err = file.Sync()
	_ = file.Close()
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(statePath))
		if err != nil {
			return err
		}
		err = directory.Sync()
		_ = directory.Close()
		return err
	}
	return nil
}

func parseAgentCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func readAgentCertificate(certificate *AgentCertificateConfig) (*x509.Certificate, []byte, error) {
	data, err := os.ReadFile(certificate.FileConfig.Certificate.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("cannot read existing certificate: %w", err)
	}
	leaf, err := parseAgentCertificate(data)
	if err != nil {
		return nil, data, nil
	}
	return leaf, data, nil
}

func certificateSerialMatches(serial string, leaf *x509.Certificate) bool {
	value, ok := new(big.Int).SetString(strings.TrimPrefix(strings.ToLower(serial), "0x"), 16)
	return ok && leaf != nil && value.Cmp(leaf.SerialNumber) == 0
}

func certificateMatchesIdentity(leaf *x509.Certificate, certificate *AgentCertificateConfig) bool {
	commonName := ""
	var altNames []string
	if certificate.CSR != "" {
		block, _ := pem.Decode([]byte(certificate.CSR))
		if block == nil {
			return false
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			return false
		}
		key, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
		if err != nil || !bytes.Equal(key, leaf.RawSubjectPublicKeyInfo) {
			return false
		}
		commonName, altNames = csr.Subject.CommonName, csr.DNSNames
		altNames = append(slices.Clone(altNames), csr.EmailAddresses...)
		for _, ip := range csr.IPAddresses {
			altNames = append(altNames, ip.String())
		}
		for _, uri := range csr.URIs {
			altNames = append(altNames, uri.String())
		}
	} else if certificate.Attributes != nil {
		commonName, altNames = certificate.Attributes.CommonName, certificate.Attributes.AltNames
		algorithm := certificate.Attributes.KeyAlgorithm
		if algorithm != "" {
			actualAlgorithm := ""
			switch key := leaf.PublicKey.(type) {
			case *rsa.PublicKey:
				actualAlgorithm = fmt.Sprintf("RSA_%d", key.N.BitLen())
			case *ecdsa.PublicKey:
				actualAlgorithm = map[int]string{256: "EC_prime256v1", 384: "EC_secp384r1", 521: "EC_secp521r1"}[key.Curve.Params().BitSize]
			}
			if algorithm != actualAlgorithm {
				return false
			}
		}
	}
	if commonName != "" && commonName != leaf.Subject.CommonName {
		return false
	}
	actual := slices.Clone(leaf.DNSNames)
	actual = append(actual, leaf.EmailAddresses...)
	for _, ip := range leaf.IPAddresses {
		actual = append(actual, ip.String())
	}
	for _, uri := range leaf.URIs {
		actual = append(actual, uri.String())
	}
	for _, name := range altNames {
		if !slices.Contains(actual, name) {
			return false
		}
	}
	return true
}

func validateManagedCertificateKey(certificate *AgentCertificateConfig, certificatePEM, key []byte) error {
	if len(key) == 0 {
		if certificate.FileConfig.PrivateKey.Path == "" {
			return nil
		}
		var err error
		key, err = os.ReadFile(certificate.FileConfig.PrivateKey.Path)
		if errors.Is(err, os.ErrNotExist) && certificate.CSR != "" {
			return nil
		}
		if err != nil {
			return fmt.Errorf("certificate private key is unavailable: %w", err)
		}
	}
	if _, err := tls.X509KeyPair(certificatePEM, key); err != nil {
		return fmt.Errorf("certificate does not match its private key: %w", err)
	}
	return nil
}

func (tm *AgentManager) recoverCertificateID(certificate *AgentCertificateConfig, leaf *x509.Certificate) (string, error) {
	httpClient, err := tm.createAuthenticatedClient()
	if err != nil {
		return "", err
	}
	serial := leaf.SerialNumber.Text(16)
	for offset := 0; ; offset += 100 {
		response, err := api.CallListCertificateProfileCertificates(httpClient, certificate.ProfileID, serial, offset)
		if err != nil {
			return "", fmt.Errorf("cannot recover existing certificate identity: %w", err)
		}
		for _, candidate := range response.Certificates {
			if !certificateSerialMatches(candidate.SerialNumber, leaf) {
				continue
			}
			bundle, err := api.CallGetCertificateBundle(httpClient, candidate.ID)
			if err != nil {
				return "", err
			}
			remoteLeaf, err := parseAgentCertificate([]byte(bundle.Certificate))
			if err != nil {
				return "", err
			}
			if bytes.Equal(leaf.Raw, remoteLeaf.Raw) {
				return candidate.ID, nil
			}
		}
		if len(response.Certificates) < 100 {
			return "", nil
		}
	}
}

func (tm *AgentManager) initializeManagedCertificate(certificateID int, certificate *AgentCertificateConfig) error {
	data, readErr := os.ReadFile(certificateStatePath(certificate))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("cannot read certificate state: %w", readErr)
	}
	var saved persistedCertificateState
	if readErr == nil {
		if err := json.Unmarshal(data, &saved); err != nil || !validPersistedCertificateState(saved) {
			return fmt.Errorf("certificate state at %s is invalid; inspect the existing certificate and any pending request before restoring or removing it", certificateStatePath(certificate))
		}
		fingerprint, err := certificateFingerprint(certificate)
		if err != nil {
			return err
		}
		if saved.State.Status == "requesting_issuance" || saved.State.Status == "requesting_renewal" {
			return fmt.Errorf("a previous certificate request has an unknown outcome; check Infisical before restoring or removing state at %s", certificateStatePath(certificate))
		}
		if saved.Fingerprint != fingerprint {
			if saved.State.CertificateRequestID != "" {
				return fmt.Errorf("issuance configuration changed while a certificate request is pending; restore the original configuration to resume it")
			}
			return tm.IssueCertificate(certificateID, certificate)
		}
		if saved.State.Status == "failed" && saved.State.CertificateRequestID == "" {
			interval := failureRetryIntervalFor(certificate)
			if saved.State.RetryCount >= effectiveMaxFailureRetries(certificate) {
				interval = failureRetryCooldownFor(certificate)
			}
			if time.Since(saved.State.LastRetry) < interval {
				tm.mutex.Lock()
				tm.certificateStates[certificateID] = &saved.State
				tm.mutex.Unlock()
				return nil
			}
		}
		tm.mutex.Lock()
		restored := saved.State
		if restored.CertificateRequestID == "" {
			restored.Status = "restoring"
		}
		tm.certificateStates[certificateID] = &restored
		tm.mutex.Unlock()
		if saved.State.CertificateRequestID != "" {
			if saved.State.Status == "failed" {
				return fmt.Errorf("previous certificate request failed: %s", saved.State.LastError)
			}
			tm.startCertificatePolling(certificateID, certificate)
			return nil
		}
	}

	leaf, certificatePEM, err := readAgentCertificate(certificate)
	if err != nil {
		return err
	}
	if saved.State.CertificateID == "" {
		if leaf == nil || !certificateMatchesIdentity(leaf, certificate) {
			return tm.IssueCertificate(certificateID, certificate)
		}
		id, err := tm.recoverCertificateID(certificate, leaf)
		if err != nil {
			return err
		}
		if id == "" {
			return tm.IssueCertificate(certificateID, certificate)
		}
		saved.State.CertificateID = id
		hash := sha256.Sum256(leaf.Raw)
		saved.State.CertificateSHA256 = hex.EncodeToString(hash[:])
	}
	httpClient, err := tm.createAuthenticatedClient()
	if err != nil {
		return err
	}
	metadata, err := api.CallRetrieveCertificate(httpClient, saved.State.CertificateID)
	if err != nil {
		return fmt.Errorf("cannot restore certificate metadata: %w", err)
	}
	if metadata.Certificate.LatestRenewalCertificateID != "" && metadata.Certificate.LatestRenewalCertificateID != metadata.Certificate.ID {
		metadata, err = api.CallRetrieveCertificate(httpClient, metadata.Certificate.LatestRenewalCertificateID)
		if err != nil {
			return err
		}
	}
	if metadata.Certificate.Status == "revoked" {
		return fmt.Errorf("existing certificate is revoked; refusing automatic issuance or renewal")
	}
	if metadata.Certificate.Status == "expired" || !metadata.Certificate.NotAfter.After(time.Now()) {
		return tm.IssueCertificate(certificateID, certificate)
	}
	if metadata.Certificate.ID == "" || metadata.Certificate.Status != "active" {
		return fmt.Errorf("existing certificate is not active")
	}

	repair := leaf == nil || !certificateSerialMatches(metadata.Certificate.SerialNumber, leaf) || saved.State.CertificateSHA256 == ""
	if leaf != nil && saved.State.CertificateSHA256 != "" {
		hash := sha256.Sum256(leaf.Raw)
		repair = repair || hex.EncodeToString(hash[:]) != saved.State.CertificateSHA256
	}
	var bundle *api.CertificateBundleResponse
	chainHash := saved.State.ChainSHA256
	if certificate.FileConfig.Chain.Path != "" {
		if chainHash == "" || saved.State.ChainOmitRoot != chainOmitRoot(certificate) {
			bundle, err = api.CallGetCertificateBundle(httpClient, metadata.Certificate.ID)
			if err != nil {
				return err
			}
			_, chainHash, err = certificateChainOutput(certificate, bundle.CertificateChain)
			if err != nil {
				return err
			}
		}
		chain, err := os.ReadFile(certificate.FileConfig.Chain.Path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("cannot read certificate chain: %w", err)
		}
		_, actualHash, parseErr := formatCertificateChain(string(chain), false)
		repair = repair || err != nil || parseErr != nil || actualHash != chainHash
	}
	if !repair {
		if !certificateMatchesIdentity(leaf, certificate) {
			return fmt.Errorf("existing certificate does not match the configured identity")
		}
		for _, output := range []string{certificate.FileConfig.PrivateKey.Path} {
			if output == "" {
				continue
			}
			outputData, err := os.ReadFile(output)
			if errors.Is(err, os.ErrNotExist) && certificate.CSR != "" {
				continue
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("cannot read certificate output %s: %w", output, err)
			}
			if len(outputData) == 0 {
				repair = true
			} else if output == certificate.FileConfig.PrivateKey.Path {
				if _, err := tls.X509KeyPair(certificatePEM, outputData); err != nil {
					repair = true
				}
			}
		}
	}
	if repair {
		if bundle == nil {
			bundle, err = api.CallGetCertificateBundle(httpClient, metadata.Certificate.ID)
			if err != nil {
				return err
			}
		}
		leaf, err = parseAgentCertificate([]byte(bundle.Certificate))
		if err != nil || !certificateSerialMatches(metadata.Certificate.SerialNumber, leaf) || !certificateMatchesIdentity(leaf, certificate) {
			return fmt.Errorf("stored certificate bundle does not match the certificate identity")
		}
		if err := validateManagedCertificateKey(certificate, []byte(bundle.Certificate), []byte(bundle.PrivateKey)); err != nil {
			return err
		}
		chain, hash, err := certificateChainOutput(certificate, bundle.CertificateChain)
		if err != nil {
			return err
		}
		chainHash = hash
		response := &api.CertificateResponse{Certificate: &api.CertificateData{
			CertificateID: metadata.Certificate.ID, SerialNumber: bundle.SerialNumber,
			Certificate: bundle.Certificate, PrivateKey: bundle.PrivateKey, CertificateChain: chain,
		}}
		delivery := saved.State
		if delivery.DeliveryHook == "" && saved.State.CertificateID != "" && saved.State.CertificateID != metadata.Certificate.ID {
			delivery.DeliveryHook = "renewal"
		}
		delivery.CertificateID = metadata.Certificate.ID
		setManagedCertificateState(&delivery, leaf, certificate)
		delivery.ChainSHA256, delivery.ChainOmitRoot = chainHash, chainOmitRoot(certificate)
		if err := persistCertificateState(certificate, &delivery); err != nil {
			return err
		}
		saved.State = delivery
		if err := tm.writeManagedCertificateFiles(certificate, response); err != nil {
			return err
		}
	}
	if time.Now().Before(leaf.NotBefore) {
		return fmt.Errorf("existing certificate is not valid yet")
	}
	if !time.Now().Before(leaf.NotAfter) {
		return tm.IssueCertificate(certificateID, certificate)
	}
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	state := tm.certificateStates[certificateID]
	state.CertificateID = metadata.Certificate.ID
	setManagedCertificateState(state, leaf, certificate)
	state.ChainSHA256, state.ChainOmitRoot = chainHash, chainOmitRoot(certificate)
	state.DeliveryHook = saved.State.DeliveryHook
	if err := persistCertificateState(certificate, state); err != nil {
		return err
	}
	if err := tm.finishManagedCertificateDelivery(certificateID, certificate, state); err != nil {
		return err
	}
	if certificate.CSR == "" && tm.ShouldRenewCertificate(certificateID) {
		return tm.RenewCertificate(certificateID, certificate)
	}
	return nil
}

func setManagedCertificateState(state *CertificateState, leaf *x509.Certificate, certificate *AgentCertificateConfig) {
	hash := sha256.Sum256(leaf.Raw)
	state.CertificateSHA256 = hex.EncodeToString(hash[:])
	state.SerialNumber = leaf.SerialNumber.Text(16)
	state.CommonName = leaf.Subject.CommonName
	state.IssuedAt = leaf.NotBefore
	state.ExpiresAt = leaf.NotAfter
	state.Status = "active"
	state.LastError = ""
	state.RetryCount = 0
	state.CertificateRequestID = ""
	state.NextRenewalCheck = time.Now().Add(statusCheckIntervalFor(certificate))
	if duration, err := parseDurationWithDays(certificate.Lifecycle.RenewBeforeExpiry); err == nil {
		renewAt := leaf.NotAfter.Add(-duration)
		if renewAt.After(time.Now()) && renewAt.Before(state.NextRenewalCheck) {
			state.NextRenewalCheck = renewAt
		}
	}
}

func (tm *AgentManager) completeManagedCertificate(certificateID int, certificate *AgentCertificateConfig, response *api.CertificateResponse, renewal bool) error {
	if response.Certificate == nil || response.Certificate.CertificateID == "" {
		return fmt.Errorf("issued certificate response has no certificate identity")
	}
	state := tm.certificateStates[certificateID]
	state.CertificateID = response.Certificate.CertificateID
	state.CertificateRequestID = ""
	state.Status = "active"
	state.DeliveryHook = "issuance"
	if renewal {
		state.DeliveryHook = "renewal"
	}
	// Save the identity before touching output files so a partial delivery can be repaired without another CA request.
	if err := persistCertificateState(certificate, state); err != nil {
		return err
	}
	leaf, err := parseAgentCertificate([]byte(response.Certificate.Certificate))
	if err != nil {
		return fmt.Errorf("cannot parse issued certificate: %w", err)
	}
	if !certificateMatchesIdentity(leaf, certificate) {
		return fmt.Errorf("issued certificate does not match the configured identity")
	}
	if err := validateManagedCertificateKey(certificate, []byte(response.Certificate.Certificate), []byte(response.Certificate.PrivateKey)); err != nil {
		return err
	}
	setManagedCertificateState(state, leaf, certificate)
	certificateData := *response.Certificate
	if certificate.FileConfig.Chain.Path != "" && strings.TrimSpace(certificateData.CertificateChain) == "" {
		httpClient, err := tm.createAuthenticatedClient()
		if err != nil {
			return err
		}
		bundle, err := api.CallGetCertificateBundle(httpClient, state.CertificateID)
		if err != nil {
			return err
		}
		bundleLeaf, err := parseAgentCertificate([]byte(bundle.Certificate))
		if err != nil || !bytes.Equal(bundleLeaf.Raw, leaf.Raw) {
			return fmt.Errorf("stored certificate bundle does not match the issued certificate")
		}
		certificateData.CertificateChain = bundle.CertificateChain
	}
	chain, hash, err := certificateChainOutput(certificate, certificateData.CertificateChain)
	if err != nil {
		return err
	}
	certificateData.CertificateChain = chain
	state.ChainSHA256, state.ChainOmitRoot = hash, chainOmitRoot(certificate)
	if err := persistCertificateState(certificate, state); err != nil {
		return err
	}
	if err := tm.writeManagedCertificateFiles(certificate, &api.CertificateResponse{Certificate: &certificateData}); err != nil {
		return err
	}
	if err := tm.finishManagedCertificateDelivery(certificateID, certificate, state); err != nil {
		return err
	}
	event := log.Info().Str("Certificate", tm.getCertificateDisplayName(certificateID, certificate)).Str("serial", state.SerialNumber)
	if renewal {
		event.Msg("certificate renewed successfully")
	} else {
		event.Msg("certificate issued successfully")
	}
	return nil
}

func (tm *AgentManager) finishManagedCertificateDelivery(certificateID int, certificate *AgentCertificateConfig, state *CertificateState) error {
	switch state.DeliveryHook {
	case "renewal":
		tm.ExecutePostHook(certificate.PostHooks.OnRenewal.Command, certificate.PostHooks.OnRenewal.Timeout, "renewal", certificateID, certificate)
	case "issuance":
		tm.ExecutePostHook(certificate.PostHooks.OnIssuance.Command, certificate.PostHooks.OnIssuance.Timeout, "issuance", certificateID, certificate)
	default:
		return nil
	}
	state.DeliveryHook = ""
	return persistCertificateState(certificate, state)
}

func (tm *AgentManager) writeManagedCertificateFiles(certificate *AgentCertificateConfig, response *api.CertificateResponse) error {
	if err := tm.WriteCertificateFiles(certificate, response); err != nil {
		return err
	}
	if certificate.FileConfig.Chain.Path != "" && response.Certificate.CertificateChain == "" {
		permission := os.FileMode(0600)
		if configured, err := strconv.ParseUint(certificate.FileConfig.Chain.Permission, 8, 32); err == nil {
			permission = os.FileMode(configured)
		}
		if err := os.MkdirAll(filepath.Dir(certificate.FileConfig.Chain.Path), 0755); err != nil {
			return err
		}
		return os.WriteFile(certificate.FileConfig.Chain.Path, nil, permission)
	}
	return nil
}

func (tm *AgentManager) startCertificatePolling(certificateID int, certificate *AgentCertificateConfig) {
	tm.certificatePollers.Add(1)
	go func() {
		defer tm.certificatePollers.Done()
		tm.PollCertificateRequest(certificateID, certificate)
	}()
}

func (tm *AgentManager) waitForCertificatePoll(interval time.Duration) bool {
	ctx := tm.certificateContext
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
