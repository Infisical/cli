package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/rs/zerolog/log"
)

// certificateStateRecord is written next to the certificate file so a restarted
// agent can pick up the certificate it already issued instead of issuing a new one.
type certificateStateRecord struct {
	CertificateID string `json:"certificate_id"`
	SerialNumber  string `json:"serial_number"`
	// ConfigFingerprint is a hash of the certificate's configuration (see configFingerprint),
	// not of the certificate itself.
	ConfigFingerprint string `json:"config_fingerprint"`
	// Files lists the outputs that were actually written. A configured private key or
	// chain is legitimately absent when Infisical returns none (ACME or CSR issuance).
	Files []string `json:"files"`
}

func certificateStateFilePath(certConfig *AgentCertificateConfig) string {
	certificatePath := certConfig.FileConfig.Certificate.Path
	if certificatePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(certificatePath), "."+filepath.Base(certificatePath)+".infisical-agent-state.json")
}

// configFingerprint hashes the parts of the certificate configuration that decide what
// gets issued and where it is written, so editing them leads to a fresh certificate rather
// than resuming the old one. File permissions are left out since changing them alone is
// not worth a new certificate.
func configFingerprint(certConfig *AgentCertificateConfig) string {
	output := certConfig.FileConfig
	payload, _ := json.Marshal(struct {
		ProfileID       string
		ApplicationID   string
		CSR             string
		Attributes      *CertificateAttributes
		CertificatePath string
		PrivateKeyPath  string
		ChainPath       string
		ChainOmitRoot   *bool
	}{
		ProfileID:       certConfig.ProfileID,
		ApplicationID:   certConfig.ApplicationID,
		CSR:             certConfig.CSR,
		Attributes:      certConfig.Attributes,
		CertificatePath: output.Certificate.Path,
		PrivateKeyPath:  output.PrivateKey.Path,
		ChainPath:       output.Chain.Path,
		ChainOmitRoot:   output.Chain.OmitRoot,
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func writeCertificateStateFile(certConfig *AgentCertificateConfig, certificateID, serialNumber string, writtenPaths []string) error {
	statePath := certificateStateFilePath(certConfig)
	if statePath == "" || certificateID == "" {
		return nil
	}

	contents, err := json.Marshal(certificateStateRecord{
		CertificateID:     certificateID,
		SerialNumber:      serialNumber,
		ConfigFingerprint: configFingerprint(certConfig),
		Files:             writtenPaths,
	})
	if err != nil {
		return err
	}

	// Write then rename so a crash mid-write never leaves a truncated record behind.
	tmp, err := os.CreateTemp(filepath.Dir(statePath), filepath.Base(statePath)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), statePath)
}

func removeCertificateStateFile(certConfig *AgentCertificateConfig) error {
	statePath := certificateStateFilePath(certConfig)
	if statePath == "" {
		return nil
	}
	if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func allFilesExist(paths []string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

func readCertificateStateFile(certConfig *AgentCertificateConfig) (*certificateStateRecord, error) {
	statePath := certificateStateFilePath(certConfig)
	if statePath == "" {
		return nil, os.ErrNotExist
	}

	contents, err := os.ReadFile(statePath)
	if err != nil {
		return nil, err
	}

	var record certificateStateRecord
	if err := json.Unmarshal(contents, &record); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %v", statePath, err)
	}
	return &record, nil
}

// resumeCertificateFromDisk adopts the certificate already on disk when it is still the
// one Infisical issued for this config and is active. It returns false when the agent
// should issue a new certificate instead.
func (tm *AgentManager) resumeCertificateFromDisk(certificateId int, certConfig *AgentCertificateConfig) bool {
	displayName := tm.getCertificateDisplayName(certificateId, certConfig)

	record, err := readCertificateStateFile(certConfig)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Warn().Str("Certificate", displayName).Msgf("unable to read saved certificate state; issuing a new certificate: %v", err)
		}
		return false
	}

	if record.ConfigFingerprint != configFingerprint(certConfig) {
		log.Info().Str("Certificate", displayName).Msg("certificate configuration changed since the certificate on disk was issued; issuing a new certificate")
		return false
	}

	serialOnDisk, ok := serialOfCertificateOnDisk(certConfig)
	if !allFilesExist(record.Files) || !ok || !serialEquals(serialOnDisk, record.SerialNumber) {
		log.Info().Str("Certificate", displayName).Msg("certificate files on disk are missing or do not match the saved state; issuing a new certificate")
		return false
	}

	httpClient, err := tm.createAuthenticatedClient()
	if err != nil {
		log.Warn().Str("Certificate", displayName).Msgf("unable to verify the certificate on disk; issuing a new certificate: %v", err)
		return false
	}

	existing, err := api.CallRetrieveCertificate(httpClient, record.CertificateID)
	if err != nil {
		log.Warn().Str("Certificate", displayName).Msgf("unable to verify the certificate on disk with Infisical; issuing a new certificate: %v", err)
		return false
	}

	if status := effectiveCertificateStatus(existing); status != api.CertificateStatusActive {
		log.Info().Str("Certificate", displayName).Str("status", string(status)).Msg("certificate on disk is no longer active; issuing a new certificate")
		return false
	}

	if existing.Certificate.ID != record.CertificateID || !serialEquals(serialOnDisk, existing.Certificate.SerialNumber) {
		log.Info().Str("Certificate", displayName).Msg("certificate on disk does not match the one recorded in Infisical; issuing a new certificate")
		return false
	}

	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	state := tm.certificateStates[certificateId]
	state.CertificateID = existing.Certificate.ID
	state.SerialNumber = existing.Certificate.SerialNumber
	state.CommonName = existing.Certificate.CommonName
	state.IssuedAt = existing.Certificate.NotBefore
	state.ExpiresAt = existing.Certificate.NotAfter
	state.Status = "active"
	state.LastReportedStatus = "active"
	state.LastError = ""
	state.RetryCount = 0

	if renewBeforeDuration, err := parseDurationWithDays(certConfig.Lifecycle.RenewBeforeExpiry); err == nil {
		state.NextRenewalCheck = state.ExpiresAt.Add(-renewBeforeDuration)
	} else {
		state.NextRenewalCheck = state.ExpiresAt.Add(-24 * time.Hour)
	}

	if !tm.ShouldRenewCertificate(certificateId) {
		log.Info().Str("Certificate", displayName).Str("serial", state.SerialNumber).Time("expires", state.ExpiresAt).Msg("resuming management of the existing certificate on disk")
		return true
	}

	// The agent never renews CSR-based certificates, so a fresh issuance is the
	// only way to replace one that has entered its renewal window.
	if certConfig.CSR != "" || certConfig.CSRPath != "" {
		state.Status = "pending"
		log.Info().Str("Certificate", displayName).Msg("certificate on disk is within its renewal window; issuing a new certificate")
		return false
	}

	log.Info().Str("Certificate", displayName).Msg("certificate on disk is within its renewal window; renewing")
	if err := tm.RenewCertificate(certificateId, certConfig); err != nil {
		// Nothing retries a failed renewal for profile-based certificates, so issue a
		// new certificate rather than letting the one on disk run out.
		log.Error().Str("Certificate", displayName).Msgf("failed to renew certificate; issuing a new certificate: %v", err)
		state.Status = "pending"
		return false
	}
	return true
}
