package agent

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type CertAgentTestHelper struct {
	T             *testing.T
	ProjectID     string
	ProjectSlug   string
	ProfileSlug   string
	ProfileID     string
	PolicyID      string
	CaID          string
	IdentityToken string
	AdminToken    string
	InfisicalURL  string
	TempDir       string
	ClientID      string
	ClientSecret  string
}

func (h *CertAgentTestHelper) CreateInternalCA() {
	t := h.T
	body := map[string]interface{}{
		"name":      "test-root-ca",
		"projectId": h.ProjectID,
		"status":    "active",
		"configuration": map[string]interface{}{
			"type":          "root",
			"friendlyName":  "Test Root CA",
			"commonName":    "Test Root CA",
			"organization":  "Test Org",
			"ou":            "",
			"country":       "US",
			"province":      "",
			"locality":      "",
			"maxPathLength": -1,
			"keyAlgorithm":  "RSA_2048",
			"notAfter":      time.Now().AddDate(10, 0, 0).UTC().Format(time.RFC3339),
		},
	}

	respBody := h.doPost("/v1/cert-manager/ca/internal", body)

	var resp map[string]interface{}
	err := json.Unmarshal(respBody, &resp)
	require.NoError(t, err, "Failed to unmarshal create CA response: %s", string(respBody))

	caID := ""
	if id, ok := resp["id"].(string); ok {
		caID = id
	} else if ca, ok := resp["ca"].(map[string]interface{}); ok {
		if id, ok := ca["id"].(string); ok {
			caID = id
		}
	}
	require.NotEmpty(t, caID, "CA ID should not be empty, response: %s", string(respBody))

	h.CaID = caID
}

type CertificatePolicyOption func(*certificatePolicyConfig)

type certificatePolicyConfig struct {
	allowAltNames            bool
	allowKeyAlgorithms       []string
	allowSignatureAlgorithms []string
	allowKeyUsages           []string
	allowExtendedKeyUsages   []string
}

func WithAllowAltNames() CertificatePolicyOption {
	return func(c *certificatePolicyConfig) {
		c.allowAltNames = true
	}
}

func WithAllowKeyAlgorithms(algorithms ...string) CertificatePolicyOption {
	return func(c *certificatePolicyConfig) {
		c.allowKeyAlgorithms = algorithms
	}
}

func WithAllowSignatureAlgorithms(algorithms ...string) CertificatePolicyOption {
	return func(c *certificatePolicyConfig) {
		c.allowSignatureAlgorithms = algorithms
	}
}

func WithAllowKeyUsages(usages ...string) CertificatePolicyOption {
	return func(c *certificatePolicyConfig) {
		c.allowKeyUsages = usages
	}
}

func WithAllowExtendedKeyUsages(usages ...string) CertificatePolicyOption {
	return func(c *certificatePolicyConfig) {
		c.allowExtendedKeyUsages = usages
	}
}

func (h *CertAgentTestHelper) CreateCertificatePolicy(name string, opts ...CertificatePolicyOption) {
	t := h.T

	cfg := &certificatePolicyConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	subject := []map[string]interface{}{
		{
			"type":    "common_name",
			"allowed": []string{"*"},
		},
	}

	body := map[string]interface{}{
		"projectId": h.ProjectID,
		"name":      name,
		"subject":   subject,
	}

	if cfg.allowAltNames {
		body["sans"] = []map[string]interface{}{
			{
				"type":    "dns_name",
				"allowed": []string{"*"},
			},
		}
	}

	if len(cfg.allowKeyAlgorithms) > 0 || len(cfg.allowSignatureAlgorithms) > 0 {
		algorithms := map[string]interface{}{}
		if len(cfg.allowKeyAlgorithms) > 0 {
			algorithms["keyAlgorithm"] = cfg.allowKeyAlgorithms
		}
		if len(cfg.allowSignatureAlgorithms) > 0 {
			algorithms["signature"] = cfg.allowSignatureAlgorithms
		}
		body["algorithms"] = algorithms
	}

	if len(cfg.allowKeyUsages) > 0 {
		body["keyUsages"] = map[string]interface{}{
			"allowed": cfg.allowKeyUsages,
		}
	}

	if len(cfg.allowExtendedKeyUsages) > 0 {
		body["extendedKeyUsages"] = map[string]interface{}{
			"allowed": cfg.allowExtendedKeyUsages,
		}
	}

	respBody := h.doPost("/v1/cert-manager/certificate-policies", body)

	var resp map[string]interface{}
	err := json.Unmarshal(respBody, &resp)
	require.NoError(t, err, "Failed to unmarshal create policy response: %s", string(respBody))

	policyID := ""
	if policy, ok := resp["certificatePolicy"].(map[string]interface{}); ok {
		if id, ok := policy["id"].(string); ok {
			policyID = id
		}
	}
	require.NotEmpty(t, policyID, "Policy ID should not be empty, response: %s", string(respBody))

	h.PolicyID = policyID
}

func (h *CertAgentTestHelper) CreateCertificateProfile(slug string) {
	t := h.T
	body := map[string]interface{}{
		"projectId":           h.ProjectID,
		"caId":                h.CaID,
		"certificatePolicyId": h.PolicyID,
		"slug":                slug,
		"enrollmentType":      "api",
		"issuerType":          "ca",
		"apiConfig": map[string]interface{}{
			"autoRenew": false,
		},
	}

	respBody := h.doPost("/v1/cert-manager/certificate-profiles", body)

	var resp map[string]interface{}
	err := json.Unmarshal(respBody, &resp)
	require.NoError(t, err, "Failed to unmarshal create profile response: %s", string(respBody))

	profileID := ""
	profileSlug := ""
	if profile, ok := resp["certificateProfile"].(map[string]interface{}); ok {
		if id, ok := profile["id"].(string); ok {
			profileID = id
		}
		if s, ok := profile["slug"].(string); ok {
			profileSlug = s
		}
	}
	require.NotEmpty(t, profileID, "Profile ID should not be empty, response: %s", string(respBody))

	h.ProfileID = profileID
	h.ProfileSlug = profileSlug
}

type addUniversalAuthRequest struct {
	AccessTokenTTL          int `json:"accessTokenTTL"`
	AccessTokenMaxTTL       int `json:"accessTokenMaxTTL"`
	AccessTokenNumUsesLimit int `json:"accessTokenNumUsesLimit"`
	AccessTokenTrustedIps   []struct {
		IpAddress string `json:"ipAddress"`
	} `json:"accessTokenTrustedIps"`
}

type createUniversalAuthClientSecretRequest struct{}

func (h *CertAgentTestHelper) SetupUniversalAuth(identityID string) {
	t := h.T

	body := addUniversalAuthRequest{
		AccessTokenTTL:          2592000,
		AccessTokenMaxTTL:       2592000,
		AccessTokenNumUsesLimit: 0,
		AccessTokenTrustedIps: []struct {
			IpAddress string `json:"ipAddress"`
		}{
			{IpAddress: "0.0.0.0/0"},
			{IpAddress: "::/0"},
		},
	}

	respBody := h.doPostWithToken(fmt.Sprintf("/v1/auth/universal-auth/identities/%s", identityID), body, h.AdminToken)

	var rawResp map[string]interface{}
	err := json.Unmarshal(respBody, &rawResp)
	require.NoError(t, err, "Failed to unmarshal universal auth response: %s", string(respBody))

	clientID := ""
	if id, ok := rawResp["clientId"].(string); ok {
		clientID = id
	} else if nested, ok := rawResp["identityUniversalAuth"].(map[string]interface{}); ok {
		if id, ok := nested["clientId"].(string); ok {
			clientID = id
		}
	}
	require.NotEmpty(t, clientID, "Client ID should not be empty, response: %s", string(respBody))

	h.ClientID = clientID

	csRespBody := h.doPostWithToken(fmt.Sprintf("/v1/auth/universal-auth/identities/%s/client-secrets", identityID), createUniversalAuthClientSecretRequest{}, h.AdminToken)

	var csRawResp map[string]interface{}
	err = json.Unmarshal(csRespBody, &csRawResp)
	require.NoError(t, err, "Failed to unmarshal client secret response: %s", string(csRespBody))

	clientSecret := ""
	if s, ok := csRawResp["clientSecret"].(string); ok {
		clientSecret = s
	} else if nested, ok := csRawResp["clientSecretData"].(map[string]interface{}); ok {
		if s, ok := nested["clientSecret"].(string); ok {
			clientSecret = s
		}
	}
	require.NotEmpty(t, clientSecret, "Client secret should not be empty, response: %s", string(csRespBody))

	h.ClientSecret = clientSecret
}

func (h *CertAgentTestHelper) doPost(path string, body interface{}) []byte {
	return h.doPostWithToken(path, body, h.IdentityToken)
}

func (h *CertAgentTestHelper) doPostWithToken(path string, body interface{}, token string) []byte {
	t := h.T

	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)

	url := h.InfisicalURL + "/api" + path
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.True(t, resp.StatusCode >= 200 && resp.StatusCode < 300,
		"API request to %s failed with status %d: %s", path, resp.StatusCode, string(respBody))

	return respBody
}

func (h *CertAgentTestHelper) doPostRaw(path string, body interface{}) (int, []byte) {
	t := h.T

	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)

	url := h.InfisicalURL + "/api" + path
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.IdentityToken)

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, respBody
}

func (h *CertAgentTestHelper) doPatchWithToken(path string, body interface{}, token string) (int, []byte) {
	t := h.T

	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)

	url := h.InfisicalURL + "/api" + path
	req, err := http.NewRequest("PATCH", url, bytes.NewReader(jsonBody))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, respBody
}

func (h *CertAgentTestHelper) CreateAcmeCARaw(name, dnsConnectionID, directoryUrl, provider, hostedZoneId, accountEmail string) (int, []byte) {
	body := map[string]interface{}{
		"name":      name,
		"projectId": h.ProjectID,
		"status":    "active",
		"configuration": map[string]interface{}{
			"dnsAppConnectionId": dnsConnectionID,
			"dnsProviderConfig": map[string]interface{}{
				"provider":     provider,
				"hostedZoneId": hostedZoneId,
			},
			"directoryUrl": directoryUrl,
			"accountEmail": accountEmail,
		},
	}
	return h.doPostRaw("/v1/cert-manager/ca/acme", body)
}

func (h *CertAgentTestHelper) DisableAcmeCA(caID string) {
	t := h.T

	body := map[string]interface{}{
		"status": "disabled",
	}

	statusCode, respBody := h.doPatchWithToken(fmt.Sprintf("/v1/cert-manager/ca/acme/%s", caID), body, h.IdentityToken)
	require.True(t, statusCode >= 200 && statusCode < 300,
		"Failed to disable ACME CA, status %d: %s", statusCode, string(respBody))
}

func CertFilePaths(dir string) (certPath, keyPath, chainPath string) {
	return filepath.Join(dir, "cert.pem"),
		filepath.Join(dir, "key.pem"),
		filepath.Join(dir, "chain.pem")
}

type agentConfig struct {
	Version      string                   `yaml:"version"`
	Infisical    agentInfisicalConfig     `yaml:"infisical"`
	Auth         agentAuthConfig          `yaml:"auth"`
	Certificates []agentCertificateConfig `yaml:"certificates,omitempty"`
}

type agentInfisicalConfig struct {
	Address string `yaml:"address"`
}

type agentAuthConfig struct {
	Type   string                   `yaml:"type"`
	Config agentUniversalAuthConfig `yaml:"config"`
}

type agentUniversalAuthConfig struct {
	ClientID     string `yaml:"client-id"`
	ClientSecret string `yaml:"client-secret"`
}

type agentCertificateConfig struct {
	ProjectSlug string                      `yaml:"project-slug"`
	ProfileName string                      `yaml:"profile-name"`
	CSR         string                      `yaml:"csr,omitempty"`
	CSRPath     string                      `yaml:"csr-path,omitempty"`
	Attributes  *agentCertificateAttributes `yaml:"attributes,omitempty"`
	Lifecycle   agentCertificateLifecycle   `yaml:"lifecycle"`
	FileOutput  agentCertificateFileOutput  `yaml:"file-output"`
	PostHooks   *agentCertificatePostHooks  `yaml:"post-hooks,omitempty"`
}

type agentCertificateAttributes struct {
	CommonName         string   `yaml:"common-name,omitempty"`
	TTL                string   `yaml:"ttl,omitempty"`
	KeyAlgorithm       string   `yaml:"key-algorithm,omitempty"`
	SignatureAlgorithm string   `yaml:"signature-algorithm,omitempty"`
	KeyUsages          []string `yaml:"key-usages,omitempty"`
	ExtendedKeyUsages  []string `yaml:"extended-key-usages,omitempty"`
	AltNames           []string `yaml:"alt-names,omitempty"`
}

type agentCertificateLifecycle struct {
	RenewBeforeExpiry   string `yaml:"renew-before-expiry"`
	StatusCheckInterval string `yaml:"status-check-interval"`
}

type agentCertificateFileOutput struct {
	Certificate agentFileOutputEntry `yaml:"certificate"`
	PrivateKey  agentFileOutputEntry `yaml:"private-key"`
	Chain       agentFileOutputEntry `yaml:"chain"`
}

type agentFileOutputEntry struct {
	Path       string `yaml:"path"`
	Permission string `yaml:"permission,omitempty"`
}

type agentCertificatePostHooks struct {
	OnIssuance *agentPostHookEntry `yaml:"on-issuance,omitempty"`
	OnRenewal  *agentPostHookEntry `yaml:"on-renewal,omitempty"`
	OnFailure  *agentPostHookEntry `yaml:"on-failure,omitempty"`
}

type agentPostHookEntry struct {
	Command string `yaml:"command"`
	Timeout int    `yaml:"timeout"`
}

func (h *CertAgentTestHelper) GenerateAgentConfig(opts AgentConfigOptions) string {
	t := h.T

	var certs []agentCertificateConfig
	for _, cert := range opts.Certificates {
		c := agentCertificateConfig{
			ProjectSlug: cert.ProjectSlug,
			ProfileName: cert.ProfileSlug,
			CSR:         cert.CSR,
			CSRPath:     cert.CSRPath,
			Attributes: &agentCertificateAttributes{
				CommonName:         cert.CommonName,
				TTL:                cert.TTL,
				KeyAlgorithm:       cert.KeyAlgorithm,
				SignatureAlgorithm: cert.SignatureAlgorithm,
				KeyUsages:          cert.KeyUsages,
				ExtendedKeyUsages:  cert.ExtendedKeyUsages,
				AltNames:           cert.AltNames,
			},
			Lifecycle: agentCertificateLifecycle{
				RenewBeforeExpiry:   cert.RenewBeforeExpiry,
				StatusCheckInterval: cert.StatusCheckInterval,
			},
			FileOutput: agentCertificateFileOutput{
				Certificate: agentFileOutputEntry{Path: cert.CertPath, Permission: cert.CertPermission},
				PrivateKey:  agentFileOutputEntry{Path: cert.KeyPath, Permission: cert.KeyPermission},
				Chain:       agentFileOutputEntry{Path: cert.ChainPath, Permission: cert.ChainPermission},
			},
		}

		if cert.PostHookOnIssuance != "" || cert.PostHookOnRenewal != "" || cert.PostHookOnFailure != "" {
			c.PostHooks = &agentCertificatePostHooks{}
			if cert.PostHookOnIssuance != "" {
				c.PostHooks.OnIssuance = &agentPostHookEntry{Command: cert.PostHookOnIssuance, Timeout: 30}
			}
			if cert.PostHookOnRenewal != "" {
				c.PostHooks.OnRenewal = &agentPostHookEntry{Command: cert.PostHookOnRenewal, Timeout: 30}
			}
			if cert.PostHookOnFailure != "" {
				c.PostHooks.OnFailure = &agentPostHookEntry{Command: cert.PostHookOnFailure, Timeout: 30}
			}
		}

		certs = append(certs, c)
	}

	cfg := agentConfig{
		Version: "v1",
		Infisical: agentInfisicalConfig{
			Address: h.InfisicalURL,
		},
		Auth: agentAuthConfig{
			Type: "universal-auth",
			Config: agentUniversalAuthConfig{
				ClientID:     opts.ClientIDPath,
				ClientSecret: opts.ClientSecretPath,
			},
		},
		Certificates: certs,
	}

	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)

	configPath := filepath.Join(h.TempDir, "agent-config.yaml")
	err = os.WriteFile(configPath, data, 0644)
	require.NoError(t, err)

	return configPath
}

type AgentConfigOptions struct {
	ClientIDPath     string
	ClientSecretPath string
	Certificates     []CertificateConfigEntry
}

type CertificateConfigEntry struct {
	ProjectSlug         string
	ProfileSlug         string
	CommonName          string
	TTL                 string
	RenewBeforeExpiry   string
	StatusCheckInterval string
	CertPath            string
	KeyPath             string
	ChainPath           string
	PostHookOnIssuance  string
	PostHookOnRenewal   string
	AltNames            []string
	CertPermission      string
	KeyPermission       string
	ChainPermission     string
	PostHookOnFailure   string
	CSR                 string
	CSRPath             string
	KeyAlgorithm        string
	SignatureAlgorithm  string
	KeyUsages           []string
	ExtendedKeyUsages   []string
}

func (h *CertAgentTestHelper) WriteCredentialFiles() (clientIDPath, clientSecretPath string) {
	t := h.T

	clientIDPath = filepath.Join(h.TempDir, "client-id")
	err := os.WriteFile(clientIDPath, []byte(h.ClientID), 0600)
	require.NoError(t, err)

	clientSecretPath = filepath.Join(h.TempDir, "client-secret")
	err = os.WriteFile(clientSecretPath, []byte(h.ClientSecret), 0600)
	require.NoError(t, err)

	return clientIDPath, clientSecretPath
}

func VerifyCertificateFile(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read certificate file at %s", path)
	require.NotEmpty(t, data, "Certificate file at %s is empty", path)

	block, _ := pem.Decode(data)
	require.NotNil(t, block, "Failed to decode PEM block from %s", path)
	require.Equal(t, "CERTIFICATE", block.Type, "Expected CERTIFICATE PEM block, got %s", block.Type)

	_, err = x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Failed to parse x509 certificate from %s", path)
}

func VerifyPrivateKeyFile(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read private key file at %s", path)
	require.NotEmpty(t, data, "Private key file at %s is empty", path)

	block, _ := pem.Decode(data)
	require.NotNil(t, block, "Failed to decode PEM block from %s", path)

	_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			_, err = x509.ParseECPrivateKey(block.Bytes)
			require.NoError(t, err, "Failed to parse private key from %s (tried PKCS8, PKCS1, EC)", path)
		}
	}
}

func VerifyChainFile(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read chain file at %s", path)
	if len(data) == 0 {
		return
	}

	block, _ := pem.Decode(data)
	require.NotNil(t, block, "Failed to decode PEM block from chain file %s", path)
	require.Equal(t, "CERTIFICATE", block.Type, "Expected CERTIFICATE PEM block in chain, got %s", block.Type)
}

func VerifyCertificateAltNames(t *testing.T, certPath string, expectedAltNames []string) {
	t.Helper()

	data, err := os.ReadFile(certPath)
	require.NoError(t, err, "Failed to read certificate file at %s", certPath)

	block, _ := pem.Decode(data)
	require.NotNil(t, block, "Failed to decode PEM block from %s", certPath)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Failed to parse x509 certificate from %s", certPath)

	for _, expected := range expectedAltNames {
		require.Contains(t, cert.DNSNames, expected, "Certificate should contain SAN DNS name %s, got %v", expected, cert.DNSNames)
	}
}

func VerifyFilePermission(t *testing.T, filePath string, expectedPerm os.FileMode) {
	t.Helper()

	info, err := os.Stat(filePath)
	require.NoError(t, err, "Failed to stat file at %s", filePath)

	actualPerm := info.Mode().Perm()
	require.Equal(t, expectedPerm, actualPerm, "File %s has permission %o, expected %o", filePath, actualPerm, expectedPerm)
}

func VerifyCertificateCommonName(t *testing.T, certPath string, expectedCN string) {
	t.Helper()

	data, err := os.ReadFile(certPath)
	require.NoError(t, err, "Failed to read certificate file at %s", certPath)

	block, _ := pem.Decode(data)
	require.NotNil(t, block, "Failed to decode PEM block from %s", certPath)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Failed to parse x509 certificate from %s", certPath)

	require.Equal(t, expectedCN, cert.Subject.CommonName,
		"Certificate CN mismatch: expected %s, got %s", expectedCN, cert.Subject.CommonName)
}

func VerifyCertificateDNSName(t *testing.T, certPath string, expectedDNS string) {
	t.Helper()

	data, err := os.ReadFile(certPath)
	require.NoError(t, err, "Failed to read certificate file at %s", certPath)

	block, _ := pem.Decode(data)
	require.NotNil(t, block, "Failed to decode PEM block from %s", certPath)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Failed to parse x509 certificate from %s", certPath)

	require.Contains(t, cert.DNSNames, expectedDNS,
		"Certificate should contain SAN DNS name %s, got %v", expectedDNS, cert.DNSNames)
}

func VerifyCertificateKeyUsages(t *testing.T, certPath string, expectedUsages []string) {
	t.Helper()

	data, err := os.ReadFile(certPath)
	require.NoError(t, err, "Failed to read certificate file at %s", certPath)

	block, _ := pem.Decode(data)
	require.NotNil(t, block, "Failed to decode PEM block from %s", certPath)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Failed to parse x509 certificate from %s", certPath)

	keyUsageMap := map[string]x509.KeyUsage{
		"digital_signature":  x509.KeyUsageDigitalSignature,
		"key_encipherment":   x509.KeyUsageKeyEncipherment,
		"data_encipherment":  x509.KeyUsageDataEncipherment,
		"cert_sign":          x509.KeyUsageCertSign,
		"crl_sign":           x509.KeyUsageCRLSign,
		"content_commitment": x509.KeyUsageContentCommitment,
	}

	for _, usage := range expectedUsages {
		if ku, ok := keyUsageMap[usage]; ok {
			require.True(t, cert.KeyUsage&ku != 0,
				"Certificate should have key usage %s, but it does not (key usage bits: %b)", usage, cert.KeyUsage)
		}
	}
}

func VerifyCertificateExtendedKeyUsages(t *testing.T, certPath string, expectedUsages []string) {
	t.Helper()

	data, err := os.ReadFile(certPath)
	require.NoError(t, err, "Failed to read certificate file at %s", certPath)

	block, _ := pem.Decode(data)
	require.NotNil(t, block, "Failed to decode PEM block from %s", certPath)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Failed to parse x509 certificate from %s", certPath)

	extKeyUsageMap := map[string]x509.ExtKeyUsage{
		"server_auth":  x509.ExtKeyUsageServerAuth,
		"client_auth":  x509.ExtKeyUsageClientAuth,
		"code_signing": x509.ExtKeyUsageCodeSigning,
	}

	for _, usage := range expectedUsages {
		if eku, ok := extKeyUsageMap[usage]; ok {
			found := false
			for _, certEku := range cert.ExtKeyUsage {
				if certEku == eku {
					found = true
					break
				}
			}
			require.True(t, found,
				"Certificate should have extended key usage %s, but it does not", usage)
		}
	}
}

func (h *CertAgentTestHelper) IsBddNockAvailable() bool {
	url := h.InfisicalURL + "/api/__bdd_nock__/define"
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.AdminToken)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed
}

func (h *CertAgentTestHelper) SetupBddNockMocks(certCount int) {
	t := h.T

	if certCount < 1 {
		certCount = 1
	}

	fakeAccountID := "fake-account-id"
	fakeZoneID := "fake-zone-id"

	definitions := []map[string]interface{}{
		{
			"scope":  "https://api.cloudflare.com",
			"method": "GET",
			"path":   fmt.Sprintf("/client/v4/accounts/%s", fakeAccountID),
			"status": 200,
			"response": map[string]interface{}{
				"success": true,
				"result":  map[string]interface{}{"id": fakeAccountID},
			},
		},
	}

	for i := 0; i < certCount; i++ {
		definitions = append(definitions,
			map[string]interface{}{
				"scope":  "https://api.cloudflare.com",
				"method": "POST",
				"path":   fmt.Sprintf("/client/v4/zones/%s/dns_records", fakeZoneID),
				"status": 200,
				"response": map[string]interface{}{
					"success": true,
					"result":  map[string]interface{}{"id": "fake-dns-record-id"},
				},
			},
			map[string]interface{}{
				"scope":  "https://api.cloudflare.com",
				"method": "GET",
				"path": map[string]string{
					"regex": fmt.Sprintf("/client/v4/zones/%s/dns_records.*", fakeZoneID),
				},
				"status": 200,
				"response": map[string]interface{}{
					"success": true,
					"result":  []interface{}{},
				},
			},
		)
	}

	body := map[string]interface{}{
		"definitions": definitions,
	}

	h.doPostWithToken("/__bdd_nock__/define", body, h.AdminToken)
	t.Log("BDD nock mocks configured for Cloudflare API")
}

func (h *CertAgentTestHelper) CreateCloudflareAppConnection() string {
	t := h.T

	body := map[string]interface{}{
		"name":   "test-cloudflare-conn",
		"method": "api-token",
		"credentials": map[string]interface{}{
			"accountId": "fake-account-id",
			"apiToken":  "fake-api-token",
		},
	}

	respBody := h.doPostWithToken("/v1/app-connections/cloudflare", body, h.AdminToken)

	var resp map[string]interface{}
	err := json.Unmarshal(respBody, &resp)
	require.NoError(t, err, "Failed to unmarshal create Cloudflare connection response: %s", string(respBody))

	connectionID := ""
	if ac, ok := resp["appConnection"].(map[string]interface{}); ok {
		if id, ok := ac["id"].(string); ok {
			connectionID = id
		}
	}
	if connectionID == "" {
		if id, ok := resp["id"].(string); ok {
			connectionID = id
		}
	}
	require.NotEmpty(t, connectionID, "Cloudflare connection ID should not be empty, response: %s", string(respBody))

	return connectionID
}

func (h *CertAgentTestHelper) CreateAcmeCA(dnsConnectionID, directoryUrl string) {
	t := h.T

	body := map[string]interface{}{
		"name":      "test-acme-ca",
		"projectId": h.ProjectID,
		"status":    "active",
		"configuration": map[string]interface{}{
			"dnsAppConnectionId": dnsConnectionID,
			"dnsProviderConfig": map[string]interface{}{
				"provider":     "cloudflare",
				"hostedZoneId": "fake-zone-id",
			},
			"directoryUrl": directoryUrl,
			"accountEmail": "test@example.com",
		},
	}

	respBody := h.doPost("/v1/cert-manager/ca/acme", body)

	var resp map[string]interface{}
	err := json.Unmarshal(respBody, &resp)
	require.NoError(t, err, "Failed to unmarshal create ACME CA response: %s", string(respBody))

	caID := ""
	if id, ok := resp["id"].(string); ok {
		caID = id
	} else if ca, ok := resp["ca"].(map[string]interface{}); ok {
		if id, ok := ca["id"].(string); ok {
			caID = id
		}
	}
	require.NotEmpty(t, caID, "ACME CA ID should not be empty, response: %s", string(respBody))

	h.CaID = caID
}

func GenerateCSR(t *testing.T, commonName string) (csrPEM string, keyPEM string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: []string{commonName},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err, "Failed to create CSR")

	csrBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}
	csrBuf := pem.EncodeToMemory(csrBlock)

	keyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	keyBuf := pem.EncodeToMemory(keyBlock)

	return string(csrBuf), string(keyBuf)
}
