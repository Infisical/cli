package agent

import (
	"bytes"
	"context"
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

	"github.com/google/uuid"
	client "github.com/infisical/cli/e2e-tests/packages/client"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type CertAgentTestHelper struct {
	T              *testing.T
	ProjectID      string
	ProjectSlug    string
	ProfileSlug    string
	ProfileID      string
	PolicyID       string
	CaID           string
	AdminToken     string
	InfisicalURL   string
	TempDir        string
	ClientID       string
	ClientSecret   string
	IdentityClient *client.ClientWithResponses
	AdminClient    *client.ClientWithResponses
}

func (h *CertAgentTestHelper) CreateInternalCA() {
	t := h.T
	ctx := context.Background()

	friendlyName := "Test Root CA"
	commonName := "Test Root CA"
	organization := "Test Org"
	ou := ""
	country := "US"
	province := ""
	locality := ""
	maxPathLength := float32(-1)
	notAfter := time.Now().AddDate(10, 0, 0).UTC().Format(time.RFC3339)

	resp, err := h.IdentityClient.CreateInternalCertificateAuthorityV1WithResponse(ctx, client.CreateInternalCertificateAuthorityV1JSONRequestBody{
		Name:      "test-root-ca",
		ProjectId: uuid.MustParse(h.ProjectID),
		Status:    client.Active,
		Configuration: struct {
			ActiveCaCertId *openapi_types.UUID                                                          `json:"activeCaCertId"`
			CommonName     *string                                                                      `json:"commonName,omitempty"`
			Country        *string                                                                      `json:"country,omitempty"`
			Dn             *string                                                                      `json:"dn"`
			FriendlyName   *string                                                                      `json:"friendlyName,omitempty"`
			KeyAlgorithm   client.CreateInternalCertificateAuthorityV1JSONBodyConfigurationKeyAlgorithm `json:"keyAlgorithm"`
			Locality       *string                                                                      `json:"locality,omitempty"`
			MaxPathLength  *float32                                                                     `json:"maxPathLength"`
			NotAfter       *string                                                                      `json:"notAfter,omitempty"`
			NotBefore      *string                                                                      `json:"notBefore,omitempty"`
			Organization   *string                                                                      `json:"organization,omitempty"`
			Ou             *string                                                                      `json:"ou,omitempty"`
			ParentCaId     *openapi_types.UUID                                                          `json:"parentCaId"`
			Province       *string                                                                      `json:"province,omitempty"`
			SerialNumber   *string                                                                      `json:"serialNumber"`
			Type           client.CreateInternalCertificateAuthorityV1JSONBodyConfigurationType         `json:"type"`
		}{
			Type:          client.Root,
			FriendlyName:  &friendlyName,
			CommonName:    &commonName,
			Organization:  &organization,
			Ou:            &ou,
			Country:       &country,
			Province:      &province,
			Locality:      &locality,
			MaxPathLength: &maxPathLength,
			KeyAlgorithm:  client.CreateInternalCertificateAuthorityV1JSONBodyConfigurationKeyAlgorithmRSA2048,
			NotAfter:      &notAfter,
		},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode(), "Failed to create internal CA: %s", string(resp.Body))
	require.NotNil(t, resp.JSON200)

	h.CaID = resp.JSON200.Id.String()
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
	ctx := context.Background()

	cfg := &certificatePolicyConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	allAllowed := []string{"*"}
	reqBody := client.CreateCertificatePolicyJSONRequestBody{
		ProjectId: h.ProjectID,
		Name:      name,
		Subject: &[]struct {
			Allowed  *[]string                                         `json:"allowed,omitempty"`
			Denied   *[]string                                         `json:"denied,omitempty"`
			Required *[]string                                         `json:"required,omitempty"`
			Type     client.CreateCertificatePolicyJSONBodySubjectType `json:"type"`
		}{
			{
				Type:    client.CreateCertificatePolicyJSONBodySubjectType("common_name"),
				Allowed: &allAllowed,
			},
		},
	}

	if cfg.allowAltNames {
		reqBody.Sans = &[]struct {
			Allowed  *[]string                                      `json:"allowed,omitempty"`
			Denied   *[]string                                      `json:"denied,omitempty"`
			Required *[]string                                      `json:"required,omitempty"`
			Type     client.CreateCertificatePolicyJSONBodySansType `json:"type"`
		}{
			{
				Type:    client.CreateCertificatePolicyJSONBodySansType("dns_name"),
				Allowed: &allAllowed,
			},
		}
	}

	if len(cfg.allowKeyAlgorithms) > 0 || len(cfg.allowSignatureAlgorithms) > 0 {
		algos := &struct {
			KeyAlgorithm *[]string `json:"keyAlgorithm,omitempty"`
			Signature    *[]string `json:"signature,omitempty"`
		}{}
		if len(cfg.allowKeyAlgorithms) > 0 {
			algos.KeyAlgorithm = &cfg.allowKeyAlgorithms
		}
		if len(cfg.allowSignatureAlgorithms) > 0 {
			algos.Signature = &cfg.allowSignatureAlgorithms
		}
		reqBody.Algorithms = algos
	}

	if len(cfg.allowKeyUsages) > 0 {
		allowed := make([]client.CreateCertificatePolicyJSONBodyKeyUsagesAllowed, len(cfg.allowKeyUsages))
		for i, u := range cfg.allowKeyUsages {
			allowed[i] = client.CreateCertificatePolicyJSONBodyKeyUsagesAllowed(u)
		}
		reqBody.KeyUsages = &struct {
			Allowed  *[]client.CreateCertificatePolicyJSONBodyKeyUsagesAllowed  `json:"allowed,omitempty"`
			Denied   *[]client.CreateCertificatePolicyJSONBodyKeyUsagesDenied   `json:"denied,omitempty"`
			Required *[]client.CreateCertificatePolicyJSONBodyKeyUsagesRequired `json:"required,omitempty"`
		}{
			Allowed: &allowed,
		}
	}

	if len(cfg.allowExtendedKeyUsages) > 0 {
		allowed := make([]client.CreateCertificatePolicyJSONBodyExtendedKeyUsagesAllowed, len(cfg.allowExtendedKeyUsages))
		for i, u := range cfg.allowExtendedKeyUsages {
			allowed[i] = client.CreateCertificatePolicyJSONBodyExtendedKeyUsagesAllowed(u)
		}
		reqBody.ExtendedKeyUsages = &struct {
			Allowed  *[]client.CreateCertificatePolicyJSONBodyExtendedKeyUsagesAllowed  `json:"allowed,omitempty"`
			Denied   *[]client.CreateCertificatePolicyJSONBodyExtendedKeyUsagesDenied   `json:"denied,omitempty"`
			Required *[]client.CreateCertificatePolicyJSONBodyExtendedKeyUsagesRequired `json:"required,omitempty"`
		}{
			Allowed: &allowed,
		}
	}

	resp, err := h.IdentityClient.CreateCertificatePolicyWithResponse(ctx, reqBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode(), "Failed to create certificate policy: %s", string(resp.Body))
	require.NotNil(t, resp.JSON200)

	h.PolicyID = resp.JSON200.CertificatePolicy.Id.String()
}

func (h *CertAgentTestHelper) CreateCertificateProfile(slug string) {
	t := h.T
	ctx := context.Background()

	caID := uuid.MustParse(h.CaID)
	autoRenew := false
	issuerType := client.CreateCertificateProfileJSONBodyIssuerType("ca")

	resp, err := h.IdentityClient.CreateCertificateProfileWithResponse(ctx, client.CreateCertificateProfileJSONRequestBody{
		ProjectId:           h.ProjectID,
		CaId:                &caID,
		CertificatePolicyId: uuid.MustParse(h.PolicyID),
		Slug:                slug,
		EnrollmentType:      client.CreateCertificateProfileJSONBodyEnrollmentType("api"),
		IssuerType:          &issuerType,
		ApiConfig: &struct {
			AutoRenew       *bool    `json:"autoRenew,omitempty"`
			RenewBeforeDays *float32 `json:"renewBeforeDays,omitempty"`
		}{
			AutoRenew: &autoRenew,
		},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode(), "Failed to create certificate profile: %s", string(resp.Body))
	require.NotNil(t, resp.JSON200)

	h.ProfileID = resp.JSON200.CertificateProfile.Id.String()
	h.ProfileSlug = resp.JSON200.CertificateProfile.Slug
}

func (h *CertAgentTestHelper) SetupUniversalAuth(identityID string) {
	t := h.T
	ctx := context.Background()

	ttl := 2592000
	maxTTL := 2592000
	numUses := 0

	attachResp, err := h.AdminClient.AttachUniversalAuthWithResponse(ctx, identityID, client.AttachUniversalAuthJSONRequestBody{
		AccessTokenTTL:          &ttl,
		AccessTokenMaxTTL:       &maxTTL,
		AccessTokenNumUsesLimit: &numUses,
		AccessTokenTrustedIps: &[]struct {
			IpAddress string `json:"ipAddress"`
		}{
			{IpAddress: "0.0.0.0/0"},
			{IpAddress: "::/0"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, attachResp.StatusCode(), "Failed to attach universal auth: %s", string(attachResp.Body))
	require.NotNil(t, attachResp.JSON200)

	h.ClientID = attachResp.JSON200.IdentityUniversalAuth.ClientId

	csResp, err := h.AdminClient.CreateUniversalAuthClientSecretWithResponse(ctx, identityID, client.CreateUniversalAuthClientSecretJSONRequestBody{})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, csResp.StatusCode(), "Failed to create universal auth client secret: %s", string(csResp.Body))
	require.NotNil(t, csResp.JSON200)

	h.ClientSecret = csResp.JSON200.ClientSecret
}

func (h *CertAgentTestHelper) CreateAcmeCA(dnsConnectionID, directoryUrl string) {
	t := h.T
	ctx := context.Background()

	resp, err := h.IdentityClient.CreateAcmeCertificateAuthorityV1WithResponse(ctx, client.CreateAcmeCertificateAuthorityV1JSONRequestBody{
		Name:      "test-acme-ca",
		ProjectId: uuid.MustParse(h.ProjectID),
		Status:    client.CreateAcmeCertificateAuthorityV1JSONBodyStatusActive,
		Configuration: struct {
			AccountEmail       string             `json:"accountEmail"`
			DirectoryUrl       string             `json:"directoryUrl"`
			DnsAppConnectionId openapi_types.UUID `json:"dnsAppConnectionId"`
			DnsProviderConfig struct {
				HostedZoneId string                                                                                `json:"hostedZoneId"`
				Provider     client.CreateAcmeCertificateAuthorityV1JSONBodyConfigurationDnsProviderConfigProvider `json:"provider"`
			} `json:"dnsProviderConfig"`
			DnsResolver *string `json:"dnsResolver,omitempty"`
			EabHmacKey  *string `json:"eabHmacKey,omitempty"`
			EabKid      *string `json:"eabKid,omitempty"`
		}{
			DnsAppConnectionId: uuid.MustParse(dnsConnectionID),
			DnsProviderConfig: struct {
				HostedZoneId string                                                                                `json:"hostedZoneId"`
				Provider     client.CreateAcmeCertificateAuthorityV1JSONBodyConfigurationDnsProviderConfigProvider `json:"provider"`
			}{
				Provider:     client.CreateAcmeCertificateAuthorityV1JSONBodyConfigurationDnsProviderConfigProviderCloudflare,
				HostedZoneId: "fake-zone-id",
			},
			DirectoryUrl: directoryUrl,
			AccountEmail: "test@example.com",
		},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode(), "Failed to create ACME CA: %s", string(resp.Body))
	require.NotNil(t, resp.JSON200)

	h.CaID = resp.JSON200.Id.String()
}

func (h *CertAgentTestHelper) DisableAcmeCA(caID string) {
	t := h.T
	ctx := context.Background()

	status := client.UpdateAcmeCertificateAuthorityV1JSONBodyStatus("disabled")
	resp, err := h.IdentityClient.UpdateAcmeCertificateAuthorityV1WithResponse(ctx, caID, client.UpdateAcmeCertificateAuthorityV1JSONRequestBody{
		Status: &status,
	})
	require.NoError(t, err)
	require.True(t, resp.StatusCode() >= 200 && resp.StatusCode() < 300,
		"Failed to disable ACME CA, status %d: %s", resp.StatusCode(), string(resp.Body))
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

func (h *CertAgentTestHelper) CreateAcmeCARaw(name, dnsConnectionID, directoryUrl, provider, hostedZoneId, accountEmail string) (int, []byte) {
	t := h.T
	ctx := context.Background()

	resp, err := h.IdentityClient.CreateAcmeCertificateAuthorityV1WithResponse(ctx, client.CreateAcmeCertificateAuthorityV1JSONRequestBody{
		Name:      name,
		ProjectId: uuid.MustParse(h.ProjectID),
		Status:    client.CreateAcmeCertificateAuthorityV1JSONBodyStatusActive,
		Configuration: struct {
			AccountEmail       string             `json:"accountEmail"`
			DirectoryUrl       string             `json:"directoryUrl"`
			DnsAppConnectionId openapi_types.UUID `json:"dnsAppConnectionId"`
			DnsProviderConfig struct {
				HostedZoneId string                                                                                `json:"hostedZoneId"`
				Provider     client.CreateAcmeCertificateAuthorityV1JSONBodyConfigurationDnsProviderConfigProvider `json:"provider"`
			} `json:"dnsProviderConfig"`
			DnsResolver *string `json:"dnsResolver,omitempty"`
			EabHmacKey  *string `json:"eabHmacKey,omitempty"`
			EabKid      *string `json:"eabKid,omitempty"`
		}{
			DnsAppConnectionId: uuid.MustParse(dnsConnectionID),
			DnsProviderConfig: struct {
				HostedZoneId string                                                                                `json:"hostedZoneId"`
				Provider     client.CreateAcmeCertificateAuthorityV1JSONBodyConfigurationDnsProviderConfigProvider `json:"provider"`
			}{
				Provider:     client.CreateAcmeCertificateAuthorityV1JSONBodyConfigurationDnsProviderConfigProvider(provider),
				HostedZoneId: hostedZoneId,
			},
			DirectoryUrl: directoryUrl,
			AccountEmail: accountEmail,
		},
	})
	require.NoError(t, err)

	return resp.StatusCode(), resp.Body
}

func (h *CertAgentTestHelper) CreateCloudflareAppConnection() string {
	t := h.T
	ctx := context.Background()

	body, err := json.Marshal(map[string]interface{}{
		"name":   "test-cloudflare-conn",
		"method": "api-token",
		"credentials": map[string]interface{}{
			"accountId": "fake-account-id",
			"apiToken":  "fake-api-token",
		},
	})
	require.NoError(t, err)

	resp, err := h.AdminClient.CreateCloudflareAppConnectionWithBodyWithResponse(ctx, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode(), "Failed to create Cloudflare connection: %s", string(resp.Body))

	var parsed map[string]interface{}
	err = json.Unmarshal(resp.Body, &parsed)
	require.NoError(t, err)

	connectionID := ""
	if ac, ok := parsed["appConnection"].(map[string]interface{}); ok {
		if id, ok := ac["id"].(string); ok {
			connectionID = id
		}
	}
	require.NotEmpty(t, connectionID, "Cloudflare connection ID should not be empty, response: %s", string(resp.Body))

	return connectionID
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
