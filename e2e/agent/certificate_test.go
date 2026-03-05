package agent_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"

	agentHelpers "github.com/infisical/cli/e2e-tests/agent"
	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	_ = godotenv.Load("../.env")
	os.Exit(m.Run())
}

func setupCertAgentTest(t *testing.T, ctx context.Context, policyOpts ...agentHelpers.CertificatePolicyOption) *agentHelpers.CertAgentTestHelper {
	infisical := helpers.NewInfisicalService().Up(t, ctx)

	identity := infisical.CreateMachineIdentity(t, ctx, helpers.WithTokenAuth())
	require.NotNil(t, identity.TokenAuthToken)
	identityToken := *identity.TokenAuthToken

	helper := &agentHelpers.CertAgentTestHelper{
		T:             t,
		IdentityToken: identityToken,
		AdminToken:    infisical.ProvisionResult().Token,
		InfisicalURL:  infisical.ApiUrl(t),
		TempDir:       t.TempDir(),
	}

	helper.SetupUniversalAuth(identity.Id)
	slog.Info("Universal auth configured", "clientID", helper.ClientID)

	bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(identityToken)
	require.NoError(t, err)

	identityClient, err := client.NewClientWithResponses(
		infisical.ApiUrl(t),
		client.WithHTTPClient(&http.Client{}),
		client.WithRequestEditorFn(bearerAuth.Intercept),
	)
	require.NoError(t, err)

	projectType := client.CertManager
	projectResp, err := identityClient.CreateProjectWithResponse(ctx, client.CreateProjectJSONRequestBody{
		ProjectName: "cert-test-" + helpers.RandomSlug(2),
		Type:        &projectType,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, projectResp.StatusCode(), "Failed to create project: %s", string(projectResp.Body))

	helper.ProjectID = projectResp.JSON200.Project.Id
	helper.ProjectSlug = projectResp.JSON200.Project.Slug
	slog.Info("Created cert-manager project", "id", helper.ProjectID, "slug", helper.ProjectSlug)

	helper.CreateInternalCA()
	slog.Info("Created internal CA", "id", helper.CaID)

	helper.CreateCertificatePolicy("test-policy-"+helpers.RandomSlug(2), policyOpts...)
	slog.Info("Created certificate policy", "id", helper.PolicyID)

	helper.CreateCertificateProfile("test-profile-" + helpers.RandomSlug(2))
	slog.Info("Created certificate profile", "id", helper.ProfileID, "name", helper.ProfileSlug)

	return helper
}

func certAgent_BasicCertificateIssuance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "test.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "certificate management engine starting",
		Timeout:          60 * time.Second,
		Interval:         2 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result, "Agent failed to start cert management engine")

	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "certificate issued successfully",
		Timeout:          120 * time.Second,
		Interval:         2 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result, "Certificate was not issued successfully")

	agentHelpers.VerifyCertificateFile(t, certPath)
	agentHelpers.VerifyPrivateKeyFile(t, keyPath)
	agentHelpers.VerifyChainFile(t, chainPath)
	agentHelpers.VerifyCertificateCommonName(t, certPath, "test.example.com")
}

func certAgent_CertificateRenewal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx,
		agentHelpers.WithAllowKeyAlgorithms("RSA_2048"),
		agentHelpers.WithAllowSignatureAlgorithms("SHA256-RSA"),
	)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	// Use short TTL (2m) and renew-before-expiry (1m30s) so renewal triggers at ~30s after issuance.
	// Explicitly set algorithms so the backend stores them correctly in the DB for renewal validation.
	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "renew.example.com",
				TTL:                 "2m",
				RenewBeforeExpiry:   "1m30s",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
				KeyAlgorithm:        "RSA_2048",
				SignatureAlgorithm:  "RSA-SHA256",
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "certificate issued successfully",
		Timeout:          120 * time.Second,
		Interval:         2 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result, "Initial certificate was not issued")

	initialCert, err := os.ReadFile(certPath)
	require.NoError(t, err)
	require.NotEmpty(t, initialCert)

	// Wait for the agent to complete renewal. With TTL=2m and renew-before-expiry=1m30s,
	// renewal should trigger ~30s after issuance.
	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Timeout:          90 * time.Second,
		Interval:         3 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "certificate renewed successfully") ||
				strings.Contains(stderr, "successfully renewed certificate") {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, waitResult, "Certificate renewal should complete. stderr:\n%s", cmd.Stderr())

	renewedCert, err := os.ReadFile(certPath)
	require.NoError(t, err)
	require.NotEqual(t, string(initialCert), string(renewedCert), "Certificate content should have changed after renewal")

	agentHelpers.VerifyCertificateFile(t, certPath)
	agentHelpers.VerifyPrivateKeyFile(t, keyPath)
}

func certAgent_PostHookExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	markerFile := filepath.Join(helper.TempDir, "hook-executed")

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "hook.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
				PostHookOnIssuance:  fmt.Sprintf("touch %s", markerFile),
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env: map[string]string{
			"PATH": os.Getenv("PATH"),
		},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "post-hook execution successful",
		Timeout:          120 * time.Second,
		Interval:         2 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result, "Post-hook was not executed successfully")

	_, err := os.Stat(markerFile)
	require.NoError(t, err, "Post-hook marker file should exist at %s", markerFile)

}

func certAgent_MultipleCertificates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx)

	firstProfileName := helper.ProfileSlug

	helper.CreateCertificateProfile("second-profile-" + helpers.RandomSlug(2))
	secondProfileName := helper.ProfileSlug
	slog.Info("Created second certificate profile", "name", secondProfileName)

	certDir1 := filepath.Join(helper.TempDir, "cert1")
	certDir2 := filepath.Join(helper.TempDir, "cert2")
	require.NoError(t, os.MkdirAll(certDir1, 0755))
	require.NoError(t, os.MkdirAll(certDir2, 0755))

	certPath1, keyPath1, chainPath1 := agentHelpers.CertFilePaths(certDir1)
	certPath2, keyPath2, chainPath2 := agentHelpers.CertFilePaths(certDir2)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         firstProfileName,
				CommonName:          "multi1.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath1,
				KeyPath:             keyPath1,
				ChainPath:           chainPath1,
			},
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         secondProfileName,
				CommonName:          "multi2.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath2,
				KeyPath:             keyPath2,
				ChainPath:           chainPath2,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "certificate management engine starting",
		Timeout:          60 * time.Second,
		Interval:         2 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result, "Agent failed to start cert management engine")

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Timeout:          120 * time.Second,
		Interval:         3 * time.Second,
		Condition: func() helpers.ConditionResult {
			if strings.Count(cmd.Stderr(), "certificate issued successfully") >= 2 {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, waitResult, "Both certificates should have been issued")

	agentHelpers.VerifyCertificateFile(t, certPath1)
	agentHelpers.VerifyPrivateKeyFile(t, keyPath1)
	agentHelpers.VerifyChainFile(t, chainPath1)

	agentHelpers.VerifyCertificateFile(t, certPath2)
	agentHelpers.VerifyPrivateKeyFile(t, keyPath2)
	agentHelpers.VerifyChainFile(t, chainPath2)

}

func certAgent_FilePermissions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "perms.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
				CertPermission:      "0644",
				KeyPermission:       "0640",
				ChainPermission:     "0644",
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "certificate issued successfully",
		Timeout:          120 * time.Second,
		Interval:         2 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result, "Certificate was not issued successfully")

	agentHelpers.VerifyCertificateFile(t, certPath)
	agentHelpers.VerifyPrivateKeyFile(t, keyPath)
	agentHelpers.VerifyChainFile(t, chainPath)

	agentHelpers.VerifyFilePermission(t, certPath, 0644)
	agentHelpers.VerifyFilePermission(t, keyPath, 0640)
	agentHelpers.VerifyFilePermission(t, chainPath, 0644)

}

func certAgent_AltNames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx, agentHelpers.WithAllowAltNames())

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	expectedAltNames := []string{"sub1.example.com", "sub2.example.com"}

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "altnames.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
				AltNames:            expectedAltNames,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "certificate issued successfully",
		Timeout:          120 * time.Second,
		Interval:         2 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result, "Certificate was not issued successfully")

	agentHelpers.VerifyCertificateFile(t, certPath)
	agentHelpers.VerifyPrivateKeyFile(t, keyPath)
	agentHelpers.VerifyChainFile(t, chainPath)

	agentHelpers.VerifyCertificateAltNames(t, certPath, expectedAltNames)

}

func certAgent_CSRBasedIssuance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx,
		agentHelpers.WithAllowKeyAlgorithms("RSA_2048"),
		agentHelpers.WithAllowSignatureAlgorithms("SHA256-RSA"),
		agentHelpers.WithAllowAltNames(),
	)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, _, chainPath := agentHelpers.CertFilePaths(certDir)
	keyPath := filepath.Join(certDir, "key.pem")

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	csrPEM, _ := agentHelpers.GenerateCSR(t, "csr-test.example.com")

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "csr-test.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
				CSR:                 csrPEM,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Timeout:          120 * time.Second,
		Interval:         2 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "certificate issued successfully") {
				return helpers.ConditionSuccess
			}
			if strings.Contains(stderr, "failed to issue certificate") {
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})

	require.Equal(t, helpers.WaitSuccess, waitResult, "CSR-based issuance should succeed. stderr:\n%s", cmd.Stderr())

	agentHelpers.VerifyCertificateFile(t, certPath)
	agentHelpers.VerifyChainFile(t, chainPath)
}

func certAgent_CSRPathBasedIssuance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx,
		agentHelpers.WithAllowKeyAlgorithms("RSA_2048"),
		agentHelpers.WithAllowSignatureAlgorithms("SHA256-RSA"),
		agentHelpers.WithAllowAltNames(),
	)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, _, chainPath := agentHelpers.CertFilePaths(certDir)
	keyPath := filepath.Join(certDir, "key.pem")

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	csrPEM, _ := agentHelpers.GenerateCSR(t, "csrpath-test.example.com")
	csrFilePath := filepath.Join(helper.TempDir, "test.csr")
	err := os.WriteFile(csrFilePath, []byte(csrPEM), 0600)
	require.NoError(t, err)

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "csrpath-test.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
				CSRPath:             csrFilePath,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Timeout:          120 * time.Second,
		Interval:         2 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "certificate issued successfully") {
				return helpers.ConditionSuccess
			}
			if strings.Contains(stderr, "failed to issue certificate") {
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})

	require.Equal(t, helpers.WaitSuccess, waitResult, "CSR-path based issuance should succeed. stderr:\n%s", cmd.Stderr())

	agentHelpers.VerifyCertificateFile(t, certPath)
	agentHelpers.VerifyChainFile(t, chainPath)
}

func certAgent_AcmeCA_CertificateIssuance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper, _ := setupAcmeCertAgentTest(t, ctx)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "acme-test.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Timeout:          180 * time.Second,
		Interval:         3 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "certificate issued successfully") {
				return helpers.ConditionSuccess
			}
			if strings.Contains(stderr, "failed to issue certificate") ||
				strings.Contains(stderr, "initial certificate issuance failed") ||
				strings.Contains(stderr, "certificate request failed") {
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})

	require.Equal(t, helpers.WaitSuccess, waitResult, "ACME certificate issuance should succeed. stderr:\n%s", cmd.Stderr())

	agentHelpers.VerifyCertificateFile(t, certPath)
	agentHelpers.VerifyPrivateKeyFile(t, keyPath)
	if _, err := os.Stat(chainPath); err == nil {
		agentHelpers.VerifyChainFile(t, chainPath)
	}
}

func setupAcmeCertAgentTest(t *testing.T, ctx context.Context, certCount ...int) (*agentHelpers.CertAgentTestHelper, string) { //nolint:unparam
	return setupAcmeCertAgentTestWithOpts(t, ctx, nil, certCount...)
}

func setupAcmeCertAgentTestWithOpts(t *testing.T, ctx context.Context, policyOpts []agentHelpers.CertificatePolicyOption, certCount ...int) (*agentHelpers.CertAgentTestHelper, string) {
	infisical := helpers.NewInfisicalService(helpers.WithAcme()).Up(t, ctx)

	identity := infisical.CreateMachineIdentity(t, ctx, helpers.WithTokenAuth())
	require.NotNil(t, identity.TokenAuthToken)
	identityToken := *identity.TokenAuthToken

	helper := &agentHelpers.CertAgentTestHelper{
		T:             t,
		IdentityToken: identityToken,
		AdminToken:    infisical.ProvisionResult().Token,
		InfisicalURL:  infisical.ApiUrl(t),
		TempDir:       t.TempDir(),
	}

	helper.SetupUniversalAuth(identity.Id)

	bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(identityToken)
	require.NoError(t, err)

	identityClient, err := client.NewClientWithResponses(
		infisical.ApiUrl(t),
		client.WithHTTPClient(&http.Client{}),
		client.WithRequestEditorFn(bearerAuth.Intercept),
	)
	require.NoError(t, err)

	projectType := client.CertManager
	projectResp, err := identityClient.CreateProjectWithResponse(ctx, client.CreateProjectJSONRequestBody{
		ProjectName: "cert-acme-" + helpers.RandomSlug(2),
		Type:        &projectType,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, projectResp.StatusCode(), "Failed to create project: %s", string(projectResp.Body))

	helper.ProjectID = projectResp.JSON200.Project.Id
	helper.ProjectSlug = projectResp.JSON200.Project.Slug

	if !helper.IsBddNockAvailable() {
		t.Skip("BDD nock API not available — backend was not built with Dockerfile.dev")
	}

	nockCertCount := 1
	if len(certCount) > 0 && certCount[0] > 1 {
		nockCertCount = certCount[0]
	}
	helper.SetupBddNockMocks(nockCertCount)

	connectionID := helper.CreateCloudflareAppConnection()

	helper.CreateAcmeCA(connectionID, helpers.PebbleInternalUrl())

	helper.CreateCertificatePolicy("acme-policy-"+helpers.RandomSlug(2), policyOpts...)
	helper.CreateCertificateProfile("acme-profile-" + helpers.RandomSlug(2))

	return helper, connectionID
}

func certAgent_AcmeCA_Validation_DuplicateCAName(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper, connectionID := setupAcmeCertAgentTest(t, ctx)

	statusCode, respBody := helper.CreateAcmeCARaw(
		"test-acme-ca",
		connectionID,
		helpers.PebbleInternalUrl(),
		"cloudflare",
		"fake-zone-id",
		"test@example.com",
	)

	require.Equal(t, http.StatusBadRequest, statusCode, "Duplicate CA name should return 400 Bad Request, got status %d: %s", statusCode, string(respBody))
}

func certAgent_AcmeCA_Validation_InvalidDirectoryUrl(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper, connectionID := setupAcmeCertAgentTest(t, ctx)

	statusCode, respBody := helper.CreateAcmeCARaw(
		"invalid-url-ca",
		connectionID,
		"not-a-valid-url",
		"cloudflare",
		"fake-zone-id",
		"test@example.com",
	)

	require.Equal(t, http.StatusUnprocessableEntity, statusCode, "Invalid directory URL should return 422 Unprocessable Entity, got status %d: %s", statusCode, string(respBody))
}

func certAgent_AcmeCA_Validation_MissingRequiredFields(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper, connectionID := setupAcmeCertAgentTest(t, ctx)

	statusCode, respBody := helper.CreateAcmeCARaw(
		"missing-email-ca",
		connectionID,
		helpers.PebbleInternalUrl(),
		"cloudflare",
		"fake-zone-id",
		"",
	)

	require.Equal(t, http.StatusUnprocessableEntity, statusCode, "Missing accountEmail should return 422 Unprocessable Entity, got status %d: %s", statusCode, string(respBody))

	statusCode, respBody = helper.CreateAcmeCARaw(
		"missing-zone-ca",
		connectionID,
		helpers.PebbleInternalUrl(),
		"cloudflare",
		"",
		"test@example.com",
	)

	require.Equal(t, http.StatusUnprocessableEntity, statusCode, "Missing hostedZoneId should return 422 Unprocessable Entity, got status %d: %s", statusCode, string(respBody))

}

func certAgent_AcmeCA_Validation_InvalidDnsProvider(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper, connectionID := setupAcmeCertAgentTest(t, ctx)

	statusCode, respBody := helper.CreateAcmeCARaw(
		"invalid-provider-ca",
		connectionID,
		helpers.PebbleInternalUrl(),
		"invalid-provider",
		"fake-zone-id",
		"test@example.com",
	)

	require.Equal(t, http.StatusUnprocessableEntity, statusCode, "Invalid DNS provider should return 422 Unprocessable Entity, got status %d: %s", statusCode, string(respBody))
}

func certAgent_AcmeCA_Validation_NonexistentAppConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper, _ := setupAcmeCertAgentTest(t, ctx)

	statusCode, respBody := helper.CreateAcmeCARaw(
		"bad-conn-ca",
		"00000000-0000-0000-0000-000000000000",
		helpers.PebbleInternalUrl(),
		"cloudflare",
		"fake-zone-id",
		"test@example.com",
	)

	require.Equal(t, http.StatusNotFound, statusCode, "Nonexistent app connection should return 404 Not Found, got status %d: %s", statusCode, string(respBody))
}

func certAgent_AcmeCA_DisabledCA(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper, _ := setupAcmeCertAgentTest(t, ctx)

	helper.DisableAcmeCA(helper.CaID)
	slog.Info("Disabled ACME CA", "id", helper.CaID)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "disabled-ca.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Timeout:          120 * time.Second,
		Interval:         3 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "failed to issue certificate") ||
				strings.Contains(stderr, "initial certificate issuance failed") ||
				strings.Contains(stderr, "CA is disabled") {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})

	require.Equal(t, helpers.WaitSuccess, waitResult, "Agent should report failure when CA is disabled")

	_, err := os.Stat(certPath)
	require.True(t, os.IsNotExist(err), "Certificate file should not exist when CA is disabled")

}

func certAgent_AcmeCA_MultipleCertificates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper, _ := setupAcmeCertAgentTest(t, ctx, 2)

	firstProfileSlug := helper.ProfileSlug

	helper.CreateCertificateProfile("acme-profile2-" + helpers.RandomSlug(2))
	secondProfileSlug := helper.ProfileSlug

	certDir1 := filepath.Join(helper.TempDir, "cert1")
	certDir2 := filepath.Join(helper.TempDir, "cert2")
	require.NoError(t, os.MkdirAll(certDir1, 0755))
	require.NoError(t, os.MkdirAll(certDir2, 0755))

	certPath1, keyPath1, chainPath1 := agentHelpers.CertFilePaths(certDir1)
	certPath2, keyPath2, chainPath2 := agentHelpers.CertFilePaths(certDir2)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         firstProfileSlug,
				CommonName:          "acme-multi1.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath1,
				KeyPath:             keyPath1,
				ChainPath:           chainPath1,
			},
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         secondProfileSlug,
				CommonName:          "acme-multi2.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath2,
				KeyPath:             keyPath2,
				ChainPath:           chainPath2,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Timeout:          600 * time.Second,
		Interval:         3 * time.Second,
		Condition: func() helpers.ConditionResult {
			_, err1 := os.Stat(certPath1)
			_, err2 := os.Stat(certPath2)
			if err1 == nil && err2 == nil {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})

	require.Equal(t, helpers.WaitSuccess, waitResult, "Both ACME certificates should be issued. stderr:\n%s", cmd.Stderr())

	agentHelpers.VerifyCertificateFile(t, certPath1)
	agentHelpers.VerifyPrivateKeyFile(t, keyPath1)
	if _, err := os.Stat(chainPath1); err == nil {
		agentHelpers.VerifyChainFile(t, chainPath1)
	}

	agentHelpers.VerifyCertificateFile(t, certPath2)
	agentHelpers.VerifyPrivateKeyFile(t, keyPath2)
	if _, err := os.Stat(chainPath2); err == nil {
		agentHelpers.VerifyChainFile(t, chainPath2)
	}
}

func certAgent_AcmeCA_PostHookExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper, _ := setupAcmeCertAgentTest(t, ctx)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	markerFile := filepath.Join(helper.TempDir, "acme-hook-executed")

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "acme-hook.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
				PostHookOnIssuance:  fmt.Sprintf("touch %s", markerFile),
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env: map[string]string{
			"PATH": os.Getenv("PATH"),
		},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Timeout:          180 * time.Second,
		Interval:         3 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "post-hook execution successful") {
				return helpers.ConditionSuccess
			}
			if strings.Contains(stderr, "failed to issue certificate") ||
				strings.Contains(stderr, "initial certificate issuance failed") {
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})

	require.Equal(t, helpers.WaitSuccess, waitResult, "ACME post-hook should execute successfully. stderr:\n%s", cmd.Stderr())

	_, err := os.Stat(markerFile)
	require.NoError(t, err, "Post-hook marker file should exist at %s", markerFile)
	agentHelpers.VerifyCertificateFile(t, certPath)
}

func certAgent_AcmeCA_CSRBasedIssuance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper, _ := setupAcmeCertAgentTestWithOpts(t, ctx, []agentHelpers.CertificatePolicyOption{
		agentHelpers.WithAllowKeyAlgorithms("RSA_2048"),
		agentHelpers.WithAllowSignatureAlgorithms("SHA256-RSA"),
		agentHelpers.WithAllowAltNames(),
	})

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, _, chainPath := agentHelpers.CertFilePaths(certDir)
	keyPath := filepath.Join(certDir, "key.pem")

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	csrPEM, _ := agentHelpers.GenerateCSR(t, "acme-csr.example.com")

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "acme-csr.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
				CSR:                 csrPEM,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Timeout:          180 * time.Second,
		Interval:         3 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "certificate issued successfully") {
				return helpers.ConditionSuccess
			}
			if strings.Contains(stderr, "failed to issue certificate") ||
				strings.Contains(stderr, "initial certificate issuance failed") ||
				strings.Contains(stderr, "certificate request failed") {
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})

	require.Equal(t, helpers.WaitSuccess, waitResult, "ACME CSR-based issuance should succeed. stderr:\n%s", cmd.Stderr())

	agentHelpers.VerifyCertificateFile(t, certPath)
	if _, err := os.Stat(chainPath); err == nil {
		agentHelpers.VerifyChainFile(t, chainPath)
	}
	agentHelpers.VerifyCertificateDNSName(t, certPath, "acme-csr.example.com")
}

func certAgent_IssuanceFailureReporting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         "nonexistent-profile-" + helpers.RandomSlug(2),
				CommonName:          "failure.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  120 * time.Second,
		Interval: 2 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "failed to resolve") ||
				strings.Contains(stderr, "failed to issue certificate") ||
				strings.Contains(stderr, "certificate request failed") ||
				strings.Contains(stderr, "initial certificate issuance failed") {
				return helpers.ConditionSuccess
			}
			if !cmd.IsRunning() {
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})

	require.True(t, waitResult == helpers.WaitSuccess || waitResult == helpers.WaitBreakEarly,
		"Agent should report a failure for nonexistent profile")

	stderr := cmd.Stderr()
	require.True(t,
		strings.Contains(stderr, "failed to resolve") ||
			strings.Contains(stderr, "failed to issue certificate") ||
			strings.Contains(stderr, "initial certificate issuance failed"),
		"Agent should log the failure reason in stderr")

	_, err := os.Stat(certPath)
	require.True(t, os.IsNotExist(err), "Certificate file should not exist when issuance fails")
}

func certAgent_CertificateWithFullAttributes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx,
		agentHelpers.WithAllowKeyAlgorithms("RSA_2048"),
		agentHelpers.WithAllowKeyUsages("digital_signature", "key_encipherment"),
		agentHelpers.WithAllowExtendedKeyUsages("server_auth"),
	)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "fullattrs.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
				KeyAlgorithm:        "RSA_2048",
				KeyUsages:           []string{"digital_signature", "key_encipherment"},
				ExtendedKeyUsages:   []string{"server_auth"},
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Timeout:          120 * time.Second,
		Interval:         2 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "certificate issued successfully") {
				return helpers.ConditionSuccess
			}
			if strings.Contains(stderr, "failed to issue certificate") ||
				strings.Contains(stderr, "initial certificate issuance failed") {
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})

	require.Equal(t, helpers.WaitSuccess, waitResult, "Certificate with full attributes should be issued. stderr:\n%s", cmd.Stderr())

	agentHelpers.VerifyCertificateFile(t, certPath)
	agentHelpers.VerifyPrivateKeyFile(t, keyPath)
	agentHelpers.VerifyChainFile(t, chainPath)

	agentHelpers.VerifyCertificateCommonName(t, certPath, "fullattrs.example.com")
	agentHelpers.VerifyCertificateKeyUsages(t, certPath, []string{"digital_signature", "key_encipherment"})
	agentHelpers.VerifyCertificateExtendedKeyUsages(t, certPath, []string{"server_auth"})
}

func certAgent_Validation_RenewBeforeExpiryExceedsTTL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	// renew-before-expiry (2h) exceeds TTL (1h)
	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "invalid-renew.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "2h",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  30 * time.Second,
		Interval: 1 * time.Second,
		Condition: func() helpers.ConditionResult {
			if !cmd.IsRunning() {
				return helpers.ConditionSuccess
			}
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "renew-before-expiry") && strings.Contains(stderr, "must be less than TTL") {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, waitResult, "Agent should fail validation for renew-before-expiry > TTL")

	stderr := cmd.Stderr()
	require.Contains(t, stderr, "renew-before-expiry", "Stderr should mention renew-before-expiry")
	require.Contains(t, stderr, "must be less than TTL", "Stderr should mention TTL constraint")

}

func certAgent_Validation_BothCSRAndCSRPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	csrPEM, _ := agentHelpers.GenerateCSR(t, "both-csr.example.com")
	csrFilePath := filepath.Join(helper.TempDir, "test.csr")
	err := os.WriteFile(csrFilePath, []byte(csrPEM), 0600)
	require.NoError(t, err)

	// Set both CSR and CSRPath — this should be rejected
	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "both-csr.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
				CSR:                 csrPEM,
				CSRPath:             csrFilePath,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  30 * time.Second,
		Interval: 1 * time.Second,
		Condition: func() helpers.ConditionResult {
			if !cmd.IsRunning() {
				return helpers.ConditionSuccess
			}
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "cannot specify both") {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, waitResult, "Agent should fail validation for both CSR and CSR-path")

	stderr := cmd.Stderr()
	require.Contains(t, stderr, "cannot specify both", "Stderr should mention that both CSR and CSR-path cannot be specified")

}

func certAgent_Validation_InvalidAuthCredentials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	fakeClientIDPath := filepath.Join(helper.TempDir, "fake-client-id")
	err := os.WriteFile(fakeClientIDPath, []byte("fake-client-id-00000"), 0600)
	require.NoError(t, err)

	fakeClientSecretPath := filepath.Join(helper.TempDir, "fake-client-secret")
	err = os.WriteFile(fakeClientSecretPath, []byte("fake-client-secret-00000"), 0600)
	require.NoError(t, err)

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     fakeClientIDPath,
		ClientSecretPath: fakeClientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "badauth.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  60 * time.Second,
		Interval: 2 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "unable to authenticate") ||
				strings.Contains(stderr, "UniversalAuthLogin failed") ||
				strings.Contains(stderr, "failed to create authenticated client") ||
				strings.Contains(stderr, "failed to resolve certificate name references") {
				return helpers.ConditionSuccess
			}
			if !cmd.IsRunning() {
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})

	require.True(t, waitResult == helpers.WaitSuccess || waitResult == helpers.WaitBreakEarly,
		"Agent should fail with invalid credentials")

}

func certAgent_Validation_MissingCertificatePath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "nopath.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            "",
				KeyPath:             "",
				ChainPath:           "",
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  120 * time.Second,
		Interval: 2 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "certificate.path is required") ||
				strings.Contains(stderr, "failed to write certificate") {
				return helpers.ConditionSuccess
			}
			if !cmd.IsRunning() {
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})

	require.True(t, waitResult == helpers.WaitSuccess || waitResult == helpers.WaitBreakEarly,
		"Agent should fail when certificate file paths are empty")

	stderr := cmd.Stderr()
	require.True(t,
		strings.Contains(stderr, "certificate.path is required") ||
			strings.Contains(stderr, "failed to write certificate"),
		"Stderr should report a path-related validation error, got:\n%s", stderr)
}

func certAgent_Validation_NonexistentProjectSlug(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         "nonexistent-project-slug",
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "bad-project.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  60 * time.Second,
		Interval: 2 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "failed to resolve") {
				return helpers.ConditionSuccess
			}
			if !cmd.IsRunning() {
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})

	require.True(t, waitResult == helpers.WaitSuccess || waitResult == helpers.WaitBreakEarly,
		"Agent should fail with nonexistent project slug")

	stderr := cmd.Stderr()
	require.Contains(t, stderr, "failed to resolve",
		"Agent should report resolution failure for nonexistent project slug")

}


func certAgent_OnRenewalPostHook(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Renewal re-validates the original cert's algorithms against the policy.
	helper := setupCertAgentTest(t, ctx,
		agentHelpers.WithAllowKeyAlgorithms("RSA_2048"),
		agentHelpers.WithAllowSignatureAlgorithms("SHA256-RSA"),
	)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	renewalMarker := filepath.Join(helper.TempDir, "on-renewal-hook-executed")

	// Short TTL (2m) and renew-before-expiry (1m30s) so renewal triggers ~30s after issuance
	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "renewal-hook.example.com",
				TTL:                 "2m",
				KeyAlgorithm:        "RSA_2048",
				SignatureAlgorithm:  "RSA-SHA256",
				RenewBeforeExpiry:   "1m30s",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
				PostHookOnRenewal:   fmt.Sprintf("touch %s", renewalMarker),
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env: map[string]string{
			"PATH": os.Getenv("PATH"),
		},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	// Wait for initial issuance
	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "certificate issued successfully",
		Timeout:          120 * time.Second,
		Interval:         2 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result, "Initial certificate should be issued")

	// Wait for renewal to complete and on-renewal hook to fire
	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Timeout:          90 * time.Second,
		Interval:         3 * time.Second,
		Condition: func() helpers.ConditionResult {
			if _, err := os.Stat(renewalMarker); err == nil {
				return helpers.ConditionSuccess
			}
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "certificate renewed successfully") ||
				strings.Contains(stderr, "successfully renewed certificate") {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, waitResult, "On-renewal hook should fire after renewal. stderr:\n%s", cmd.Stderr())

	_, err := os.Stat(renewalMarker)
	require.NoError(t, err, "On-renewal post-hook marker file should exist at %s", renewalMarker)
}

func certAgent_SignatureAlgorithm(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	helper := setupCertAgentTest(t, ctx,
		agentHelpers.WithAllowKeyAlgorithms("RSA_2048"),
		agentHelpers.WithAllowSignatureAlgorithms("SHA256-RSA"),
	)

	certDir := filepath.Join(helper.TempDir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0755))
	certPath, keyPath, chainPath := agentHelpers.CertFilePaths(certDir)

	clientIDPath, clientSecretPath := helper.WriteCredentialFiles()

	configPath := helper.GenerateAgentConfig(agentHelpers.AgentConfigOptions{
		ClientIDPath:     clientIDPath,
		ClientSecretPath: clientSecretPath,
		Certificates: []agentHelpers.CertificateConfigEntry{
			{
				ProjectSlug:         helper.ProjectSlug,
				ProfileSlug:         helper.ProfileSlug,
				CommonName:          "sigalg.example.com",
				TTL:                 "1h",
				RenewBeforeExpiry:   "10m",
				StatusCheckInterval: "5s",
				CertPath:            certPath,
				KeyPath:             keyPath,
				ChainPath:           chainPath,
				KeyAlgorithm:        "RSA_2048",
				SignatureAlgorithm:  "RSA-SHA256",
			},
		},
	})

	cmd := helpers.Command{
		Test: t,
		Args: []string{"cert-manager", "agent", "--config", configPath, "--verbose"},
		Env:  map[string]string{},
	}
	cmd.Start(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Agent stderr:\n%s", cmd.Stderr())
			t.Logf("Agent stdout:\n%s", cmd.Stdout())
		}
		cmd.Stop()
	})

	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Timeout:          120 * time.Second,
		Interval:         2 * time.Second,
		Condition: func() helpers.ConditionResult {
			stderr := cmd.Stderr()
			if strings.Contains(stderr, "certificate issued successfully") {
				return helpers.ConditionSuccess
			}
			if strings.Contains(stderr, "failed to issue certificate") ||
				strings.Contains(stderr, "initial certificate issuance failed") {
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, waitResult, "Certificate with signature algorithm should be issued. stderr:\n%s", cmd.Stderr())

	agentHelpers.VerifyCertificateFile(t, certPath)
	agentHelpers.VerifyPrivateKeyFile(t, keyPath)
	agentHelpers.VerifyChainFile(t, chainPath)
	agentHelpers.VerifyCertificateCommonName(t, certPath, "sigalg.example.com")
}

func TestCertAgent_InternalCA(t *testing.T) {
	t.Run("BasicCertificateIssuance", certAgent_BasicCertificateIssuance)
	t.Run("CertificateRenewal", certAgent_CertificateRenewal)
	t.Run("PostHookExecution", certAgent_PostHookExecution)
	t.Run("MultipleCertificates", certAgent_MultipleCertificates)
	t.Run("FilePermissions", certAgent_FilePermissions)
	t.Run("AltNames", certAgent_AltNames)
	t.Run("CSRBasedIssuance", certAgent_CSRBasedIssuance)
	t.Run("CSRPathBasedIssuance", certAgent_CSRPathBasedIssuance)
	t.Run("IssuanceFailureReporting", certAgent_IssuanceFailureReporting)
	t.Run("CertificateWithFullAttributes", certAgent_CertificateWithFullAttributes)
	t.Run("Validation_RenewBeforeExpiryExceedsTTL", certAgent_Validation_RenewBeforeExpiryExceedsTTL)
	t.Run("Validation_BothCSRAndCSRPath", certAgent_Validation_BothCSRAndCSRPath)
	t.Run("Validation_InvalidAuthCredentials", certAgent_Validation_InvalidAuthCredentials)
	t.Run("Validation_MissingCertificatePath", certAgent_Validation_MissingCertificatePath)
	t.Run("Validation_NonexistentProjectSlug", certAgent_Validation_NonexistentProjectSlug)
	t.Run("OnRenewalPostHook", certAgent_OnRenewalPostHook)
	t.Run("SignatureAlgorithm", certAgent_SignatureAlgorithm)
}

func TestCertAgent_AcmeCA(t *testing.T) {
	t.Run("CertificateIssuance", certAgent_AcmeCA_CertificateIssuance)
	t.Run("Validation_DuplicateCAName", certAgent_AcmeCA_Validation_DuplicateCAName)
	t.Run("Validation_InvalidDirectoryUrl", certAgent_AcmeCA_Validation_InvalidDirectoryUrl)
	t.Run("Validation_MissingRequiredFields", certAgent_AcmeCA_Validation_MissingRequiredFields)
	t.Run("Validation_InvalidDnsProvider", certAgent_AcmeCA_Validation_InvalidDnsProvider)
	t.Run("Validation_NonexistentAppConnection", certAgent_AcmeCA_Validation_NonexistentAppConnection)
	t.Run("DisabledCA", certAgent_AcmeCA_DisabledCA)
	t.Run("MultipleCertificates", certAgent_AcmeCA_MultipleCertificates)
	t.Run("PostHookExecution", certAgent_AcmeCA_PostHookExecution)
	t.Run("CSRBasedIssuance", certAgent_AcmeCA_CSRBasedIssuance)
}
