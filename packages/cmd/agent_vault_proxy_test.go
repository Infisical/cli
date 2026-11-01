package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// Cleared so a value set in the developer's shell can't reach the test.
var agentVaultProxyEnv = []string{
	"INFISICAL_AGENT_VAULT_PROXY_TOKEN",
	"INFISICAL_AGENT_VAULT_DATA_DIR",
	"INFISICAL_AGENT_VAULT_PORT",
	"INFISICAL_AGENT_VAULT_CA_CERT",
	"INFISICAL_AGENT_VAULT_CA_KEY",
	"INFISICAL_AGENT_VAULT_ENROLLMENT_TOKEN",
}

func readProxyInputs(t *testing.T, env map[string]string, args ...string) (agentVaultProxyInputs, error) {
	t.Helper()
	for _, k := range agentVaultProxyEnv {
		t.Setenv(k, env[k])
	}
	cmd := &cobra.Command{Use: "proxy"}
	addAgentVaultProxyFlags(cmd)
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatal(err)
	}
	return readAgentVaultProxyInputs(cmd)
}

func caPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestAgentVaultProxyNeedsBothHalvesOfACa(t *testing.T) {
	certPEM, keyPEM := caPair(t)
	if _, err := readProxyInputs(t, nil, "--ca-cert", certPEM); err == nil || err.Error() != "--ca-cert and --ca-key go together" {
		t.Fatalf("cert alone: got %v", err)
	}
	if _, err := readProxyInputs(t, map[string]string{"INFISICAL_AGENT_VAULT_CA_KEY": keyPEM}); err == nil || err.Error() != "--ca-cert and --ca-key go together" {
		t.Fatalf("key alone: got %v", err)
	}
}

func TestAgentVaultProxyNamesTheCaFlagItCouldNotRead(t *testing.T) {
	_, keyPEM := caPair(t)
	_, err := readProxyInputs(t, map[string]string{"INFISICAL_AGENT_VAULT_CA_KEY": keyPEM}, "--ca-cert", "/nowhere/ca.crt")
	if err == nil || err.Error() != "--ca-cert is not a PEM, base64 PEM or readable file: /nowhere/ca.crt" {
		t.Fatalf("got %v", err)
	}
}

func TestAgentVaultProxyWarnsAboutAKeyInAFlagOnly(t *testing.T) {
	certPEM, keyPEM := caPair(t)
	in, err := readProxyInputs(t, nil, "--ca-cert", certPEM, "--ca-key", keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if in.ownCa == nil {
		t.Fatal("the CA was not loaded")
	}
	if len(in.warnings) != 1 || !strings.Contains(in.warnings[0], "process list") {
		t.Fatalf("an inline key in a flag must warn, got %v", in.warnings)
	}

	in, err = readProxyInputs(t, map[string]string{"INFISICAL_AGENT_VAULT_CA_CERT": certPEM, "INFISICAL_AGENT_VAULT_CA_KEY": keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	if in.ownCa == nil || len(in.warnings) != 0 {
		t.Fatalf("a key in the env must load without a warning, got %v", in.warnings)
	}
}

func TestAgentVaultProxyKeepsTheDataDirWithAProxyToken(t *testing.T) {
	in, err := readProxyInputs(t, map[string]string{"INFISICAL_AGENT_VAULT_PROXY_TOKEN": "pxt"}, "--data-dir", "/var/lib/av")
	if err != nil {
		t.Fatal(err)
	}
	if in.proxyToken != "pxt" || in.dataDir != "/var/lib/av" {
		t.Fatalf("got token %q and data dir %q", in.proxyToken, in.dataDir)
	}
	if len(in.warnings) != 0 {
		t.Fatalf("got warnings %v", in.warnings)
	}
}

func TestAgentVaultProxyIgnoresADeprecatedEnrollmentToken(t *testing.T) {
	in, err := readProxyInputs(t, nil, "--enrollment-token", "avp_old")
	if err != nil {
		t.Fatalf("an enrollment token from an old unit file failed the start: %v", err)
	}
	if len(in.warnings) != 0 {
		t.Fatalf("got warnings %v", in.warnings)
	}

	cmd := &cobra.Command{Use: "proxy"}
	addAgentVaultProxyFlags(cmd)
	if flag := cmd.Flags().Lookup("enrollment-token"); flag == nil || !flag.Hidden || flag.Deprecated == "" {
		t.Fatal("--enrollment-token should be registered, hidden and deprecated")
	}
}

func TestAgentVaultProxyPortFromEnvLosesToTheFlag(t *testing.T) {
	env := map[string]string{"INFISICAL_AGENT_VAULT_PORT": "18000"}
	in, err := readProxyInputs(t, env)
	if err != nil || in.port != 18000 {
		t.Fatalf("env port: got %d, %v", in.port, err)
	}
	in, err = readProxyInputs(t, env, "--port", "19000")
	if err != nil || in.port != 19000 {
		t.Fatalf("flag must win over env: got %d, %v", in.port, err)
	}
	if _, err := readProxyInputs(t, map[string]string{"INFISICAL_AGENT_VAULT_PORT": "http"}); err == nil {
		t.Fatal("a port that is not a number was accepted")
	}
	if _, err := readProxyInputs(t, map[string]string{"INFISICAL_AGENT_VAULT_PORT": "70000"}); err == nil {
		t.Fatal("a port out of range was accepted")
	}
}

func TestAgentVaultProxyNamesTheEnvVarAValueCameFrom(t *testing.T) {
	_, keyPEM := caPair(t)
	_, err := readProxyInputs(t, map[string]string{
		"INFISICAL_AGENT_VAULT_CA_CERT": "/nowhere/ca.crt",
		"INFISICAL_AGENT_VAULT_CA_KEY":  keyPEM,
	})
	if err == nil || err.Error() != "INFISICAL_AGENT_VAULT_CA_CERT is not a PEM, base64 PEM or readable file: /nowhere/ca.crt" {
		t.Fatalf("cert from env: got %v", err)
	}

	certPEM, _ := caPair(t)
	_, err = readProxyInputs(t, map[string]string{"INFISICAL_AGENT_VAULT_CA_KEY": "s3cret"}, "--ca-cert", certPEM)
	if err == nil || err.Error() != "INFISICAL_AGENT_VAULT_CA_KEY is not a PEM, base64 PEM or readable file (value hidden)" {
		t.Fatalf("key from env: got %v", err)
	}

	_, err = readProxyInputs(t, map[string]string{"INFISICAL_AGENT_VAULT_PORT": "70000"})
	if err == nil || !strings.HasPrefix(err.Error(), "INFISICAL_AGENT_VAULT_PORT must be between") {
		t.Fatalf("port from env: got %v", err)
	}
	_, err = readProxyInputs(t, nil, "--port", "70000")
	if err == nil || !strings.HasPrefix(err.Error(), "--port must be between") {
		t.Fatalf("port from flag: got %v", err)
	}
}
