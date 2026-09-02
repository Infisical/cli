package cmd

import (
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
)

func TestBuildAgentVaultRunEnvPointsAtTheProxyAndStripsCredentials(t *testing.T) {
	parent := []string{
		"HOME=/home/dev",
		"INFISICAL_TOKEN=should-not-leak",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET=should-not-leak",
		"HTTPS_PROXY=http://stale:3128",
		"NO_PROXY=internal.example.com",
	}
	env := envToMap(buildAgentVaultRunEnv(parent, "10.0.1.5:17323", "agv_tok", "/tmp/ca.pem", "metadata.google.internal"))

	if env["HOME"] != "/home/dev" {
		t.Fatalf("unrelated variables must pass through, got HOME=%q", env["HOME"])
	}
	for _, k := range []string{"INFISICAL_TOKEN", "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"} {
		if _, ok := env[k]; ok {
			t.Fatalf("%s must be stripped: the agent holds nothing from Infisical", k)
		}
	}
	want := "http://agv_tok@10.0.1.5:17323"
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if env[k] != want {
			t.Fatalf("%s = %q, want %q", k, env[k], want)
		}
	}
	for _, part := range []string{"localhost", "127.0.0.1", "internal.example.com", "metadata.google.internal"} {
		if !strings.Contains(env["NO_PROXY"], part) {
			t.Fatalf("NO_PROXY %q must merge the operator's and the flag's entries with the required ones", env["NO_PROXY"])
		}
	}
	for _, k := range caTrustEnvVars {
		if env[k] != "/tmp/ca.pem" {
			t.Fatalf("%s = %q, want the CA path", k, env[k])
		}
	}
}

func TestBuildAgentVaultRunEnvWithoutCaTrustSetsNoTrustVariables(t *testing.T) {
	env := envToMap(buildAgentVaultRunEnv([]string{"SSL_CERT_FILE=/etc/ssl/corp.pem"}, "proxy:17323", "agv_tok", "", ""))
	if env["SSL_CERT_FILE"] != "/etc/ssl/corp.pem" {
		t.Fatalf("--no-ca-trust must leave the operator's own trust variables alone, got %q", env["SSL_CERT_FILE"])
	}
	if _, ok := env["NODE_EXTRA_CA_CERTS"]; ok {
		t.Fatal("no CA variable may be set when no CA file was written")
	}
}

func TestAgentVaultFingerprintsEqualToleratesCopyFormats(t *testing.T) {
	served := "SHA256:9F:2C:AB:00"
	for _, pinned := range []string{"SHA256:9F:2C:AB:00", "sha256:9f:2c:ab:00", "9F2CAB00", " 9f:2c:ab:00 "} {
		if !agentVaultFingerprintsEqual(pinned, served) {
			t.Fatalf("%q should match %q", pinned, served)
		}
	}
	if agentVaultFingerprintsEqual("SHA256:9F:2C:AB:01", served) {
		t.Fatal("a different fingerprint must not match")
	}
	if agentVaultFingerprintsEqual("", served) {
		t.Fatal("an empty pin must never match")
	}
}

func TestResolveAgentVaultBundleIDsKeepsOrderAndNamesUnknowns(t *testing.T) {
	bundles := []api.AgentVaultAccessBundle{{ID: "id-a", Name: "alpha"}, {ID: "id-b", Name: "beta"}}

	ids, err := resolveAgentVaultBundleIDs([]string{"beta", "alpha"}, bundles)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Join(ids, ",") != "id-b,id-a" {
		t.Fatalf("order must follow the flags, got %v", ids)
	}

	_, err = resolveAgentVaultBundleIDs([]string{"alpha", "gamma"}, bundles)
	if err == nil || !strings.Contains(err.Error(), `"gamma"`) || !strings.Contains(err.Error(), "alpha, beta") {
		t.Fatalf("an unknown bundle must be named alongside the reachable ones, got %v", err)
	}
}

func TestAgentVaultProxyURLCarriesTheTokenAsTheUser(t *testing.T) {
	if got := agentVaultProxyURL("10.0.1.5:17323", "agv_a/b"); got != "http://agv_a%2Fb@10.0.1.5:17323" {
		t.Fatalf("unexpected proxy URL %q", got)
	}
}
