package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func selfSignedPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestOnlyThePinnedCertificateIsTrusted(t *testing.T) {
	genuine := selfSignedPEM(t, "genuine")
	appended := selfSignedPEM(t, "appended")

	kept, fp, err := agentVaultCaFingerprint(genuine + appended)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, genuineFp, _ := agentVaultCaFingerprint(genuine)
	if fp != genuineFp {
		t.Fatalf("fingerprint must be of the first certificate")
	}
	if string(kept) != genuine {
		t.Fatalf("only the checked certificate may be kept, got %d bytes for a %d byte certificate", len(kept), len(genuine))
	}
	if strings.Count(string(kept), "BEGIN CERTIFICATE") != 1 {
		t.Fatal("exactly one certificate must be written")
	}
}

func TestBuildAgentVaultRunEnvPointsAtTheProxy(t *testing.T) {
	parent := []string{
		"HOME=/home/dev",
		"HTTPS_PROXY=http://stale:3128",
		"NO_PROXY=internal.example.com",
	}
	env := envToMap(buildAgentVaultRunEnv(parent, "10.0.1.5:17323", "agv_tok", "/tmp/ca.pem", "metadata.google.internal"))

	if env["HOME"] != "/home/dev" {
		t.Fatalf("unrelated variables must pass through, got HOME=%q", env["HOME"])
	}
	want := "http://x-agent-vault:agv_tok@10.0.1.5:17323"
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

// Both halves have to be present or undici, urllib, requests and libcurl send no credentials at all.
func TestAgentVaultProxyURLCarriesTheTokenAsThePassword(t *testing.T) {
	if got := agentVaultProxyURL("10.0.1.5:17323", "agv_a/b"); got != "http://x-agent-vault:agv_a%2Fb@10.0.1.5:17323" {
		t.Fatalf("unexpected proxy URL %q", got)
	}
}

func TestTrimProxySchemeIgnoresCase(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"127.0.0.1:17323", "127.0.0.1:17323"},
		{"http://127.0.0.1:17323", "127.0.0.1:17323"},
		{"https://127.0.0.1:17323", "127.0.0.1:17323"},
		{"HTTPS://127.0.0.1:17323", "127.0.0.1:17323"},
		{"HtTp://proxy.local:17323", "proxy.local:17323"},
		// A host that merely starts with the letters keeps them.
		{"https-proxy.local:17323", "https-proxy.local:17323"},
	} {
		if got := trimProxyScheme(tc.in); got != tc.want {
			t.Errorf("trimProxyScheme(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// pflag discards a lone empty value, so --access-bundle "" parses to an empty slice and only the flag
// set remembers it was given. A blank alongside a real name has to go too, or the one-bundle limit
// reports two to someone who named one.
func TestNonBlankDropsValuesThatNameNothing(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want int
	}{
		{nil, 0},
		{[]string{""}, 0},
		{[]string{"  "}, 0},
		{[]string{"", "real"}, 1},
		{[]string{"a", " ", "b"}, 2},
		{[]string{" spaced "}, 1},
	} {
		if got := nonBlank(tc.in); len(got) != tc.want {
			t.Errorf("nonBlank(%q) kept %d (%q), want %d", tc.in, len(got), got, tc.want)
		}
	}
	if got := nonBlank([]string{" coding-agent "}); got[0] != "coding-agent" {
		t.Errorf("surrounding space should be trimmed, got %q", got[0])
	}
}

func TestAgentVaultCaFilePathIsPerProxy(t *testing.T) {
	a, err := agentVaultCaFilePath("/data", "0b1e2c1c-3f7e-4f1a-9f3e-2a1b3c4d5e6f")
	if err != nil {
		t.Fatal(err)
	}
	b, err := agentVaultCaFilePath("/data", "7c9e6679-7425-40de-944b-e07fc1f90ae7")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two proxies share one CA file: %s", a)
	}
	if filepath.Dir(a) != "/data" || filepath.Dir(b) != "/data" {
		t.Fatalf("CA files left the data dir: %s, %s", a, b)
	}
}

func TestAgentVaultCaFilePathRefusesNonUuidIds(t *testing.T) {
	for _, id := range []string{"", "ca", "x/../../../.ssh/authorized_keys", "..\\..\\evil"} {
		if p, err := agentVaultCaFilePath("/data", id); err == nil {
			t.Fatalf("proxy ID %q was accepted into path %s", id, p)
		}
	}
}

func TestValidateProxyAddr(t *testing.T) {
	for _, addr := range []string{"10.0.1.5:17323", "proxy.internal:17323", "localhost:17323", "[2001:db8::1]:17323"} {
		if err := validateProxyAddr(addr); err != nil {
			t.Errorf("%q should be accepted: %v", addr, err)
		}
	}
	for _, addr := range []string{
		"10.0.1.5", "2001:db8::1", "[2001:db8::1]", // no port
		":17323", "10.0.1.5:", "", // no host, no port
		"user:pw@host:17323", "socks5://10.0.1.5:1080", "10.0.1.5:17323:extra",
		"10.0.1.5:17323/path", "10.0.1.5:abc", "10.0.1.5:99999", "10.0.1.5:0", "exa mple.com:17323",
	} {
		if err := validateProxyAddr(addr); err == nil {
			t.Errorf("%q should be refused", addr)
		}
	}
}

func TestValidateProxyAddrNamesWhatFollowsThePort(t *testing.T) {
	for _, addr := range []string{"10.0.1.5:17323/path", "10.0.1.5:17323?x=1", "10.0.1.5:17323#frag"} {
		err := validateProxyAddr(addr)
		if err == nil || !strings.Contains(err.Error(), "nothing after the port") {
			t.Errorf("%q: want the trailing-path message, got %v", addr, err)
		}
	}
}

func sessionTokenCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "run", Run: func(*cobra.Command, []string) {}}
	cmd.Flags().String("session-token", "", "")
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestResolveAgentVaultSessionTokenPrefersTheFlag(t *testing.T) {
	t.Setenv(agentVaultSessionTokenEnv, "agv_from_env")

	token, source, err := resolveAgentVaultSessionToken(sessionTokenCmd(t, "--session-token", "agv_from_flag"))
	if err != nil {
		t.Fatal(err)
	}
	if token != "agv_from_flag" || source != agentVaultSourceFlag {
		t.Errorf("the flag should win over the environment, got %q source=%v", token, source)
	}
}

func TestResolveAgentVaultSessionTokenFallsBackToTheEnvironment(t *testing.T) {
	t.Setenv(agentVaultSessionTokenEnv, "  agv_from_env  ")

	token, source, err := resolveAgentVaultSessionToken(sessionTokenCmd(t))
	if err != nil {
		t.Fatal(err)
	}
	if token != "agv_from_env" {
		t.Errorf("want the environment value trimmed, got %q", token)
	}
	if source != agentVaultSourceEnv {
		t.Errorf("a token out of the environment must report itself as such, got %v", source)
	}
}

func TestResolveAgentVaultSessionTokenIgnoresABlankEnvironmentValue(t *testing.T) {
	t.Setenv(agentVaultSessionTokenEnv, "   ")

	token, source, err := resolveAgentVaultSessionToken(sessionTokenCmd(t))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" || source != agentVaultSourceNone {
		t.Errorf("a blank variable names no session, got %q source=%v", token, source)
	}
}

func TestResolveAgentVaultSessionTokenRefusesAnEmptyFlag(t *testing.T) {
	t.Setenv(agentVaultSessionTokenEnv, "agv_from_env")

	if _, _, err := resolveAgentVaultSessionToken(sessionTokenCmd(t, "--session-token", "")); err == nil {
		t.Fatal("an explicitly empty --session-token should be an error, not a fall back to the environment")
	}
}

func TestResolveAgentVaultSessionTokenWithNeitherSourceIsEmpty(t *testing.T) {
	t.Setenv(agentVaultSessionTokenEnv, "")

	token, source, err := resolveAgentVaultSessionToken(sessionTokenCmd(t))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" || source != agentVaultSourceNone {
		t.Errorf("want no token, got %q source=%v", token, source)
	}
}

func TestBuildAgentVaultRunEnvDropsAStaleSessionTokenVariable(t *testing.T) {
	parent := []string{agentVaultSessionTokenEnv + "=agv_stale", "PATH=/usr/bin"}

	env := buildAgentVaultRunEnv(parent, "10.0.1.5:17323", "agv_minted", "", "")

	for _, kv := range env {
		if strings.Contains(kv, "agv_stale") {
			t.Fatalf("a session other than this run's reached the agent through %q", kv)
		}
	}
	if !strings.Contains(strings.Join(env, " "), "agv_minted") {
		t.Error("the minted session should still reach the agent in the proxy URL")
	}
}

func TestBuildAgentVaultRunEnvKeepsTheVariableThatHoldsThisSession(t *testing.T) {
	// Removing it here would hide nothing: the same token is the proxy password either way.
	parent := []string{agentVaultSessionTokenEnv + "=agv_this_run", "PATH=/usr/bin"}

	env := buildAgentVaultRunEnv(parent, "10.0.1.5:17323", "agv_this_run", "", "")

	var kept bool
	for _, kv := range env {
		if kv == agentVaultSessionTokenEnv+"=agv_this_run" {
			kept = true
		}
	}
	if !kept {
		t.Errorf("the variable naming this run's own session should be left alone, got %q", env)
	}
}

func TestAgentVaultSourceNameBlamesWhatWasActuallyUsed(t *testing.T) {
	if got := agentVaultSourceName(agentVaultSourceEnv, "--session-token", agentVaultSessionTokenEnv); got != agentVaultSessionTokenEnv {
		t.Errorf("a variable should be named in the message, got %q", got)
	}
	if got := agentVaultSourceName(agentVaultSourceFlag, "--session-token", agentVaultSessionTokenEnv); got != "--session-token" {
		t.Errorf("a flag should be named in the message, got %q", got)
	}
}

func accessBundleCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "run", Run: func(*cobra.Command, []string) {}}
	cmd.Flags().StringArray("access-bundle", nil, "")
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestResolveAgentVaultAccessBundlesPrefersTheFlag(t *testing.T) {
	t.Setenv(agentVaultAccessBundleEnv, "from-env")

	bundles, source, err := resolveAgentVaultAccessBundles(accessBundleCmd(t, "--access-bundle", "from-flag"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 1 || bundles[0] != "from-flag" || source != agentVaultSourceFlag {
		t.Errorf("the flag should win over the environment, got %q source=%v", bundles, source)
	}
}

func TestResolveAgentVaultAccessBundlesFallsBackToTheEnvironment(t *testing.T) {
	t.Setenv(agentVaultAccessBundleEnv, "  code-review  ")

	bundles, source, err := resolveAgentVaultAccessBundles(accessBundleCmd(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 1 || bundles[0] != "code-review" || source != agentVaultSourceEnv {
		t.Errorf("want the environment value trimmed, got %q source=%v", bundles, source)
	}
}

func TestResolveAgentVaultAccessBundlesIgnoresABlankEnvironmentValue(t *testing.T) {
	t.Setenv(agentVaultAccessBundleEnv, "   ")

	bundles, source, err := resolveAgentVaultAccessBundles(accessBundleCmd(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 0 || source != agentVaultSourceNone {
		t.Errorf("a blank variable names no bundle, got %q source=%v", bundles, source)
	}
}

func TestResolveAgentVaultAccessBundlesRefusesAnEmptyFlag(t *testing.T) {
	t.Setenv(agentVaultAccessBundleEnv, "from-env")

	if _, _, err := resolveAgentVaultAccessBundles(accessBundleCmd(t, "--access-bundle", "")); err == nil {
		t.Fatal("an explicitly empty --access-bundle should be an error, not a fall back to the environment")
	}
}

func TestResolveAgentVaultAccessBundlesKeepsEveryFlagName(t *testing.T) {
	// The count is what the one-bundle rule rejects by name, so both have to survive resolution.
	bundles, _, err := resolveAgentVaultAccessBundles(accessBundleCmd(t, "--access-bundle", "a", "--access-bundle", "b"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 2 {
		t.Errorf("want both names, got %q", bundles)
	}
}

func TestDecideAgentVaultSession(t *testing.T) {
	const (
		none = agentVaultSourceNone
		env  = agentVaultSourceEnv
		flag = agentVaultSourceFlag
	)
	for _, tc := range []struct {
		name        string
		token       agentVaultSource
		bundle      agentVaultSource
		wantErr     bool
		wantToken   bool
		wantWarning bool
	}{
		{"neither names a session", none, none, true, false, false},
		{"bundle variable alone mints", none, env, false, false, false},
		{"bundle flag alone mints", none, flag, false, false, false},
		{"token variable alone runs on it", env, none, false, true, false},
		{"token flag alone runs on it", flag, none, false, true, false},
		{"both flags is a conflict", flag, flag, true, false, false},
		{"both variables is a tie we refuse", env, env, true, false, false},
		{"token flag beats the bundle variable", flag, env, false, true, true},
		{"bundle flag beats the token variable", env, flag, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useToken, warning, err := decideAgentVaultSession(tc.token, tc.bundle)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if useToken != tc.wantToken {
				t.Errorf("useToken = %v, want %v", useToken, tc.wantToken)
			}
			if (warning != "") != tc.wantWarning {
				t.Errorf("warning = %q, want one %v", warning, tc.wantWarning)
			}
		})
	}
}

func TestDecideAgentVaultSessionTieErrorNamesBothVariables(t *testing.T) {
	// Both ways out have to be named: unsetting one variable, or a flag that picks between them.
	_, _, err := decideAgentVaultSession(agentVaultSourceEnv, agentVaultSourceEnv)
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{agentVaultSessionTokenEnv, agentVaultAccessBundleEnv, "--session-token", "--access-bundle"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message should name %q, got %q", want, err)
		}
	}
}
