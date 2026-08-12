package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/agentproxy"
	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/spf13/cobra"
)

func newRunTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "run"}
	c.Flags().StringArray("pass-env", nil, "")
	c.Flags().StringArray("set-env", nil, "")
	return c
}

func envToMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}

func TestBuildLocalAgentEnvScrubsSecretsAndToken(t *testing.T) {
	t.Setenv("INFISICAL_TOKEN", "dev.jwt.secret")
	t.Setenv("INFISICAL_DOMAIN", "https://app.infisical.com/api")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "should-be-scrubbed")
	t.Setenv("ANTHROPIC_API_KEY", "sk-should-be-scrubbed")
	t.Setenv("MY_PASSWORD", "hunter2")
	t.Setenv("HARMLESS", "keep-me")

	cmd := newRunTestCmd()
	placeholders := []agentproxy.Placeholder{{Key: "STRIPE_KEY", Value: "__PLACEHOLDER__"}}
	env := envToMap(buildLocalAgentEnv(cmd, "http://session:listener-secret@127.0.0.1:51234", "/tmp/ca.pem", placeholders))

	// The developer token must never reach the child, by name or by value anywhere.
	if _, ok := env["INFISICAL_TOKEN"]; ok {
		t.Error("INFISICAL_TOKEN must be scrubbed from the child env")
	}
	if _, ok := env["INFISICAL_DOMAIN"]; ok {
		t.Error("INFISICAL_DOMAIN must be scrubbed from the child env")
	}
	for k, v := range env {
		if strings.Contains(v, "dev.jwt.secret") {
			t.Errorf("developer token leaked into child env var %q=%q", k, v)
		}
	}

	for _, k := range []string{"AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY", "MY_PASSWORD"} {
		if _, ok := env[k]; ok {
			t.Errorf("secret-shaped var %q must be scrubbed", k)
		}
	}

	if env["HARMLESS"] != "keep-me" {
		t.Error("non-secret vars must be preserved")
	}
	// Both cases must be set: curl honours only lowercase http_proxy for plain-HTTP URLs, so an
	// uppercase-only env would send those requests to DNS instead of the proxy.
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		if env[k] != "http://session:listener-secret@127.0.0.1:51234" {
			t.Errorf("%s = %q; want the listener's proxy URL", k, env[k])
		}
	}
	if env["no_proxy"] != env["NO_PROXY"] {
		t.Errorf("no_proxy (%q) must match NO_PROXY (%q)", env["no_proxy"], env["NO_PROXY"])
	}
	// Loopback only, and the only thing in the userinfo is this run's listener secret, which grants use of
	// the listener rather than access to any credential.
	if !strings.Contains(env["HTTPS_PROXY"], "127.0.0.1") {
		t.Errorf("proxy URL must be loopback, got %q", env["HTTPS_PROXY"])
	}
	if env["SSL_CERT_FILE"] != "/tmp/ca.pem" || env["NODE_EXTRA_CA_CERTS"] != "/tmp/ca.pem" {
		t.Error("CA trust vars must point at the local CA cert")
	}
	if env["STRIPE_KEY"] != "__PLACEHOLDER__" {
		t.Error("placeholder must be injected")
	}
	if !strings.Contains(env["NO_PROXY"], "127.0.0.1") {
		t.Errorf("NO_PROXY must include localhost, got %q", env["NO_PROXY"])
	}
}

func TestBuildLocalAgentEnvPassEnvOverridesScrub(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-real")
	cmd := newRunTestCmd()
	_ = cmd.Flags().Set("pass-env", "ANTHROPIC_API_KEY")

	env := envToMap(buildLocalAgentEnv(cmd, "http://127.0.0.1:1", "/tmp/ca.pem", nil))
	if env["ANTHROPIC_API_KEY"] != "sk-real" {
		t.Errorf("--pass-env must re-admit a scrubbed var, got %q", env["ANTHROPIC_API_KEY"])
	}
}

func TestBuildLocalAgentEnvSetEnvWins(t *testing.T) {
	cmd := newRunTestCmd()
	_ = cmd.Flags().Set("set-env", "FEATURE_FLAG=on")
	env := envToMap(buildLocalAgentEnv(cmd, "http://127.0.0.1:1", "/tmp/ca.pem", nil))
	if env["FEATURE_FLAG"] != "on" {
		t.Errorf("--set-env must inject a literal, got %q", env["FEATURE_FLAG"])
	}
}

// The listener secret is what stops another process on this machine using the broker: the sandbox fences the
// agent, but --no-sandbox and the shared-network fallback do not.
func TestLocalProxyURLCarriesTheListenerSecret(t *testing.T) {
	u := localProxyURL("127.0.0.1:51234", "s3cret")
	if u != "http://session:s3cret@127.0.0.1:51234" {
		t.Fatalf("local proxy URL = %q; want the listener secret in the userinfo", u)
	}
}

func TestDefaultAgentStateWritePaths(t *testing.T) {
	home := t.TempDir()
	// Create ~/.claude (dir) and ~/.claude.json (file); leave ~/.codex absent.
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := sandbox.AgentStateWritePaths(home)
	has := func(p string) bool {
		for _, g := range got {
			if g == filepath.Join(home, p) {
				return true
			}
		}
		return false
	}
	if !has(".claude") || !has(".claude.json") {
		t.Errorf("expected existing agent paths to be included, got %v", got)
	}
	if has(".codex") {
		t.Errorf("non-existent ~/.codex must NOT be included (bwrap --bind would fail), got %v", got)
	}
	if sandbox.AgentStateWritePaths("") != nil {
		t.Error("empty home must return nil")
	}
}

func TestIsSecretShapedEnvName(t *testing.T) {
	shaped := []string{"GITHUB_TOKEN", "aws_secret_access_key", "DB_PASSWORD", "X_API_KEY", "MY_CREDENTIAL"}
	for _, n := range shaped {
		if !isSecretShapedEnvName(n) {
			t.Errorf("%q should be treated as secret-shaped", n)
		}
	}
	plain := []string{"HOME", "PATH", "TERM", "LANG", "EDITOR"}
	for _, n := range plain {
		if isSecretShapedEnvName(n) {
			t.Errorf("%q should NOT be treated as secret-shaped", n)
		}
	}
}
