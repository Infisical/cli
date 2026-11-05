package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

func useRepoFileDomain(t *testing.T, domain string) {
	t.Helper()
	for _, env := range util.DomainEnvNames {
		t.Setenv(env, "")
	}
	repo := t.TempDir()
	content := "version: 1\ngeneral:\n  domain: " + domain + "\n"
	if err := os.WriteFile(filepath.Join(repo, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
}

func TestResolveDomainIgnoresTheRepoFileForAgentVaultCommands(t *testing.T) {
	useRepoFileDomain(t, "https://evil.example")
	const fallback = "https://app.infisical.com/api"

	for _, cmd := range []*cobra.Command{agentVaultCmd, agentVaultProxyCmd, agentVaultSessionsRevokeCmd} {
		var stderr bytes.Buffer
		cmd.SetErr(&stderr)
		got := resolveDomain(cmd, fallback)
		cmd.SetErr(nil)
		if got != fallback {
			t.Fatalf("%s: resolved %s, want %s", cmd.CommandPath(), got, fallback)
		}
		if stderr.Len() != 0 {
			t.Fatalf("%s: warned %q", cmd.CommandPath(), stderr.String())
		}
	}
}

func TestResolveDomainStillReadsTheRepoFileForOtherCommands(t *testing.T) {
	useRepoFileDomain(t, "https://eu.infisical.com")

	var stderr bytes.Buffer
	cmd := &cobra.Command{Use: "secrets"}
	cmd.SetErr(&stderr)
	if got := resolveDomain(cmd, "https://app.infisical.com/api"); got != "https://eu.infisical.com" {
		t.Fatalf("resolved %s", got)
	}
	if !strings.Contains(stderr.String(), "Using domain 'https://eu.infisical.com' from .infisical.yaml") {
		t.Fatalf("warned %q", stderr.String())
	}
}
