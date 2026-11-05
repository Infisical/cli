package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
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

func useProfileDomain(t *testing.T, domain string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the home folder is not HOME here")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, util.CONFIG_FOLDER_NAME)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(models.ConfigFile{LoggedInUserDomain: domain})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, util.CONFIG_FILE_NAME), content, 0o600); err != nil {
		t.Fatal(err)
	}
}

var agentVaultDomainTestCommands = []*cobra.Command{agentVaultCmd, agentVaultProxyCmd, agentVaultSessionsRevokeCmd}

func resolveAgentVaultDomain(t *testing.T, cmd *cobra.Command, flagValue string) (string, error) {
	t.Helper()
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	defer cmd.SetErr(nil)
	got, err := resolveDomain(cmd, flagValue)
	if stderr.Len() != 0 {
		t.Fatalf("%s: warned %q", cmd.CommandPath(), stderr.String())
	}
	return got, err
}

func TestResolveDomainStopsAgentVaultCommandsWhenTheRepoFileNamesAnotherInstance(t *testing.T) {
	useProfileDomain(t, "https://app.infisical.com/api")
	useRepoFileDomain(t, "https://eu.infisical.com")
	const want = ".infisical.yaml sets the domain https://eu.infisical.com, but Agent Vault commands don't read it. Pass --domain https://eu.infisical.com or set INFISICAL_DOMAIN."

	for _, cmd := range agentVaultDomainTestCommands {
		if _, err := resolveAgentVaultDomain(t, cmd, "https://app.infisical.com/api"); err == nil || err.Error() != want {
			t.Fatalf("%s: got error %v, want %q", cmd.CommandPath(), err, want)
		}
	}
}

func TestResolveDomainLetsTheFlagWinOverTheRepoFileForAgentVaultCommands(t *testing.T) {
	useProfileDomain(t, "https://app.infisical.com/api")
	useRepoFileDomain(t, "https://eu.infisical.com")

	cmd := &cobra.Command{Use: "proxy"}
	cmd.Flags().String("domain", "", "")
	agentVaultCmd.AddCommand(cmd)
	t.Cleanup(func() { agentVaultCmd.RemoveCommand(cmd) })
	if err := cmd.Flags().Set("domain", "https://self-hosted.example.com"); err != nil {
		t.Fatal(err)
	}

	got, err := resolveAgentVaultDomain(t, cmd, "https://self-hosted.example.com")
	if err != nil || got != "https://self-hosted.example.com" {
		t.Fatalf("resolved %s, %v", got, err)
	}
}

func TestResolveDomainLetsTheVariableWinOverTheRepoFileForAgentVaultCommands(t *testing.T) {
	useProfileDomain(t, "https://app.infisical.com/api")
	useRepoFileDomain(t, "https://eu.infisical.com")
	t.Setenv(util.INFISICAL_DOMAIN_ENV_NAME, "https://self-hosted.example.com")

	for _, cmd := range agentVaultDomainTestCommands {
		got, err := resolveAgentVaultDomain(t, cmd, "https://app.infisical.com/api")
		if err != nil || got != "https://self-hosted.example.com" {
			t.Fatalf("%s: resolved %s, %v", cmd.CommandPath(), got, err)
		}
	}
}

func TestResolveDomainAllowsAgentVaultCommandsWhenTheRepoFileMatchesTheProfile(t *testing.T) {
	useProfileDomain(t, "https://eu.infisical.com/api")
	useRepoFileDomain(t, "https://eu.infisical.com/")
	const fallback = "https://eu.infisical.com/api"

	for _, cmd := range agentVaultDomainTestCommands {
		got, err := resolveAgentVaultDomain(t, cmd, fallback)
		if err != nil || got != fallback {
			t.Fatalf("%s: resolved %s, %v", cmd.CommandPath(), got, err)
		}
	}
}

func TestResolveDomainComparesTheRepoFileWithTheDefaultWhenNoOneIsLoggedIn(t *testing.T) {
	useProfileDomain(t, "")
	useRepoFileDomain(t, "https://app.infisical.com")
	const fallback = "https://app.infisical.com/api"

	for _, cmd := range agentVaultDomainTestCommands {
		got, err := resolveAgentVaultDomain(t, cmd, fallback)
		if err != nil || got != fallback {
			t.Fatalf("%s: resolved %s, %v", cmd.CommandPath(), got, err)
		}
	}
}

func TestResolveDomainIgnoresAnInvalidRepoFileDomainForAgentVaultCommands(t *testing.T) {
	useProfileDomain(t, "https://app.infisical.com/api")
	useRepoFileDomain(t, "not-a-url")
	const fallback = "https://app.infisical.com/api"

	for _, cmd := range agentVaultDomainTestCommands {
		got, err := resolveAgentVaultDomain(t, cmd, fallback)
		if err != nil || got != fallback {
			t.Fatalf("%s: resolved %s, %v", cmd.CommandPath(), got, err)
		}
	}
}

func TestResolveDomainUsesTheProfileForAgentVaultCommandsWithoutARepoFile(t *testing.T) {
	useProfileDomain(t, "https://app.infisical.com/api")
	for _, env := range util.DomainEnvNames {
		t.Setenv(env, "")
	}
	t.Chdir(t.TempDir())
	const fallback = "https://app.infisical.com/api"

	for _, cmd := range agentVaultDomainTestCommands {
		got, err := resolveAgentVaultDomain(t, cmd, fallback)
		if err != nil || got != fallback {
			t.Fatalf("%s: resolved %s, %v", cmd.CommandPath(), got, err)
		}
	}
}

func TestResolveDomainStillReadsTheRepoFileForOtherCommands(t *testing.T) {
	useRepoFileDomain(t, "https://eu.infisical.com")

	var stderr bytes.Buffer
	cmd := &cobra.Command{Use: "secrets"}
	cmd.SetErr(&stderr)
	if got, err := resolveDomain(cmd, "https://app.infisical.com/api"); err != nil || got != "https://eu.infisical.com" {
		t.Fatalf("resolved %s, %v", got, err)
	}
	if !strings.Contains(stderr.String(), "Using domain 'https://eu.infisical.com' from .infisical.yaml") {
		t.Fatalf("warned %q", stderr.String())
	}
}
