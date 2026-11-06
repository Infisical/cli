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
	"github.com/spf13/pflag"
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
	const want = ".infisical.yaml names a server that Agent Vault commands don't read. Pass --domain <domain> or set INFISICAL_DOMAIN."

	for _, cmd := range agentVaultDomainTestCommands {
		if _, err := resolveAgentVaultDomain(t, cmd, "https://app.infisical.com/api"); err == nil || err.Error() != want {
			t.Fatalf("%s: got error %v, want %q", cmd.CommandPath(), err, want)
		}
	}
}

// The file arrives with a cloned repo, so its value is never echoed into a message a user may copy from.
func TestResolveDomainNeverRepeatsTheRepoFileDomainForAgentVaultCommands(t *testing.T) {
	useProfileDomain(t, "https://app.infisical.com/api")
	const malicious = "https://evil.example/$(curl x)"
	useRepoFileDomain(t, "'"+malicious+"'")
	if domain, valid := util.GetDomainFromFile(); domain != malicious || !valid {
		t.Fatalf("the file domain should read back as a valid %q, got %q (valid %v)", malicious, domain, valid)
	}

	for _, cmd := range agentVaultDomainTestCommands {
		_, err := resolveAgentVaultDomain(t, cmd, "https://app.infisical.com/api")
		if err == nil || strings.Contains(err.Error(), "evil.example") || strings.Contains(err.Error(), "curl") {
			t.Fatalf("%s: got error %v", cmd.CommandPath(), err)
		}
	}
}

// setAgentVaultRunFlags sets flags on the real run command, which resolveDomain recognizes by identity, and
// resets them when the test ends.
func setAgentVaultRunFlags(t *testing.T, values map[string]string) {
	t.Helper()
	t.Cleanup(func() {
		for _, name := range []string{"session-token", "no-skills", "access-bundle"} {
			flag := agentVaultRunCmd.Flags().Lookup(name)
			if slice, ok := flag.Value.(pflag.SliceValue); ok {
				_ = slice.Replace(nil)
			} else {
				_ = flag.Value.Set(flag.DefValue)
			}
			flag.Changed = false
		}
	})
	for name, value := range values {
		if err := agentVaultRunCmd.Flags().Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestResolveDomainLetsAgentVaultRunOnASessionTokenWithoutSkillsIgnoreTheRepoFile(t *testing.T) {
	cases := []struct {
		name      string
		flags     map[string]string
		tokenEnv  string
		bundleEnv string
	}{
		{name: "token flag", flags: map[string]string{"session-token": "agv_x", "no-skills": "true"}},
		{name: "token variable", flags: map[string]string{"no-skills": "true"}, tokenEnv: "agv_x"},
		{name: "token flag beats a bundle variable", flags: map[string]string{"session-token": "agv_x", "no-skills": "true"}, bundleEnv: "coding-agent"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			useProfileDomain(t, "https://app.infisical.com/api")
			useRepoFileDomain(t, "https://eu.infisical.com")
			t.Setenv(agentVaultSessionTokenEnv, c.tokenEnv)
			t.Setenv(agentVaultAccessBundleEnv, c.bundleEnv)
			setAgentVaultRunFlags(t, c.flags)

			got, err := resolveAgentVaultDomain(t, agentVaultRunCmd, "https://app.infisical.com/api")
			if err != nil || got != "https://app.infisical.com/api" {
				t.Fatalf("resolved %s, %v", got, err)
			}
		})
	}
}

func TestResolveDomainStillStopsAgentVaultRunWhenItWouldContactInfisical(t *testing.T) {
	cases := []struct {
		name      string
		flags     map[string]string
		tokenEnv  string
		bundleEnv string
	}{
		{name: "token without --no-skills", flags: map[string]string{"session-token": "agv_x"}},
		{name: "--no-skills without a token", flags: map[string]string{"no-skills": "true"}},
		{name: "--no-skills minting over a bundle", flags: map[string]string{"access-bundle": "coding-agent", "no-skills": "true"}, tokenEnv: "agv_x"},
		{name: "--no-skills with both variables", flags: map[string]string{"no-skills": "true"}, tokenEnv: "agv_x", bundleEnv: "coding-agent"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			useProfileDomain(t, "https://app.infisical.com/api")
			useRepoFileDomain(t, "https://eu.infisical.com")
			t.Setenv(agentVaultSessionTokenEnv, c.tokenEnv)
			t.Setenv(agentVaultAccessBundleEnv, c.bundleEnv)
			setAgentVaultRunFlags(t, c.flags)

			if _, err := resolveAgentVaultDomain(t, agentVaultRunCmd, "https://app.infisical.com/api"); err == nil {
				t.Fatal("want the run stopped")
			}
		})
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
	const fallback = "https://app.infisical.com/api"

	for _, cmd := range agentVaultDomainTestCommands {
		got, err := resolveAgentVaultDomain(t, cmd, fallback)
		if err != nil || got != "https://eu.infisical.com/api" {
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
	useProfileDomain(t, "https://eu.infisical.com/api")
	for _, env := range util.DomainEnvNames {
		t.Setenv(env, "")
	}
	t.Chdir(t.TempDir())
	const fallback = "https://app.infisical.com/api"

	for _, cmd := range agentVaultDomainTestCommands {
		got, err := resolveAgentVaultDomain(t, cmd, fallback)
		if err != nil || got != "https://eu.infisical.com/api" {
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
