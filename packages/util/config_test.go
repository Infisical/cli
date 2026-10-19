package util

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
)

func TestWorkspaceConfigDomain(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		wantDomain string
	}{
		{"domain field is parsed", "testdata/infisical-with-domain.json", "https://custom.infisical.com"},
		{"existing config without a domain field parses to empty", "testdata/infisical-default-env.json", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := GetWorkspaceConfigByPath(tc.path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Domain != tc.wantDomain {
				t.Errorf("Domain = %q, want %q", cfg.Domain, tc.wantDomain)
			}
		})
	}
}

func TestGetEnvDomain(t *testing.T) {
	const unset = "\x00" // sentinel: leave the env var unset for this case

	cases := []struct {
		name    string
		domain  string // INFISICAL_DOMAIN
		apiURL  string // INFISICAL_API_URL (legacy)
		wantVal string
		wantEnv string
		wantOk  bool
	}{
		{"prefers INFISICAL_DOMAIN over legacy", "https://domain.infisical.com", "https://apiurl.infisical.com", "https://domain.infisical.com", INFISICAL_DOMAIN_ENV_NAME, true},
		{"falls back to legacy INFISICAL_API_URL", unset, "https://apiurl.infisical.com", "https://apiurl.infisical.com", LEGACY_INFISICAL_API_URL_ENV_NAME, true},
		{"blank INFISICAL_DOMAIN falls through to legacy", "  ", "https://apiurl.infisical.com", "https://apiurl.infisical.com", LEGACY_INFISICAL_API_URL_ENV_NAME, true},
		{"neither set", unset, unset, "", "", false},
		{"both blank are treated as unset", "  ", "  ", "", "", false},
	}

	setOrUnset := func(t *testing.T, key, val string) {
		t.Helper()
		t.Setenv(key, "") // register restore-on-cleanup, then mutate freely below
		if val == unset {
			os.Unsetenv(key)
			return
		}
		os.Setenv(key, val)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setOrUnset(t, INFISICAL_DOMAIN_ENV_NAME, tc.domain)
			setOrUnset(t, LEGACY_INFISICAL_API_URL_ENV_NAME, tc.apiURL)

			got, ok := GetEnvDomain()
			if ok != tc.wantOk {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOk)
			}
			if got != tc.wantVal {
				t.Errorf("value = %q, want %q", got, tc.wantVal)
			}

			gotDomain, gotEnv, gotOk := GetEnvDomainSource()
			if gotOk != tc.wantOk {
				t.Fatalf("GetEnvDomainSource ok = %v, want %v", gotOk, tc.wantOk)
			}
			if gotDomain != tc.wantVal {
				t.Errorf("GetEnvDomainSource value = %q, want %q", gotDomain, tc.wantVal)
			}
			if gotEnv != tc.wantEnv {
				t.Errorf("GetEnvDomainSource env = %q, want %q", gotEnv, tc.wantEnv)
			}
		})
	}
}

func TestGetDomainFromWorkspaceFile(t *testing.T) {
	cases := []struct {
		name       string
		contents   string
		wantDomain string
		wantUsable bool
	}{
		{"https domain is usable", `{"domain":"https://eu.infisical.com"}`, "https://eu.infisical.com", true},
		{"http domain is usable", `{"domain":"http://localhost:8080"}`, "http://localhost:8080", true},
		{"surrounding whitespace is trimmed", `{"domain":"  https://eu.infisical.com  "}`, "https://eu.infisical.com", true},
		{"domain with an /api suffix is usable", `{"domain":"https://eu.infisical.com/api/"}`, "https://eu.infisical.com/api/", true},
		{"absent domain is not usable", `{"defaultEnvironment":"dev"}`, "", false},
		{"schemeless domain is reported unusable", `{"domain":"eu.infisical.com"}`, "eu.infisical.com", false},
		{"scheme-only https is reported unusable", `{"domain":"https://"}`, "https://", false},
		{"scheme-only http is reported unusable", `{"domain":"http://"}`, "http://", false},
		{"non-http scheme is reported unusable", `{"domain":"ftp://example.com"}`, "ftp://example.com", false},
		{"whitespace domain is reported unusable", `{"domain":"   "}`, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeWorkspace(t, tc.contents)

			gotDomain, gotUsable := GetDomainFromFile()
			if gotDomain != tc.wantDomain {
				t.Errorf("domain = %q, want %q", gotDomain, tc.wantDomain)
			}
			if gotUsable != tc.wantUsable {
				t.Errorf("usable = %v, want %v", gotUsable, tc.wantUsable)
			}
		})
	}
}

const legacyWorkspaceJSON = `{
	"workspaceId": "proj-123",
	"defaultEnvironment": "dev",
	"gitBranchToEnvironmentMapping": {"main": "prod"},
	"defaultSecretPath": "/backend",
	"domain": "https://eu.infisical.com"
}`

const workspaceYAML = `general:
  domain: https://eu.infisical.com
secrets-management:
  project-id: proj-123
  default-environment: dev
  default-secret-path: /backend
  mappings:
    git-branch-to-environment:
      main: prod
`

func assertFullWorkspaceConfig(t *testing.T, cfg models.WorkspaceConfigFile, wantProjectID string) {
	t.Helper()
	if cfg.WorkspaceId != wantProjectID {
		t.Errorf("WorkspaceId = %q, want %q", cfg.WorkspaceId, wantProjectID)
	}
	if cfg.DefaultEnvironment != "dev" {
		t.Errorf("DefaultEnvironment = %q, want dev", cfg.DefaultEnvironment)
	}
	if cfg.DefaultSecretPath != "/backend" {
		t.Errorf("DefaultSecretPath = %q, want /backend", cfg.DefaultSecretPath)
	}
	if cfg.Domain != "https://eu.infisical.com" {
		t.Errorf("Domain = %q, want https://eu.infisical.com", cfg.Domain)
	}
	if got := cfg.GitBranchToEnvironmentMapping["main"]; got != "prod" {
		t.Errorf("GitBranchToEnvironmentMapping[main] = %q, want prod", got)
	}
}

func writeTestFile(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// makeDirReadOnly blocks creating files in dir for the rest of the test, so a .infisical.yaml can't be written.
func makeDirReadOnly(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions don't block writes here")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

// captureStderr sends what the CLI prints to stderr into the returned buffer for the rest of the test.
func captureStderr(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	original := GetStderrWriter
	GetStderrWriter = func() io.Writer { return &buf }
	t.Cleanup(func() { GetStderrWriter = original })
	return &buf
}

// enableWorkspaceConfigMessages turns the yaml messages on for the rest of the test, as the root command does
// outside --silent and structured output.
func enableWorkspaceConfigMessages(t *testing.T) {
	t.Helper()
	EnableWorkspaceConfigMessages()
	t.Cleanup(func() { workspaceConfigMessagesEnabled = false })
}

// startNewRun forgets that the reminder to remove the legacy json was shown, as if the CLI was run again.
func startNewRun() {
	legacyWorkspaceConfigReminderShown = false
}

func TestLegacyWorkspaceConfigRemovalMessage(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
	yamlPath := filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
	writeTestFile(t, jsonPath, legacyWorkspaceJSON)
	stderr := captureStderr(t)
	enableWorkspaceConfigMessages(t)
	startNewRun()

	readWorkspaceConfig := func(t *testing.T) string {
		t.Helper()
		stderr.Reset()
		cfg, err := GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("GetWorkSpaceFromFilePath: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")
		return stderr.String()
	}
	assertContains := func(t *testing.T, out string, wants ...string) {
		t.Helper()
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Errorf("output missing %q, got:\n%s", want, out)
			}
		}
	}

	bothFilesExist := []string{"Both .infisical.yaml and .infisical.json exist in " + dir, "the legacy " + jsonPath + " is no longer used and you can remove it"}

	// the run that creates the yaml says both files exist
	out := readWorkspaceConfig(t)
	assertContains(t, out, append([]string{"Created " + yamlPath}, bothFilesExist...)...)
	if out := readWorkspaceConfig(t); out != "" {
		t.Errorf("expected the message once per run, got on the second read:\n%s", out)
	}

	// later runs keep saying it while both files exist, without creating the yaml again
	for run := 2; run <= 3; run++ {
		startNewRun()
		out := readWorkspaceConfig(t)
		assertContains(t, out, bothFilesExist...)
		if strings.Contains(out, "Created ") {
			t.Errorf("run %d: the yaml already exists, so it should not be created again, got:\n%s", run, out)
		}
		if out := readWorkspaceConfig(t); out != "" {
			t.Errorf("run %d: expected the message once per run, got on the second read:\n%s", run, out)
		}
	}

	// nothing to say once the json is gone
	if err := os.Remove(jsonPath); err != nil {
		t.Fatalf("remove %s: %v", jsonPath, err)
	}
	startNewRun()
	if out := readWorkspaceConfig(t); out != "" {
		t.Errorf("expected no message once the legacy json is removed, got:\n%s", out)
	}
}

func TestLegacyWorkspaceConfigMessagesSilenced(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
	writeTestFile(t, jsonPath, legacyWorkspaceJSON)
	// --silent and structured output leave the messages off
	stderr := captureStderr(t)

	// the run that creates the yaml, then a later run where both files exist
	for run := 1; run <= 2; run++ {
		startNewRun()
		cfg, err := GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("run %d: GetWorkSpaceFromFilePath: %v", run, err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")
		if !fileExists(filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)) {
			t.Fatalf("run %d: the yaml should still be created in silent mode", run)
		}
		if out := stderr.String(); out != "" {
			t.Errorf("run %d: expected no output in silent mode, got:\n%s", run, out)
		}
	}
}

func TestGetWorkSpaceFromFilePath(t *testing.T) {
	t.Run("reads yaml when only yaml exists", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME), workspaceYAML)

		cfg, err := GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")
	})

	t.Run("reads legacy json and creates a yaml beside it", func(t *testing.T) {
		dir := t.TempDir()
		jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		yamlPath := filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, legacyWorkspaceJSON)

		cfg, err := GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")

		yamlCfg, err := readWorkspaceConfigYaml(yamlPath)
		if err != nil {
			t.Fatalf("yaml should be created when reading the legacy json: %v", err)
		}
		assertFullWorkspaceConfig(t, yamlCfg, "proj-123")

		raw, err := os.ReadFile(jsonPath)
		if err != nil {
			t.Fatalf("legacy %s should not be removed: %v", jsonPath, err)
		}
		if string(raw) != legacyWorkspaceJSON {
			t.Errorf("legacy json was modified:\n%s", raw)
		}

		// later reads come from the yaml
		cfg, err = GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("unexpected error on the second read: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")
	})

	t.Run("falls back to the legacy json when the yaml can't be created", func(t *testing.T) {
		dir := t.TempDir()
		jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, legacyWorkspaceJSON)
		makeDirReadOnly(t, dir)

		cfg, err := GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("a failed yaml creation should not fail the read: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")
		if fileExists(filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)) {
			t.Error("yaml should not exist in a read-only directory")
		}
		if !fileExists(jsonPath) {
			t.Errorf("legacy %s should not be removed", jsonPath)
		}
	})

	t.Run("prefers yaml and leaves json untouched when both exist", func(t *testing.T) {
		dir := t.TempDir()
		jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, `{"workspaceId":"from-json"}`)
		writeTestFile(t, filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME), workspaceYAML)

		cfg, err := GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")
		if !fileExists(jsonPath) {
			t.Errorf("legacy %s should not be removed when yaml already exists", jsonPath)
		}
	})

	t.Run("malformed json returns an error and keeps the json", func(t *testing.T) {
		dir := t.TempDir()
		jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, `{not json`)

		if _, err := GetWorkSpaceFromFilePath(dir); err == nil {
			t.Fatal("expected an error for malformed json")
		}
		if !fileExists(jsonPath) {
			t.Errorf("legacy %s should not be removed", jsonPath)
		}
		if fileExists(filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)) {
			t.Error("yaml should not be created from malformed json")
		}
	})

	t.Run("errors when neither file exists", func(t *testing.T) {
		if _, err := GetWorkSpaceFromFilePath(t.TempDir()); err == nil {
			t.Fatal("expected an error when no config file exists")
		}
	})
}

func TestGetWorkSpaceFromFileReadsParentLegacyConfig(t *testing.T) {
	root := t.TempDir()
	jsonPath := filepath.Join(root, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
	writeTestFile(t, jsonPath, legacyWorkspaceJSON)
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Chdir(nested)

	cfg, err := GetWorkSpaceFromFile()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFullWorkspaceConfig(t, cfg, "proj-123")
	if !fileExists(jsonPath) {
		t.Errorf("legacy %s should not be removed", jsonPath)
	}
	yamlPath := filepath.Join(root, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
	if !fileExists(yamlPath) {
		t.Error("yaml should be created next to the legacy json, not in the current directory")
	}
	if fileExists(filepath.Join(nested, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)) {
		t.Error("yaml should not be created in the current directory")
	}

	found, err := FindWorkspaceConfigFile()
	if err != nil {
		t.Fatalf("FindWorkspaceConfigFile: %v", err)
	}
	if filepath.Base(found) != INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME {
		t.Errorf("FindWorkspaceConfigFile = %q, want the created yaml file", found)
	}
}

func TestConvertLegacyWorkspaceConfigToYaml(t *testing.T) {
	t.Run("carries every field over and leaves the json in place", func(t *testing.T) {
		dir := t.TempDir()
		jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		yamlPath := filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, legacyWorkspaceJSON)

		if err := convertLegacyWorkspaceConfigToYaml(jsonPath, yamlPath); err != nil {
			t.Fatalf("convertLegacyWorkspaceConfigToYaml: %v", err)
		}

		cfg, err := readWorkspaceConfigYaml(yamlPath)
		if err != nil {
			t.Fatalf("readWorkspaceConfigYaml: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")

		raw, err := os.ReadFile(yamlPath)
		if err != nil {
			t.Fatalf("read %s: %v", yamlPath, err)
		}
		if !strings.HasPrefix(string(raw), "version: 1\n") {
			t.Errorf("yaml should start with the config version, got:\n%s", raw)
		}

		info, err := os.Stat(yamlPath)
		if err != nil {
			t.Fatalf("stat %s: %v", yamlPath, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("yaml perm = %o, want 600", info.Mode().Perm())
		}
		if !fileExists(jsonPath) {
			t.Error("the legacy json should be left in place")
		}
	})

	t.Run("refuses to overwrite an existing yaml", func(t *testing.T) {
		dir := t.TempDir()
		jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		yamlPath := filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, legacyWorkspaceJSON)
		const existingYAML = "secrets-management:\n  project-id: proj-existing\n"
		writeTestFile(t, yamlPath, existingYAML)

		if err := convertLegacyWorkspaceConfigToYaml(jsonPath, yamlPath); err == nil {
			t.Fatal("expected an error when the yaml already exists")
		}
		raw, err := os.ReadFile(yamlPath)
		if err != nil {
			t.Fatalf("read %s: %v", yamlPath, err)
		}
		if string(raw) != existingYAML {
			t.Errorf("existing yaml was modified:\n%s", raw)
		}
	})

	t.Run("invalid json leaves no yaml behind", func(t *testing.T) {
		dir := t.TempDir()
		jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		yamlPath := filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, "{not json")

		if err := convertLegacyWorkspaceConfigToYaml(jsonPath, yamlPath); err == nil {
			t.Fatal("expected an error for invalid json")
		}
		if fileExists(yamlPath) {
			t.Error("no yaml should be written when the json cannot be read")
		}
	})
}

func TestResolveWorkspaceConfigFile(t *testing.T) {
	t.Run("empty dir walks up from cwd", func(t *testing.T) {
		root := t.TempDir()
		jsonPath := filepath.Join(root, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, legacyWorkspaceJSON)
		nested := filepath.Join(root, "a", "b")
		if err := os.MkdirAll(nested, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		t.Chdir(nested)

		got, err := ResolveWorkspaceConfigFile("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != jsonPath {
			t.Errorf("got %q, want %q", got, jsonPath)
		}
	})

	t.Run("explicit dir does not walk up", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, INFISICAL_WORKSPACE_CONFIG_FILE_NAME), legacyWorkspaceJSON)
		empty := filepath.Join(root, "empty")
		if err := os.MkdirAll(empty, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		t.Chdir(root)

		if _, err := ResolveWorkspaceConfigFile("empty"); err == nil {
			t.Error("expected an error when the explicit dir has no config")
		}
	})

	t.Run("explicit dir prefers yaml and returns an absolute path", func(t *testing.T) {
		root := t.TempDir()
		cfgDir := filepath.Join(root, "cfg")
		if err := os.MkdirAll(cfgDir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		writeTestFile(t, filepath.Join(cfgDir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME), legacyWorkspaceJSON)
		yamlPath := filepath.Join(cfgDir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, yamlPath, workspaceYAML)
		t.Chdir(root)

		got, err := ResolveWorkspaceConfigFile("cfg")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !filepath.IsAbs(got) {
			t.Errorf("expected an absolute path, got %q", got)
		}
		if filepath.Base(got) != INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME {
			t.Errorf("expected the yaml to win, got %q", got)
		}
	})
}
