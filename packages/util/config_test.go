package util

import (
	"os"
	"path/filepath"
	"runtime"
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

	t.Run("migrates json to yaml and removes json", func(t *testing.T) {
		dir := t.TempDir()
		jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		yamlPath := filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, legacyWorkspaceJSON)

		cfg, err := GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")

		if fileExists(jsonPath) {
			t.Errorf("legacy %s should have been removed", jsonPath)
		}
		migrated, err := readWorkspaceConfigYaml(yamlPath)
		if err != nil {
			t.Fatalf("reading migrated yaml: %v", err)
		}
		assertFullWorkspaceConfig(t, migrated, "proj-123")

		info, err := os.Stat(yamlPath)
		if err != nil {
			t.Fatalf("stat yaml: %v", err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("yaml perm = %o, want 600", info.Mode().Perm())
		}

		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 {
			t.Errorf("expected only %s in dir, got %v", INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME, entries)
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
			t.Errorf("legacy %s should not be removed when migration fails", jsonPath)
		}
		if fileExists(filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)) {
			t.Error("yaml should not be created from malformed json")
		}
	})

	t.Run("falls back to json when yaml cannot be written", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("read-only directories are not enforced on windows or for root")
		}
		dir := t.TempDir()
		jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, legacyWorkspaceJSON)
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0o700) })

		cfg, err := GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")
		if !fileExists(jsonPath) {
			t.Errorf("legacy %s should not be removed when migration fails", jsonPath)
		}
		if fileExists(filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)) {
			t.Error("yaml should not exist when it could not be written")
		}
	})

	t.Run("errors when neither file exists", func(t *testing.T) {
		if _, err := GetWorkSpaceFromFilePath(t.TempDir()); err == nil {
			t.Fatal("expected an error when no config file exists")
		}
	})
}

func TestGetWorkSpaceFromFileMigratesParentConfig(t *testing.T) {
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
	if fileExists(jsonPath) {
		t.Errorf("legacy %s should have been removed", jsonPath)
	}

	found, err := FindWorkspaceConfigFile()
	if err != nil {
		t.Fatalf("FindWorkspaceConfigFile: %v", err)
	}
	if filepath.Base(found) != INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME {
		t.Errorf("FindWorkspaceConfigFile = %q, want the yaml file", found)
	}
}
