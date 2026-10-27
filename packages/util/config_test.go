package util

import (
	"maps"
	"os"
	"path/filepath"
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
		writeTestFile(t, filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME), workspaceYAML)

		cfg, err := GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")
	})

	t.Run("reads legacy json when only json exists", func(t *testing.T) {
		dir := t.TempDir()
		jsonPath := filepath.Join(dir, LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, legacyWorkspaceJSON)

		cfg, err := GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")

		if !fileExists(jsonPath) {
			t.Errorf("legacy %s should not be removed", jsonPath)
		}
		if fileExists(filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)) {
			t.Error("yaml should not be created when reading the legacy json")
		}
	})

	t.Run("prefers yaml and leaves json untouched when both exist", func(t *testing.T) {
		dir := t.TempDir()
		jsonPath := filepath.Join(dir, LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, `{"workspaceId":"from-json"}`)
		writeTestFile(t, filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME), workspaceYAML)

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
		jsonPath := filepath.Join(dir, LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, `{not json`)

		if _, err := GetWorkSpaceFromFilePath(dir); err == nil {
			t.Fatal("expected an error for malformed json")
		}
		if !fileExists(jsonPath) {
			t.Errorf("legacy %s should not be removed", jsonPath)
		}
		if fileExists(filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)) {
			t.Error("yaml should not be created from malformed json")
		}
	})

	t.Run("errors when neither file exists", func(t *testing.T) {
		if _, err := GetWorkSpaceFromFilePath(t.TempDir()); err == nil {
			t.Fatal("expected an error when no config file exists")
		}
	})
}

const workspaceYAMLCurrent = `general:
  domain: https://eu.infisical.com
secrets-management:
  project-id: proj-123
  environment: dev
  secret-path: /backend
  overrides:
    git-branch:
      - branch: main
        environment: prod
      - branch: staging
        environment: staging
`

func TestWorkspaceConfigYamlSchemas(t *testing.T) {
	readYaml := func(t *testing.T, contents string) (models.WorkspaceConfigFile, error) {
		t.Helper()
		dir := t.TempDir()
		yamlPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, yamlPath, contents)
		cfg, err := GetWorkSpaceFromFilePath(dir)

		raw, readErr := os.ReadFile(yamlPath)
		if readErr != nil {
			t.Fatalf("read %s: %v", yamlPath, readErr)
		}
		if string(raw) != contents {
			t.Errorf("%s should not be modified when read, got:\n%s", yamlPath, raw)
		}
		return cfg, err
	}

	t.Run("reads the current keys", func(t *testing.T) {
		cfg, err := readYaml(t, workspaceYAMLCurrent)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")
		if got := cfg.GitBranchToEnvironmentMapping["staging"]; got != "staging" {
			t.Errorf("GitBranchToEnvironmentMapping[staging] = %q, want staging", got)
		}
	})

	t.Run("reads the deprecated default-environment, default-secret-path and mappings", func(t *testing.T) {
		cfg, err := readYaml(t, workspaceYAML)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")
	})

	t.Run("the current keys win over the deprecated ones", func(t *testing.T) {
		cfg, err := readYaml(t, `secrets-management:
  project-id: proj-123
  default-environment: old-default
  default-secret-path: /old
  mappings:
    git-branch-to-environment:
      main: old-main
      feature: old-feature
  environment: dev
  secret-path: /backend
  overrides:
    git-branch:
      - branch: main
        environment: prod
`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.DefaultEnvironment != "dev" {
			t.Errorf("DefaultEnvironment = %q, want dev", cfg.DefaultEnvironment)
		}
		if cfg.DefaultSecretPath != "/backend" {
			t.Errorf("DefaultSecretPath = %q, want /backend", cfg.DefaultSecretPath)
		}
		// the deprecated mappings are ignored, not merged with the overrides
		want := map[string]string{"main": "prod"}
		if !maps.Equal(cfg.GitBranchToEnvironmentMapping, want) {
			t.Errorf("GitBranchToEnvironmentMapping = %v, want %v", cfg.GitBranchToEnvironmentMapping, want)
		}
	})

	t.Run("overrides alone keep the deprecated default-environment and default-secret-path", func(t *testing.T) {
		cfg, err := readYaml(t, `secrets-management:
  project-id: proj-123
  default-environment: prod
  default-secret-path: /old
  mappings:
    git-branch-to-environment:
      main: old-main
  overrides:
    git-branch:
      - branch: feature/x
        environment: staging
`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.DefaultEnvironment != "prod" {
			t.Errorf("DefaultEnvironment = %q, want prod", cfg.DefaultEnvironment)
		}
		if cfg.DefaultSecretPath != "/old" {
			t.Errorf("DefaultSecretPath = %q, want /old", cfg.DefaultSecretPath)
		}
		want := map[string]string{"feature/x": "staging"}
		if !maps.Equal(cfg.GitBranchToEnvironmentMapping, want) {
			t.Errorf("GitBranchToEnvironmentMapping = %v, want %v", cfg.GitBranchToEnvironmentMapping, want)
		}
	})

	t.Run("environment and secret-path alone keep the deprecated mappings", func(t *testing.T) {
		cfg, err := readYaml(t, `secrets-management:
  project-id: proj-123
  default-environment: old-default
  default-secret-path: /old
  mappings:
    git-branch-to-environment:
      main: prod
  environment: dev
  secret-path: /backend
`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.DefaultEnvironment != "dev" {
			t.Errorf("DefaultEnvironment = %q, want dev", cfg.DefaultEnvironment)
		}
		if cfg.DefaultSecretPath != "/backend" {
			t.Errorf("DefaultSecretPath = %q, want /backend", cfg.DefaultSecretPath)
		}
		want := map[string]string{"main": "prod"}
		if !maps.Equal(cfg.GitBranchToEnvironmentMapping, want) {
			t.Errorf("GitBranchToEnvironmentMapping = %v, want %v", cfg.GitBranchToEnvironmentMapping, want)
		}
	})

	t.Run("first override for a branch wins and entries without a branch are skipped", func(t *testing.T) {
		cfg, err := readYaml(t, `secrets-management:
  project-id: proj-123
  overrides:
    git-branch:
      - environment: orphan
      - branch: main
        environment: prod
      - branch: main
        environment: staging
`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := map[string]string{"main": "prod"}
		if !maps.Equal(cfg.GitBranchToEnvironmentMapping, want) {
			t.Errorf("GitBranchToEnvironmentMapping = %v, want %v", cfg.GitBranchToEnvironmentMapping, want)
		}
	})
}

func TestGetWorkSpaceFromFileReadsParentLegacyConfig(t *testing.T) {
	root := t.TempDir()
	jsonPath := filepath.Join(root, LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
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
	if fileExists(filepath.Join(root, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)) {
		t.Error("yaml should not be created when reading the legacy json")
	}

	found, err := FindWorkspaceConfigFile()
	if err != nil {
		t.Fatalf("FindWorkspaceConfigFile: %v", err)
	}
	if filepath.Base(found) != LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME {
		t.Errorf("FindWorkspaceConfigFile = %q, want the legacy json file", found)
	}
}
