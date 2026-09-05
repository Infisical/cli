package util

import (
	"os"
	"path/filepath"
	"testing"
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
		wantOk  bool
	}{
		{"prefers INFISICAL_DOMAIN over legacy", "https://domain.infisical.com", "https://apiurl.infisical.com", "https://domain.infisical.com", true},
		{"falls back to legacy INFISICAL_API_URL", unset, "https://apiurl.infisical.com", "https://apiurl.infisical.com", true},
		{"blank INFISICAL_DOMAIN falls through to legacy", "  ", "https://apiurl.infisical.com", "https://apiurl.infisical.com", true},
		{"neither set", unset, unset, "", false},
		{"both blank are treated as unset", "  ", "  ", "", false},
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
		})
	}
}

func TestResolveWorkspaceIdForMachineIdentity(t *testing.T) {
	t.Run("explicit value wins over file", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile(filepath.Join(dir, ".infisical.json"), []byte(`{"workspaceId":"fromfile"}`), 0o600); err != nil {
			t.Fatalf("write workspace: %v", err)
		}

		got, err := ResolveWorkspaceIdForMachineIdentity("", "fromflag")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "fromflag" {
			t.Fatalf("got %q, want fromflag", got)
		}
	})

	t.Run("falls back to .infisical.json in cwd", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile(filepath.Join(dir, ".infisical.json"), []byte(`{"workspaceId":"fromfile"}`), 0o600); err != nil {
			t.Fatalf("write workspace: %v", err)
		}

		got, err := ResolveWorkspaceIdForMachineIdentity("", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "fromfile" {
			t.Fatalf("got %q, want fromfile", got)
		}
	})

	t.Run("falls back to .infisical.json in parent directory", func(t *testing.T) {
		parent := t.TempDir()
		if err := os.WriteFile(filepath.Join(parent, ".infisical.json"), []byte(`{"workspaceId":"fromparent"}`), 0o600); err != nil {
			t.Fatalf("write workspace: %v", err)
		}
		child := filepath.Join(parent, "nested", "dir")
		if err := os.MkdirAll(child, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		t.Chdir(child)

		got, err := ResolveWorkspaceIdForMachineIdentity("", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "fromparent" {
			t.Fatalf("got %q, want fromparent", got)
		}
	})

	t.Run("uses explicit projectConfigFilePath when provided", func(t *testing.T) {
		// cwd is empty; the file lives in a different dir passed explicitly.
		t.Chdir(t.TempDir())
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".infisical.json"), []byte(`{"workspaceId":"fromexplicitpath"}`), 0o600); err != nil {
			t.Fatalf("write workspace: %v", err)
		}

		got, err := ResolveWorkspaceIdForMachineIdentity(dir, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "fromexplicitpath" {
			t.Fatalf("got %q, want fromexplicitpath", got)
		}
	})

	t.Run("explicit path takes precedence over cwd file", func(t *testing.T) {
		// cwd has a file with one id, the explicit path has another.
		cwd := t.TempDir()
		t.Chdir(cwd)
		if err := os.WriteFile(filepath.Join(cwd, ".infisical.json"), []byte(`{"workspaceId":"fromcwd"}`), 0o600); err != nil {
			t.Fatalf("write workspace: %v", err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".infisical.json"), []byte(`{"workspaceId":"fromexplicitpath"}`), 0o600); err != nil {
			t.Fatalf("write workspace: %v", err)
		}

		got, err := ResolveWorkspaceIdForMachineIdentity(dir, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "fromexplicitpath" {
			t.Fatalf("got %q, want fromexplicitpath", got)
		}
	})

	t.Run("error when no file and no explicit value", func(t *testing.T) {
		t.Chdir(t.TempDir())
		_, err := ResolveWorkspaceIdForMachineIdentity("", "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("error when explicit path file is missing", func(t *testing.T) {
		t.Chdir(t.TempDir())
		_, err := ResolveWorkspaceIdForMachineIdentity(t.TempDir(), "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("error when workspaceId is empty in config file", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile(filepath.Join(dir, ".infisical.json"), []byte(`{"workspaceId":""}`), 0o600); err != nil {
			t.Fatalf("write workspace: %v", err)
		}

		_, err := ResolveWorkspaceIdForMachineIdentity("", "")
		if err == nil {
			t.Fatal("expected error when workspaceId is empty, got nil")
		}
	})
}

