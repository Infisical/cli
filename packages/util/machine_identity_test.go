package util

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
)

func TestGetAllEnvironmentVariables_MachineIdentityFallsBackToConfig(t *testing.T) {
	const fileWorkspaceID = "ws-from-config-file"

	var seenProjectID atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenProjectID.Store(r.URL.Query().Get("projectId"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[]}`))
	}))
	defer srv.Close()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	prevURL := config.INFISICAL_URL
	config.INFISICAL_URL = parsed.Scheme + "://" + parsed.Host + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = prevURL })

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, ".infisical.json"), []byte(`{"workspaceId":"`+fileWorkspaceID+`"}`), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	_, err = GetAllEnvironmentVariables(models.GetAllSecretsParameters{
		UniversalAuthAccessToken: "fake-universal-auth-token",
		Environment:              "dev",
	}, "")
	if err != nil {
		t.Fatalf("GetAllEnvironmentVariables: %v", err)
	}

	got, _ := seenProjectID.Load().(string)
	if got != fileWorkspaceID {
		t.Fatalf("workspace id sent to API = %q, want %q (issue #365: --projectId missing should fall back to .infisical.json)", got, fileWorkspaceID)
	}
}

func TestGetAllEnvironmentVariables_MachineIdentityFlagWins(t *testing.T) {
	const flagWorkspaceID = "ws-from-flag"
	const fileWorkspaceID = "ws-from-config-file"

	var seenProjectID atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenProjectID.Store(r.URL.Query().Get("projectId"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[]}`))
	}))
	defer srv.Close()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	prevURL := config.INFISICAL_URL
	config.INFISICAL_URL = parsed.Scheme + "://" + parsed.Host + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = prevURL })

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, ".infisical.json"), []byte(`{"workspaceId":"`+fileWorkspaceID+`"}`), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	_, err = GetAllEnvironmentVariables(models.GetAllSecretsParameters{
		UniversalAuthAccessToken: "fake-universal-auth-token",
		WorkspaceId:              flagWorkspaceID,
		Environment:              "dev",
	}, "")
	if err != nil {
		t.Fatalf("GetAllEnvironmentVariables: %v", err)
	}

	got, _ := seenProjectID.Load().(string)
	if got != flagWorkspaceID {
		t.Fatalf("workspace id sent to API = %q, want %q (--projectId should win over .infisical.json)", got, flagWorkspaceID)
	}
}


func TestGetAllFolders_MachineIdentityFallsBackToConfig(t *testing.T) {
	const fileWorkspaceID = "ws-from-config-file"

	var seenWorkspaceID atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenWorkspaceID.Store(r.URL.Query().Get("workspaceId"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"folders":[]}`))
	}))
	defer srv.Close()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	prevURL := config.INFISICAL_URL
	config.INFISICAL_URL = parsed.Scheme + "://" + parsed.Host + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = prevURL })

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, ".infisical.json"), []byte(`{"workspaceId":"`+fileWorkspaceID+`"}`), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	_, err = GetAllFolders(models.GetAllFoldersParameters{
		UniversalAuthAccessToken: "fake-universal-auth-token",
		Environment:              "dev",
	})
	if err != nil {
		t.Fatalf("GetAllFolders: %v", err)
	}

	got, _ := seenWorkspaceID.Load().(string)
	if got != fileWorkspaceID {
		t.Fatalf("workspace id sent to API = %q, want %q (issue #365: --projectId missing should fall back to .infisical.json)", got, fileWorkspaceID)
	}
}
