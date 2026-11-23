package util

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
)

func writeWorkspaceFile(t *testing.T, dir string, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveMachineIdentityWorkspaceId(t *testing.T) {
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, `{"workspaceId":"from-file"}`)

	t.Run("an explicit project ID wins over the config file", func(t *testing.T) {
		got, err := ResolveMachineIdentityWorkspaceId("explicit", dir)
		if err != nil || got != "explicit" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("falls back to the config file in the given directory", func(t *testing.T) {
		got, err := ResolveMachineIdentityWorkspaceId("", dir)
		if err != nil || got != "from-file" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("falls back to the nearest config file from the working directory", func(t *testing.T) {
		nested := filepath.Join(dir, "a", "b")
		if err := os.MkdirAll(nested, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(nested)
		got, err := ResolveMachineIdentityWorkspaceId("", "")
		if err != nil || got != "from-file" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("errors when there is no project ID anywhere", func(t *testing.T) {
		empty := t.TempDir()
		_, err := ResolveMachineIdentityWorkspaceId("", empty)
		if err == nil || !strings.Contains(err.Error(), "Project ID is required when using machine identity") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("errors when the config file has no workspaceId", func(t *testing.T) {
		noId := t.TempDir()
		writeWorkspaceFile(t, noId, `{"defaultEnvironment":"dev"}`)
		_, err := ResolveMachineIdentityWorkspaceId("", noId)
		if err == nil || !strings.Contains(err.Error(), "workspaceId") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestGetAllEnvironmentVariablesMachineIdentityUsesWorkspaceConfigFile(t *testing.T) {
	var gotProjectId string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProjectId = r.URL.Query().Get("projectId")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[{"id":"s1","secretKey":"KEY","secretValue":"value","type":"shared"}],"imports":[]}`))
	}))
	t.Cleanup(server.Close)
	orig := config.INFISICAL_URL
	config.INFISICAL_URL = server.URL
	t.Cleanup(func() { config.INFISICAL_URL = orig })

	dir := t.TempDir()
	writeWorkspaceFile(t, dir, `{"workspaceId":"project-from-file"}`)
	t.Chdir(dir)

	secrets, err := GetAllEnvironmentVariables(models.GetAllSecretsParameters{
		Environment:              "dev",
		SecretsPath:              "/",
		UniversalAuthAccessToken: "token",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || gotProjectId != "project-from-file" {
		t.Fatalf("secrets=%v projectId=%q", secrets, gotProjectId)
	}
}
