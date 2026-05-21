package util

import (
	"testing"
)

func TestGetWorkspaceConfigByPath_WithApiUrl(t *testing.T) {
	cfg, err := GetWorkspaceConfigByPath("testdata/infisical-with-api-url.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.WorkspaceId != "test-workspace-id" {
		t.Errorf("expected workspaceId 'test-workspace-id', got '%s'", cfg.WorkspaceId)
	}
	if cfg.ApiUrl != "https://custom.infisical.com/api" {
		t.Errorf("expected apiUrl 'https://custom.infisical.com/api', got '%s'", cfg.ApiUrl)
	}
}

func TestGetWorkspaceConfigByPath_WithoutApiUrl(t *testing.T) {
	cfg, err := GetWorkspaceConfigByPath("testdata/infisical-default-env.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ApiUrl != "" {
		t.Errorf("expected empty apiUrl, got '%s'", cfg.ApiUrl)
	}
}

func TestGetWorkspaceConfigByPath_WithMalformedApiUrl(t *testing.T) {
	cfg, err := GetWorkspaceConfigByPath("testdata/infisical-with-malformed-api-url.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ApiUrl != "not-a-valid-url" {
		t.Errorf("expected apiUrl 'not-a-valid-url', got '%s'", cfg.ApiUrl)
	}
}
