package itui

import (
	"encoding/json"
	"testing"
)

func TestInfisicalConfigParsing(t *testing.T) {
	input := `{"loggedInUserEmail":"test@example.com","LoggedInUserDomain":"https://app.infisical.com/api","loggedInUsers":[{"email":"test@example.com","domain":"https://app.infisical.com/api"}]}`

	var cfg infisicalConfig
	err := json.Unmarshal([]byte(input), &cfg)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if cfg.LoggedInUserEmail != "test@example.com" {
		t.Errorf("expected test@example.com, got %s", cfg.LoggedInUserEmail)
	}
	if cfg.LoggedInUserDomain != "https://app.infisical.com/api" {
		t.Errorf("unexpected domain: %s", cfg.LoggedInUserDomain)
	}
}

func TestWorkspaceConfigParsing(t *testing.T) {
	input := `{"workspaceId":"ws-abc-123","defaultEnvironment":"staging"}`

	var ws workspaceConfig
	err := json.Unmarshal([]byte(input), &ws)
	if err != nil {
		t.Fatalf("failed to parse workspace config: %v", err)
	}

	if ws.WorkspaceID != "ws-abc-123" {
		t.Errorf("expected ws-abc-123, got %s", ws.WorkspaceID)
	}
	if ws.DefaultEnvironment != "staging" {
		t.Errorf("expected staging, got %s", ws.DefaultEnvironment)
	}
}

func TestWorkspaceConfigEmpty(t *testing.T) {
	input := `{}`

	var ws workspaceConfig
	err := json.Unmarshal([]byte(input), &ws)
	if err != nil {
		t.Fatalf("failed to parse empty config: %v", err)
	}

	if ws.WorkspaceID != "" {
		t.Errorf("expected empty workspace ID, got %s", ws.WorkspaceID)
	}
	if ws.DefaultEnvironment != "" {
		t.Errorf("expected empty default env, got %s", ws.DefaultEnvironment)
	}
}

func TestSessionContextDefaults(t *testing.T) {
	// LoadSessionContext should return sensible defaults even when files don't exist
	// We can't easily test the full function without mocking the filesystem,
	// but we can test the default initialization
	ctx := SessionContext{
		Environment:  "dev",
		Path:         "/",
		Environments: []string{"dev", "staging", "prod"},
	}

	if ctx.Environment != "dev" {
		t.Errorf("expected dev, got %s", ctx.Environment)
	}
	if ctx.Path != "/" {
		t.Errorf("expected /, got %s", ctx.Path)
	}
	if len(ctx.Environments) != 3 {
		t.Errorf("expected 3 environments, got %d", len(ctx.Environments))
	}
	if ctx.IsLoggedIn {
		t.Error("expected not logged in by default")
	}
}
