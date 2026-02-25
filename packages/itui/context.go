package itui

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// infisicalConfig mirrors ~/.infisical/infisical-config.json
type infisicalConfig struct {
	LoggedInUserEmail  string `json:"loggedInUserEmail"`
	LoggedInUserDomain string `json:"LoggedInUserDomain"`
}

// workspaceConfig mirrors .infisical.json in the project directory
type workspaceConfig struct {
	WorkspaceID        string `json:"workspaceId"`
	DefaultEnvironment string `json:"defaultEnvironment"`
}

// LoadSessionContext loads the session context from config files
func LoadSessionContext() SessionContext {
	ctx := SessionContext{
		Environment:  "dev",
		Path:         "/",
		Environments: []string{"dev", "staging", "prod"},
	}

	// Load user info from ~/.infisical/infisical-config.json
	if cfg, err := loadInfisicalConfig(); err == nil {
		ctx.UserEmail = cfg.LoggedInUserEmail
		ctx.IsLoggedIn = cfg.LoggedInUserEmail != ""
	}

	// Load workspace info from .infisical.json in cwd
	if ws, err := loadWorkspaceConfig(); err == nil {
		ctx.ProjectID = ws.WorkspaceID
		if ws.DefaultEnvironment != "" {
			ctx.Environment = ws.DefaultEnvironment
		}
	}

	// Try to get project name (we'll use the ProjectID for now)
	if ctx.ProjectID != "" {
		ctx.ProjectName = ctx.ProjectID
	}

	return ctx
}

func loadInfisicalConfig() (*infisicalConfig, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(homeDir, ".infisical", "infisical-config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var cfg infisicalConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func loadWorkspaceConfig() (*workspaceConfig, error) {
	data, err := os.ReadFile(".infisical.json")
	if err != nil {
		return nil, err
	}

	var ws workspaceConfig
	if err := json.Unmarshal(data, &ws); err != nil {
		return nil, err
	}

	return &ws, nil
}
