package itui

import "time"

// FocusedPane tracks which pane has keyboard focus
type FocusedPane int

const (
	PaneSecretBrowser FocusedPane = iota
	PaneDetailOutput
	PanePrompt
)

// AppMode tracks the overall UI state
type AppMode int

const (
	ModeNormal AppMode = iota
	ModePromptInput
	ModeCommandPreview
	ModeConfirmation
	ModeEnvPicker
	ModeSecretForm
	ModeHelp
	ModeSearch
)

// Secret mirrors the JSON output from infisical export --format=json
type Secret struct {
	Key                   string `json:"key"`
	Value                 string `json:"value"`
	Type                  string `json:"type"`
	ID                    string `json:"_id"`
	SecretPath            string `json:"secretPath"`
	WorkspaceID           string `json:"workspace"`
	Comment               string `json:"comment"`
	Tags                  []Tag  `json:"tags"`
	SkipMultilineEncoding bool   `json:"skipMultilineEncoding"`
}

// Tag on a secret
type Tag struct {
	ID   string `json:"_id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// SessionContext holds the current TUI session state
type SessionContext struct {
	UserEmail    string
	ProjectID    string
	ProjectName  string
	Environment  string
	Path         string
	IsLoggedIn   bool
	LoginExpired bool
	Environments []string
}

// AIResponse is the structured response from the AI model
type AIResponse struct {
	Command              string `json:"command"`
	Explanation          string `json:"explanation"`
	ActionType           string `json:"action_type"`
	RequiresConfirmation bool   `json:"requires_confirmation"`
}

// CommandResult holds the output of an executed CLI command
type CommandResult struct {
	Command  string
	Stdout   string
	Stderr   string
	Error    error
	ExecTime time.Duration
}
