package itui

import (
	"testing"
)

func TestParseValidAIResponse(t *testing.T) {
	input := `{"command": "infisical export --env=prod --format=json", "explanation": "Lists all production secrets", "action_type": "read", "requires_confirmation": false}`

	resp, err := parseAIResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Command != "infisical export --env=prod --format=json" {
		t.Errorf("expected command 'infisical export --env=prod --format=json', got '%s'", resp.Command)
	}
	if resp.Explanation != "Lists all production secrets" {
		t.Errorf("expected explanation 'Lists all production secrets', got '%s'", resp.Explanation)
	}
	if resp.ActionType != "read" {
		t.Errorf("expected action_type 'read', got '%s'", resp.ActionType)
	}
	if resp.RequiresConfirmation {
		t.Error("expected requires_confirmation false")
	}
}

func TestParseAIResponseWithMarkdownFences(t *testing.T) {
	input := "```json\n{\"command\": \"infisical secrets delete KEY --env=dev\", \"explanation\": \"Deletes KEY from dev\", \"action_type\": \"destructive\", \"requires_confirmation\": true}\n```"

	resp, err := parseAIResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Command != "infisical secrets delete KEY --env=dev" {
		t.Errorf("unexpected command: %s", resp.Command)
	}
	if resp.ActionType != "destructive" {
		t.Errorf("expected destructive, got %s", resp.ActionType)
	}
	if !resp.RequiresConfirmation {
		t.Error("expected requires_confirmation true for destructive action")
	}
}

func TestParseAIResponseClarification(t *testing.T) {
	input := `{"command": "", "explanation": "Which environment do you want to delete from?", "action_type": "read", "requires_confirmation": false}`

	resp, err := parseAIResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Command != "" {
		t.Errorf("expected empty command for clarification, got '%s'", resp.Command)
	}
	if resp.Explanation != "Which environment do you want to delete from?" {
		t.Errorf("unexpected explanation: %s", resp.Explanation)
	}
}

func TestParseAIResponseInvalidJSON(t *testing.T) {
	input := "Sorry, I don't understand that request."

	resp, err := parseAIResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return the text as explanation with empty command
	if resp.Command != "" {
		t.Errorf("expected empty command, got '%s'", resp.Command)
	}
	if resp.Explanation != "Sorry, I don't understand that request." {
		t.Errorf("unexpected explanation: %s", resp.Explanation)
	}
}

func TestParseAIResponseEmbeddedJSON(t *testing.T) {
	input := "Here is the command:\n{\"command\": \"infisical secrets set KEY=val --env=dev\", \"explanation\": \"Sets KEY\", \"action_type\": \"write\", \"requires_confirmation\": true}\nLet me know if you need help."

	resp, err := parseAIResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Command != "infisical secrets set KEY=val --env=dev" {
		t.Errorf("unexpected command: %s", resp.Command)
	}
	if resp.ActionType != "write" {
		t.Errorf("expected write, got %s", resp.ActionType)
	}
}

func TestBuildSystemPrompt(t *testing.T) {
	ctx := SessionContext{
		UserEmail:   "test@example.com",
		ProjectID:   "proj-123",
		ProjectName: "test-project",
		Environment: "staging",
		Path:        "/backend",
	}

	prompt := buildSystemPrompt(ctx)

	if len(prompt) == 0 {
		t.Error("system prompt should not be empty")
	}

	// Check that context values are interpolated
	tests := []struct {
		name     string
		contains string
	}{
		{"user email", "test@example.com"},
		{"project ID", "proj-123"},
		{"project name", "test-project"},
		{"environment", "staging"},
		{"path", "/backend"},
		{"response format", "JSON"},
		{"infisical CLI reference", "infisical secrets"},
	}

	for _, tt := range tests {
		if !containsStr(prompt, tt.contains) {
			t.Errorf("system prompt missing %s (%s)", tt.name, tt.contains)
		}
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
