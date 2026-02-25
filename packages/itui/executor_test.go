package itui

import (
	"encoding/json"
	"testing"
)

func TestParseSecretsJSON(t *testing.T) {
	input := `[
		{"key":"DATABASE_URL","workspace":"ws-123","value":"postgres://localhost:5432/db","type":"shared","_id":"sec-1","secretPath":"/","tags":[],"comment":"Main DB"},
		{"key":"API_KEY","workspace":"ws-123","value":"sk-test-123","type":"shared","_id":"sec-2","secretPath":"/","tags":[],"comment":""}
	]`

	var secrets []Secret
	err := json.Unmarshal([]byte(input), &secrets)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}

	if secrets[0].Key != "DATABASE_URL" {
		t.Errorf("expected DATABASE_URL, got %s", secrets[0].Key)
	}
	if secrets[0].Value != "postgres://localhost:5432/db" {
		t.Errorf("unexpected value: %s", secrets[0].Value)
	}
	if secrets[0].Type != "shared" {
		t.Errorf("expected shared, got %s", secrets[0].Type)
	}
	if secrets[0].Comment != "Main DB" {
		t.Errorf("expected 'Main DB', got '%s'", secrets[0].Comment)
	}

	if secrets[1].Key != "API_KEY" {
		t.Errorf("expected API_KEY, got %s", secrets[1].Key)
	}
}

func TestParseSecretsEmptyArray(t *testing.T) {
	var secrets []Secret
	err := json.Unmarshal([]byte("[]"), &secrets)
	if err != nil {
		t.Fatalf("failed to parse empty array: %v", err)
	}
	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(secrets))
	}
}

func TestParseSecretsNull(t *testing.T) {
	// infisical export outputs "null" for empty projects
	var secrets []Secret
	err := json.Unmarshal([]byte("null"), &secrets)
	if err != nil {
		t.Fatalf("failed to parse null: %v", err)
	}
	if secrets != nil {
		t.Logf("null unmarshals to nil slice, which is expected")
	}
}

func TestParseSecretsMalformedJSON(t *testing.T) {
	var secrets []Secret
	err := json.Unmarshal([]byte("not json at all"), &secrets)
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    "secrets set KEY=value --env=dev",
			expected: []string{"secrets", "set", "KEY=value", "--env=dev"},
		},
		{
			input:    "secrets set KEY='value with spaces' --env=dev",
			expected: []string{"secrets", "set", "KEY=value with spaces", "--env=dev"},
		},
		{
			input:    `secrets set KEY="another value" --env=prod`,
			expected: []string{"secrets", "set", "KEY=another value", "--env=prod"},
		},
		{
			input:    "export --format=json --env=staging",
			expected: []string{"export", "--format=json", "--env=staging"},
		},
		{
			input:    "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		result := splitArgs(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("splitArgs(%q): expected %d args, got %d (%v)", tt.input, len(tt.expected), len(result), result)
			continue
		}
		for i, arg := range result {
			if arg != tt.expected[i] {
				t.Errorf("splitArgs(%q)[%d]: expected %q, got %q", tt.input, i, tt.expected[i], arg)
			}
		}
	}
}

func TestBuildSetArgs(t *testing.T) {
	e := &Executor{binaryPath: "infisical"}
	// Simulate what RunRaw does for a set command
	cmd := "infisical secrets set DB_URL=postgres://localhost --env=dev --path=/"
	result := splitArgs(cmd[len("infisical "):]) // strip "infisical " prefix

	expected := []string{"secrets", "set", "DB_URL=postgres://localhost", "--env=dev", "--path=/"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d args, got %d: %v", len(expected), len(result), result)
	}

	for i, arg := range result {
		if arg != expected[i] {
			t.Errorf("arg[%d]: expected %q, got %q", i, expected[i], arg)
		}
	}

	_ = e // satisfy linter
}
