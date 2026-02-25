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

func TestParseSetCommand(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantKV     []string
		wantFlags  []string
	}{
		{
			name:      "simple set",
			input:     "infisical secrets set DB_URL=postgres://localhost --env=dev",
			wantKV:    []string{"DB_URL=postgres://localhost"},
			wantFlags: []string{"--env=dev"},
		},
		{
			name:      "set with path",
			input:     "infisical secrets set API_KEY=sk-test-123 --env=staging --path=/backend",
			wantKV:    []string{"API_KEY=sk-test-123"},
			wantFlags: []string{"--env=staging", "--path=/backend"},
		},
		{
			name:      "multiple KV pairs",
			input:     "infisical secrets set KEY1=val1 KEY2=val2 --env=dev",
			wantKV:    []string{"KEY1=val1", "KEY2=val2"},
			wantFlags: []string{"--env=dev"},
		},
		{
			name:      "without infisical prefix",
			input:     "secrets set MY_SECRET=hello --env=prod",
			wantKV:    []string{"MY_SECRET=hello"},
			wantFlags: []string{"--env=prod"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kv, flags := ParseSetCommand(tt.input)
			if len(kv) != len(tt.wantKV) {
				t.Errorf("kv: expected %v, got %v", tt.wantKV, kv)
			} else {
				for i, v := range kv {
					if v != tt.wantKV[i] {
						t.Errorf("kv[%d]: expected %q, got %q", i, tt.wantKV[i], v)
					}
				}
			}
			if len(flags) != len(tt.wantFlags) {
				t.Errorf("flags: expected %v, got %v", tt.wantFlags, flags)
			} else {
				for i, v := range flags {
					if v != tt.wantFlags[i] {
						t.Errorf("flags[%d]: expected %q, got %q", i, tt.wantFlags[i], v)
					}
				}
			}
		})
	}
}

func TestIsSecretsSetCommand(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"infisical secrets set KEY=val --env=dev", true},
		{"secrets set KEY=val --env=dev", true},
		{"infisical secrets get KEY --env=dev", false},
		{"infisical export --format=json", false},
		{"infisical secrets delete KEY --env=dev", false},
	}

	for _, tt := range tests {
		got := IsSecretsSetCommand(tt.input)
		if got != tt.want {
			t.Errorf("IsSecretsSetCommand(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
