package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"gopkg.in/yaml.v2"
)

func TestSuggestedValue(t *testing.T) {
	cases := map[string]string{
		"6f1c2a3e-8b4d-4c1a-9e2f-3a5b7c9d1e0f":   "6f1c2a3e-8b4d-4c1a-9e2f-3a5b7c9d1e0f",
		"6F1C2A3E-8B4D-4C1A-9E2F-3A5B7C9D1E0F":   "6F1C2A3E-8B4D-4C1A-9E2F-3A5B7C9D1E0F",
		"{6f1c2a3e-8b4d-4c1a-9e2f-3a5b7c9d1e0f}": "<v>",
		"payments-api":                           "payments-api",
		"qa":                                     "qa",
		"DB_PASSWORD":                            "DB_PASSWORD",
		"/app/api":                               "/app/api",
		"/":                                      "/",
		"":                                       "<v>",
		"has space":                              "<v>",
		"qa; rm -rf /":                           "<v>",
		"$(whoami)":                              "<v>",
		"`id`":                                   "<v>",
		"a'b":                                    "<v>",
		"line\nbreak":                            "<v>",
		"/app/../etc":                            "<v>",
		"st.abc.def.ghi":                         "<v>",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig": "<v>",
		strings.Repeat("a", 65):                    "<v>",
		strings.Repeat("a", 64):                    strings.Repeat("a", 64),
	}
	for in, want := range cases {
		if got := SuggestedValue(in, "v"); got != want {
			t.Errorf("SuggestedValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSuggestedDomain(t *testing.T) {
	cases := map[string]string{
		"https://eu.infisical.com":           "https://eu.infisical.com",
		"http://localhost:8080/api":          "http://localhost:8080/api",
		"https://user:pass@example.com":      "<domain>",
		"https://example.com/?token=abc":     "<domain>",
		"ftp://example.com":                  "<domain>",
		"example.com":                        "<domain>",
		"https://example.com/$(id)":          "<domain>",
		"https://example.com/#frag":          "<domain>",
		"https://example.com/ ; rm -rf /tmp": "<domain>",
	}
	for in, want := range cases {
		if got := SuggestedDomain(in); got != want {
			t.Errorf("SuggestedDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func sampleError() *CLIError {
	return &CLIError{
		Code:    "environment_not_found",
		Message: `Environment "stagng" doesn't exist in project "payments-api".`,
		Next: []NextStep{{
			Purpose: "To see the environments in this project",
			Command: "infisical secrets-manager environments get --projectId 6f1c2a3e-8b4d-4c1a-9e2f-3a5b7c9d1e0f",
		}},
	}
}

func TestWriteCLIErrorText(t *testing.T) {
	var out bytes.Buffer
	WriteCLIError(&out, sampleError(), "")
	want := `Environment "stagng" doesn't exist in project "payments-api".` + "\n" +
		"To see the environments in this project, run: infisical secrets-manager environments get --projectId 6f1c2a3e-8b4d-4c1a-9e2f-3a5b7c9d1e0f\n"
	if out.String() != want {
		t.Errorf("text output:\n%s\nwant:\n%s", out.String(), want)
	}

	out.Reset()
	WriteCLIError(&out, &CLIError{Code: "x", Message: "Only a sentence."}, "")
	if out.String() != "Only a sentence.\n" {
		t.Errorf("an error with no next step should print one line, got %q", out.String())
	}
}

func TestWriteCLIErrorJSON(t *testing.T) {
	err := sampleError()
	err.Cause = fmt.Errorf("wrapped: %w", &api.APIError{StatusCode: 404, ReqId: "req-123", ErrorMessage: "Environment with slug 'stagng' not found"})
	var out bytes.Buffer
	WriteCLIError(&out, err, OUTPUT_FORMAT_JSON)

	var parsed map[string]map[string]any
	if jsonErr := json.Unmarshal(out.Bytes(), &parsed); jsonErr != nil {
		t.Fatalf("not JSON: %v\n%s", jsonErr, out.String())
	}
	body := parsed["error"]
	if body["code"] != "environment_not_found" || body["message"] != err.Message || body["statusCode"] != float64(404) || body["requestId"] != "req-123" {
		t.Errorf("unexpected body: %v", body)
	}
	if next, _ := body["next"].([]any); len(next) != 1 || next[0] != err.Next[0].Command {
		t.Errorf("next should hold only the commands, got %v", body["next"])
	}
	if !strings.HasSuffix(out.String(), "}\n") || strings.Count(out.String(), "\n") != 1 {
		t.Errorf("JSON should be one line, got %q", out.String())
	}

	out.Reset()
	WriteCLIError(&out, &CLIError{Code: "nothing_to_update", Message: "Nothing to update."}, OUTPUT_FORMAT_JSON)
	if !strings.Contains(out.String(), `"next":[]`) || strings.Contains(out.String(), "statusCode") {
		t.Errorf("no next steps should be [] and no API cause should omit statusCode, got %s", out.String())
	}

	out.Reset()
	WriteCLIError(&out, &CLIError{Code: "x", Message: "M.", Next: []NextStep{{Purpose: "To p", Command: "infisical a KEY=<value>"}}}, OUTPUT_FORMAT_JSON)
	if !strings.Contains(out.String(), "KEY=<value>") {
		t.Errorf("placeholders should stay readable in JSON, got %s", out.String())
	}
}

func TestWriteCLIErrorYAML(t *testing.T) {
	var out bytes.Buffer
	WriteCLIError(&out, sampleError(), OUTPUT_FORMAT_YAML)
	var parsed struct {
		Error struct {
			Code string   `yaml:"code"`
			Next []string `yaml:"next"`
		} `yaml:"error"`
	}
	if err := yaml.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("not YAML: %v\n%s", err, out.String())
	}
	if parsed.Error.Code != "environment_not_found" || len(parsed.Error.Next) != 1 {
		t.Errorf("unexpected YAML: %s", out.String())
	}
}

// A suggestion built from unexpected input must still never print a credential.
func TestWriteCLIErrorNeverPrintsCredentials(t *testing.T) {
	secrets := []string{"st.abc123.def456.ghi789", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "hunter2-client-secret"}
	err := &CLIError{Code: "x", Message: "Something failed.", Next: []NextStep{
		{Purpose: "To retry", Command: "infisical secrets-manager projects list --token " + secrets[0]},
		{Purpose: "To retry", Command: "infisical secrets-manager projects list --token=" + secrets[1]},
		{Purpose: "To retry", Command: "infisical login --client-secret " + secrets[2]},
		{Purpose: "To retry", Command: "infisical secrets-manager secrets get X " + secrets[0]},
	}}
	for _, format := range []string{"", OUTPUT_FORMAT_JSON, OUTPUT_FORMAT_YAML} {
		var out bytes.Buffer
		WriteCLIError(&out, err, format)
		for _, secret := range secrets {
			if strings.Contains(out.String(), secret) {
				t.Errorf("format %q printed a credential:\n%s", format, out.String())
			}
		}
		if !strings.Contains(out.String(), "<redacted>") {
			t.Errorf("format %q should mark what it removed:\n%s", format, out.String())
		}
	}
}

func TestWriteCLIErrorStripsControlCharacters(t *testing.T) {
	var out bytes.Buffer
	WriteCLIError(&out, &CLIError{Code: "x", Message: "Bad \x1b[31mred\x1b[0m name."}, "")
	if strings.Contains(out.String(), "\x1b") {
		t.Errorf("escape sequence reached the terminal: %q", out.String())
	}
}
