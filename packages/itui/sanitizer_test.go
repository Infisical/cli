package itui

import (
	"strings"
	"testing"
)

func TestSanitizePrompt_SetToValue(t *testing.T) {
	input := "set DATABASE_URL to postgres://user:pass@host:5432/db in staging"
	sanitized, cache := SanitizePrompt(input, nil)

	if strings.Contains(sanitized, "postgres://") {
		t.Errorf("sanitized prompt still contains secret value: %s", sanitized)
	}
	if !strings.Contains(sanitized, "[VALUE_") {
		t.Errorf("sanitized prompt should contain placeholder: %s", sanitized)
	}
	if len(cache) == 0 {
		t.Error("cache should have entries")
	}

	// Verify the value is in the cache
	found := false
	for _, v := range cache {
		if strings.Contains(v, "postgres://") {
			found = true
			break
		}
	}
	if !found {
		t.Error("cache should contain the original value")
	}
}

func TestSanitizePrompt_KnownSecretValues(t *testing.T) {
	input := "show me the secret with value sk-test-12345"
	knownValues := []string{"sk-test-12345"}
	sanitized, cache := SanitizePrompt(input, knownValues)

	if strings.Contains(sanitized, "sk-test-12345") {
		t.Errorf("sanitized prompt still contains known secret value: %s", sanitized)
	}
	if len(cache) == 0 {
		t.Error("cache should have entries for known values")
	}
}

func TestSanitizePrompt_NoValueToRedact(t *testing.T) {
	input := "show me all production secrets"
	sanitized, cache := SanitizePrompt(input, nil)

	if sanitized != input {
		t.Errorf("prompt should be unchanged: got %q, want %q", sanitized, input)
	}
	if len(cache) != 0 {
		t.Errorf("cache should be empty for read-only prompt, got %d entries", len(cache))
	}
}

func TestSanitizePrompt_EnvNamesNotRedacted(t *testing.T) {
	input := "set API_KEY to prod"
	sanitized, cache := SanitizePrompt(input, nil)

	// "prod" is a common word and should NOT be redacted
	if strings.Contains(sanitized, "[VALUE_") {
		t.Errorf("common word 'prod' should not be redacted: %s (cache: %v)", sanitized, cache)
	}
}

func TestHydrateCommand(t *testing.T) {
	command := "infisical secrets set DATABASE_URL=[VALUE_1] --env=staging"
	cache := map[string]string{
		"[VALUE_1]": "postgres://user:pass@host:5432/db",
	}

	hydrated := HydrateCommand(command, cache)
	expected := "infisical secrets set DATABASE_URL=postgres://user:pass@host:5432/db --env=staging"

	if hydrated != expected {
		t.Errorf("hydration failed:\n  got:  %s\n  want: %s", hydrated, expected)
	}
}

func TestHydrateCommand_MultiplePlaceholders(t *testing.T) {
	command := "infisical secrets set KEY1=[VALUE_1] KEY2=[VALUE_2] --env=dev"
	cache := map[string]string{
		"[VALUE_1]": "value-one",
		"[VALUE_2]": "value-two",
	}

	hydrated := HydrateCommand(command, cache)

	if !strings.Contains(hydrated, "KEY1=value-one") {
		t.Errorf("missing first value: %s", hydrated)
	}
	if !strings.Contains(hydrated, "KEY2=value-two") {
		t.Errorf("missing second value: %s", hydrated)
	}
}

func TestHydrateCommand_EmptyCache(t *testing.T) {
	command := "infisical export --format=json --env=dev"
	hydrated := HydrateCommand(command, nil)

	if hydrated != command {
		t.Errorf("command should be unchanged with empty cache: %s", hydrated)
	}
}

func TestSanitizePrompt_KeyEqualsValue(t *testing.T) {
	input := "set API_KEY=sk-secret-token-123"
	sanitized, cache := SanitizePrompt(input, nil)

	if strings.Contains(sanitized, "sk-secret-token-123") {
		t.Errorf("sanitized should not contain secret: %s", sanitized)
	}
	if len(cache) == 0 {
		t.Error("cache should have the value")
	}
}
