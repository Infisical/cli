package cmd

import (
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestFormatAsYaml(t *testing.T) {
	tests := []struct {
		name     string
		input    []models.SingleEnvironmentVariable
		expected string
	}{
		{
			name:     "Empty input",
			input:    []models.SingleEnvironmentVariable{},
			expected: "{}\n",
		},
		{
			name: "Single environment variable",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "VALUE1"},
			},
			expected: "KEY1: VALUE1\n",
		},
		{
			name: "Multiple environment variables",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "VALUE1"},
				{Key: "KEY2", Value: "VALUE2"},
				{Key: "KEY3", Value: "VALUE3"},
			},
			expected: "KEY1: VALUE1\nKEY2: VALUE2\nKEY3: VALUE3\n",
		},
		{
			name: "Overwriting duplicate keys",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "VALUE1"},
				{Key: "KEY1", Value: "VALUE2"},
			},
			expected: "KEY1: VALUE2\n",
		},
		{
			name: "Special characters in values",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "Value with spaces"},
				{Key: "KEY2", Value: "Value:with:colons"},
				{Key: "KEY3", Value: "Value\nwith\nnewlines"},
			},
			expected: "KEY1: Value with spaces\nKEY2: Value:with:colons\nKEY3: |-\n  Value\n  with\n  newlines\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := formatAsYaml(tt.input)
			assert.NoError(t, err)

			// Compare the result with the expected output
			assert.Equal(t, tt.expected, result)

			// Additionally, parse the result back into a map to ensure it's valid YAML
			var resultMap map[string]string
			err = yaml.Unmarshal([]byte(result), &resultMap)
			assert.NoError(t, err)

			// Create an expected map from the input
			expectedMap := make(map[string]string)
			for _, env := range tt.input {
				expectedMap[env.Key] = env.Value
			}

			assert.Equal(t, expectedMap, resultMap)
		})
	}
}

func TestFormatAsDotEnvEval(t *testing.T) {
	tests := []struct {
		name     string
		input    []models.SingleEnvironmentVariable
		expected string
	}{
		{
			name:     "Empty input",
			input:    []models.SingleEnvironmentVariable{},
			expected: "",
		},
		{
			name: "Simple value",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "simple"},
			},
			expected: "export KEY1='simple'\n",
		},
		{
			name: "Value containing single quote",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "it's a value"},
			},
			expected: "export KEY1='it'\\''s a value'\n",
		},
		{
			name: "Multiline value is preserved verbatim",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "line1\nline2"},
			},
			expected: "export KEY1='line1\nline2'\n",
		},
		{
			name: "Multiline value with skipMultilineEncoding set still emits real newlines",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "line1\nline2", SkipMultilineEncoding: true},
			},
			expected: "export KEY1='line1\nline2'\n",
		},
		{
			name: "Shell metacharacters are preserved literally inside single quotes",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: `$(rm -rf /) "quotes" \backslash`},
			},
			expected: "export KEY1='$(rm -rf /) \"quotes\" \\backslash'\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, formatAsDotEnvEval(tt.input))
		})
	}
}

func TestPosixShellQuote(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{input: "", expected: "''"},
		{input: "plain", expected: "'plain'"},
		{input: "it's", expected: `'it'\''s'`},
		{input: "'leading", expected: `''\''leading'`},
		{input: "trailing'", expected: `'trailing'\'''`},
		{input: "a'b'c", expected: `'a'\''b'\''c'`},
		{input: "with\nnewline", expected: "'with\nnewline'"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, posixShellQuote(tt.input))
		})
	}
}

func TestQuoteCharacter(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  string
		expectErr bool
	}{
		{name: "single", input: "single", expected: "'"},
		{name: "double", input: "double", expected: "\""},
		{name: "none", input: "none", expected: ""},
		{name: "empty defaults to single", input: "", expected: "'"},
		{name: "case insensitive", input: "DOUBLE", expected: "\""},
		{name: "invalid value returns error", input: "backtick", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := quoteCharacter(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestFormatAsDotEnv(t *testing.T) {
	tests := []struct {
		name     string
		input    []models.SingleEnvironmentVariable
		quote    string
		expected string
	}{
		{
			name:     "single quote keeps the existing default behavior",
			input:    []models.SingleEnvironmentVariable{{Key: "KEY1", Value: "VALUE1"}, {Key: "KEY2", Value: "VALUE2"}},
			quote:    "'",
			expected: "KEY1='VALUE1'\nKEY2='VALUE2'\n",
		},
		{
			name:     "double quote wraps values in double quotes",
			input:    []models.SingleEnvironmentVariable{{Key: "KEY1", Value: "VALUE1"}},
			quote:    "\"",
			expected: "KEY1=\"VALUE1\"\n",
		},
		{
			name:     "none emits bare values for docker --env-file",
			input:    []models.SingleEnvironmentVariable{{Key: "KEY1", Value: "VALUE1"}},
			quote:    "",
			expected: "KEY1=VALUE1\n",
		},
		{
			name:     "double quote with multiline-encoded value emits escaped newlines for dotenv expansion",
			input:    []models.SingleEnvironmentVariable{{Key: "PRIVATE_KEY", Value: "line1\nline2", SkipMultilineEncoding: true}},
			quote:    "\"",
			expected: "PRIVATE_KEY=\"line1\\nline2\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, formatAsDotEnv(tt.input, tt.quote))
		})
	}
}

func TestFormatAsDotEnvExport(t *testing.T) {
	tests := []struct {
		name     string
		input    []models.SingleEnvironmentVariable
		quote    string
		expected string
	}{
		{
			name:     "single quote keeps the existing default behavior",
			input:    []models.SingleEnvironmentVariable{{Key: "KEY1", Value: "VALUE1"}},
			quote:    "'",
			expected: "export KEY1='VALUE1'\n",
		},
		{
			name:     "double quote wraps values in double quotes",
			input:    []models.SingleEnvironmentVariable{{Key: "KEY1", Value: "VALUE1"}},
			quote:    "\"",
			expected: "export KEY1=\"VALUE1\"\n",
		},
		{
			name:     "none emits bare values",
			input:    []models.SingleEnvironmentVariable{{Key: "KEY1", Value: "VALUE1"}},
			quote:    "",
			expected: "export KEY1=VALUE1\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, formatAsDotEnvExport(tt.input, tt.quote))
		})
	}
}
