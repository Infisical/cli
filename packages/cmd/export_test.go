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

func TestFormatEnvsDotEnvQuoteStyles(t *testing.T) {
	envs := []models.SingleEnvironmentVariable{
		{Key: "PLAIN", Value: "value"},
		{Key: "PRIVATE_KEY", Value: "line 1\nline 2", SkipMultilineEncoding: true},
		{Key: "JSON", Value: `{"enabled":true}`},
	}

	tests := []struct {
		name       string
		quoteStyle string
		format     string
		expected   string
	}{
		{
			name:       "single quote style preserves existing dotenv output",
			quoteStyle: DotEnvQuoteStyleSingle,
			format:     FormatDotenv,
			expected:   "PLAIN='value'\nPRIVATE_KEY='line 1\\nline 2'\nJSON='{\"enabled\":true}'\n",
		},
		{
			name:       "double quote style wraps dotenv values in double quotes",
			quoteStyle: DotEnvQuoteStyleDouble,
			format:     FormatDotenv,
			expected:   "PLAIN=\"value\"\nPRIVATE_KEY=\"line 1\\nline 2\"\nJSON=\"{\\\"enabled\\\":true}\"\n",
		},
		{
			name:       "none quote style leaves dotenv values unquoted",
			quoteStyle: DotEnvQuoteStyleNone,
			format:     FormatDotenv,
			expected:   "PLAIN=value\nPRIVATE_KEY=line 1\\nline 2\nJSON={\"enabled\":true}\n",
		},
		{
			name:       "double quote style works with dotenv export",
			quoteStyle: DotEnvQuoteStyleDouble,
			format:     FormatDotEnvExport,
			expected:   "export PLAIN=\"value\"\nexport PRIVATE_KEY=\"line 1\\nline 2\"\nexport JSON=\"{\\\"enabled\\\":true}\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := formatEnvs(envs, tt.format, tt.quoteStyle)

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatEnvsRejectsInvalidDotEnvQuoteStyle(t *testing.T) {
	_, err := formatEnvs(
		[]models.SingleEnvironmentVariable{{Key: "KEY", Value: "VALUE"}},
		FormatDotenv,
		"invalid",
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid dotenv quote style")
}

func TestFormatEnvsRejectsSingleQuoteStyleForSingleQuoteValues(t *testing.T) {
	_, err := formatEnvs(
		[]models.SingleEnvironmentVariable{{Key: "KEY", Value: "it's private"}},
		FormatDotenv,
		DotEnvQuoteStyleSingle,
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "single quote style cannot be used")
}

func TestValidateDotEnvQuoteStyleForFormatRejectsUnusedNonDefaultQuoteStyle(t *testing.T) {
	tests := []struct {
		name             string
		format           string
		quoteStyle       string
		quoteStyleSet    bool
		expectedErrorMsg string
	}{
		{
			name:             "rejects double quote style for json output",
			format:           FormatJson,
			quoteStyle:       DotEnvQuoteStyleDouble,
			quoteStyleSet:    true,
			expectedErrorMsg: "--quote can only be used with dotenv",
		},
		{
			name:             "rejects none quote style for csv output",
			format:           FormatCSV,
			quoteStyle:       DotEnvQuoteStyleNone,
			quoteStyleSet:    true,
			expectedErrorMsg: "--quote can only be used with dotenv",
		},
		{
			name:          "allows unchanged default quote style for json output",
			format:        FormatJson,
			quoteStyle:    DotEnvQuoteStyleSingle,
			quoteStyleSet: false,
		},
		{
			name:          "allows explicit default quote style for yaml output",
			format:        FormatYaml,
			quoteStyle:    DotEnvQuoteStyleSingle,
			quoteStyleSet: true,
		},
		{
			name:          "allows double quote style for dotenv output",
			format:        FormatDotenv,
			quoteStyle:    DotEnvQuoteStyleDouble,
			quoteStyleSet: true,
		},
		{
			name:          "allows none quote style for dotenv export output",
			format:        FormatDotEnvExport,
			quoteStyle:    DotEnvQuoteStyleNone,
			quoteStyleSet: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDotEnvQuoteStyleForFormat(tt.format, tt.quoteStyle, tt.quoteStyleSet)

			if tt.expectedErrorMsg == "" {
				assert.NoError(t, err)
				return
			}

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErrorMsg)
		})
	}
}
