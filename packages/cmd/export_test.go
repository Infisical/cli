package cmd

import (
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
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

func TestMergeSecretsByKey(t *testing.T) {
	tests := []struct {
		name     string
		input    []models.SingleEnvironmentVariable
		expected []models.SingleEnvironmentVariable
	}{
		{
			name:     "Empty input",
			input:    []models.SingleEnvironmentVariable{},
			expected: []models.SingleEnvironmentVariable{},
		},
		{
			name: "Distinct keys are all kept",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "VALUE1"},
				{Key: "KEY2", Value: "VALUE2"},
			},
			expected: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "VALUE1"},
				{Key: "KEY2", Value: "VALUE2"},
			},
		},
		{
			name: "Duplicate keys across paths keep the last value",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "FROM_FIRST_PATH"},
				{Key: "KEY2", Value: "VALUE2"},
				{Key: "KEY1", Value: "FROM_SECOND_PATH"},
			},
			expected: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "FROM_SECOND_PATH"},
				{Key: "KEY2", Value: "VALUE2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.SortSecretsByKeys(mergeSecretsByKey(tt.input))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMergeAndFilterSecrets(t *testing.T) {
	teamTag := []models.Tag{{Slug: "team"}}

	tests := []struct {
		name     string
		input    []models.SingleEnvironmentVariable
		tagSlugs string
		expected []models.SingleEnvironmentVariable
	}{
		{
			name: "An untagged secret on a later path drops the tagged one from an earlier path",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "old", Tags: teamTag},
				{Key: "KEY2", Value: "kept", Tags: teamTag},
				{Key: "KEY1", Value: "new"},
			},
			tagSlugs: "team",
			expected: []models.SingleEnvironmentVariable{
				{Key: "KEY2", Value: "kept", Tags: teamTag},
			},
		},
		{
			name: "A tagged secret on a later path overrides an untagged one from an earlier path",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "old"},
				{Key: "KEY1", Value: "new", Tags: teamTag},
			},
			tagSlugs: "team",
			expected: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "new", Tags: teamTag},
			},
		},
		{
			name: "Without tags the merged result is returned as is",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY2", Value: "VALUE2"},
				{Key: "KEY1", Value: "old"},
				{Key: "KEY1", Value: "new"},
			},
			tagSlugs: "",
			expected: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "new"},
				{Key: "KEY2", Value: "VALUE2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, mergeAndFilterSecrets(tt.input, tt.tagSlugs))
		})
	}
}

func newExportTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "export"}
	c.Flags().StringArray("path", []string{"/"}, "")
	return c
}

func TestExportPathFlagAcceptsMultipleValues(t *testing.T) {
	// the export command must declare --path as a repeatable string array
	paths, err := exportCmd.Flags().GetStringArray("path")
	assert.NoError(t, err)
	assert.Equal(t, []string{"/"}, paths)

	// repeated --path values accumulate instead of overwriting one another
	cmd := newExportTestCmd()
	assert.NoError(t, cmd.Flags().Set("path", "/first"))
	assert.NoError(t, cmd.Flags().Set("path", "/second"))

	paths, err = cmd.Flags().GetStringArray("path")
	assert.NoError(t, err)
	assert.Equal(t, []string{"/first", "/second"}, paths)
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
