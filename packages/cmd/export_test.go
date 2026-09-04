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

func TestFormatAsDotEnv(t *testing.T) {
	tests := []struct {
		name      string
		input     []models.SingleEnvironmentVariable
		quoteChar string
		expected  string
	}{
		{
			name:      "Empty input",
			input:     []models.SingleEnvironmentVariable{},
			quoteChar: QuoteCharSingle,
			expected:  "",
		},
		{
			name: "Single quotes are the default wrapping",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "VALUE1"},
				{Key: "KEY2", Value: "VALUE2"},
			},
			quoteChar: QuoteCharSingle,
			expected:  "KEY1='VALUE1'\nKEY2='VALUE2'\n",
		},
		{
			name: "Double quotes wrap the value",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "VALUE1"},
			},
			quoteChar: QuoteCharDouble,
			expected:  "KEY1=\"VALUE1\"\n",
		},
		{
			name: "Encoded newlines are left intact so double quoted values stay multiline",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "line1\nline2", SkipMultilineEncoding: true},
			},
			quoteChar: QuoteCharDouble,
			expected:  "KEY1=\"line1\\nline2\"\n",
		},
		{
			name: "Embedded double quotes are written verbatim in double quote mode",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: `say "hi"`},
			},
			quoteChar: QuoteCharDouble,
			expected:  `KEY1="say "hi""` + "\n",
		},
		{
			name: "Embedded double quotes are written verbatim in single quote mode",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: `say "hi"`},
			},
			quoteChar: QuoteCharSingle,
			expected:  `KEY1='say "hi"'` + "\n",
		},
		{
			name: "Backslashes are written verbatim in double quote mode",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: `C:\Users\`},
			},
			quoteChar: QuoteCharDouble,
			expected:  `KEY1="C:\Users\"` + "\n",
		},
		{
			name: "Backslash quote sequences are written verbatim",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: `say \"hi\"`},
			},
			quoteChar: QuoteCharDouble,
			expected:  `KEY1="say \"hi\""` + "\n",
		},
		{
			name: "Multiline encoding still applies alongside backslashes",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "C:\\dir\nmore", SkipMultilineEncoding: true},
			},
			quoteChar: QuoteCharDouble,
			expected:  `KEY1="C:\dir\nmore"` + "\n",
		},
		{
			name: "Backslashes are written verbatim in single quote mode",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: `C:\Users\`},
			},
			quoteChar: QuoteCharSingle,
			expected:  `KEY1='C:\Users\'` + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, formatAsDotEnv(tt.input, tt.quoteChar))
		})
	}
}

func TestQuoteDotEnvValueOnlyChangesTheWrapper(t *testing.T) {
	envs := []models.SingleEnvironmentVariable{
		{Key: "PLAIN", Value: "VALUE1"},
		{Key: "QUOTES", Value: `say "hi" and 'bye'`},
		{Key: "BACKSLASHES", Value: `C:\Users\`},
		{Key: "BACKSLASH_QUOTES", Value: `say \"hi\"`},
		{Key: "MULTILINE", Value: "line1\nline2", SkipMultilineEncoding: true},
	}

	for _, env := range envs {
		t.Run(env.Key, func(t *testing.T) {
			single := quoteDotEnvValue(env, QuoteCharSingle)
			double := quoteDotEnvValue(env, QuoteCharDouble)

			assert.Equal(t, QuoteCharSingle, string(single[0]))
			assert.Equal(t, QuoteCharSingle, string(single[len(single)-1]))
			assert.Equal(t, QuoteCharDouble, string(double[0]))
			assert.Equal(t, QuoteCharDouble, string(double[len(double)-1]))

			// Only the wrapping character may differ between the two styles. The
			// value in between is never rewritten beyond the multiline encoding
			// that both styles already share, so neither style can corrupt a
			// round trip by introducing escape characters of its own.
			singleInner := single[1 : len(single)-1]
			doubleInner := double[1 : len(double)-1]

			assert.Equal(t, singleInner, doubleInner)
			assert.Equal(t, escapeNewLinesIfRequired(env), singleInner)
		})
	}
}

func TestFormatAsDotEnvExport(t *testing.T) {
	tests := []struct {
		name      string
		input     []models.SingleEnvironmentVariable
		quoteChar string
		expected  string
	}{
		{
			name:      "Empty input",
			input:     []models.SingleEnvironmentVariable{},
			quoteChar: QuoteCharSingle,
			expected:  "",
		},
		{
			name: "Single quotes are the default wrapping",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: "VALUE1"},
			},
			quoteChar: QuoteCharSingle,
			expected:  "export KEY1='VALUE1'\n",
		},
		{
			name: "Double quotes wrap the value verbatim",
			input: []models.SingleEnvironmentVariable{
				{Key: "KEY1", Value: `say "hi"`},
			},
			quoteChar: QuoteCharDouble,
			expected:  `export KEY1="say "hi""` + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, formatAsDotEnvExport(tt.input, tt.quoteChar))
		})
	}
}

func TestFormatEnvsQuoteChar(t *testing.T) {
	envs := []models.SingleEnvironmentVariable{
		{Key: "KEY1", Value: "VALUE1"},
	}

	tests := []struct {
		name      string
		format    string
		quoteChar string
		expected  string
	}{
		{
			name:      "dotenv honours the quote character",
			format:    FormatDotenv,
			quoteChar: QuoteCharDouble,
			expected:  "KEY1=\"VALUE1\"\n",
		},
		{
			name:      "dotenv-export honours the quote character",
			format:    FormatDotEnvExport,
			quoteChar: QuoteCharDouble,
			expected:  "export KEY1=\"VALUE1\"\n",
		},
		{
			name:      "dotenv-eval keeps its shell safe quoting",
			format:    FormatDotEnvEval,
			quoteChar: QuoteCharDouble,
			expected:  "export KEY1='VALUE1'\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := formatEnvs(envs, tt.format, tt.quoteChar)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}

	// Every format that does not wrap values in a configurable quote must
	// produce byte identical output no matter what the flag is set to.
	for _, format := range []string{FormatJson, FormatYaml, FormatCSV, FormatDotEnvEval} {
		t.Run(format+" ignores the quote character", func(t *testing.T) {
			withSingle, err := formatEnvs(envs, format, QuoteCharSingle)
			assert.NoError(t, err)

			withDouble, err := formatEnvs(envs, format, QuoteCharDouble)
			assert.NoError(t, err)

			assert.Equal(t, withSingle, withDouble)
		})
	}
}

func TestValidateDotEnvQuoteChar(t *testing.T) {
	tests := []struct {
		name        string
		quoteChar   string
		expectError bool
	}{
		{name: "Single quote is allowed", quoteChar: QuoteCharSingle},
		{name: "Double quote is allowed", quoteChar: QuoteCharDouble},
		{name: "Empty value is rejected", quoteChar: "", expectError: true},
		{name: "Backtick is rejected", quoteChar: "`", expectError: true},
		{name: "Arbitrary character is rejected", quoteChar: "x", expectError: true},
		{name: "Multiple characters are rejected", quoteChar: `""`, expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDotEnvQuoteChar(tt.quoteChar)
			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
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
