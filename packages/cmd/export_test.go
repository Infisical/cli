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

func TestFormatAsAppSettingsJson(t *testing.T) {
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
			name: "Flat primitive types parsing",
			input: []models.SingleEnvironmentVariable{
				{Key: "PORT", Value: "8080"},
				{Key: "DEBUG", Value: "true"},
				{Key: "NAME", Value: "MyApplication"},
				{Key: "NULL_VAL", Value: "null"},
			},
			expected: `{
  "DEBUG": true,
  "NAME": "MyApplication",
  "NULL_VAL": null,
  "PORT": 8080
}`,
		},
		{
			name: "Nested keys with colons",
			input: []models.SingleEnvironmentVariable{
				{Key: "AWS:Region", Value: "us-east-1"},
				{Key: "ConnectionStrings:Default", Value: "Server=myServerAddress;Database=myDataBase;"},
			},
			expected: `{
  "AWS": {
    "Region": "us-east-1"
  },
  "ConnectionStrings": {
    "Default": "Server=myServerAddress;Database=myDataBase;"
  }
}`,
		},
		{
			name: "Nested keys with double underscores",
			input: []models.SingleEnvironmentVariable{
				{Key: "AWS__Region", Value: "us-east-2"},
				{Key: "ConnectionStrings__Default", Value: "Server=otherServer;"},
			},
			expected: `{
  "AWS": {
    "Region": "us-east-2"
  },
  "ConnectionStrings": {
    "Default": "Server=otherServer;"
  }
}`,
		},
		{
			name: "Values as JSON objects/arrays",
			input: []models.SingleEnvironmentVariable{
				{Key: "AWS", Value: `{"Region":"us-west-2","Version":"v2"}`},
				{Key: "TAGS", Value: `["production","web"]`},
			},
			expected: `{
  "AWS": {
    "Region": "us-west-2",
    "Version": "v2"
  },
  "TAGS": [
    "production",
    "web"
  ]
}`,
		},
		{
			name: "Deep nesting and merging objects",
			input: []models.SingleEnvironmentVariable{
				{Key: "AWS:Credentials:AccessKey", Value: "AKIAIOSFODNN7EXAMPLE"},
				{Key: "AWS:Credentials:SecretKey", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
				{Key: "AWS:Region", Value: "us-east-1"},
			},
			expected: `{
  "AWS": {
    "Credentials": {
      "AccessKey": "AKIAIOSFODNN7EXAMPLE",
      "SecretKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    },
    "Region": "us-east-1"
  }
}`,
		},
		{
			name: "Merging parsed JSON objects and explicit nested keys in any order",
			input: []models.SingleEnvironmentVariable{
				{Key: "AWS", Value: `{"Region":"us-east-1"}`},
				{Key: "AWS:SecretKey", Value: "abc"},
			},
			expected: `{
  "AWS": {
    "Region": "us-east-1",
    "SecretKey": "abc"
  }
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatAsAppSettingsJson(tt.input)
			assert.JSONEq(t, tt.expected, result)
		})
	}
}
