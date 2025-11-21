package cmd

import (
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
)

func TestHyphenSecretsEnvVars(t *testing.T) {
	// Mock the GetAllEnvironmentVariables function
	originalFunc := getAllEnvironmentVariablesFunc
	defer func() {
		getAllEnvironmentVariablesFunc = originalFunc
	}()

	// some test secrets with hyphens in keys
	testSecrets := []models.SingleEnvironmentVariable{
		{
			Key:   "my-secret",
			Value: "value1",
		},
		{
			Key:   "another_key",
			Value: "value2",
		},
		{
			Key:   "nosecret",
			Value: "value3",
		},
	}

	// Mock the function to return our test secrets
	getAllEnvironmentVariablesFunc = func(params models.GetAllSecretsParameters, projectConfigPath string) ([]models.SingleEnvironmentVariable, error) {
		return testSecrets, nil
	}

	// Call fetchAndFormatSecretsForShell with test parameters
	result, err := fetchAndFormatSecretsForShell(
		models.GetAllSecretsParameters{},
		"",
		false,
		nil,
	)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Build a map from the environment variables to verify conversion
	envVarMap := make(map[string]string)
	for _, envVar := range result.Variables {
		// Parse "KEY=VALUE" format
		var key, value string
		for i := 0; i < len(envVar); i++ {
			if envVar[i] == '=' {
				key = envVar[:i]
				value = envVar[i+1:]
				break
			}
		}
		envVarMap[key] = value
	}

	// Verify that hyphens are converted to underscores in environment variables
	if val, ok := envVarMap["my_secret"]; !ok || val != "value1" {
		t.Errorf("Expected 'my_secret' to be in environment variables with value 'value1', got %v", val)
	}
	if val, ok := envVarMap["another_key"]; !ok || val != "value2" {
		t.Errorf("Expected 'another_key' to be in environment variables with value 'value2', got %v", val)
	}
	if val, ok := envVarMap["nosecret"]; !ok || val != "value3" {
		t.Errorf("Expected 'nosecret' to be in environment variables with value 'value3', got %v", val)
	}

	// Verify that hyphenated versions are NOT present (they should be converted to underscores)
	if _, ok := envVarMap["my-secret"]; ok {
		t.Errorf("Did not expect 'my-secret' in environment variables (should be converted to 'my_secret')")
	}

}
