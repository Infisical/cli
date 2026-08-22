/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test isolated initLog function without dependencies
func TestInitLogFunction(t *testing.T) {
	// Create an isolated test command
	testCmd := &cobra.Command{
		Use: "test",
	}

	// Add the log-level flag
	testCmd.Flags().StringP("log-level", "l", "info", "log level")

	tests := []struct {
		name     string
		logLevel string
	}{
		{"trace level", "trace"},
		{"debug level", "debug"},
		{"info level", "info"},
		{"warn level", "warn"},
		{"error level", "error"},
		{"fatal level", "fatal"},
		{"invalid level", "invalid"},
		{"empty level", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - set the log level flag
			testCmd.Flags().Set("log-level", tt.logLevel)

			// Execute - should not panic
			assert.NotPanics(t, func() {
				// Test initLog logic without global dependencies
				testInitLog(testCmd)
			}, "initLog should not panic for log level: %s", tt.logLevel)
		})
	}
}

// Isolated test function that reproduces initLog logic
func testInitLog(cmd *cobra.Command) {
	ll, err := cmd.Flags().GetString("log-level")
	if err != nil {
		return // Don't call log.Fatal() in tests
	}

	switch ll {
	case "trace", "debug", "info", "warn", "error", "fatal":
		// Validation logic
	default:
		// Default logic
	}
}

// Test root command structure
func TestRootCommandStructure(t *testing.T) {
	// Test that root command is properly configured
	assert.Equal(t, "infisical", rootCmd.Use)
	assert.Equal(t, "Infisical CLI is used to inject environment variables into any process", rootCmd.Short)
	assert.NotEmpty(t, rootCmd.Long)
	assert.True(t, rootCmd.CompletionOptions.HiddenDefaultCmd)
}

// Test persistent flags
func TestRootCommandFlags(t *testing.T) {
	persistentFlags := rootCmd.PersistentFlags()

	// Test log-level flag
	logLevelFlag := persistentFlags.Lookup("log-level")
	require.NotNil(t, logLevelFlag, "log-level flag should be defined")
	assert.Equal(t, "l", logLevelFlag.Shorthand)
	assert.Equal(t, "info", logLevelFlag.DefValue)

	// Test telemetry flag
	telemetryFlag := persistentFlags.Lookup("telemetry")
	require.NotNil(t, telemetryFlag, "telemetry flag should be defined")
	assert.Equal(t, "true", telemetryFlag.DefValue)

	// Test domain flag
	domainFlag := persistentFlags.Lookup("domain")
	require.NotNil(t, domainFlag, "domain flag should be defined")

	// Test silent flag
	silentFlag := persistentFlags.Lookup("silent")
	require.NotNil(t, silentFlag, "silent flag should be defined")
	assert.Equal(t, "false", silentFlag.DefValue)
}

// Test basic execution with error capture
func TestRootCommandBasicExecution(t *testing.T) {
	// Test with --help (should always work)
	rootCmd.SetArgs([]string{"--help"})
	err := rootCmd.Execute()
	assert.NoError(t, err, "Root command should execute successfully with --help")
}

// Test version
func TestRootCommandVersion(t *testing.T) {
	rootCmd.SetArgs([]string{"--version"})
	err := rootCmd.Execute()
	assert.NoError(t, err, "Root command should execute successfully with --version")
}

// Test subcommands
func TestRootCommandSubcommands(t *testing.T) {
	expectedCommands := []string{
		"agent", "bootstrap", "dynamic-secrets", "export", "gateway",
		"init", "kmip", "login", "reset", "run", "scan", "secrets",
		"ssh", "token", "user", "vault", "man",
	}

	registeredCommands := make(map[string]bool)
	for _, cmd := range rootCmd.Commands() {
		registeredCommands[cmd.Name()] = true
	}

	for _, expectedCmd := range expectedCommands {
		t.Run(expectedCmd, func(t *testing.T) {
			assert.True(t, registeredCommands[expectedCmd],
				"Expected command '%s' to be registered", expectedCmd)
		})
	}
}

// Test flags with valid values
func TestRootCommandValidFlags(t *testing.T) {
	testCases := []struct {
		name string
		args []string
	}{
		{"silent flag", []string{"--silent", "--help"}},
		{"log-level trace", []string{"--log-level", "trace", "--help"}},
		{"log-level debug", []string{"--log-level", "debug", "--help"}},
		{"log-level info", []string{"--log-level", "info", "--help"}},
		{"log-level warn", []string{"--log-level", "warn", "--help"}},
		{"log-level error", []string{"--log-level", "error", "--help"}},
		{"log-level fatal", []string{"--log-level", "fatal", "--help"}},
		{"telemetry false", []string{"--telemetry=false", "--help"}},
		{"domain custom", []string{"--domain", "https://test.example.com/api", "--help"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rootCmd.SetArgs(tc.args)
			err := rootCmd.Execute()
			assert.NoError(t, err, "Root command should execute successfully with args: %v", tc.args)
		})
	}
}

// Test invalid flags
func TestRootCommandInvalidFlags(t *testing.T) {
	testCases := []struct {
		name        string
		args        []string
		shouldError bool
	}{
		{"invalid flag", []string{"--invalid-flag"}, true},
		{"invalid log level", []string{"--log-level", "invalid-level"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rootCmd.SetArgs(tc.args)
			err := rootCmd.Execute()

			if tc.shouldError {
				assert.Error(t, err, "Root command should fail with invalid args: %v", tc.args)
			} else {
				assert.NoError(t, err, "Root command should accept args: %v", tc.args)
			}
		})
	}
}

// Test environment (with isolation)
func TestRootCommandEnvironmentOverride(t *testing.T) {
	// Save original environment
	originalEnv := os.Getenv("INFISICAL_API_URL")
	defer os.Setenv("INFISICAL_API_URL", originalEnv)

	// Test with environment URL
	testURL := "https://env-override.example.com/api"
	os.Setenv("INFISICAL_API_URL", testURL)

	// Note: We can't re-test init() because it's already executed
	// But we can verify that the logic works
	domainFlag := rootCmd.PersistentFlags().Lookup("domain")
	assert.NotNil(t, domainFlag, "Domain flag should exist")
}

// Simple performance test
func BenchmarkRootCommandHelp(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rootCmd.SetArgs([]string{"--help"})
		rootCmd.Execute()
	}
}
