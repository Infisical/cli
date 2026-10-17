package cmd

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func TestTelemetryFlagDisablesTelemetry(t *testing.T) {
	flag := RootCmd.PersistentFlags().Lookup("telemetry")
	originalFlagValue := flag.Value.String()
	originalFlagChanged := flag.Changed
	silentFlag := RootCmd.PersistentFlags().Lookup("silent")
	originalSilentValue := silentFlag.Value.String()
	originalSilentChanged := silentFlag.Changed
	originalOut := RootCmd.OutOrStdout()
	originalErr := RootCmd.ErrOrStderr()
	originalTelemetry := Telemetry
	originalAPIKey := telemetry.POSTHOG_API_KEY_FOR_CLI
	originalLogger := log.Logger
	originalLogLevel := zerolog.GlobalLevel()
	testCommand := &cobra.Command{Use: "telemetry-regression-test", Run: func(*cobra.Command, []string) {}}
	RootCmd.AddCommand(testCommand)
	t.Cleanup(func() {
		RootCmd.RemoveCommand(testCommand)
		_ = flag.Value.Set(originalFlagValue)
		flag.Changed = originalFlagChanged
		_ = silentFlag.Value.Set(originalSilentValue)
		silentFlag.Changed = originalSilentChanged
		RootCmd.SetArgs(nil)
		RootCmd.SetOut(originalOut)
		RootCmd.SetErr(originalErr)
		Telemetry = originalTelemetry
		telemetry.POSTHOG_API_KEY_FOR_CLI = originalAPIKey
		log.Logger = originalLogger
		zerolog.SetGlobalLevel(originalLogLevel)
	})

	telemetry.POSTHOG_API_KEY_FOR_CLI = "test-api-key"
	Telemetry = telemetry.NewTelemetry(true)
	telemetry.POSTHOG_API_KEY_FOR_CLI = ""
	RootCmd.SetOut(&bytes.Buffer{})
	RootCmd.SetErr(&bytes.Buffer{})
	RootCmd.SetArgs([]string{"--telemetry=false", "--silent", testCommand.Name()})

	if _, err := RootCmd.ExecuteC(); err != nil {
		t.Fatalf("execute root command: %v", err)
	}
	if Telemetry == nil {
		t.Fatal("telemetry was not initialized")
	}
	if reflect.ValueOf(Telemetry).Elem().FieldByName("isEnabled").Bool() {
		t.Fatal("telemetry remained enabled after --telemetry=false")
	}
}

func TestFilterReservedEnvVars(t *testing.T) {

	// some test env vars.
	// HOME and PATH are reserved key words and should be filtered out
	// XDG_SESSION_ID and LC_CTYPE are reserved key word prefixes and should be filtered out
	// The filter function only checks the keys of the env map, so we dont need to set any values
	env := map[string]models.SingleEnvironmentVariable{
		"test":           {},
		"test2":          {},
		"HOME":           {},
		"PATH":           {},
		"XDG_SESSION_ID": {},
		"LC_CTYPE":       {},
	}

	// check to see if there are any reserved key words in secrets to inject
	filterReservedEnvVars(env)

	if len(env) != 2 {
		t.Errorf("Expected 2 secrets to be returned, got %d", len(env))
	}
	if _, ok := env["test"]; !ok {
		t.Errorf("Expected test to be returned")
	}
	if _, ok := env["test2"]; !ok {
		t.Errorf("Expected test2 to be returned")
	}
	if _, ok := env["HOME"]; ok {
		t.Errorf("Expected HOME to be filtered out")
	}
	if _, ok := env["PATH"]; ok {
		t.Errorf("Expected PATH to be filtered out")
	}
	if _, ok := env["XDG_SESSION_ID"]; ok {
		t.Errorf("Expected XDG_SESSION_ID to be filtered out")
	}
	if _, ok := env["LC_CTYPE"]; ok {
		t.Errorf("Expected LC_CTYPE to be filtered out")
	}

}
