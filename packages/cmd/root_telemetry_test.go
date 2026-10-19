package cmd

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
)

// executeRootForTelemetry runs a throwaway subcommand through RootCmd, so flags are parsed and the cobra
// initializers run exactly as they do for a real command, and reports whether telemetry ended up enabled.
func executeRootForTelemetry(t *testing.T, args ...string) bool {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFISICAL_DISABLE_UPDATE_CHECK", "true")
	t.Setenv(util.INFISICAL_PROFILE_ENV_NAME, "")
	t.Setenv(util.INFISICAL_ORG_ENV_NAME, "")

	// A key gives the instance a client, so SetEnabled can turn it on; nothing is captured, so nothing is sent.
	originalKey := telemetry.POSTHOG_API_KEY_FOR_CLI
	telemetry.POSTHOG_API_KEY_FOR_CLI = "test-key"
	originalTelemetry := Telemetry
	Telemetry = telemetry.NewTelemetry(true)
	telemetry.POSTHOG_API_KEY_FOR_CLI = originalKey

	originalURL := config.INFISICAL_URL
	originalDomainSet := config.INFISICAL_DOMAIN_EXPLICITLY_SET
	originalLogger := log.Logger
	originalLevel := zerolog.GlobalLevel()
	sub := &cobra.Command{Use: "telemetry-test", Run: func(*cobra.Command, []string) {}}
	RootCmd.AddCommand(sub)
	t.Cleanup(func() {
		RootCmd.RemoveCommand(sub)
		for _, name := range []string{"telemetry", "silent"} {
			flag := RootCmd.PersistentFlags().Lookup(name)
			_ = flag.Value.Set(flag.DefValue)
			flag.Changed = false
		}
		RootCmd.SetArgs(nil)
		RootCmd.SetOut(nil)
		RootCmd.SetErr(nil)
		Telemetry = originalTelemetry
		util.TelemetryOptedOut = false
		config.INFISICAL_URL = originalURL
		config.INFISICAL_DOMAIN_EXPLICITLY_SET = originalDomainSet
		log.Logger = originalLogger
		zerolog.SetGlobalLevel(originalLevel)
	})

	RootCmd.SetOut(&bytes.Buffer{})
	RootCmd.SetErr(&bytes.Buffer{})
	RootCmd.SetArgs(append(append([]string{}, args...), "--silent", sub.Use))
	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if util.TelemetryOptedOut == Telemetry.IsEnabled() {
		t.Fatalf("the opt-out passed to the re-login (%v) disagrees with telemetry being enabled (%v)", util.TelemetryOptedOut, Telemetry.IsEnabled())
	}
	return Telemetry.IsEnabled()
}

func TestTelemetryFlagIsAppliedAfterParsing(t *testing.T) {
	t.Run("--telemetry=false disables", func(t *testing.T) {
		if executeRootForTelemetry(t, "--telemetry=false") {
			t.Fatal("telemetry stayed enabled after --telemetry=false")
		}
	})

	t.Run("enabled by default", func(t *testing.T) {
		if !executeRootForTelemetry(t) {
			t.Fatal("telemetry should stay enabled when nothing opts out")
		}
	})
}
