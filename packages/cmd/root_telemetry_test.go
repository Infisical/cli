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

// clearTelemetryEnv keeps an opt-out set on the machine running the tests from leaking into them.
func clearTelemetryEnv(t *testing.T) {
	t.Helper()
	t.Setenv(util.INFISICAL_DISABLE_TELEMETRY_NAME, "")
	t.Setenv(util.DO_NOT_TRACK_NAME, "")
}

// executeRootForTelemetry runs a throwaway subcommand through RootCmd, so flags are parsed and the cobra
// initializers run exactly as they do for a real command, and reports whether telemetry ended up enabled.
func executeRootForTelemetry(t *testing.T, env map[string]string, args ...string) bool {
	t.Helper()
	clearTelemetryEnv(t)
	for name, value := range env {
		t.Setenv(name, value)
	}
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
		if executeRootForTelemetry(t, nil, "--telemetry=false") {
			t.Fatal("telemetry stayed enabled after --telemetry=false")
		}
	})

	t.Run("enabled by default", func(t *testing.T) {
		if !executeRootForTelemetry(t, nil) {
			t.Fatal("telemetry should stay enabled when nothing opts out")
		}
	})

	t.Run("INFISICAL_DISABLE_TELEMETRY=1 disables", func(t *testing.T) {
		if executeRootForTelemetry(t, map[string]string{util.INFISICAL_DISABLE_TELEMETRY_NAME: "1"}) {
			t.Fatal("telemetry stayed enabled after INFISICAL_DISABLE_TELEMETRY=1")
		}
	})

	t.Run("DO_NOT_TRACK=1 disables", func(t *testing.T) {
		if executeRootForTelemetry(t, map[string]string{util.DO_NOT_TRACK_NAME: "1"}) {
			t.Fatal("telemetry stayed enabled after DO_NOT_TRACK=1")
		}
	})
}

func TestTelemetryEnabledPrecedence(t *testing.T) {
	cases := []struct {
		name        string
		flag        string // empty leaves --telemetry unset
		disableEnv  string
		doNotTrack  string
		wantEnabled bool
	}{
		{name: "nothing set", wantEnabled: true},
		{name: "flag false", flag: "false", wantEnabled: false},
		{name: "explicit flag true beats DO_NOT_TRACK", flag: "true", doNotTrack: "1", wantEnabled: true},
		{name: "explicit flag true beats INFISICAL_DISABLE_TELEMETRY", flag: "true", disableEnv: "1", wantEnabled: true},
		{name: "INFISICAL_DISABLE_TELEMETRY=1", disableEnv: "1", wantEnabled: false},
		{name: "INFISICAL_DISABLE_TELEMETRY=true", disableEnv: "true", wantEnabled: false},
		{name: "INFISICAL_DISABLE_TELEMETRY=false keeps it on", disableEnv: "false", wantEnabled: true},
		{name: "INFISICAL_DISABLE_TELEMETRY=0 keeps it on", disableEnv: "0", wantEnabled: true},
		{name: "INFISICAL_DISABLE_TELEMETRY=no still opts out", disableEnv: "no", wantEnabled: false},
		{name: "INFISICAL_DISABLE_TELEMETRY=false does not override DO_NOT_TRACK", disableEnv: "false", doNotTrack: "1", wantEnabled: false},
		{name: "DO_NOT_TRACK=1", doNotTrack: "1", wantEnabled: false},
		{name: "DO_NOT_TRACK=true", doNotTrack: "true", wantEnabled: false},
		{name: "DO_NOT_TRACK=yes", doNotTrack: "yes", wantEnabled: false},
		{name: "DO_NOT_TRACK=0", doNotTrack: "0", wantEnabled: true},
		{name: "DO_NOT_TRACK=false", doNotTrack: "false", wantEnabled: true},
		{name: "DO_NOT_TRACK= FALSE ", doNotTrack: " FALSE ", wantEnabled: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearTelemetryEnv(t)
			t.Setenv(util.INFISICAL_DISABLE_TELEMETRY_NAME, tc.disableEnv)
			t.Setenv(util.DO_NOT_TRACK_NAME, tc.doNotTrack)

			root := &cobra.Command{Use: "infisical"}
			root.PersistentFlags().Bool("telemetry", true, "")
			if tc.flag != "" {
				if err := root.PersistentFlags().Set("telemetry", tc.flag); err != nil {
					t.Fatal(err)
				}
			}

			if got := telemetryEnabled(root); got != tc.wantEnabled {
				t.Fatalf("telemetryEnabled() = %v, want %v", got, tc.wantEnabled)
			}
		})
	}
}
