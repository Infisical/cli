package cmd

import (
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

func TestShouldReadSavedSession(t *testing.T) {
	cases := []struct {
		name                        string
		silent                      bool
		hasExplicitToken            bool
		hasUniversalAuthCredentials bool
		want                        bool
	}{
		{name: "interactive user command", want: true},
		{name: "service token", hasExplicitToken: true, want: false},
		{name: "universal auth login", hasUniversalAuthCredentials: true, want: false},
		{name: "silent command", silent: true, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldReadSavedSession(tc.silent, tc.hasExplicitToken, tc.hasUniversalAuthCredentials); got != tc.want {
				t.Errorf("shouldReadSavedSession(%v, %v, %v) = %v, want %v", tc.silent, tc.hasExplicitToken, tc.hasUniversalAuthCredentials, got, tc.want)
			}
		})
	}
}

func TestHasExplicitUniversalAuthCredentials(t *testing.T) {
	newLoginCommand := func() *cobra.Command {
		cmd := &cobra.Command{Use: "login"}
		cmd.Flags().String("method", "user", "")
		cmd.Flags().String("client-id", "", "")
		cmd.Flags().String("client-secret", "", "")
		return cmd
	}

	t.Run("flags", func(t *testing.T) {
		cmd := newLoginCommand()
		if err := cmd.Flags().Set("method", string(util.AuthStrategy.UNIVERSAL_AUTH)); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Flags().Set("client-id", "test-client-id"); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Flags().Set("client-secret", "test-client-secret"); err != nil {
			t.Fatal(err)
		}

		if !hasExplicitUniversalAuthCredentials(cmd) {
			t.Fatal("expected universal auth flags to bypass the saved-session lookup")
		}
	})

	t.Run("environment variables", func(t *testing.T) {
		cmd := newLoginCommand()
		if err := cmd.Flags().Set("method", string(util.AuthStrategy.UNIVERSAL_AUTH)); err != nil {
			t.Fatal(err)
		}
		t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME, "test-client-id")
		t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME, "test-client-secret")

		if !hasExplicitUniversalAuthCredentials(cmd) {
			t.Fatal("expected universal auth environment variables to bypass the saved-session lookup")
		}
	})
}

func TestRootPersistentPreRunSavedSessionLookup(t *testing.T) {
	originalLookup := getCurrentLoggedInUserDetails
	t.Cleanup(func() { getCurrentLoggedInUserDetails = originalLookup })
	originalURL := config.INFISICAL_URL
	t.Cleanup(func() { config.INFISICAL_URL = originalURL })
	t.Setenv("INFISICAL_DISABLE_UPDATE_CHECK", "1")
	t.Setenv("INFISICAL_DISABLE_MIGRATION_NOTICE", "1")

	lookupCalls := 0
	getCurrentLoggedInUserDetails = func(bool) (util.LoggedInUserDetails, error) {
		lookupCalls++
		return util.LoggedInUserDetails{}, nil
	}

	newCommand := func(use string) *cobra.Command {
		cmd := &cobra.Command{Use: use}
		cmd.Flags().Bool("silent", false, "")
		cmd.Flags().String("token", "", "")
		cmd.Flags().String("method", "user", "")
		cmd.Flags().String("client-id", "", "")
		cmd.Flags().String("client-secret", "", "")
		return cmd
	}

	cases := []struct {
		name    string
		command *cobra.Command
		setup   func(t *testing.T, cmd *cobra.Command)
		want    int
	}{
		{
			name:    "INFISICAL_TOKEN environment variable",
			command: newCommand("run"),
			setup: func(t *testing.T, cmd *cobra.Command) {
				t.Setenv(util.INFISICAL_TOKEN_NAME, "st.test")
			},
			want: 0,
		},
		{
			name:    "universal auth flags",
			command: newCommand("login"),
			setup: func(t *testing.T, cmd *cobra.Command) {
				for flag, value := range map[string]string{
					"method":        string(util.AuthStrategy.UNIVERSAL_AUTH),
					"client-id":     "test-client-id",
					"client-secret": "test-client-secret",
				} {
					if err := cmd.Flags().Set(flag, value); err != nil {
						t.Fatal(err)
					}
				}
			},
			want: 0,
		},
		{
			name:    "universal auth environment variables",
			command: newCommand("login"),
			setup: func(t *testing.T, cmd *cobra.Command) {
				if err := cmd.Flags().Set("method", string(util.AuthStrategy.UNIVERSAL_AUTH)); err != nil {
					t.Fatal(err)
				}
				t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME, "test-client-id")
				t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME, "test-client-secret")
			},
			want: 0,
		},
		{
			name:    "normal saved-session command",
			command: newCommand("run"),
			setup:   func(*testing.T, *cobra.Command) {},
			want:    1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookupCalls = 0
			config.INFISICAL_URL = "https://app.infisical.com/api"
			tc.setup(t, tc.command)

			RootCmd.PersistentPreRun(tc.command, nil)

			if lookupCalls != tc.want {
				t.Fatalf("saved-session lookup called %d times, want %d", lookupCalls, tc.want)
			}
		})
	}
}
