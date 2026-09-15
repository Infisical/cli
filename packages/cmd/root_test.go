package cmd

import (
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
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

func TestWarnIfTokenOverridesSavedSessionSkipsPlatformKeyring(t *testing.T) {
	originalLookup := getCurrentLoggedInUserDetails
	t.Cleanup(func() { getCurrentLoggedInUserDetails = originalLookup })

	lookupCalls := 0
	getCurrentLoggedInUserDetails = func(bool) (util.LoggedInUserDetails, error) {
		lookupCalls++
		return util.LoggedInUserDetails{}, nil
	}

	command := &cobra.Command{}
	serviceToken := &models.TokenDetails{Source: "INFISICAL_TOKEN environment variable"}
	warnIfTokenOverridesSavedSession(command, false, serviceToken, false)
	warnIfTokenOverridesSavedSession(command, false, nil, true)
	warnIfTokenOverridesSavedSession(command, true, nil, false)

	if lookupCalls != 0 {
		t.Fatalf("saved-session lookup called %d times; machine-authenticated and silent commands must not read the platform keyring", lookupCalls)
	}

	warnIfTokenOverridesSavedSession(command, false, nil, false)
	if lookupCalls != 1 {
		t.Fatalf("saved-session lookup called %d times after an interactive user command, want 1", lookupCalls)
	}
}
