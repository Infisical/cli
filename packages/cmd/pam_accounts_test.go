package cmd

import (
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
)

func TestNewPAMAccountViewAccess(t *testing.T) {
	noApprovers := "This account requires approval, but its folder has no approvers yet."
	cases := []struct {
		name            string
		account         api.PAMAccessibleAccount
		machineIdentity bool
		access          string
		reason          string
	}{
		{"ready", api.PAMAccessibleAccount{CanLaunch: true}, false, pamAccessReady, ""},
		{"no launch", api.PAMAccessibleAccount{}, false, pamAccessUnavailable, "permission to launch"},
		{"no approvers", api.PAMAccessibleAccount{CanLaunch: true, RequiresApproval: true, DisabledReason: &noApprovers}, false, pamAccessUnavailable, "no approvers"},
		{"needs approval", api.PAMAccessibleAccount{CanLaunch: true, RequiresApproval: true}, false, pamAccessNeedsApproval, ""},
		{"mfa user", api.PAMAccessibleAccount{CanLaunch: true, RequireMfa: true}, false, pamAccessReady, ""},
		{"mfa machine identity", api.PAMAccessibleAccount{CanLaunch: true, RequireMfa: true}, true, pamAccessUnavailable, "machine identity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.account.FolderName, tc.account.Name = "prod", "db"
			view := newPAMAccountView(tc.account, tc.machineIdentity)
			if view.Access != tc.access {
				t.Fatalf("access = %q, want %q", view.Access, tc.access)
			}
			if tc.reason != "" && (view.DisabledReason == nil || !strings.Contains(*view.DisabledReason, tc.reason)) {
				t.Fatalf("reason = %v, want it to mention %q", view.DisabledReason, tc.reason)
			}
			if (view.Access == pamAccessUnavailable) != (view.Example == "") {
				t.Fatalf("example = %q for access %q; only unavailable accounts have none", view.Example, view.Access)
			}
		})
	}
}
