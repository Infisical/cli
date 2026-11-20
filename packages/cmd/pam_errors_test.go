package cmd

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
)

func pamConstructedErrors() []*util.CLIError {
	cause := errors.New("cause")
	invocation := pamAccessInvocation{Path: "prod/orders-db", HasCommand: true}
	return []*util.CLIError{
		errPAMAuthRequired(cause),
		errPAMAccountNotFound("prod/orders-db", cause),
		errPAMAccountOrFolderNotFound("prod"),
		errPAMInvalidPath("prod"),
		errPAMInvalidPath("a b; rm -rf /"),
		errPAMApprovalPending(invocation, "3f1c2a3e-6d2b-4b8e-9a6e-1f2d3c4b5a69", false),
		errPAMApprovalPending(invocation, "", true),
		errPAMApprovalRequired(invocation),
		errPAMApprovalNotConfigured(invocation),
		errPAMReasonRequired(invocation, false),
		errPAMReasonRequired(invocation, true),
		errPAMMFARequired(invocation, "https://app.infisical.com/mfa-session/abc123", "abc123"),
		errPAMSessionExpired(invocation, time.Hour, false),
		errPAMSessionExpired(invocation, time.Hour, true),
		errPAMMissingCommand("prod/orders-db"),
		errPAMTokenExpired("INFISICAL_TOKEN environment variable"),
		errPAMCommandNotSupported(invocation, "Windows RDP"),
		errPAMAgenticRemoved(),
		errPAMInvalidDuration("soon"),
		errPAMServiceToken(),
		errPAMPermissionDenied(cause),
	}
}

func TestPAMSuggestionsNeverEchoTheCommandOrUnsafePaths(t *testing.T) {
	invocation := pamAccessInvocation{Path: "prod/orders db; rm -rf /", HasCommand: true}
	err := errPAMReasonRequired(invocation, false)
	if got := err.Next[0].Command; got != `infisical pam access <folder/account> --reason "<reason>" -- <command>` {
		t.Errorf("unexpected suggestion %q", got)
	}
	if strings.Contains(err.Message, "rm -rf") {
		t.Errorf("message repeats unsafe input: %q", err.Message)
	}

	if got := pamLookupArg("prod/"); got != "prod" {
		t.Errorf("a bare folder name must print, got %q", got)
	}
	if got := pamAccountArg("prod"); got != "<folder/account>" {
		t.Errorf("an access suggestion must never be a bare name, got %q", got)
	}

	safe := pamAccessInvocation{Path: "/prod/orders-db"}
	if got := safe.accessCommand(""); got != "infisical pam access prod/orders-db" {
		t.Errorf("unexpected suggestion %q", got)
	}
}
