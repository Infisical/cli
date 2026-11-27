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
		errPAMPermissionDenied(cause, pamDeniedLaunch),
		errPAMTokenRejected(cause),
		errPAMInvalidAuthMethod("kerberos"),
		errPAMMachineIdentityLogin("universal-auth", cause),
		errPAMLoginUnreadable(cause, false),
		errPAMLoginUnreadable(cause, true),
		errPAMApprovedRerun(invocation),
		errPAMMFARequiredAfterApproval(invocation, "https://app.infisical.com/mfa-session/abc123", "abc123"),
		errPAMNotMember(cause, true),
		errPAMDevicePostureFailed("prod/orders-db", cause),
		errPAMDeviceCheckFailed(nil),
		errPAMDeviceInfoUnavailable(cause),
		errPAMInvalidVerificationCode("abc; rm -rf /"),
		errPAMVerificationCode(404, cause),
		errPAMVerificationCode(400, cause),
		errPAMVerificationCode(409, cause),
		errPAMVerificationCode(403, cause),
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

func TestPAMTokenExpiredNamesTheFlagWithoutLookingLikeAValue(t *testing.T) {
	message := util.RedactCredentials(errPAMTokenExpired("--token flag").Message)
	if strings.Contains(message, "<redacted>") {
		t.Errorf("redaction mangled the message: %q", message)
	}
}

func TestPAMRerunHintsKeepTheReason(t *testing.T) {
	invocation := pamAccessInvocation{Path: "prod/orders-db", HasCommand: true, Reason: "INC-4021"}
	got := errPAMMFARequired(invocation, "https://app.infisical.com/mfa", "abc123").Next[0].Command
	if !strings.Contains(got, `--reason "INC-4021"`) {
		t.Errorf("MFA rerun drops the reason: %q", got)
	}
	if got := errPAMReasonRequired(invocation, false).Next[0].Command; strings.Count(got, "--reason") != 1 {
		t.Errorf("reason given twice: %q", got)
	}
	unsafe := pamAccessInvocation{Path: "prod/orders-db", Reason: "fix it; rm -rf /"}
	if got := unsafe.accessCommand(""); strings.Contains(got, "rm -rf") {
		t.Errorf("unsafe reason echoed: %q", got)
	}
}

func TestPAMLongerDuration(t *testing.T) {
	cases := map[time.Duration]string{0: "<duration>", 20 * time.Second: "1m", 30 * time.Minute: "1h", time.Hour: "2h", 75 * time.Minute: "2h30m", 3 * time.Hour: "6h"}
	for in, want := range cases {
		if got := pamLongerDuration(in); got != want {
			t.Errorf("pamLongerDuration(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestPAMApprovalPendingAgentSentenceOnlyWithoutTerminal(t *testing.T) {
	agent := errPAMApprovalPending(pamAccessInvocation{Path: "prod/db"}, "", false).Message
	person := errPAMApprovalPending(pamAccessInvocation{Path: "prod/db", Interactive: true}, "", false).Message
	if !strings.Contains(agent, "Don't look for another way") || strings.Contains(person, "Don't look for another way") {
		t.Errorf("agent: %q\nperson: %q", agent, person)
	}
}
