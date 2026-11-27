package cmd

import (
	"errors"
	"fmt"
	pam "github.com/Infisical/infisical-merge/packages/pam/local"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
)

const (
	errCodeAccountNotFound       = "account_not_found"
	errCodeApprovalPending       = "approval_pending"
	errCodeApprovalRequired      = "approval_required"
	errCodeApprovalNotConfigured = "approval_not_configured"
	errCodeAccessApproved        = "access_approved"
	errCodeReasonRequired        = "reason_required"
	errCodeMFARequired           = "mfa_required"
	errCodeSessionExpired        = "session_expired"
	errCodeCommandNotSupported   = "command_not_supported"
	errCodeCommandRemoved        = "command_removed"
	errCodeDevicePostureFailed   = "device_posture_failed"
	errCodeDeviceInfoUnavailable = "device_info_unavailable"
	errCodeVerificationCode      = "verification_code_invalid"
)

const pamPrefix = "infisical pam"

// pamAccountArg returns path as it can safely appear in a suggested command.
func pamAccountArg(path string) string {
	if trimmed, ok := pamSafePath(path); ok && pamIsAccountPath(trimmed) {
		return trimmed
	}
	return "<folder/account>"
}

// pamLookupArg is pamAccountArg for arguments that may also name a folder.
func pamLookupArg(path string) string {
	if trimmed, ok := pamSafePath(path); ok {
		return trimmed
	}
	return "<folder/account>"
}

func pamSafePath(path string) (string, bool) {
	trimmed := strings.Trim(strings.TrimSpace(path), "/")
	return trimmed, trimmed != "" && util.SuggestedValue("/"+trimmed, "x") == "/"+trimmed
}

// pamIsAccountPath mirrors the backend, which splits a path at its first slash.
func pamIsAccountPath(path string) bool {
	folder, account, found := strings.Cut(path, "/")
	return found && folder != "" && account != ""
}

// pamAccessInvocation is what the caller ran, rebuilt for a suggestion. The command after '--' is
// never echoed: it is arbitrary text.
type pamAccessInvocation struct {
	Path       string
	HasCommand bool
	Reason     string
	Duration   time.Duration
	// Interactive is true when a person is at a terminal, so agent-only guidance is left out.
	Interactive bool
}

func (i pamAccessInvocation) accessCommand(extra string) string {
	line := pamPrefix + " access " + pamAccountArg(i.Path)
	if extra != "" {
		line += " " + extra
	}
	if i.Reason != "" && !strings.Contains(extra, "--reason") {
		line += " --reason \"" + util.SuggestedValue(i.Reason, "reason") + "\""
	}
	if i.HasCommand {
		line += " -- <command>"
	}
	return line
}

func (i pamAccessInvocation) statusStep() util.NextStep {
	return util.NextStep{Purpose: "To check whether access was approved", Command: pamPrefix + " accounts get " + pamAccountArg(i.Path)}
}

func errPAMAuthRequired(cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeAuthRequired, Cause: cause,
		Message: "You're not logged in, or your login has expired. A person has to log in; an agent can't do it for them.",
		Next:    []util.NextStep{{Purpose: "To log in", Command: "infisical login"}}}
}

// pamTokenOrigin names where a token came from without putting "--token" before a word, which the
// redactor would treat as a token value.
func pamTokenOrigin(source string) string {
	if source == "--token flag" {
		return "It was passed with --token."
	}
	return fmt.Sprintf("It came from the %s.", source)
}

func errPAMTokenExpired(source string) *util.CLIError {
	return &util.CLIError{Code: errCodeAuthRequired,
		Message: fmt.Sprintf("The machine identity access token has expired. %s Replace it with a new token, or authenticate with the identity's own credentials instead.", pamTokenOrigin(source)),
		Next:    []util.NextStep{{Purpose: "To authenticate with universal auth credentials", Command: pamPrefix + " accounts get --auth-method universal-auth"}}}
}

func errPAMTokenRejected(cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeAuthRequired, Cause: cause,
		Message: "Infisical rejected the machine identity's access token. It may have expired, been revoked, reached its maximum TTL or run out of uses. Get a new token, or authenticate with the identity's own credentials instead.",
		Next:    []util.NextStep{{Purpose: "To authenticate with universal auth credentials", Command: pamPrefix + " accounts get --auth-method universal-auth"}}}
}

func errPAMInvalidAuthMethod(authMethod string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--auth-method %s isn't supported. Use one of: %s.", quoted(authMethod, "auth method"), pamAuthMethods)}
}

func errPAMMachineIdentityLogin(authMethod string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeAuthRequired, Cause: cause,
		Message: fmt.Sprintf("Couldn't authenticate as a machine identity with %s: %v. Check the identity's credentials and that the auth method is configured on it.", quoted(authMethod, "auth method"), cause)}
}

// A profile, organization or domain selection error already says how to fix itself.
func errPAMLoginUnreadable(cause error, selectionError bool) *util.CLIError {
	if selectionError {
		return &util.CLIError{Code: errCodeInvalidFlagValue, Cause: cause,
			Message: fmt.Sprintf("Couldn't use the selected profile, organization or domain: %v.", cause)}
	}
	return &util.CLIError{Code: errCodeAuthRequired, Cause: cause,
		Message: fmt.Sprintf("Couldn't read your saved login: %v. Log in again.", cause),
		Next:    []util.NextStep{{Purpose: "To log in", Command: "infisical login"}}}
}

func errPAMNotMember(cause error, machineIdentity bool) *util.CLIError {
	message := "You aren't a member of PAM in this organization. Ask a PAM admin to add you."
	if machineIdentity {
		message = "This machine identity isn't a member of PAM in this organization. Ask a PAM admin to add it."
	}
	return &util.CLIError{Code: errCodePermissionDenied, Cause: cause, Message: message}
}

func errPAMAccountNotFound(path string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeAccountNotFound, Cause: cause,
		Message: fmt.Sprintf("PAM account %s doesn't exist, or you don't have access to it.", pamAccountArg(path)),
		Next:    []util.NextStep{{Purpose: "To list the accounts you can access", Command: pamPrefix + " accounts get"}}}
}

func errPAMAccountOrFolderNotFound(path string) *util.CLIError {
	return &util.CLIError{Code: errCodeAccountNotFound,
		Message: fmt.Sprintf("No PAM account or folder named %s exists, or you don't have access to it.", pamLookupArg(path)),
		Next:    []util.NextStep{{Purpose: "To list the accounts you can access", Command: pamPrefix + " accounts get"}}}
}

func errPAMInvalidPath(path string) *util.CLIError {
	next := []util.NextStep{{Purpose: "To list the accounts you can access", Command: pamPrefix + " accounts get"}}
	name := pamLookupArg(path)
	if name != "<folder/account>" {
		next = append(next, util.NextStep{Purpose: "To find the folder or accounts named " + name, Command: pamPrefix + " accounts get " + name})
	}
	return &util.CLIError{Code: errCodeInvalidArgument,
		Message: fmt.Sprintf("%s isn't an account path. Name the account as folder/account, for example prod/orders-db.", name),
		Next:    next}
}

func errPAMApprovalPending(invocation pamAccessInvocation, requestID string, regrant bool) *util.CLIError {
	what := "needs approval"
	if regrant {
		what = "had its approved access expire, and needs approval again"
	}
	filed := "An access request is waiting for a person to approve it in Infisical"
	if requestID != "" {
		filed = fmt.Sprintf("Access request %s was filed and is waiting for a person to approve it in Infisical", quoted(requestID, "request ID"))
	}
	message := fmt.Sprintf("%s %s. %s.", pamAccountArg(invocation.Path), what, filed)
	if !invocation.Interactive {
		message += " Don't look for another way to reach this account."
	}
	return &util.CLIError{Code: errCodeApprovalPending,
		Message: message,
		Next:    []util.NextStep{invocation.statusStep(), {Purpose: "To connect once it's approved", Command: invocation.accessCommand("")}}}
}

func errPAMApprovedRerun(invocation pamAccessInvocation) *util.CLIError {
	return &util.CLIError{Code: errCodeAccessApproved,
		Message: fmt.Sprintf("Access to %s was approved, but it isn't active yet. Run the command again to connect.", pamAccountArg(invocation.Path)),
		Next:    []util.NextStep{{Purpose: "To connect", Command: invocation.accessCommand("")}}}
}

func errPAMApprovalRequired(invocation pamAccessInvocation) *util.CLIError {
	return &util.CLIError{Code: errCodeApprovalRequired,
		Message: fmt.Sprintf("%s needs approval, and --no-approval-request was set, so no access request was filed.", pamAccountArg(invocation.Path)),
		Next:    []util.NextStep{{Purpose: "To file an access request", Command: invocation.accessCommand("--reason \"<reason>\"")}}}
}

func errPAMApprovalNotConfigured(invocation pamAccessInvocation) *util.CLIError {
	return &util.CLIError{Code: errCodeApprovalNotConfigured,
		Message: fmt.Sprintf("%s needs approval, but its folder has no approvers, so nobody can approve a request. Ask a folder admin to add approvers on the folder's Approvals tab.", pamAccountArg(invocation.Path))}
}

func errPAMReasonRequired(invocation pamAccessInvocation, forRequest bool) *util.CLIError {
	message := fmt.Sprintf("%s requires a reason, which is recorded for audit.", pamAccountArg(invocation.Path))
	if forRequest {
		message = fmt.Sprintf("%s needs approval, and its access request requires a reason. No request was filed.", pamAccountArg(invocation.Path))
	}
	return &util.CLIError{Code: errCodeReasonRequired, Message: message,
		Next: []util.NextStep{{Purpose: "To try again with a reason", Command: invocation.accessCommand("--reason \"<reason>\"")}}}
}

func errPAMMFARequired(invocation pamAccessInvocation, url, mfaSessionID string) *util.CLIError {
	return &util.CLIError{Code: errCodeMFARequired,
		Message: fmt.Sprintf("%s requires MFA. Ask the person you're working for to open %s and complete verification, then run the command again with --mfa-session.", pamAccountArg(invocation.Path), url),
		Next:    []util.NextStep{{Purpose: "To connect after verification", Command: invocation.accessCommand("--mfa-session " + util.SuggestedValue(mfaSessionID, "mfa-session-id"))}}}
}

func errPAMMFARequiredAfterApproval(invocation pamAccessInvocation, url, mfaSessionID string) *util.CLIError {
	err := errPAMMFARequired(invocation, url, mfaSessionID)
	err.Message = fmt.Sprintf("Access to %s was approved. The account also requires MFA, and each verification works for one connection, so it needs MFA once more. Ask the person you're working for to open %s and complete verification, then run the command again with --mfa-session.", pamAccountArg(invocation.Path), url)
	return err
}

func errPAMSessionExpired(invocation pamAccessInvocation, ranFor time.Duration, awsCredentials bool) *util.CLIError {
	if awsCredentials {
		return &util.CLIError{Code: errCodeSessionExpired,
			Message: fmt.Sprintf("The AWS credentials for %s expired after %s, before the command finished, so the command was stopped. A longer --duration doesn't extend them.", pamAccountArg(invocation.Path), ranFor),
			Next:    []util.NextStep{{Purpose: "To run it again with new credentials", Command: invocation.accessCommand("")}}}
	}
	return &util.CLIError{Code: errCodeSessionExpired,
		Message: fmt.Sprintf("The PAM session for %s ended after %s, before the command finished, so the command was stopped.", pamAccountArg(invocation.Path), ranFor),
		Next:    []util.NextStep{{Purpose: "To run it again with a longer session, up to the account's maximum session length", Command: invocation.accessCommand("--duration " + pamLongerDuration(invocation.Duration))}}}
}

// pamLongerDuration suggests twice the requested duration, written the way --duration takes it.
func pamLongerDuration(requested time.Duration) string {
	if requested <= 0 {
		return "<duration>"
	}
	longer := (2 * requested).Round(time.Minute)
	if longer < time.Minute {
		longer = time.Minute
	}
	hours, minutes := int(longer.Hours()), int(longer.Minutes())%60
	switch {
	case hours == 0:
		return fmt.Sprintf("%dm", minutes)
	case minutes == 0:
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh%dm", hours, minutes)
}

func errPAMMissingCommand(path string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidArgument,
		Message: "Nothing follows '--'. Put the command to run after it, or drop the '--' to start an interactive session.",
		Next:    []util.NextStep{{Purpose: "To run one command", Command: pamPrefix + " access " + pamAccountArg(path) + " -- <command>"}}}
}

func errPAMCommandNotSupported(invocation pamAccessInvocation, typeLabel string) *util.CLIError {
	return &util.CLIError{Code: errCodeCommandNotSupported,
		Message: fmt.Sprintf("%s is a %s account, which can't run a command after '--'. Drop the '--' to start an RDP proxy, then open the .rdp file it prints with an RDP client. The proxy runs until you stop it, so start it in the background.", pamAccountArg(invocation.Path), typeLabel),
		Next:    []util.NextStep{{Purpose: "To start the proxy in the background", Command: pamPrefix + " access " + pamAccountArg(invocation.Path) + " < /dev/null > infisical-rdp.log 2>&1 &"}}}
}

func errPAMAgenticRemoved() *util.CLIError {
	return &util.CLIError{Code: errCodeCommandRemoved,
		Message: "infisical pam agentic access was removed. Agents now run the PAM commands directly: list accounts, then run one command against an account.",
		Next: []util.NextStep{
			{Purpose: "To list the accounts you can access", Command: pamPrefix + " accounts get"},
			{Purpose: "To run a command against one", Command: pamPrefix + " access <folder/account> -- <command>"},
		}}
}

func errPAMInvalidDuration(value string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--duration %s isn't a positive duration: use a format like 30m, 1h or 2h30m.", quoted(value, "duration"))}
}

func errPAMServiceToken() *util.CLIError {
	return &util.CLIError{Code: errCodeServiceTokenUnsupported,
		Message: "PAM doesn't accept service tokens. Use a machine identity access token or credentials, or log in as a user.",
		Next:    []util.NextStep{{Purpose: "To log in as a user", Command: "infisical login"}}}
}

const (
	pamDeniedLaunch  = "You don't have permission to launch sessions on this account. Ask a folder admin for the Connector role on it."
	pamDeniedRequest = "You don't have permission to request access to this account. Ask a folder admin for a role on it."
	pamDeniedList    = "You don't have permission to list PAM accounts. Ask a PAM admin for a role on the folders or accounts you need."
)

func errPAMPermissionDenied(cause error, message string) *util.CLIError {
	return &util.CLIError{Code: errCodePermissionDenied, Cause: cause,
		Message: message,
		Next:    []util.NextStep{{Purpose: "To list the accounts you can access", Command: pamPrefix + " accounts get"}}}
}

func errPAMDevicePostureFailed(path string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeDevicePostureFailed, Cause: cause,
		Message: fmt.Sprintf("Access denied. This device doesn't meet the device posture policy for %s. Fix the failed checks above and try again. Changes can take a few minutes to show up.", pamAccountArg(path))}
}

func errPAMDeviceCheckUnavailable(cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeDevicePostureFailed, Cause: cause,
		Message: "Infisical couldn't check this device. Try again in a few minutes, or contact your admin if it keeps happening."}
}

func errPAMDeviceCheckFailed(cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeDevicePostureFailed, Cause: cause,
		Message: "Device check failed. Your browser shows which checks failed."}
}

func errPAMDeviceInfoUnavailable(cause error) *util.CLIError {
	message := "Couldn't read this device's serial number, which the device check needs."
	var infoErr *util.DeviceInfoError
	if errors.As(cause, &infoErr) {
		message = infoErr.Message
	}
	return &util.CLIError{Code: errCodeDeviceInfoUnavailable, Cause: cause, Message: message}
}

func errPAMInvalidVerificationCode(code string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidArgument,
		Message: fmt.Sprintf("%s isn't a device check code. Copy the code your browser shows, for example ABCD-EF23.", quoted(code, "code"))}
}

func errPAMVerificationCode(statusCode int, cause error) *util.CLIError {
	var message string
	switch statusCode {
	case 404:
		message = "No device check is waiting for this code. Check the code your browser shows and try again."
	case 400:
		message = "This code expired. Start the device check again in your browser to get a new code."
	case 409:
		message = "This code was already used. Start the device check again in your browser to get a new code."
	default:
		message = "This code belongs to another user. Log in as the user who started the device check in the browser, then try again."
	}
	return &util.CLIError{Code: errCodeVerificationCode, Cause: cause, Message: message,
		Next: verificationCodeNext(statusCode)}
}

func verificationCodeNext(statusCode int) []util.NextStep {
	if statusCode == 403 {
		return []util.NextStep{{Purpose: "To log in", Command: "infisical login"}}
	}
	return nil
}

func pamVerificationCodeStatus(err error) (int, bool) {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return 0, false
	}
	switch apiErr.StatusCode {
	case 404, 409:
		return apiErr.StatusCode, true
	case 400:
		return 400, apiErr.Name == pam.DeviceVerificationCodeExpiredName
	case 403:
		return 403, apiErr.Name != "TokenError"
	}
	return 0, false
}
