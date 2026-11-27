package cmd

import (
	"fmt"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
)

const (
	errCodeApplicationNotFound           = "application_not_found"
	errCodeProfileNotFound               = "profile_not_found"
	errCodeProfileNotAPIEnabled          = "profile_not_api_enabled"
	errCodeProfileRequired               = "profile_required"
	errCodeCertificateNotFound           = "certificate_not_found"
	errCodeCertificateRequestNotFound    = "certificate_request_not_found"
	errCodeCertificateRequestPending     = "certificate_request_pending"
	errCodeCertificateRequestRejected    = "certificate_request_rejected"
	errCodeCertificateRevocationPending  = "certificate_revocation_pending"
	errCodeCertificateRevocationRejected = "certificate_revocation_rejected"
	errCodePrivateKeyUnavailable         = "private_key_unavailable"
	errCodeCertificateUnavailable        = "certificate_unavailable"
)

var certManagerErrorCodes = []string{
	errCodeApplicationNotFound, errCodeProfileNotFound, errCodeProfileNotAPIEnabled, errCodeProfileRequired,
	errCodeCertificateNotFound, errCodeCertificateRequestNotFound, errCodeCertificateRequestPending,
	errCodeCertificateRequestRejected, errCodeCertificateRevocationPending, errCodeCertificateRevocationRejected,
	errCodePrivateKeyUnavailable, errCodeCertificateUnavailable,
}

const certManagerPrefix = "infisical cert-manager"

func applicationFlag(application string) string {
	return " --application " + util.SuggestedValue(application, "application")
}

func errApplicationRequired() *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: "--application is required: pass the name or ID of the application the certificate belongs to.",
		Next:    []util.NextStep{{Purpose: "To see your applications", Command: certManagerPrefix + " applications get"}}}
}

func errApplicationNotFound(application string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeApplicationNotFound, Cause: cause,
		Message: fmt.Sprintf("Application %s doesn't exist, or you can't access it.", quoted(application, "application")),
		Next:    []util.NextStep{{Purpose: "To see your applications", Command: certManagerPrefix + " applications get"}}}
}

func profileNames(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return listOf(names)
}

// usable lists the profiles the command could use instead: the API-enabled ones to issue from, or
// every attached one to filter by.
func errProfileNotFound(profile, application string, usable []string) *util.CLIError {
	return &util.CLIError{Code: errCodeProfileNotFound,
		Message: fmt.Sprintf("Profile %s isn't attached to application %s. Profiles you can use here: %s.", quoted(profile, "profile"), quoted(application, "application"), profileNames(usable)),
		Next:    []util.NextStep{{Purpose: "To see the application's profiles", Command: certManagerPrefix + " applications get " + util.SuggestedValue(application, "application")}}}
}

func errProfileNotAPIEnabled(profile, application string) *util.CLIError {
	return &util.CLIError{Code: errCodeProfileNotAPIEnabled,
		Message: fmt.Sprintf("Profile %s is attached to application %s without API enrollment, so the CLI can't issue from it. Configure API enrollment under the application's Settings tab in Infisical, or pick another profile.", quoted(profile, "profile"), quoted(application, "application")),
		Next:    []util.NextStep{{Purpose: "To see the profiles with API enrollment", Command: certManagerPrefix + " applications get " + util.SuggestedValue(application, "application")}}}
}

func errProfileRequired(application string, apiProfiles []string) *util.CLIError {
	message := fmt.Sprintf("Application %s has no profile with API enrollment. Configure API enrollment for a profile under the application's Settings tab in Infisical.", quoted(application, "application"))
	if len(apiProfiles) > 0 {
		message = fmt.Sprintf("Application %s has several profiles with API enrollment (%s): pass one with --certificate-profile.", quoted(application, "application"), listOf(apiProfiles))
	}
	return &util.CLIError{Code: errCodeProfileRequired, Message: message,
		Next: []util.NextStep{{Purpose: "To see the application's profiles", Command: certManagerPrefix + " applications get " + util.SuggestedValue(application, "application")}}}
}

func errCertificateNotFound(certificateID, application string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeCertificateNotFound, Cause: cause,
		Message: fmt.Sprintf("Certificate %s doesn't exist in application %s, or you can't access it. Nothing was changed.", quoted(certificateID, "certificate-id"), quoted(application, "application")),
		Next:    []util.NextStep{{Purpose: "To see the application's certificates", Command: certManagerPrefix + " certificates get" + applicationFlag(application)}}}
}

func errCertificateRequestNotFound(requestID, application string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeCertificateRequestNotFound, Cause: cause,
		Message: fmt.Sprintf("Certificate request %s doesn't exist in application %s, or you can't access it.", quoted(requestID, "request-id"), quoted(application, "application")),
		Next:    []util.NextStep{{Purpose: "To see the application's certificate requests", Command: certManagerPrefix + " certificates requests get" + applicationFlag(application)}}}
}

// instance is instanceFlags of the command that failed, so the suggestion reaches the same Infisical.
func certificateRequestPickup(requestID, application, instance string) string {
	return certManagerPrefix + " certificates requests get " + util.SuggestedValue(requestID, "request-id") + applicationFlag(application) + instance
}

// withDetail adds what a wait last learned (waitDetail) to a message.
func withDetail(message, detail string) string {
	if detail == "" {
		return message
	}
	return message + " " + detail
}

// pendingValidationHint is for a request the CA hasn't issued yet. The CA may be waiting for proof of
// domain control, or still processing, as GoDaddy reports a renewal it's preparing.
func pendingValidationHint(status string) string {
	if status != api.CertificateRequestStatusPendingValidation {
		return ""
	}
	return " Check the request with the CA, and complete any validation it asks for, such as a DNS record or an email."
}

func errCertificateRequestPending(requestID, status, application, instance, detail string) *util.CLIError {
	message := fmt.Sprintf("Certificate request %s isn't issued yet (status %s), so nothing was written.", quoted(requestID, "request-id"), quoted(status, "status")) + pendingValidationHint(status)
	return &util.CLIError{Code: errCodeCertificateRequestPending,
		Message: withDetail(message, detail),
		Next:    []util.NextStep{{Purpose: "To pick up the certificate once it's issued", Command: certificateRequestPickup(requestID, application, instance) + " --wait"}}}
}

// errCertificateRequestWithoutApplication is certificate_request_not_found for a request the server
// reports no application for: one made outside an application, or a server too old to report it.
func errCertificateRequestWithoutApplication(requestID, application string) *util.CLIError {
	err := errCertificateRequestNotFound(requestID, application, nil)
	err.Message = fmt.Sprintf("Certificate request %s doesn't belong to application %s: Infisical reports no application for it. It was made outside an application, or your Infisical server is older than this CLI and doesn't report the application yet; upgrade the server to pick it up here.", quoted(requestID, "request-id"), quoted(application, "application"))
	return err
}

func errCertificateUnavailable(requestID string) *util.CLIError {
	return &util.CLIError{Code: errCodeCertificateUnavailable,
		Message: fmt.Sprintf("Certificate request %s was issued, but its certificate is no longer in Infisical (it was deleted). Nothing was written: issue the certificate again.", quoted(requestID, "request-id"))}
}

// action is the command to run again, "issue" or "renew".
func errCertificateRequestRejected(requestID, status, reason, action string) *util.CLIError {
	outcome, advice := "was "+status, "Fix the request and "+action+" the certificate again."
	if status == api.CertificateRequestStatusFailed {
		outcome, advice = "failed", "Check the reason, then "+action+" the certificate again."
	}
	if reason = strings.TrimSpace(reason); reason != "" {
		outcome += fmt.Sprintf(" (%s)", util.SanitizeDisplay(strings.TrimSuffix(reason, ".")))
	}
	return &util.CLIError{Code: errCodeCertificateRequestRejected,
		Message: fmt.Sprintf("Certificate request %s %s, so no certificate was issued. %s", quoted(requestID, "request-id"), outcome, advice)}
}

// approved says the approval was granted, but Infisical hadn't marked the certificate revoked when the
// wait ended.
func errCertificateRevocationPending(certificateID, approvalRequestID, application, instance string, approved bool, detail string) *util.CLIError {
	message := fmt.Sprintf("The revocation of certificate %s is waiting for approval (approval request %s), and the certificate isn't revoked until it's approved. Follow the request under Approval Requests in Certificate Manager.", quoted(certificateID, "certificate-id"), quoted(approvalRequestID, "approval-request-id"))
	if approved {
		message = fmt.Sprintf("The revocation of certificate %s was approved (approval request %s), but Infisical hadn't marked the certificate revoked when the wait ended. Check its status before you act again.", quoted(certificateID, "certificate-id"), quoted(approvalRequestID, "approval-request-id"))
	}
	return &util.CLIError{Code: errCodeCertificateRevocationPending, Message: withDetail(message, detail),
		Next: []util.NextStep{{Purpose: "To check whether it's revoked",
			Command: certManagerPrefix + " certificates get " + util.SuggestedValue(certificateID, "certificate-id") + applicationFlag(application) + instance}}}
}

// outcome is the approval request's status: rejected, expired or cancelled.
func errCertificateRevocationRejected(certificateID, approvalRequestID, outcome string) *util.CLIError {
	return &util.CLIError{Code: errCodeCertificateRevocationRejected,
		Message: fmt.Sprintf("The revocation of certificate %s was %s (approval request %s), so the certificate wasn't revoked. Run the revocation again, and ask an approver of the application to review it.", quoted(certificateID, "certificate-id"), outcome, quoted(approvalRequestID, "approval-request-id"))}
}

func errCertificateRevocationUndecidable(certificateID, approvalRequestID string) *util.CLIError {
	return &util.CLIError{Code: errCodeCertificateRevocationRejected,
		Message: fmt.Sprintf("The revocation of certificate %s is stuck: too few of the approvers on approval request %s can still approve it. The request stays open and can pass if those approvers get their access back. Otherwise, ask an admin of the application to update its revocation approvers, then run the revocation again, which replaces the request.", quoted(certificateID, "certificate-id"), quoted(approvalRequestID, "approval-request-id"))}
}

func errPrivateKeyUnavailable(certificateID string) *util.CLIError {
	return &util.CLIError{Code: errCodePrivateKeyUnavailable,
		Message: fmt.Sprintf("Certificate %s has no private key in Infisical, for example because it was issued from a CSR. Nothing was written: leave out --output-private-key-file and --include-private-key.", quoted(certificateID, "certificate-id"))}
}

func errInvalidChoice(flag, value string, choices []string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--%s %s isn't valid: use one of %s. Nothing was sent.", flag, quoted(value, flag), strings.Join(choices, ", "))}
}

func errInvalidFlag(flag, problem string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--%s %s. Nothing was sent.", flag, problem)}
}

func errFlagsConflict(flag, other, why string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--%s can't be used with --%s: %s. Nothing was sent.", flag, other, why)}
}

func errOutputFileExists(flag, path string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--%s %s already exists: pass --force to overwrite it, or choose another path. Nothing was sent or written.", flag, quoted(path, "file"))}
}

func errNotAnID(kind, value string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidArgument,
		Message: fmt.Sprintf("%s isn't a %s ID: pass the ID Infisical shows for it. Nothing was sent.", quoted(value, "value"), kind)}
}
