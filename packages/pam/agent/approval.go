package agent

import (
	"errors"
	"fmt"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
)

// Error names the API uses for its two approval gates. Both mean the same thing here: there is no
// session to hand out until a reviewer acts, and an access request is what starts that.
const approvalRequiredErrorName = "PAM_APPROVAL_REQUIRED"
const grantExpiredErrorName = "PAM_GRANT_EXPIRED"

// apiDuration renders a duration the way the API parses it. Durations go through npm ms
// server-side, which can't read Go compound formats like "2h30m", so plain milliseconds it is.
func apiDuration(duration time.Duration) string {
	return fmt.Sprintf("%dms", duration.Milliseconds())
}

// isApprovalGate reports whether a failed session creation was refused by an approval policy rather
// than something the caller could fix.
func isApprovalGate(err error) bool {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Name == approvalRequiredErrorName || apiErr.Name == grantExpiredErrorName
}

// approvalGate is what the API tells us about an account's approval policy when it refuses a
// session. It decides whether raising a request is worth attempting.
type approvalGate struct {
	// hasApprovalPolicy is false when the folder has no approvers, so no request could ever be
	// granted. Defaults to true, since an older API that omits the field does have approvers.
	hasApprovalPolicy bool
	// hasPendingRequest is true when a request for this account is already in flight, from an earlier
	// connection or from before this run started.
	hasPendingRequest bool
	// expired distinguishes a grant that ran out from an account that was never granted.
	expired bool
}

func readApprovalGate(err error) approvalGate {
	gate := approvalGate{hasApprovalPolicy: true}

	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return gate
	}

	gate.expired = apiErr.Name == grantExpiredErrorName

	if details, ok := apiErr.Details.(map[string]any); ok {
		if value, ok := details["hasApprovalPolicy"].(bool); ok {
			gate.hasApprovalPolicy = value
		}
		if value, ok := details["hasPendingRequest"].(bool); ok {
			gate.hasPendingRequest = value
		}
	}
	return gate
}

// raiseAccessRequest submits an access request for one account.
func raiseAccessRequest(httpClient *resty.Client, path, reason string, duration time.Duration) (string, error) {
	response, err := api.CallPAMCreateAccessRequest(httpClient, api.PAMCreateAccessRequestBody{
		Path:     path,
		Reason:   reason,
		Duration: apiDuration(duration),
	})
	if err != nil {
		return "", err
	}
	return response.Request.ID, nil
}

// awaitingApprovalError is what a connection gets while its account is gated. It names the account
// and says the wait is the only thing left to do, since this text is what a person reads in the log
// file and the teardown summary.
//
// A regrant is called out separately: an account that worked earlier in the run and stopped is a
// different thing to read about than one that was never usable, and the cause is a grant running out
// rather than anything going wrong.
func awaitingApprovalError(path string, regrant bool) error {
	if regrant {
		return fmt.Errorf(
			"%s had its access grant expire. A fresh access request is awaiting approval; the account "+
				"works again on the first connection after a reviewer approves it", path)
	}
	return fmt.Errorf(
		"%s is awaiting approval: an access request has been raised and a reviewer has to approve it. "+
			"It starts working on the first connection after that, with nothing to restart", path)
}

// approvalErrorText turns a failed request into something a person can act on, naming the
// misconfiguration the API reports rather than leaving a bare status code.
func approvalErrorText(err error) string {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return err.Error()
	}
	if apiErr.ErrorMessage != "" {
		return apiErr.ErrorMessage
	}
	return err.Error()
}
