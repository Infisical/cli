package pam

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

const mfaRequiredErrorName = "SESSION_MFA_REQUIRED"

type ApprovalGate struct {
	// HasApprovalPolicy is false when the folder has no approvers, so no request could be granted.
	HasApprovalPolicy bool
	HasPendingRequest bool
	RequireReason     bool
	// Expired distinguishes a grant that ran out from an account that was never granted.
	Expired bool
}

func apiErrorNamed(err error, names ...string) (*api.APIError, bool) {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return nil, false
	}
	for _, name := range names {
		if apiErr.Name == name {
			return apiErr, true
		}
	}
	return nil, false
}

func ApprovalGateFrom(err error) (ApprovalGate, bool) {
	apiErr, ok := apiErrorNamed(err, approvalRequiredErrorName, grantExpiredErrorName)
	if !ok {
		return ApprovalGate{}, false
	}

	// An older API that omits hasApprovalPolicy does have approvers.
	gate := ApprovalGate{HasApprovalPolicy: true, Expired: apiErr.Name == grantExpiredErrorName}
	if details, ok := apiErr.Details.(map[string]any); ok {
		if value, ok := details["hasApprovalPolicy"].(bool); ok {
			gate.HasApprovalPolicy = value
		}
		if value, ok := details["hasPendingRequest"].(bool); ok {
			gate.HasPendingRequest = value
		}
		if value, ok := details["requireReason"].(bool); ok {
			gate.RequireReason = value
		}
	}
	return gate, true
}

func IsReasonRequired(err error) bool {
	_, ok := apiErrorNamed(err, reasonRequiredErrorName)
	return ok
}

type MFAChallenge struct {
	SessionID string
	Method    string
}

func (c MFAChallenge) URL() string {
	return fmt.Sprintf("%s/mfa-session/%s", strings.TrimSuffix(config.INFISICAL_URL, "/api"), c.SessionID)
}

func MFAChallengeFrom(err error) (MFAChallenge, bool) {
	apiErr, ok := apiErrorNamed(err, mfaRequiredErrorName)
	if !ok {
		return MFAChallenge{}, false
	}
	challenge := MFAChallenge{}
	if details, ok := apiErr.Details.(map[string]any); ok {
		challenge.SessionID, _ = details["mfaSessionId"].(string)
		challenge.Method, _ = details["mfaMethod"].(string)
	}
	return challenge, challenge.SessionID != ""
}

func RaiseAccessRequest(httpClient *resty.Client, path, reason string, duration time.Duration) (string, error) {
	response, err := api.CallPAMCreateAccessRequest(httpClient, api.PAMCreateAccessRequestBody{
		Path:     path,
		Reason:   reason,
		Duration: APIDuration(duration),
	})
	if err != nil {
		return "", err
	}
	return response.Request.ID, nil
}
