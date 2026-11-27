package pam

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
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

const accessRequestStatusApproved = "approved"

// RaiseAccessRequest files an access request. approved is true when an auto-approval rule granted it
// on submission, so the caller can connect at once, reusing deviceVerificationID when it's set.
func RaiseAccessRequest(httpClient *resty.Client, path, reason string, duration time.Duration) (requestID string, approved bool, deviceVerificationID string, err error) {
	response, deviceVerificationID, err := createAccessRequest(httpClient, api.PAMCreateAccessRequestBody{
		Path:     path,
		Reason:   reason,
		Duration: APIDuration(duration),
	})
	if err != nil {
		return "", false, "", err
	}
	return response.Request.ID, response.Request.Status == accessRequestStatusApproved, deviceVerificationID, nil
}

func createAccessRequest(httpClient *resty.Client, body api.PAMCreateAccessRequestBody) (api.PAMCreateAccessRequestResponse, string, error) {
	stderr := util.GetStderrWriter()
	verificationID, err := CheckDeviceBeforeRequest(httpClient, body.Path, stderr)
	if err != nil {
		return api.PAMCreateAccessRequestResponse{}, "", err
	}
	body.DeviceVerificationId = verificationID

	response, err := api.CallPAMCreateAccessRequest(httpClient, body)
	if err == nil {
		return response, verificationID, nil
	}
	retryID, handled, failure := ResolveDeviceGate(httpClient, err, stderr, true)
	if !handled {
		return api.PAMCreateAccessRequestResponse{}, "", err
	}
	if failure != nil {
		return api.PAMCreateAccessRequestResponse{}, "", failure
	}
	body.DeviceVerificationId = retryID
	response, err = api.CallPAMCreateAccessRequest(httpClient, body)
	if err != nil {
		return api.PAMCreateAccessRequestResponse{}, "", err
	}
	return response, retryID, nil
}

func IsDeviceError(err error) bool {
	var postureErr *DevicePostureError
	var infoErr *util.DeviceInfoError
	return errors.As(err, &postureErr) || errors.As(err, &infoErr)
}
