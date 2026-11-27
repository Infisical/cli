package pam

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

const (
	deviceVerificationRequiredCode = "DEVICE_VERIFICATION_REQUIRED"
	devicePostureFailedCode        = "DEVICE_POSTURE_FAILED"
)

var collectDeviceInfo = util.CollectDeviceInfo

type DeviceRequirement struct {
	AccountID  string
	AccessType string
}

// DevicePostureError means the device was checked and didn't pass. Its checks are already printed.
type DevicePostureError struct {
	Verification *api.PAMDeviceVerification
}

func (e *DevicePostureError) Error() string {
	if e.Verification != nil && e.Verification.Status == api.PAMDeviceVerificationError && e.Verification.Message != "" {
		return "device check failed: " + e.Verification.Message
	}
	return "this device doesn't meet the device posture policy"
}

func deviceGateDetails(err error) (string, map[string]any) {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 {
		return "", nil
	}
	details, _ := apiErr.Details.(map[string]any)
	code, _ := details["code"].(string)
	return code, details
}

func DeviceVerificationRequiredFrom(err error) (DeviceRequirement, bool) {
	code, details := deviceGateDetails(err)
	if code != deviceVerificationRequiredCode {
		return DeviceRequirement{}, false
	}
	requirement := DeviceRequirement{}
	requirement.AccountID, _ = details["accountId"].(string)
	requirement.AccessType, _ = details["accessType"].(string)
	return requirement, true
}

func DevicePostureFailedFrom(err error) (*api.PAMDeviceVerification, bool) {
	code, details := deviceGateDetails(err)
	if code != devicePostureFailedCode {
		return nil, false
	}
	raw, marshalErr := json.Marshal(details["verification"])
	if marshalErr != nil {
		return &api.PAMDeviceVerification{}, true
	}
	var verification api.PAMDeviceVerification
	if json.Unmarshal(raw, &verification) != nil {
		return &api.PAMDeviceVerification{}, true
	}
	return &verification, true
}

func ResolveDeviceGate(httpClient *resty.Client, err error, w io.Writer, forAutoApproval bool) (verificationID string, handled bool, failure error) {
	if verification, ok := DevicePostureFailedFrom(err); ok {
		PrintDeviceChecks(w, CheckingDeviceHeader(verification, ""), verification, api.PAMDeviceInfo{})
		return "", true, &DevicePostureError{Verification: verification}
	}

	requirement, ok := DeviceVerificationRequiredFrom(err)
	if !ok {
		return "", false, nil
	}

	device, deviceErr := collectDeviceInfo()
	if deviceErr != nil {
		return "", true, deviceErr
	}

	response, checkErr := api.CallPAMCheckDevice(httpClient, api.PAMCheckDeviceRequest{
		AccountId:       requirement.AccountID,
		AccessType:      requirement.AccessType,
		ForAutoApproval: forAutoApproval,
		Device:          &device,
	})
	if checkErr != nil {
		return "", true, checkErr
	}
	if response.Verification == nil {
		return "", true, fmt.Errorf("Infisical asked for a device check on this account, then reported that no device policy applies to it")
	}

	PrintDeviceChecks(w, CheckingDeviceHeader(response.Verification, ""), response.Verification, device)
	if response.Verification.Status != api.PAMDeviceVerificationPassed {
		return "", true, &DevicePostureError{Verification: response.Verification}
	}
	return response.Verification.Id, true, nil
}

// Any failure skips the check: the server still enforces the policy when the request is created.
func CheckDeviceBeforeRequest(httpClient *resty.Client, path string, w io.Writer) (verificationID string, err error) {
	account, found, lookupErr := LookupAccessibleAccount(httpClient, path)
	if lookupErr != nil || !found || account.Id == "" {
		log.Debug().Err(lookupErr).Msg("Skipping the device check before the access request: account lookup failed")
		return "", nil
	}

	device, deviceErr := collectDeviceInfo()
	if deviceErr != nil {
		log.Debug().Err(deviceErr).Msg("Skipping the device check before the access request")
		return "", nil
	}

	response, checkErr := api.CallPAMCheckDevice(httpClient, api.PAMCheckDeviceRequest{
		AccountId:       account.Id,
		ForAutoApproval: true,
		Device:          &device,
	})
	if checkErr != nil {
		log.Debug().Err(checkErr).Msg("Skipping the device check before the access request")
		return "", nil
	}
	if response.Verification == nil || len(response.AppliesTo) == 0 {
		return "", nil
	}

	PrintDeviceChecks(w, CheckingDeviceHeader(response.Verification, ""), response.Verification, device)
	if response.Verification.Status == api.PAMDeviceVerificationPassed {
		return response.Verification.Id, nil
	}
	if containsString(response.AppliesTo, api.PAMDevicePolicyTemplate) {
		return "", &DevicePostureError{Verification: response.Verification}
	}
	fmt.Fprintln(w, "This device didn't pass, so the request goes to an approver instead of being approved automatically.")
	fmt.Fprintln(w)
	return "", nil
}

func containsString(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func CheckingDeviceHeader(verification *api.PAMDeviceVerification, accountPath string) string {
	providers := "your device management provider"
	if verification != nil && len(verification.Providers) > 0 {
		providers = strings.Join(verification.Providers, " and ")
	}
	if accountPath != "" {
		return fmt.Sprintf("Checking this device with %s for %s...", providers, accountPath)
	}
	return fmt.Sprintf("Checking this device with %s...", providers)
}

// local fills in what the server's device record leaves out.
func PrintDeviceChecks(w io.Writer, header string, verification *api.PAMDeviceVerification, local api.PAMDeviceInfo) {
	fmt.Fprintln(w, util.SanitizeDisplay(header))
	if verification == nil {
		verification = &api.PAMDeviceVerification{}
	}

	if line := deviceLine(verification.Device, local); line != "" {
		fmt.Fprintf(w, "  Device  %s\n", util.SanitizeDisplay(line))
	}

	if verification.Status == api.PAMDeviceVerificationError && verification.Message != "" {
		fmt.Fprintf(w, "\n  %s\n", util.SanitizeDisplay(verification.Message))
	}
	if verification.Status == api.PAMDeviceVerificationExpired && len(verification.Checks) == 0 {
		fmt.Fprintln(w, "\n  This device check expired.")
	}

	labelWidth := 20
	for _, check := range verification.Checks {
		if len(check.Label) > labelWidth {
			labelWidth = len(check.Label)
		}
	}

	var order []string
	groups := map[string][]api.PAMDeviceCheck{}
	for _, check := range verification.Checks {
		if _, seen := groups[check.Provider]; !seen {
			order = append(order, check.Provider)
		}
		groups[check.Provider] = append(groups[check.Provider], check)
	}

	passMark := color.New(color.FgGreen).Sprint("✔")
	failMark := color.New(color.FgRed).Sprint("✘")
	for _, provider := range order {
		fmt.Fprintf(w, "\n  %s\n", util.SanitizeDisplay(provider))
		for _, check := range groups[provider] {
			mark := failMark
			if check.Passed {
				mark = passMark
			}
			line := fmt.Sprintf("    %s %-*s  %s", mark, labelWidth, util.SanitizeDisplay(check.Label), util.SanitizeDisplay(check.Detail))
			fmt.Fprintln(w, strings.TrimRight(line, " "))
		}
	}
	fmt.Fprintln(w)
}

func deviceLine(device *api.PAMVerifiedDevice, local api.PAMDeviceInfo) string {
	model, osLabel, serial := local.Model, strings.TrimSpace(local.OSName+" "+local.OSVersion), local.SerialNumber
	if device != nil {
		if device.Model != "" {
			model = device.Model
		}
		if device.OS != "" {
			osLabel = device.OS
		}
		if device.Serial != "" {
			serial = device.Serial
		}
	}
	var parts []string
	for _, part := range []string{model, osLabel} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	if serial != "" {
		parts = append(parts, "serial "+serial)
	}
	return strings.Join(parts, ", ")
}
