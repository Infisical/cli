package pam

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
)

func TestPrintDeviceChecks(t *testing.T) {
	color.NoColor = true
	verification := &api.PAMDeviceVerification{
		Status:      api.PAMDeviceVerificationFailed,
		AccountName: "prod-dbs/pg-bg",
		Providers:   []string{"Rippling"},
		Device:      &api.PAMVerifiedDevice{Serial: "C02FX4ZHMD6R", Model: "MacBook Pro (14-inch, M3)", OS: "macOS 15.4.1"},
		Checks: []api.PAMDeviceCheck{
			{Provider: "Rippling", Label: "Managed Device", Passed: true, Detail: "Enrolled in Rippling and assigned to you."},
			{Provider: "Rippling", Label: "Disk Encrypted", Passed: false, Detail: "FileVault is off."},
		},
	}
	var out bytes.Buffer
	PrintDeviceChecks(&out, CheckingDeviceHeader(verification, verification.AccountName), verification, api.PAMDeviceInfo{})

	want := "Checking this device with Rippling for prod-dbs/pg-bg...\n" +
		"  Device  MacBook Pro (14-inch, M3), macOS 15.4.1, serial C02FX4ZHMD6R\n" +
		"\n" +
		"  Rippling\n" +
		"    ✔ Managed Device        Enrolled in Rippling and assigned to you.\n" +
		"    ✘ Disk Encrypted        FileVault is off.\n" +
		"\n"
	if out.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestPrintDeviceChecksGroupsProvidersInArrivalOrder(t *testing.T) {
	color.NoColor = true
	verification := &api.PAMDeviceVerification{
		Providers: []string{"Rippling", "SentinelOne"},
		Checks: []api.PAMDeviceCheck{
			{Provider: "SentinelOne", Label: "Agent Running", Passed: true},
			{Provider: "Rippling", Label: "Managed Device", Passed: true},
			{Provider: "SentinelOne", Label: "No Threats", Passed: true},
		},
	}
	var out bytes.Buffer
	PrintDeviceChecks(&out, CheckingDeviceHeader(verification, ""), verification, api.PAMDeviceInfo{SerialNumber: "X1", Model: "Mac16,7", OSName: "macOS", OSVersion: "15.4.1"})
	got := out.String()
	want := "Checking this device with Rippling and SentinelOne...\n" +
		"  Device  Mac16,7, macOS 15.4.1, serial X1\n" +
		"\n  SentinelOne\n" +
		"    ✔ Agent Running\n" +
		"    ✔ No Threats\n" +
		"\n  Rippling\n" +
		"    ✔ Managed Device\n" +
		"\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestDeviceGateParsing(t *testing.T) {
	required := &api.APIError{StatusCode: 403, Name: "PermissionDenied", Details: map[string]any{
		"code": "DEVICE_VERIFICATION_REQUIRED", "accountId": "a1", "accessType": "session",
	}}
	requirement, ok := DeviceVerificationRequiredFrom(required)
	if !ok || requirement.AccountID != "a1" || requirement.AccessType != "session" {
		t.Errorf("got %+v, %v", requirement, ok)
	}
	if _, ok := DevicePostureFailedFrom(required); ok {
		t.Error("a verification-required error isn't a posture failure")
	}

	failed := &api.APIError{StatusCode: 403, Details: map[string]any{
		"code": "DEVICE_POSTURE_FAILED",
		"verification": map[string]any{
			"id": "v1", "status": "failed", "providers": []any{"Rippling"},
			"checks": []any{map[string]any{"provider": "Rippling", "label": "Disk Encrypted", "passed": false}},
		},
	}}
	verification, ok := DevicePostureFailedFrom(failed)
	if !ok || verification.Id != "v1" || len(verification.Checks) != 1 || verification.Checks[0].Label != "Disk Encrypted" {
		t.Errorf("got %+v, %v", verification, ok)
	}

	other := &api.APIError{StatusCode: 404, Details: map[string]any{"code": "DEVICE_VERIFICATION_REQUIRED"}}
	if _, ok := DeviceVerificationRequiredFrom(other); ok {
		t.Error("only a 403 is a device gate")
	}
}

type deviceStubServer struct {
	checkStatus      int
	checkBody        string
	createStatus     []int
	createBodies     []string
	createRequests   []map[string]any
	checkRequests    []map[string]any
	accountsResponse string
}

func (s *deviceStubServer) start(t *testing.T) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/pam/accounts/accessible":
			_, _ = io.WriteString(w, s.accountsResponse)
		case "/v1/pam/device-verifications/check":
			s.checkRequests = append(s.checkRequests, body)
			w.WriteHeader(s.checkStatus)
			_, _ = io.WriteString(w, s.checkBody)
		case "/v1/pam/access-requests":
			i := len(s.createRequests)
			s.createRequests = append(s.createRequests, body)
			w.WriteHeader(s.createStatus[i])
			_, _ = io.WriteString(w, s.createBodies[i])
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	oldURL, oldCollect := config.INFISICAL_URL, collectDeviceInfo
	config.INFISICAL_URL = server.URL
	collectDeviceInfo = func() (api.PAMDeviceInfo, error) {
		return api.PAMDeviceInfo{SerialNumber: "C02FX4ZHMD6R", Platform: "macos"}, nil
	}
	t.Cleanup(func() {
		server.Close()
		config.INFISICAL_URL, collectDeviceInfo = oldURL, oldCollect
	})
}

const stubAccounts = `{"accounts":[{"id":"acc-1","name":"pg-bg","folderName":"prod-dbs"}],"totalCount":1}`
const stubCreated = `{"request":{"id":"req-1","status":"approved"}}`

func verificationJSON(status string, appliesTo string) string {
	return `{"verification":{"id":"ver-1","status":"` + status + `","providers":["Rippling"],"checks":[{"provider":"Rippling","label":"Disk Encrypted","passed":` +
		map[bool]string{true: "true", false: "false"}[status == "passed"] + `}]},"appliesTo":` + appliesTo + `}`
}

func TestCreateAccessRequestSendsAPassedAutoApprovalCheck(t *testing.T) {
	s := &deviceStubServer{accountsResponse: stubAccounts, checkStatus: 200, checkBody: verificationJSON("passed", `["auto-approval"]`),
		createStatus: []int{200}, createBodies: []string{stubCreated}}
	s.start(t)

	_, id, err := createAccessRequest(resty.New(), api.PAMCreateAccessRequestBody{Path: "prod-dbs/pg-bg", Duration: "3600000ms"})
	if err != nil || id != "ver-1" {
		t.Fatalf("id %q, err %v", id, err)
	}
	if s.checkRequests[0]["forAutoApproval"] != true || s.checkRequests[0]["accountId"] != "acc-1" {
		t.Errorf("unexpected check body %v", s.checkRequests[0])
	}
	if s.createRequests[0]["deviceVerificationId"] != "ver-1" {
		t.Errorf("request sent without the verification: %v", s.createRequests[0])
	}
}

func TestCreateAccessRequestFailedAutoApprovalStillFiles(t *testing.T) {
	s := &deviceStubServer{accountsResponse: stubAccounts, checkStatus: 200, checkBody: verificationJSON("failed", `["auto-approval"]`),
		createStatus: []int{200}, createBodies: []string{`{"request":{"id":"req-1","status":"pending"}}`}}
	s.start(t)

	_, id, err := createAccessRequest(resty.New(), api.PAMCreateAccessRequestBody{Path: "prod-dbs/pg-bg"})
	if err != nil || id != "" {
		t.Fatalf("id %q, err %v", id, err)
	}
	if _, sent := s.createRequests[0]["deviceVerificationId"]; sent {
		t.Errorf("a failed check must not be sent: %v", s.createRequests[0])
	}
}

func TestCreateAccessRequestFailedTemplateStops(t *testing.T) {
	s := &deviceStubServer{accountsResponse: stubAccounts, checkStatus: 200, checkBody: verificationJSON("failed", `["template","auto-approval"]`)}
	s.start(t)

	_, _, err := createAccessRequest(resty.New(), api.PAMCreateAccessRequestBody{Path: "prod-dbs/pg-bg"})
	var postureErr *DevicePostureError
	if !errors.As(err, &postureErr) || len(s.createRequests) != 0 {
		t.Fatalf("expected a posture error and no request, got %v, %d requests", err, len(s.createRequests))
	}
}

func TestCreateAccessRequestOlderServerSkipsTheCheck(t *testing.T) {
	s := &deviceStubServer{accountsResponse: stubAccounts, checkStatus: 404, checkBody: `{"message":"Route not found"}`,
		createStatus: []int{200}, createBodies: []string{stubCreated}}
	s.start(t)

	if _, id, err := createAccessRequest(resty.New(), api.PAMCreateAccessRequestBody{Path: "prod-dbs/pg-bg"}); err != nil || id != "" {
		t.Fatalf("id %q, err %v", id, err)
	}
}

func TestCreateAccessRequestAnswersADeviceGateOnce(t *testing.T) {
	gate := `{"message":"Device check required","error":"PermissionDenied","details":{"code":"DEVICE_VERIFICATION_REQUIRED","accountId":"acc-1","accessType":"session"}}`
	s := &deviceStubServer{accountsResponse: `{"accounts":[],"totalCount":0}`, checkStatus: 200, checkBody: verificationJSON("passed", `["template"]`),
		createStatus: []int{403, 200}, createBodies: []string{gate, stubCreated}}
	s.start(t)

	_, id, err := createAccessRequest(resty.New(), api.PAMCreateAccessRequestBody{Path: "prod-dbs/pg-bg"})
	if err != nil || id != "ver-1" || len(s.createRequests) != 2 || s.createRequests[1]["deviceVerificationId"] != "ver-1" {
		t.Fatalf("id %q, err %v, requests %v", id, err, s.createRequests)
	}
	if s.checkRequests[0]["accessType"] != "session" {
		t.Errorf("access type not passed on: %v", s.checkRequests[0])
	}
}
