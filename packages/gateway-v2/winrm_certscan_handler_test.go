package gatewayv2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/gateway-v2/certscan"
	"github.com/Infisical/infisical-merge/packages/gateway-v2/winrm"
)

func serveWinrmScan(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/scan-certificates", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), winrmTargetContextKey{}, winrmTarget{Host: "10.0.0.5", Port: 5985}))
	rec := httptest.NewRecorder()
	serveWinrmMux().ServeHTTP(rec, req)
	return rec
}

func TestWinrmScanCertificatesReturnsStoreResults(t *testing.T) {
	original := scanWinrmCertificateStores
	t.Cleanup(func() { scanWinrmCertificateStores = original })

	var gotStores []string
	var gotMax int
	scanWinrmCertificateStores = func(_ context.Context, creds winrm.Credentials, stores []string, max int) (winrm.StoreScanResult, error) {
		if creds.Host != "10.0.0.5" || creds.Port != 5985 || creds.Username != "svc" {
			t.Fatalf("unexpected credentials: %+v", creds)
		}
		gotStores, gotMax = stores, max
		return winrm.StoreScanResult{
			Hostname: "web-01",
			Records: []certscan.StoreCertificate{
				{Store: "My", Thumbprint: "AA", Requested: true, DER: []byte{0x30, 0x00}},
			},
			DeniedStores: []string{"WebHosting"},
			HitLimit:     true,
		}, nil
	}

	rec := serveWinrmScan(t, `{"username":"svc","password":"p","params":{"stores":["My","WebHosting"],"maxCertificates":250}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(gotStores) != 2 || gotMax != 250 {
		t.Fatalf("unexpected scan args: stores=%v max=%d", gotStores, gotMax)
	}

	var body struct {
		Result certscan.StoreScanResponse `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Result.Host.Hostname != "web-01" || len(body.Result.Certificates) != 1 ||
		body.Result.Certificates[0].Status != certscan.StatusParseError ||
		body.Result.TruncatedReason != certscan.TruncatedMaxFiles ||
		len(body.Result.DeniedStores) != 1 || body.Result.Pool == nil {
		t.Fatalf("unexpected response: %+v", body.Result)
	}
}

func TestWinrmScanCertificatesRejectsUnknownStore(t *testing.T) {
	rec := serveWinrmScan(t, `{"username":"svc","password":"p","params":{"stores":["My","Disallowed"]}}`)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "unsupported certificate store") {
		t.Fatalf("expected the store to be rejected, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestWinrmScanCertificatesRejectsAnOutOfRangeLimit(t *testing.T) {
	for _, max := range []string{"0", "5001", "-1"} {
		rec := serveWinrmScan(t, `{"username":"svc","password":"p","params":{"stores":["My"],"maxCertificates":`+max+`}}`)
		if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "maxCertificates must be between") {
			t.Fatalf("expected maxCertificates=%s to be rejected, got %d: %s", max, rec.Code, rec.Body.String())
		}
	}
}

func TestWinrmScanCertificatesReportsBusyGateway(t *testing.T) {
	for range winrmStoreScanConcurrency {
		winrmStoreScanSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for range winrmStoreScanConcurrency {
			<-winrmStoreScanSlots
		}
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/scan-certificates", strings.NewReader(`{"username":"svc","password":"p","params":{"stores":["My"],"maxCertificates":10}}`))
	ctx, cancel := context.WithCancel(context.WithValue(req.Context(), winrmTargetContextKey{}, winrmTarget{Host: "10.0.0.5", Port: 5985}))
	cancel()
	rec := httptest.NewRecorder()
	serveWinrmMux().ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"kind":"busy"`) {
		t.Fatalf("expected 503 busy, got %d: %s", rec.Code, rec.Body.String())
	}
}
