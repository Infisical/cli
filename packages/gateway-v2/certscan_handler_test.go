package gatewayv2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/infisical-merge/packages/gateway-v2/certscan"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = previous })
	return &buf
}

func TestCertificateScanHandlerLogsRecoveredPanic(t *testing.T) {
	var sessionClosed atomic.Bool
	host, port := startHangingSSHServer(t, &sessionClosed)

	previousScan := runCertificateScan
	runCertificateScan = func(context.Context, certscan.Runner, certscan.Request) (certscan.Response, error) {
		panic("boom from scan")
	}
	t.Cleanup(func() { runCertificateScan = previousScan })
	logs := captureLogs(t)

	body, _ := json.Marshal(map[string]any{
		"authMethod":        "password",
		"username":          "scanner",
		"password":          "test",
		"searchFolderPaths": []string{"/etc/ssl"},
		"maxFolderDepth":    8,
		"maxFileSizeBytes":  1024,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/scan-certificates", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), rpcTargetContextKey{}, rpcTarget{host: host, port: port}))
	rw := newBufferedResponseWriter()

	dispatchRPC(discoveryMux(), rw, req, "discovery")

	if rw.status != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rw.status, rw.body.String())
	}
	if !strings.Contains(logs.String(), "discovery: recovered from panic") || !strings.Contains(logs.String(), "boom from scan") {
		t.Fatalf("expected the panic to be logged, got %q", logs.String())
	}
}

type rpcErrorBody struct {
	Error struct {
		Message string `json:"message"`
		Kind    string `json:"kind"`
	} `json:"error"`
}

func serveCertificateScan(t *testing.T, host string, port int, timeoutMs int) (int, rpcErrorBody) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"authMethod":        "password",
		"username":          "scanner",
		"password":          "test",
		"timeoutMs":         timeoutMs,
		"searchFolderPaths": []string{"/etc/ssl"},
		"maxFolderDepth":    8,
		"maxFileSizeBytes":  1024,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/scan-certificates", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), rpcTargetContextKey{}, rpcTarget{host: host, port: port}))
	rec := httptest.NewRecorder()
	handleDiscoveryScanCertificates(rec, req)
	var decoded rpcErrorBody
	_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
	return rec.Code, decoded
}

func TestCertificateScanHandlerReportsDialTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	addr := listener.Addr().(*net.TCPAddr)

	code, body := serveCertificateScan(t, "127.0.0.1", addr.Port, 300)

	if code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", code)
	}
	if body.Error.Message != "failed to dial target SSH server: timed out after 300ms" || body.Error.Kind != string(failureKindTransport) {
		t.Fatalf("unexpected error %+v", body.Error)
	}
}

func TestCertificateScanHandlerReportsScanTimeout(t *testing.T) {
	var sessionClosed atomic.Bool
	host, port := startHangingSSHServer(t, &sessionClosed)
	previousScan := runCertificateScan
	t.Cleanup(func() { runCertificateScan = previousScan })
	runCertificateScan = func(ctx context.Context, _ certscan.Runner, _ certscan.Request) (certscan.Response, error) {
		<-ctx.Done()
		return certscan.Response{}, errors.New("ssh: session closed")
	}
	code, body := serveCertificateScan(t, host, port, 300)
	if code != http.StatusGatewayTimeout || body.Error.Message != "The certificate scan did not finish in time" {
		t.Fatalf("expected a timeout error, got %d %+v", code, body.Error)
	}
}
