package gatewayv2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDispatchRPCRecoversAPanicBeforeAnyResponse(t *testing.T) {
	logs := captureLogs(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/exec", func(http.ResponseWriter, *http.Request) { panic("boom from exec") })
	rw := newBufferedResponseWriter()

	dispatchRPC(mux, rw, httptest.NewRequest(http.MethodPost, "/v1/exec", nil), "discovery")

	if rw.status != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rw.status)
	}
	var body rpcErrorBody
	if err := json.Unmarshal(rw.body.Bytes(), &body); err != nil || body.Error.Message != "The request failed unexpectedly" {
		t.Fatalf("unexpected body %q", rw.body.String())
	}
	if !strings.Contains(logs.String(), "discovery: recovered from panic") || !strings.Contains(logs.String(), "boom from exec") || !strings.Contains(logs.String(), `"path":"/v1/exec"`) {
		t.Fatalf("expected the panic to be logged, got %q", logs.String())
	}
}

func TestDispatchRPCKeepsAResponseWrittenBeforeAPanic(t *testing.T) {
	captureLogs(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sweep", func(w http.ResponseWriter, _ *http.Request) {
		writeRPCJSON(w, http.StatusOK, map[string][]string{"open": {}})
		panic("boom after write")
	})
	rw := newBufferedResponseWriter()

	dispatchRPC(mux, rw, httptest.NewRequest(http.MethodPost, "/v1/sweep", nil), "discovery")

	if rw.status != http.StatusOK || rw.body.String() != `{"open":[]}` {
		t.Fatalf("expected the written response to be kept, got %d %q", rw.status, rw.body.String())
	}
}
