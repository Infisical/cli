package gatewayv2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebAppConnectionTestUsesCertificateTargetAndWorkerProbe(t *testing.T) {
	for _, fail := range []bool{false, true} {
		request := httptest.NewRequest(http.MethodPost, "/v1/test-connection", strings.NewReader(`{"mode":"web-app-tcp","host":"forged.example","port":1}`))
		ctx := context.WithValue(request.Context(), rpcTargetContextKey{}, rpcTarget{host: "fixture.pam.local", port: 8081})
		called := false
		ctx = context.WithValue(ctx, webAppProbeContextKey{}, func(_ context.Context, host string, port int) error {
			called = true
			if host != "fixture.pam.local" || port != 8081 {
				t.Errorf("unbound target: %s:%d", host, port)
			}
			if fail {
				return errors.New("fixture.pam.local: no such host")
			}
			return nil
		})
		response := httptest.NewRecorder()
		handleTestConnection(response, request.WithContext(ctx))
		if !called {
			t.Fatal("worker probe was not called")
		}
		if !fail && response.Code != http.StatusOK {
			t.Fatalf("success response: %s", response.Body.String())
		}
		if fail && (response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "fixture.pam.local: no such host")) {
			t.Fatalf("failure text not preserved: %s", response.Body.String())
		}
	}
}
