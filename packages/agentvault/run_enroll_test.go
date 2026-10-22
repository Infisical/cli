package agentvault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
)

// The handler sees each decoded login request; what it writes back is the response.
func fakeLogin(t *testing.T, respond func(w http.ResponseWriter, req api.LoginAgentVaultProxyRequest)) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.LoginAgentVaultProxyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("login body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		respond(w, req)
	}))
	t.Cleanup(srv.Close)
	prev := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	t.Cleanup(func() { config.INFISICAL_URL = prev })
}

func loginResponse(rootCa *api.AgentVaultProxyRootCa) api.LoginAgentVaultProxyResponse {
	return api.LoginAgentVaultProxyResponse{
		ProxyID:     "p1",
		Name:        "edge",
		AccessToken: "tok",
		Config:      api.AgentVaultProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, PollInterval: 60},
		RootCa:      rootCa,
	}
}

func TestEnrollUsesAndSavesTheCaInfisicalReturns(t *testing.T) {
	certPEM, _, pkcs8 := caPairPEM(t)
	fakeLogin(t, func(w http.ResponseWriter, req api.LoginAgentVaultProxyRequest) {
		if req.RootCaCertificate != "" {
			t.Errorf("no CA was passed, yet the login sent one")
		}
		_ = json.NewEncoder(w).Encode(loginResponse(&api.AgentVaultProxyRootCa{Certificate: certPEM, PrivateKey: pkcs8}))
	})

	st := newStore(t.TempDir())
	_, ca, err := enroll(st, "avp_tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca.RootPEM()) != certPEM {
		t.Fatal("the proxy serves a CA other than the one Infisical returned")
	}
	_, saved, err := st.loadCa()
	if err != nil || saved == nil {
		t.Fatalf("the returned CA was not saved: %v", err)
	}
	if string(caPEM(saved)) != certPEM {
		t.Fatal("the saved CA is not the one Infisical returned")
	}
}

func TestEnrollWithItsOwnCaSendsAndServesIt(t *testing.T) {
	certPEM, keyPEM, _ := caPairPEM(t)
	own, err := LoadOwnCa(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	fakeLogin(t, func(w http.ResponseWriter, req api.LoginAgentVaultProxyRequest) {
		if req.RootCaCertificate != certPEM {
			t.Errorf("the login did not carry the operator's CA")
		}
		_ = json.NewEncoder(w).Encode(loginResponse(nil))
	})

	_, ca, err := enroll(newStore(t.TempDir()), "avp_tok", own)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca.RootPEM()) != certPEM {
		t.Fatal("the proxy does not serve the operator's CA")
	}
}

func TestEnrollAgainstAnOlderInfisicalSaysToUpgrade(t *testing.T) {
	for name, respond := range map[string]func(w http.ResponseWriter, req api.LoginAgentVaultProxyRequest){
		"rejects the missing certificate": func(w http.ResponseWriter, _ api.LoginAgentVaultProxyRequest) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"ValidationFailure","message":[{"path":["rootCaCertificate"],"message":"Required"}]}`))
		},
		"returns no CA": func(w http.ResponseWriter, _ api.LoginAgentVaultProxyRequest) {
			_ = json.NewEncoder(w).Encode(loginResponse(nil))
		},
	} {
		fakeLogin(t, respond)
		_, _, err := enroll(newStore(t.TempDir()), "avp_tok", nil)
		if err != errInfisicalHoldsNoCa {
			t.Fatalf("%s: expected the upgrade message, got %v", name, err)
		}
	}
}
