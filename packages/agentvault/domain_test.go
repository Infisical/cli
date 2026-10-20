package agentvault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
)

const usCloudURL = "https://app.infisical.com/api"

func setDomainGlobals(t *testing.T, url string, explicit bool) {
	t.Helper()
	prevURL, prevExplicit := config.INFISICAL_URL, config.INFISICAL_DOMAIN_EXPLICITLY_SET
	config.INFISICAL_URL, config.INFISICAL_DOMAIN_EXPLICITLY_SET = url, explicit
	t.Cleanup(func() { config.INFISICAL_URL, config.INFISICAL_DOMAIN_EXPLICITLY_SET = prevURL, prevExplicit })
}

func TestEnrollRecordsTheInstanceItEnrolledWith(t *testing.T) {
	body, err := json.Marshal(api.LoginAgentVaultProxyResponse{
		ProxyID:     "p1",
		AccessToken: "tok",
		Config:      api.AgentVaultProxyConfig{TrafficPolicy: TrafficPolicyAnyHost, PollInterval: 60},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	setDomainGlobals(t, srv.URL+"/api", true)

	st := newStore(t.TempDir())
	if _, _, err := enroll(st, "avp_tok"); err != nil {
		t.Fatal(err)
	}
	back, _, err := st.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if back.Domain != srv.URL {
		t.Fatalf("enrolled against %s but recorded %q", srv.URL, back.Domain)
	}
}

// The restart that loses --domain: the stored instance has to win over the US Cloud default.
func TestPinDomainServesAgainstTheEnrolledInstanceWhenNoneIsRequested(t *testing.T) {
	setDomainGlobals(t, usCloudURL, false)

	if err := pinDomain(persistedState{Domain: "https://eu.infisical.com"}); err != nil {
		t.Fatal(err)
	}
	if config.INFISICAL_URL != "https://eu.infisical.com/api" {
		t.Fatalf("the proxy would talk to %s", config.INFISICAL_URL)
	}
}

func TestPinDomainRefusesAnExplicitRequestForAnotherInstance(t *testing.T) {
	setDomainGlobals(t, usCloudURL, true)

	err := pinDomain(persistedState{Domain: "https://eu.infisical.com"})
	if err == nil {
		t.Fatal("the token would have been sent to an instance that did not issue it")
	}
	if !strings.Contains(err.Error(), "https://eu.infisical.com") || !strings.Contains(err.Error(), "https://app.infisical.com") {
		t.Fatalf("the message does not name both instances: %v", err)
	}
	if config.INFISICAL_URL != usCloudURL {
		t.Fatalf("the requested domain was changed to %s", config.INFISICAL_URL)
	}
}

func TestPinDomainAcceptsAnExplicitRequestForTheSameInstance(t *testing.T) {
	setDomainGlobals(t, "https://eu.infisical.com/api", true)

	if err := pinDomain(persistedState{Domain: "https://eu.infisical.com"}); err != nil {
		t.Fatal(err)
	}
}

func TestPinDomainLeavesStateWithoutADomainToTheUsualResolution(t *testing.T) {
	setDomainGlobals(t, "https://self-hosted.example.com/api", false)

	if err := pinDomain(persistedState{}); err != nil {
		t.Fatal(err)
	}
	if config.INFISICAL_URL != "https://self-hosted.example.com/api" {
		t.Fatalf("the resolved domain was changed to %s", config.INFISICAL_URL)
	}
}

func tickAgainst(t *testing.T, handler http.HandlerFunc, loaded persistedState) *store {
	t.Helper()
	ps, st := newTickFixture(t, handler, loaded)
	ps.tick(st)
	return st
}

func newTickFixture(t *testing.T, handler http.HandlerFunc, loaded persistedState) (*proxyServer, *store) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	setDomainGlobals(t, srv.URL, false)

	st := newStore(t.TempDir())
	if err := st.saveState(loaded); err != nil {
		t.Fatal(err)
	}
	ps := &proxyServer{
		opts:             Options{ProxyToken: func() string { return "tok" }},
		config:           loaded.Config,
		persisted:        loaded,
		domainRecordable: true,
	}
	resolver, err := newInfisicalResolver(ps.opts.ProxyToken)
	if err != nil {
		t.Fatal(err)
	}
	ps.cache = newSessionCache(resolver, ps.pollInterval)
	return ps, st
}

func heartbeatWith(t *testing.T, settings ProxyConfig) http.HandlerFunc {
	t.Helper()
	body, err := json.Marshal(api.AgentVaultHeartbeatResponse{
		Config: api.AgentVaultProxyConfig{TrafficPolicy: settings.TrafficPolicy, PollInterval: settings.PollInterval},
	})
	if err != nil {
		t.Fatal(err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

// A run whose domain came from .infisical.yaml must not record it: the file may come from a repository, and
// recording it would keep sending the token there after the proxy is started from anywhere else.
func TestTickDoesNotRecordADomainThatIsNotRecordable(t *testing.T) {
	settings := ProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, PollInterval: 60}
	ps, st := newTickFixture(t, heartbeatWith(t, settings), persistedState{ProxyID: "p1", AccessToken: "tok", Config: settings})
	ps.domainRecordable = false
	ps.tick(st)

	back, _, _ := st.loadState()
	if back.Domain != "" {
		t.Fatalf("recorded %q from a run whose domain was not recordable", back.Domain)
	}
}

func TestTickRetriesRecordingTheDomainAfterAFailedWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through a read-only directory")
	}
	settings := ProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, PollInterval: 60}
	ps, st := newTickFixture(t, heartbeatWith(t, settings), persistedState{ProxyID: "p1", AccessToken: "tok", Config: settings})

	if err := os.Chmod(st.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(st.dir, 0o700) })
	ps.tick(st)
	if ps.persisted.Domain != "" {
		t.Fatalf("the domain was taken as recorded although the write failed: %q", ps.persisted.Domain)
	}

	if err := os.Chmod(st.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ps.tick(st)
	back, _, err := st.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if back.Domain == "" || back.Domain != ps.persisted.Domain {
		t.Fatalf("the next tick did not record the domain: file %q, memory %q", back.Domain, ps.persisted.Domain)
	}
}

func TestDomainIsRecordable(t *testing.T) {
	cases := []struct {
		name     string
		yaml     string
		explicit bool
		want     bool
	}{
		{"the default, with no workspace file", "", false, true},
		{"a domain from .infisical.yaml", "general:\n  domain: https://evil.example\n", false, false},
		{"--domain or INFISICAL_DOMAIN over .infisical.yaml", "general:\n  domain: https://evil.example\n", true, true},
		{"an unusable domain in .infisical.yaml, which root ignores", "general:\n  domain: evil.example\n", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			if tc.yaml != "" {
				if err := os.WriteFile(filepath.Join(dir, ".infisical.yaml"), []byte(tc.yaml), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			setDomainGlobals(t, usCloudURL, tc.explicit)
			if got := domainIsRecordable(); got != tc.want {
				t.Fatalf("domainIsRecordable() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Proxies enrolled before the domain was recorded learn it from the first heartbeat their token passes,
// even when the settings in it are unchanged.
func TestTickRecordsTheInstanceOfAnOlderEnrollment(t *testing.T) {
	settings := ProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, PollInterval: 60}
	body, err := json.Marshal(api.AgentVaultHeartbeatResponse{
		Config: api.AgentVaultProxyConfig{TrafficPolicy: settings.TrafficPolicy, PollInterval: settings.PollInterval},
	})
	if err != nil {
		t.Fatal(err)
	}
	var served string
	st := tickAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		served = "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}, persistedState{ProxyID: "p1", AccessToken: "tok", Config: settings})

	back, _, err := st.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if back.Domain == "" || back.Domain != served {
		t.Fatalf("recorded %q after a heartbeat from %s", back.Domain, served)
	}
	if back.AccessToken != "tok" || back.Config != settings {
		t.Fatalf("recording the domain changed the rest of the state: %+v", back)
	}
}

// A bare 200 can come from a captive portal, so it proves nothing about which instance issued the token.
func TestTickDoesNotRecordAnInstanceFromAHeartbeatWithoutSettings(t *testing.T) {
	st := tickAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, persistedState{ProxyID: "p1", AccessToken: "tok", Config: ProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, PollInterval: 60}})

	back, _, _ := st.loadState()
	if back.Domain != "" {
		t.Fatalf("recorded %q from a heartbeat that carried no settings", back.Domain)
	}
}

func TestTickDoesNotRecordAnInstanceThatRejectedTheToken(t *testing.T) {
	st := tickAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"statusCode":403,"error":"TokenError","message":"invalid signature"}`))
	}, persistedState{ProxyID: "p1", AccessToken: "tok", Config: ProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, PollInterval: 60}})

	back, _, _ := st.loadState()
	if back.Domain != "" {
		t.Fatalf("recorded %q from an instance that refused the token", back.Domain)
	}
}
