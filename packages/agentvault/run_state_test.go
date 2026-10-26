package agentvault

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
)

func writeConf(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, proxyStateFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeCa(t *testing.T, dir string, key *ecdsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caCertFile), caPEM(cert), 0o600); err != nil {
		t.Fatal(err)
	}
}

func storeWithCa(t *testing.T) *store {
	t.Helper()
	st := newStore(t.TempDir())
	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	writeCa(t, st.dir, key, cert)
	return st
}

const enrolledConf = `{"proxyId":"p1","accessToken":"tok","config":{"trafficPolicy":"bundle-hosts"}}`

func TestStartWithoutATokenOrSavedStateAsksForAToken(t *testing.T) {
	t.Setenv("INFISICAL_AGENT_VAULT_ENROLLMENT_TOKEN", "")
	_, err := prepareStart(Options{DataDir: t.TempDir()}, "")
	if err == nil || err.Error() != "a proxy token is required: start the proxy with --proxy-token or INFISICAL_AGENT_VAULT_PROXY_TOKEN" {
		t.Fatalf("expected the proxy token message, got %v", err)
	}
}

// Remove after 2026-12-21, with proxyTokenRequired.
func TestAMissingTokenSaysTheEnrollmentTokenVariableIsNoLongerUsed(t *testing.T) {
	t.Setenv("INFISICAL_AGENT_VAULT_ENROLLMENT_TOKEN", "avp_old")
	_, err := prepareStart(Options{DataDir: t.TempDir()}, "")
	if !errors.Is(err, errProxyTokenRequired) || !strings.Contains(err.Error(), "INFISICAL_AGENT_VAULT_ENROLLMENT_TOKEN is no longer used") {
		t.Fatalf("expected the proxy token message with the enrollment variable hint, got %v", err)
	}
}

// Read-only support for proxies enrolled before enrollment tokens were removed. Remove after 2026-12-21.
func TestStartFromSavedStateNeverCallsInfisical(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		t.Errorf("starting from saved state called %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	prev := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	t.Cleanup(func() { config.INFISICAL_URL = prev })

	st := storeWithCa(t)
	writeConf(t, st.dir, enrolledConf)
	before, err := os.ReadFile(filepath.Join(st.dir, proxyStateFile))
	if err != nil {
		t.Fatal(err)
	}

	s, err := prepareStart(Options{DataDir: st.dir}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !s.legacy || s.state.AccessToken != "tok" || s.ca == nil {
		t.Fatalf("did not start from the saved state: %+v", s)
	}
	if requests.Load() != 0 {
		t.Fatalf("starting from saved state made %d requests", requests.Load())
	}
	after, err := os.ReadFile(filepath.Join(st.dir, proxyStateFile))
	if err != nil || string(after) != string(before) {
		t.Fatalf("starting from saved state rewrote %s: %v", proxyStateFile, err)
	}
	if _, err := os.Stat(filepath.Join(st.dir, tokenCacheDir)); !os.IsNotExist(err) {
		t.Fatalf("starting from saved state created the proxy token cache: %v", err)
	}
}

func TestLoadSavedStateAnIntactCaWithoutATokenIsNotAFirstRun(t *testing.T) {
	for name, conf := range map[string]*string{
		"no proxy.json":       nil,
		"empty object":        ptr(`{}`),
		"token field missing": ptr(`{"proxyId":"p1","config":{"trafficPolicy":"bundle-hosts"}}`),
	} {
		st := storeWithCa(t)
		if conf != nil {
			writeConf(t, st.dir, *conf)
		}
		_, _, err := loadSavedState(st, nil)
		if err == nil {
			t.Fatalf("%s: damaged state resolved", name)
		}
		if strings.Contains(err.Error(), "a proxy token is required") {
			t.Fatalf("%s: damaged state was reported as a first run: %v", name, err)
		}
		if !strings.Contains(err.Error(), "intact") || !strings.Contains(err.Error(), "Restore") {
			t.Fatalf("%s: the message does not point at the surviving CA and the restore: %v", name, err)
		}
	}
}

func TestLoadSavedStateATokenWithoutACaNamesTheMissingFiles(t *testing.T) {
	st := newStore(t.TempDir())
	writeConf(t, st.dir, enrolledConf)
	_, _, err := loadSavedState(st, nil)
	if err == nil || !strings.Contains(err.Error(), caKeyFile) || strings.Contains(err.Error(), "a proxy token is required") {
		t.Fatalf("expected a message naming the missing CA files, got %v", err)
	}
}

func TestLoadSavedStateRefusesAnUnknownPolicyInsteadOfAllowing(t *testing.T) {
	for _, policy := range []string{"", "bundle-host", "BUNDLE-HOSTS", "deny", "true"} {
		st := storeWithCa(t)
		writeConf(t, st.dir, `{"accessToken":"tok","config":{"trafficPolicy":"`+policy+`"}}`)
		_, _, err := loadSavedState(st, nil)
		if err == nil {
			t.Fatalf("policy %q was accepted; the proxy would have come up allowing", policy)
		}
		if !strings.Contains(err.Error(), "trafficPolicy") {
			t.Fatalf("policy %q: the message does not name the field: %v", policy, err)
		}
	}
}

func TestLoadSavedStateResumesACompleteEnrollment(t *testing.T) {
	st := storeWithCa(t)
	writeConf(t, st.dir, enrolledConf)
	state, ca, err := loadSavedState(st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.AccessToken != "tok" || state.Config.TrafficPolicy != TrafficPolicyBundleHosts || ca == nil {
		t.Fatalf("resumed state is wrong: %+v", state)
	}
}

func ptr(s string) *string { return &s }

func TestLoadSavedStateRefusesAFileThatIsNotJSON(t *testing.T) {
	for name, body := range map[string]string{"zero bytes": "", "old KEY=VALUE format": "INFISICAL_AGENT_VAULT_ACCESS_TOKEN=tok\n"} {
		st := storeWithCa(t)
		writeConf(t, st.dir, body)
		_, _, err := loadSavedState(st, nil)
		if err == nil || !strings.Contains(err.Error(), "not valid JSON") || strings.Contains(err.Error(), "a proxy token is required") {
			t.Fatalf("%s: expected a parse error naming the file, got %v", name, err)
		}
	}
}

// A file holding settings but no token, with no CA beside it, fell through every arm and started the proxy
// with a nil certificate authority.
func TestLoadSavedStateRefusesSettingsWithNoTokenAndNoCa(t *testing.T) {
	st := newStore(t.TempDir())
	writeConf(t, st.dir, `{"config":{"trafficPolicy":"bundle-hosts","pollInterval":60}}`)
	_, ca, err := loadSavedState(st, nil)
	if err == nil {
		t.Fatalf("settings-only state resolved; the proxy would start with fingerprint %q", ca.Fingerprint())
	}
	if !strings.Contains(err.Error(), "no access token") || !strings.Contains(err.Error(), "certificate authority") {
		t.Fatalf("the message should name both missing halves: %v", err)
	}
}
