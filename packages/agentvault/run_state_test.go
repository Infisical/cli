package agentvault

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
)

func writeConf(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, proxyStateFile), []byte(body), 0o600); err != nil {
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
	if err := st.saveCa(key, cert); err != nil {
		t.Fatal(err)
	}
	return st
}

const enrolledConf = `{"proxyId":"p1","accessToken":"tok","config":{"trafficPolicy":"bundle-hosts"}}`

func TestResolveStateAnEmptyDirectoryIsAFirstRun(t *testing.T) {
	_, _, _, err := resolveState(newStore(t.TempDir()), "")
	if err == nil || !strings.Contains(err.Error(), "has not enrolled yet") {
		t.Fatalf("expected the first-run message, got %v", err)
	}
}

func TestResolveStateAnIntactCaWithoutATokenIsNotAFirstRun(t *testing.T) {
	for name, conf := range map[string]*string{
		"no proxy.json":       nil,
		"empty object":        ptr(`{}`),
		"token field missing": ptr(`{"proxyId":"p1","config":{"trafficPolicy":"bundle-hosts"}}`),
	} {
		st := storeWithCa(t)
		if conf != nil {
			writeConf(t, st.dir, *conf)
		}
		_, _, _, err := resolveState(st, "")
		if err == nil {
			t.Fatalf("%s: damaged state resolved", name)
		}
		if strings.Contains(err.Error(), "has not enrolled yet") {
			t.Fatalf("%s: damaged state was reported as a first run: %v", name, err)
		}
		if !strings.Contains(err.Error(), "intact") || !strings.Contains(err.Error(), "Restore") {
			t.Fatalf("%s: the message does not point at the surviving CA and the restore: %v", name, err)
		}
	}
}

func TestResolveStateATokenWithoutACaNamesTheMissingFiles(t *testing.T) {
	st := newStore(t.TempDir())
	writeConf(t, st.dir, enrolledConf)
	_, _, _, err := resolveState(st, "")
	if err == nil || !strings.Contains(err.Error(), caKeyFile) || strings.Contains(err.Error(), "has not enrolled yet") {
		t.Fatalf("expected a message naming the missing CA files, got %v", err)
	}
}

func TestResolveStateRefusesAnUnknownPolicyInsteadOfAllowing(t *testing.T) {
	for _, policy := range []string{"", "bundle-host", "BUNDLE-HOSTS", "deny", "true"} {
		st := storeWithCa(t)
		writeConf(t, st.dir, `{"accessToken":"tok","config":{"trafficPolicy":"`+policy+`"}}`)
		_, _, _, err := resolveState(st, "")
		if err == nil {
			t.Fatalf("policy %q was accepted; the proxy would have come up allowing", policy)
		}
		if !strings.Contains(err.Error(), "trafficPolicy") {
			t.Fatalf("policy %q: the message does not name the field: %v", policy, err)
		}
	}
}

// Re-running with the same enrollment token takes its own branch out of resolveState, which used to
// return the stored state without checking the policy in it. A state file written before the
// trafficPolicy rename decodes to "", and "" blocks nothing, so that path could bring a restricted
// proxy up reaching every host.
func TestResolveStateRefusesAnUnknownPolicyOnTheEnrollmentTokenResume(t *testing.T) {
	st := storeWithCa(t)
	writeConf(t, st.dir, `{"proxyId":"p1","accessToken":"tok","enrollmentToken":"avp_tok","config":{"unmatchedHost":"deny"}}`)
	_, _, _, err := resolveState(st, "avp_tok")
	if err == nil {
		t.Fatal("a pre-rename state file was accepted on the token resume path; the proxy would have come up allowing")
	}
	if !strings.Contains(err.Error(), "trafficPolicy") {
		t.Fatalf("the message does not name the field: %v", err)
	}
}

func TestResolveStateResumesACompleteEnrollment(t *testing.T) {
	st := storeWithCa(t)
	writeConf(t, st.dir, enrolledConf)
	state, ca, _, err := resolveState(st, "")
	if err != nil {
		t.Fatal(err)
	}
	if state.AccessToken != "tok" || state.Config.TrafficPolicy != TrafficPolicyBundleHosts || ca == nil {
		t.Fatalf("resumed state is wrong: %+v", state)
	}
}

func ptr(s string) *string { return &s }

func TestResolveStateRefusesAFileThatIsNotJSON(t *testing.T) {
	for name, body := range map[string]string{"zero bytes": "", "old KEY=VALUE format": "INFISICAL_AGENT_VAULT_ACCESS_TOKEN=tok\n"} {
		st := storeWithCa(t)
		writeConf(t, st.dir, body)
		_, _, _, err := resolveState(st, "")
		if err == nil || !strings.Contains(err.Error(), "not valid JSON") || strings.Contains(err.Error(), "has not enrolled yet") {
			t.Fatalf("%s: expected a parse error naming the file, got %v", name, err)
		}
	}
}

// The damaged-state messages tell the operator to enroll again with a new token, so a token has to reach
// the enroll path over the same damage. The stub refuses the login; what matters is which error comes back.
func TestResolveStateATokenTakesTheEnrollPathOverDamagedState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"no"}`))
	}))
	t.Cleanup(srv.Close)
	prev := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	t.Cleanup(func() { config.INFISICAL_URL = prev })

	for name, body := range map[string]string{"invalid JSON": "{not json", "zero bytes": ""} {
		st := storeWithCa(t)
		writeConf(t, st.dir, body)
		_, _, _, err := resolveState(st, "avp_a_new_token")
		if err == nil {
			t.Fatalf("%s: the stub refused the login, so enrolling should have failed", name)
		}
		if strings.Contains(err.Error(), "not valid JSON") {
			t.Fatalf("%s: the damaged file was reported before the token was tried: %v", name, err)
		}
	}
}

// A file holding settings but no token, with no CA beside it, fell through every arm and started the proxy
// with a nil certificate authority.
func TestResolveStateRefusesSettingsWithNoTokenAndNoCa(t *testing.T) {
	st := newStore(t.TempDir())
	writeConf(t, st.dir, `{"config":{"trafficPolicy":"bundle-hosts","pollInterval":60}}`)
	_, ca, _, err := resolveState(st, "")
	if err == nil {
		t.Fatalf("settings-only state resolved; the proxy would start with fingerprint %q", ca.Fingerprint())
	}
	if !strings.Contains(err.Error(), "no access token") || !strings.Contains(err.Error(), "certificate authority") {
		t.Fatalf("the message should name both missing halves: %v", err)
	}
}
