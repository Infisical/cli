package agentvault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConf(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, proxyConfFile), []byte(body), 0o600); err != nil {
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

const enrolledConf = "INFISICAL_AGENT_VAULT_PROXY_ID=p1\nINFISICAL_AGENT_VAULT_ACCESS_TOKEN=tok\nINFISICAL_AGENT_VAULT_UNMATCHED_HOST=deny\n"

func TestResolveStateAnEmptyDirectoryIsAFirstRun(t *testing.T) {
	_, _, err := resolveState(newStore(t.TempDir()), "")
	if err == nil || !strings.Contains(err.Error(), "has not enrolled yet") {
		t.Fatalf("expected the first-run message, got %v", err)
	}
}

func TestResolveStateAnIntactCaWithoutATokenIsNotAFirstRun(t *testing.T) {
	for name, conf := range map[string]*string{
		"no proxy.conf":      nil,
		"empty proxy.conf":   ptr(""),
		"token line missing": ptr("INFISICAL_AGENT_VAULT_PROXY_ID=p1\nINFISICAL_AGENT_VAULT_UNMATCHED_HOST=deny\n"),
	} {
		st := storeWithCa(t)
		if conf != nil {
			writeConf(t, st.dir, *conf)
		}
		_, _, err := resolveState(st, "")
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
	_, _, err := resolveState(st, "")
	if err == nil || !strings.Contains(err.Error(), caKeyFile) || strings.Contains(err.Error(), "has not enrolled yet") {
		t.Fatalf("expected a message naming the missing CA files, got %v", err)
	}
}

func TestResolveStateRefusesAnUnknownPolicyInsteadOfAllowing(t *testing.T) {
	for _, policy := range []string{"", "denny", "DENY", "true"} {
		st := storeWithCa(t)
		writeConf(t, st.dir, "INFISICAL_AGENT_VAULT_ACCESS_TOKEN=tok\nINFISICAL_AGENT_VAULT_UNMATCHED_HOST="+policy+"\n")
		_, _, err := resolveState(st, "")
		if err == nil {
			t.Fatalf("policy %q was accepted; the proxy would have come up allowing", policy)
		}
		if !strings.Contains(err.Error(), confUnmatchedHost) {
			t.Fatalf("policy %q: the message does not name the line: %v", policy, err)
		}
	}
}

func TestResolveStateResumesACompleteEnrollment(t *testing.T) {
	st := storeWithCa(t)
	writeConf(t, st.dir, enrolledConf)
	state, ca, err := resolveState(st, "")
	if err != nil {
		t.Fatal(err)
	}
	if state.AccessToken != "tok" || state.Config.UnmatchedHost != UnmatchedDeny || ca == nil {
		t.Fatalf("resumed state is wrong: %+v", state)
	}
}

func ptr(s string) *string { return &s }
