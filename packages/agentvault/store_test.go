package agentvault

import (
	"os"
	"strings"
	"testing"
)

func TestLoadCaRefusesAKeyThatDoesNotMatchTheCertificate(t *testing.T) {
	st := newStore(t.TempDir())

	firstKey, firstCert, err := generateRootCa()
	if err != nil {
		t.Fatalf("generateRootCa: %v", err)
	}
	writeCa(t, st.dir, firstKey, firstCert)
	if _, _, err := st.loadCa(); err != nil {
		t.Fatalf("a matching pair must load: %v", err)
	}

	secondKey, _, err := generateRootCa()
	if err != nil {
		t.Fatalf("generateRootCa: %v", err)
	}
	writeCa(t, st.dir, secondKey, firstCert)

	_, _, err = st.loadCa()
	if err == nil {
		t.Fatal("a mismatched pair must be refused")
	}
	if !strings.Contains(err.Error(), "does not match") || !strings.Contains(err.Error(), st.dir) {
		t.Fatalf("the error must say what is wrong and where, got %v", err)
	}
}

func TestSaveStateRoundTripsWithoutTempFiles(t *testing.T) {
	dir := t.TempDir()
	st := newStore(dir)
	want := persistedState{
		ProxyID: "p1", ProxyName: "edge", AccessToken: "tok",
		Config: ProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, AllowedHosts: "a.example.com", PollInterval: 30},
	}
	if err := st.saveState(want); err != nil {
		t.Fatal(err)
	}
	if err := st.saveState(want); err != nil {
		t.Fatalf("second save over an existing file: %v", err)
	}
	got, _, err := st.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip changed the state:\n got %+v\nwant %+v", got, want)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != proxyStateFile {
		t.Fatalf("expected only %s in the data dir, found %v", proxyStateFile, entries)
	}
}

func TestSaveStateKeepsALineBreakInsideAValue(t *testing.T) {
	st := newStore(t.TempDir())
	in := persistedState{AccessToken: "tok", Config: ProxyConfig{
		TrafficPolicy: TrafficPolicyBundleHosts,
		AllowedHosts:  "x.example.com\ntrafficPolicy=any-host",
		PollInterval:  60,
	}}
	if err := st.saveState(in); err != nil {
		t.Fatal(err)
	}
	out, _, err := st.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if out.Config.TrafficPolicy != TrafficPolicyBundleHosts {
		t.Fatalf("a line break in one value rewrote another: policy came back %q", out.Config.TrafficPolicy)
	}
	if out.Config.AllowedHosts != in.Config.AllowedHosts {
		t.Fatalf("the value did not round-trip: %q", out.Config.AllowedHosts)
	}
}
