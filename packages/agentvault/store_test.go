package agentvault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCaRefusesAKeyThatDoesNotMatchTheCertificate(t *testing.T) {
	st := newStore(t.TempDir())

	firstKey, firstCert, err := generateRootCa()
	if err != nil {
		t.Fatalf("generateRootCa: %v", err)
	}
	if err := st.saveCa(firstKey, firstCert); err != nil {
		t.Fatalf("saveCa: %v", err)
	}
	if _, _, err := st.loadCa(); err != nil {
		t.Fatalf("a matching pair must load: %v", err)
	}

	secondKey, _, err := generateRootCa()
	if err != nil {
		t.Fatalf("generateRootCa: %v", err)
	}
	if err := st.saveCa(secondKey, firstCert); err != nil {
		t.Fatalf("saveCa: %v", err)
	}

	_, _, err = st.loadCa()
	if err == nil {
		t.Fatal("a mismatched pair must be refused")
	}
	if !strings.Contains(err.Error(), "does not match") || !strings.Contains(err.Error(), st.dir) {
		t.Fatalf("the error must say what is wrong and where, got %v", err)
	}
}

func TestProbeWritableRefusesAReadOnlyDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := newStore(dir).probeWritable()
	if err == nil {
		t.Fatal("a read-only directory passed the probe, so the enrollment token would be spent for nothing")
	}
	if !strings.Contains(err.Error(), "spend the token") {
		t.Fatalf("the message does not say what is at stake: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("the probe left files behind: %v", entries)
	}
}

func TestProbeWritableLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	if err := newStore(dir).probeWritable(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("the probe left files behind: %v", entries)
	}
}

func TestSaveStateRoundTripsWithoutTempFiles(t *testing.T) {
	dir := t.TempDir()
	st := newStore(dir)
	want := persistedState{
		ProxyID: "p1", ProxyName: "edge", AccessToken: "tok", EnrollmentToken: "enroll",
		Config: ProxyConfig{UnmatchedHost: UnmatchedDeny, BypassHosts: "a.example.com", PollInterval: 30},
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
	if len(entries) != 1 || entries[0].Name() != proxyConfFile {
		t.Fatalf("expected only %s in the data dir, found %v", proxyConfFile, entries)
	}
}
