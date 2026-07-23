package agentproxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPersistentLocalCAReuseAndHeal(t *testing.T) {
	dir := t.TempDir()

	ca1, err := newPersistentLocalCaManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	pem1 := ca1.RootPEM()
	if len(pem1) == 0 {
		t.Fatal("expected a root cert")
	}

	// Files exist with the right perms; key is 0600.
	keyInfo, err := os.Stat(filepath.Join(dir, localCAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("key perms = %v, want 0600", keyInfo.Mode().Perm())
	}

	// Second call reuses the same root (stable across runs).
	ca2, err := newPersistentLocalCaManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca2.RootPEM()) != string(pem1) {
		t.Fatal("expected the persistent root to be reused, got a different cert")
	}

	// Corrupt the cert -> next call self-heals with a fresh root.
	if err := os.WriteFile(filepath.Join(dir, localCACertFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca3, err := newPersistentLocalCaManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca3.RootPEM()) == string(pem1) {
		t.Fatal("expected a regenerated root after corruption")
	}
	if len(ca3.RootPEM()) == 0 {
		t.Fatal("expected a valid regenerated root")
	}
}

func TestPersistentLocalCAMintsFromStoredRoot(t *testing.T) {
	dir := t.TempDir()
	ca, err := newPersistentLocalCaManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.mintLeaf("api.stripe.com"); err != nil {
		t.Fatalf("minting a leaf from the persistent root failed: %v", err)
	}
}
