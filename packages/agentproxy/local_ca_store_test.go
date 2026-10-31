package agentproxy

import (
	"crypto/x509"
	"encoding/pem"
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

// A crash between the cert write and the key write leaves a new cert beside the old key. Both parse
// and neither is expired, so only a pair check catches it.
func TestPersistentLocalCAHealsMismatchedPair(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	caA, err := newPersistentLocalCaManager(dirA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newPersistentLocalCaManager(dirB); err != nil {
		t.Fatal(err)
	}

	// Graft dirB's key next to dirA's cert: a valid-but-unrelated pair.
	otherKey, err := os.ReadFile(filepath.Join(dirB, localCAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirA, localCAKeyFile), otherKey, 0o600); err != nil {
		t.Fatal(err)
	}

	healed, err := newPersistentLocalCaManager(dirA)
	if err != nil {
		t.Fatal(err)
	}
	if string(healed.RootPEM()) == string(caA.RootPEM()) {
		t.Fatal("expected a regenerated root after a mismatched key/cert pair, got the stale cert")
	}

	// And the regenerated pair must actually work.
	leaf, err := healed.mintLeaf("api.stripe.com")
	if err != nil {
		t.Fatalf("minting from the healed root failed: %v", err)
	}
	block, _ := pem.Decode(healed.RootPEM())
	if block == nil {
		t.Fatal("healed root PEM did not decode")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.CheckSignatureFrom(root); err != nil {
		t.Fatalf("leaf does not chain to the healed root: %v", err)
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
