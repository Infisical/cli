package agentproxy

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

const (
	localCACertFile = "local-ca.crt"
	localCAKeyFile  = "local-ca.key"
	// localCARenewMargin regenerates the persistent root before it actually expires.
	localCARenewMargin = 24 * time.Hour
)

// LocalCACertPath is the persistent root's public-cert path within a CA dir (what the OS trust store
// and the child's CA bundle reference).
func LocalCACertPath(dir string) string { return filepath.Join(dir, localCACertFile) }

// newPersistentLocalCaManager loads the local root from dir, or generates and writes one if it is
// missing, unparseable, or within localCARenewMargin of expiry (self-heal). The key stays on disk so
// the same root is reused across runs (and can be trusted once in the OS trust store). dir must be a
// path the sandbox denies, so the agent cannot read the key.
//
// A file lock serializes concurrent first-runs so two processes don't both generate/write.
func newPersistentLocalCaManager(dir string) (*caManager, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create local CA dir: %w", err)
	}
	unlock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	certPath := filepath.Join(dir, localCACertFile)
	keyPath := filepath.Join(dir, localCAKeyFile)

	if key, cert, ok := loadLocalRoot(certPath, keyPath); ok {
		return caManagerFromRoot(key, cert), nil
	}

	key, cert, err := generateLocalRoot()
	if err != nil {
		return nil, err
	}
	if err := writeLocalRoot(certPath, keyPath, key, cert); err != nil {
		return nil, err
	}
	return caManagerFromRoot(key, cert), nil
}

// loadLocalRoot reads and validates the root; ok is false if anything is missing, unparseable, not a
// CA, near expiry, or a key/cert pair that doesn't belong together (caller regenerates).
func loadLocalRoot(certPath, keyPath string) (*ecdsa.PrivateKey, *x509.Certificate, bool) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, false
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, false
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, false
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil || !cert.IsCA {
		return nil, nil, false
	}
	if time.Now().Add(localCARenewMargin).After(cert.NotAfter) {
		return nil, nil, false
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, false
	}
	// The cert and key are written as two separate files, so a crash between the writes can leave a new
	// cert beside the previous key. Both still parse and neither is expired, so without this check the
	// store would never self-heal and every leaf would be signed by a key the cert doesn't match.
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certPub.Equal(key.Public()) {
		return nil, nil, false
	}
	return key, cert, true
}

// writeLocalRoot writes the cert (public) and key (0600) atomically via temp-then-rename.
func writeLocalRoot(certPath, keyPath string, key *ecdsa.PrivateKey, cert *x509.Certificate) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := writeFileAtomic(certPath, certPEM, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(keyPath, keyPEM, 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// lockDir takes an exclusive lock on a lockfile in dir; the returned func releases it. Uses gofrs/flock
// so the file is portable (the CLI also builds for Windows) rather than a raw unix.Flock.
func lockDir(dir string) (func(), error) {
	fl := flock.New(filepath.Join(dir, ".ca.lock"))
	if err := fl.Lock(); err != nil {
		return nil, fmt.Errorf("failed to lock CA dir: %w", err)
	}
	return func() { _ = fl.Unlock() }, nil
}
