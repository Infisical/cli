package agentvault

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Infisical/infisical-merge/packages/util"
)

// What a proxy enrolled before proxy tokens saved in its data directory. It is only read now, apart from
// settings changes the heartbeat brings.
const (
	caKeyFile      = "ca.key"
	caCertFile     = "ca.crt"
	proxyStateFile = "proxy.json"
)

func DefaultDataDir() (string, error) {
	if os.Geteuid() == 0 {
		return "/etc/infisical/agent-vault", nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine the home directory: %w", err)
	}
	return filepath.Join(home, ".infisical", "agent-vault"), nil
}

// Same keys as the enroll response it was built from, so the file reads like the API did.
type persistedState struct {
	ProxyID     string      `json:"proxyId"`
	ProxyName   string      `json:"proxyName"`
	AccessToken string      `json:"accessToken"`
	Config      ProxyConfig `json:"config"`
}

type ProxyConfig struct {
	TrafficPolicy string `json:"trafficPolicy"`
	AllowedHosts  string `json:"allowedHosts"`
	PollInterval  int    `json:"pollInterval"`
}

type store struct {
	dir string
}

func newStore(dir string) *store { return &store{dir: dir} }

func (s *store) ensureDir() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("failed to create the data directory %q: %w", s.dir, err)
	}
	return nil
}

func (s *store) path(name string) string { return filepath.Join(s.dir, name) }

// Returns nil, nil when there is nothing stored yet, which is how a first run is told from a corrupt directory.
func (s *store) loadCa() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	keyPEM, err := os.ReadFile(s.path(caKeyFile))
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read %s: %w", caKeyFile, err)
	}

	certPEM, err := os.ReadFile(s.path(caCertFile))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read %s: %w", caCertFile, err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	certBlock, _ := pem.Decode(certPEM)
	if keyBlock == nil || certBlock == nil {
		return nil, nil, fmt.Errorf("the stored certificate authority in %s is not valid PEM", s.dir)
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse the stored certificate authority key: %w", err)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse the stored certificate authority: %w", err)
	}

	// A re-enrollment interrupted between the two files left a new key beside the old certificate, and
	// both parse, so the pair is checked here.
	if !keyMatchesCert(key, cert) {
		return nil, nil, fmt.Errorf(
			"the certificate authority in %s does not match its private key. Restore both files from a backup, or start the proxy with a proxy token from the Proxies page", s.dir)
	}
	return key, cert, nil
}

// found tells a missing file from an empty one, which is the difference between a first run and damage.
func (s *store) loadState() (state persistedState, found bool, err error) {
	data, err := os.ReadFile(s.path(proxyStateFile))
	if os.IsNotExist(err) {
		return state, false, nil
	}
	if err != nil {
		return state, false, fmt.Errorf("failed to read %s: %w", proxyStateFile, err)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedState{}, true, fmt.Errorf(
			"%s in %s is not valid JSON (%v). Restore it from a backup, or start the proxy with a proxy token from the Proxies page", proxyStateFile, s.dir, err)
	}
	return state, true, nil
}

func (s *store) saveState(state persistedState) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := util.WriteFileAtomic(s.path(proxyStateFile), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", proxyStateFile, err)
	}
	return nil
}
