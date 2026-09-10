package agentvault

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Infisical/infisical-merge/packages/util"
)

// The data directory persists because of the CA, not the enrollment: an agent that trusted this proxy's
// certificate must keep trusting it across restarts.
const (
	caKeyFile     = "ca.key"
	caCertFile    = "ca.crt"
	proxyConfFile = "proxy.conf"

	confAccessToken     = "INFISICAL_AGENT_VAULT_ACCESS_TOKEN"
	confEnrollmentToken = "INFISICAL_AGENT_VAULT_ENROLLMENT_TOKEN"
	confProxyID         = "INFISICAL_AGENT_VAULT_PROXY_ID"
	confProxyName       = "INFISICAL_AGENT_VAULT_PROXY_NAME"
	confUnmatchedHost   = "INFISICAL_AGENT_VAULT_UNMATCHED_HOST"
	confBypassHosts     = "INFISICAL_AGENT_VAULT_BYPASS_HOSTS"
	confPollInterval    = "INFISICAL_AGENT_VAULT_POLL_INTERVAL"

	probeBytes = 8 << 10
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

type persistedState struct {
	ProxyID         string
	ProxyName       string
	AccessToken     string
	EnrollmentToken string
	Config          ProxyConfig
}

type ProxyConfig struct {
	UnmatchedHost string
	BypassHosts   string
	PollInterval  int
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

// Enrollment spends a one-time token on the server, so the directory is proved writable first. MkdirAll
// passes on a read-only directory that already exists, and an empty file can be created on a full disk,
// so the probe writes about as many bytes as the CA and state files will.
func (s *store) probeWritable() error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	probe, err := os.CreateTemp(s.dir, ".probe-*")
	if err != nil {
		return fmt.Errorf("the data directory %q is not writable, so enrolling would spend the token with nowhere to store the result: %w", s.dir, err)
	}
	defer func() { _ = os.Remove(probe.Name()) }()
	if _, err := probe.Write(make([]byte, probeBytes)); err != nil {
		_ = probe.Close()
		return fmt.Errorf("the data directory %q cannot take new files, so enrolling would spend the token with nowhere to store the result: %w", s.dir, err)
	}
	return probe.Close()
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

	// A re-enrollment interrupted between the two files leaves a new key beside the old certificate, and
	// both parse, so the pair is checked here.
	certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certKey.Equal(&key.PublicKey) {
		return nil, nil, fmt.Errorf(
			"the certificate authority in %s does not match its private key, so an earlier re-enrollment was interrupted. Remove the directory and enroll again with a new token", s.dir)
	}
	return key, cert, nil
}

func (s *store) saveCa(key *ecdsa.PrivateKey, cert *x509.Certificate) error {
	if err := s.ensureDir(); err != nil {
		return err
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := util.WriteFileAtomic(s.path(caKeyFile), keyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", caKeyFile, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := util.WriteFileAtomic(s.path(caCertFile), certPEM, 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", caCertFile, err)
	}
	return nil
}

// found tells a missing file from an empty one, which is the difference between a first run and damage.
func (s *store) loadState() (state persistedState, found bool, err error) {
	data, err := os.ReadFile(s.path(proxyConfFile))
	if os.IsNotExist(err) {
		return state, false, nil
	}
	if err != nil {
		return state, false, fmt.Errorf("failed to read %s: %w", proxyConfFile, err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case confProxyID:
			state.ProxyID = value
		case confProxyName:
			state.ProxyName = value
		case confAccessToken:
			state.AccessToken = value
		case confEnrollmentToken:
			state.EnrollmentToken = value
		case confUnmatchedHost:
			state.Config.UnmatchedHost = value
		case confBypassHosts:
			state.Config.BypassHosts = value
		case confPollInterval:
			if parsed, convErr := strconv.Atoi(value); convErr == nil {
				state.Config.PollInterval = parsed
			}
		}
	}
	return state, true, nil
}

func (s *store) saveState(state persistedState) error {
	if err := s.ensureDir(); err != nil {
		return err
	}

	var b strings.Builder
	for _, pair := range [][2]string{
		{confProxyID, state.ProxyID},
		{confProxyName, state.ProxyName},
		{confAccessToken, state.AccessToken},
		{confEnrollmentToken, state.EnrollmentToken},
		{confUnmatchedHost, state.Config.UnmatchedHost},
		{confBypassHosts, state.Config.BypassHosts},
		{confPollInterval, strconv.Itoa(state.Config.PollInterval)},
	} {
		fmt.Fprintf(&b, "%s=%s\n", pair[0], pair[1])
	}

	if err := util.WriteFileAtomic(s.path(proxyConfFile), []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", proxyConfFile, err)
	}
	return nil
}
