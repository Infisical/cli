package agentvault

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Infisical/infisical-merge/packages/util"
)

// Kept apart from the state proxies enrolled before proxy tokens saved, so removing that support never
// touches it.
const (
	tokenCacheDir      = "proxy-token-cache"
	tokenCacheSettings = "settings.json"
)

// The token itself is never written, only its hash, so a start with any other token can't use the cache.
type tokenCacheEntry struct {
	TokenHash string      `json:"tokenHash"`
	ProxyID   string      `json:"proxyId"`
	Name      string      `json:"name"`
	Config    ProxyConfig `json:"config"`
	OwnCa     bool        `json:"ownCa"`
}

type tokenCache struct {
	dir       string
	tokenHash string
	entry     tokenCacheEntry
}

func newTokenCache(dataDir, proxyToken string) *tokenCache {
	sum := sha256.Sum256([]byte(proxyToken))
	return &tokenCache{dir: filepath.Join(dataDir, tokenCacheDir), tokenHash: hex.EncodeToString(sum[:])}
}

func (c *tokenCache) path(name string) string { return filepath.Join(c.dir, name) }

// The operator's own key is never copied here: they pass it on every start anyway.
func (c *tokenCache) save(state persistedState, ca *caManager, ownCa bool) error {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(c.dir, 0o700); err != nil {
		return err
	}
	// Removed first so a save cut short leaves no settings beside a CA they weren't saved with.
	if err := removeIfExists(c.path(tokenCacheSettings)); err != nil {
		return err
	}

	if ownCa {
		for _, name := range []string{caKeyFile, caCertFile} {
			if err := removeIfExists(c.path(name)); err != nil {
				return err
			}
		}
	} else {
		der, err := x509.MarshalECPrivateKey(ca.rootKey)
		if err != nil {
			return err
		}
		if err := util.WriteFileAtomic(c.path(caKeyFile), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return err
		}
		if err := util.WriteFileAtomic(c.path(caCertFile), caPEM(ca.rootCert), 0o600); err != nil {
			return err
		}
	}

	c.entry = tokenCacheEntry{
		TokenHash: c.tokenHash,
		ProxyID:   state.ProxyID,
		Name:      state.ProxyName,
		Config:    state.Config,
		OwnCa:     ownCa,
	}
	return c.writeEntry()
}

func (c *tokenCache) writeEntry() error {
	data, err := json.MarshalIndent(c.entry, "", "  ")
	if err != nil {
		return err
	}
	return util.WriteFileAtomic(c.path(tokenCacheSettings), append(data, '\n'), 0o600)
}

// Keeps the cache in step with settings the heartbeat brings, so a later start during an outage doesn't
// come back with the policy from before the change.
func (c *tokenCache) saveState(state persistedState) error {
	c.entry.Config = state.Config
	return c.writeEntry()
}

func (c *tokenCache) load(proxyToken string, own *OwnCa) (persistedState, *caManager, error) {
	data, err := os.ReadFile(c.path(tokenCacheSettings))
	if err != nil {
		return persistedState{}, nil, err
	}
	var entry tokenCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return persistedState{}, nil, fmt.Errorf("%s is not valid JSON: %w", c.path(tokenCacheSettings), err)
	}
	if entry.TokenHash != c.tokenHash {
		return persistedState{}, nil, fmt.Errorf("the settings saved in %s belong to a different proxy token", c.dir)
	}
	if !usableProxyConfig(entry.Config) {
		return persistedState{}, nil, fmt.Errorf("the settings saved in %s are not usable", c.dir)
	}

	var ca *caManager
	switch {
	case own != nil:
		ca = newCaManager(own.key, own.cert)
	case entry.OwnCa:
		return persistedState{}, nil, fmt.Errorf(
			"the settings in %s were saved while serving your own certificate authority, which is not saved; pass --ca-cert and --ca-key", c.dir)
	default:
		keyPEM, err := os.ReadFile(c.path(caKeyFile))
		if err != nil {
			return persistedState{}, nil, err
		}
		certPEM, err := os.ReadFile(c.path(caCertFile))
		if err != nil {
			return persistedState{}, nil, err
		}
		key, cert, err := parseCaPair(certPEM, keyPEM)
		if err != nil {
			return persistedState{}, nil, fmt.Errorf("the certificate authority saved in %s can't be used: %w", c.dir, err)
		}
		ca = newCaManager(key, cert)
	}

	c.entry = entry
	return persistedState{
		ProxyID:     entry.ProxyID,
		ProxyName:   entry.Name,
		AccessToken: proxyToken,
		Config:      entry.Config,
	}, ca, nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
