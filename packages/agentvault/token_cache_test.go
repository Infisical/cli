package agentvault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
)

// Bootstraps once against a healthy Infisical so the data dir holds a cache for the token "pxt".
func startedOnce(t *testing.T, own *OwnCa) (dataDir string, first startup) {
	t.Helper()
	certPEM, _, pkcs8 := caPairPEM(t)
	fakeBootstrap(t, func(w http.ResponseWriter, _ int32, _ api.AgentVaultProxyBootstrapRequest) {
		rootCa := &api.AgentVaultProxyRootCa{Certificate: certPEM, PrivateKey: pkcs8}
		if own != nil {
			rootCa = nil
		}
		_ = json.NewEncoder(w).Encode(bootstrapResponse(rootCa))
	})
	dataDir = t.TempDir()
	first, err := prepareStart(Options{DataDir: dataDir, OwnCa: own}, "pxt")
	if err != nil {
		t.Fatal(err)
	}
	if first.saver == nil {
		t.Fatal("a writable data dir was not used for the cache")
	}
	return dataDir, first
}

func infisicalAnswers(t *testing.T, status int) {
	t.Helper()
	fakeBootstrap(t, func(w http.ResponseWriter, _ int32, _ api.AgentVaultProxyBootstrapRequest) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"message":"no"}`))
	})
}

func TestTokenCacheIsWrittenPrivatelyWithoutTheToken(t *testing.T) {
	dataDir, _ := startedOnce(t, nil)
	dir := newTokenCache(dataDir, "pxt").dir

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir mode %o, want 700", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o, want 600", e.Name(), fi.Mode().Perm())
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), `"pxt"`) {
			t.Fatalf("%s holds the proxy token itself", e.Name())
		}
	}
	if len(names) != 3 || !names[tokenCacheSettings] || !names[caKeyFile] || !names[caCertFile] {
		t.Fatalf("unexpected cache contents: %v", names)
	}

	var entry tokenCacheEntry
	data, _ := os.ReadFile(filepath.Join(dir, tokenCacheSettings))
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("pxt"))
	if entry.TokenHash != hex.EncodeToString(sum[:]) || entry.ProxyID != "p1" || entry.Config.TrafficPolicy != TrafficPolicyBundleHosts {
		t.Fatalf("unexpected cache entry: %+v", entry)
	}
	if _, err := os.Stat(filepath.Join(dataDir, proxyStateFile)); !os.IsNotExist(err) {
		t.Fatalf("the cache wrote the saved-state file of proxies enrolled before proxy tokens: %v", err)
	}
}

func TestTokenCacheServesWhenInfisicalIsUnreachable(t *testing.T) {
	shortBootstrapRetries(t)
	dataDir, first := startedOnce(t, nil)
	infisicalAnswers(t, http.StatusBadGateway)

	s, err := prepareStart(Options{DataDir: dataDir}, "pxt")
	if err != nil {
		t.Fatalf("the cache was not used while Infisical was unreachable: %v", err)
	}
	if s.ca.Fingerprint() != first.ca.Fingerprint() {
		t.Fatal("the cache served a different certificate authority")
	}
	if s.state.ProxyID != "p1" || s.state.AccessToken != "pxt" || s.state.Config != first.state.Config {
		t.Fatalf("the cache served different settings: %+v", s.state)
	}
	if s.saver == nil || s.legacy {
		t.Fatalf("a start from the cache must keep it current and is not saved state: %+v", s)
	}
}

func TestTokenCacheIsNotUsedWhenInfisicalAnswers(t *testing.T) {
	shortBootstrapRetries(t)
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusBadRequest} {
		dataDir, _ := startedOnce(t, nil)
		infisicalAnswers(t, status)

		_, err := prepareStart(Options{DataDir: dataDir}, "pxt")
		if status == http.StatusUnauthorized {
			if !errors.Is(err, errProxyTokenRejected) {
				t.Fatalf("401: the cache was used or the token was not reported as rejected: %v", err)
			}
			continue
		}
		var apiErr *api.APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
			t.Fatalf("%d: the cache was used or the answer was lost: %v", status, err)
		}
	}
}

func TestARejectedProxyTokenRemovesItsCache(t *testing.T) {
	shortBootstrapRetries(t)
	dataDir, _ := startedOnce(t, nil)
	infisicalAnswers(t, http.StatusUnauthorized)

	if _, err := prepareStart(Options{DataDir: dataDir}, "pxt"); !errors.Is(err, errProxyTokenRejected) {
		t.Fatalf("expected the rejected-token message, got %v", err)
	}
	if _, err := os.Stat(newTokenCache(dataDir, "pxt").dir); !os.IsNotExist(err) {
		t.Fatalf("the cache of a rejected token was kept: %v", err)
	}
}

func TestAProxyTokenRejectedWhileRunningRemovesItsCache(t *testing.T) {
	dataDir, first := startedOnce(t, nil)
	ps, _ := newPollLoopFixture(t, http.StatusUnauthorized)
	stop := make(chan struct{})
	fatal := make(chan error, 1)
	done := runPollLoop(ps, first.saver, stop, fatal)

	select {
	case err := <-fatal:
		if err != errProxyTokenRejected {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("poll loop kept running after two 401 heartbeats")
	}
	<-done
	if _, err := os.Stat(newTokenCache(dataDir, "pxt").dir); !os.IsNotExist(err) {
		t.Fatalf("the cache of a rejected token was kept: %v", err)
	}
}

func TestARotatedTokensCacheIsRemovedOnTheNextStart(t *testing.T) {
	dataDir, first := startedOnce(t, nil)
	retired := newTokenCache(dataDir, "pxt-retired")
	if err := retired.save(persistedState{ProxyID: "p1", Config: first.state.Config}, first.ca, false); err != nil {
		t.Fatal(err)
	}
	otherProxy := newTokenCache(dataDir, "pxt-other-proxy")
	if err := otherProxy.save(persistedState{ProxyID: "p2", Config: first.state.Config}, first.ca, false); err != nil {
		t.Fatal(err)
	}
	unreadable := filepath.Join(dataDir, tokenCacheDir, "unreadable")
	if err := os.MkdirAll(unreadable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unreadable, tokenCacheSettings), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := prepareStart(Options{DataDir: dataDir}, "pxt"); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(retired.dir); !os.IsNotExist(err) {
		t.Fatalf("the retired token's cache, and the CA in it, was kept: %v", err)
	}
	for _, dir := range []string{newTokenCache(dataDir, "pxt").dir, otherProxy.dir, unreadable} {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("%s was removed: %v", dir, err)
		}
	}
}

func TestTokenCacheIsNotUsedForAnotherToken(t *testing.T) {
	shortBootstrapRetries(t)
	dataDir, _ := startedOnce(t, nil)
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	prev := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	t.Cleanup(func() { config.INFISICAL_URL = prev })

	_, err := prepareStart(Options{DataDir: dataDir}, "rotated")
	if !errors.Is(err, errBootstrapUnreachable) {
		t.Fatalf("expected the not-serving message, got %v", err)
	}
}

func TestTokenCacheWithItsOwnCaSavesNoKey(t *testing.T) {
	shortBootstrapRetries(t)
	certPEM, keyPEM, _ := caPairPEM(t)
	own, err := LoadOwnCa(OwnCaInput{Cert: certPEM, Key: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	dataDir, _ := startedOnce(t, own)
	for _, name := range []string{caKeyFile, caCertFile} {
		if _, err := os.Stat(filepath.Join(newTokenCache(dataDir, "pxt").dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s was saved for a proxy serving its own CA: %v", name, err)
		}
	}

	infisicalAnswers(t, http.StatusBadGateway)
	s, err := prepareStart(Options{DataDir: dataDir, OwnCa: own}, "pxt")
	if err != nil {
		t.Fatalf("the cache was not used with the operator's CA: %v", err)
	}
	if string(s.ca.RootPEM()) != certPEM {
		t.Fatal("the cache did not serve the operator's CA")
	}

	if _, err := prepareStart(Options{DataDir: dataDir}, "pxt"); !errors.Is(err, errBootstrapUnreachable) {
		t.Fatalf("a cache without a CA was served: %v", err)
	}
}

func TestTokenCacheFailureToWriteIsNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	certPEM, _, pkcs8 := caPairPEM(t)
	fakeBootstrap(t, func(w http.ResponseWriter, _ int32, _ api.AgentVaultProxyBootstrapRequest) {
		_ = json.NewEncoder(w).Encode(bootstrapResponse(&api.AgentVaultProxyRootCa{Certificate: certPEM, PrivateKey: pkcs8}))
	})
	dataDir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dataDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o700) })

	s, err := prepareStart(Options{DataDir: dataDir}, "pxt")
	if err != nil {
		t.Fatalf("an unwritable data dir stopped the proxy: %v", err)
	}
	if s.saver != nil {
		t.Fatal("a cache that could not be written was kept as the saver")
	}
}

func TestTokenCacheKeepsSettingsTheHeartbeatBrings(t *testing.T) {
	dataDir, first := startedOnce(t, nil)
	next := persistedState{Config: ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost, PollInterval: 15}}
	if err := first.saver.saveState(next); err != nil {
		t.Fatal(err)
	}

	reloaded := newTokenCache(dataDir, "pxt")
	state, _, err := reloaded.load("pxt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.Config != next.Config || state.ProxyID != "p1" {
		t.Fatalf("the heartbeat's settings were not saved: %+v", state)
	}
}

func TestTokenCacheKeepsEachTokenApart(t *testing.T) {
	dataDir := t.TempDir()
	a := newTokenCache(dataDir, "pxt-a")
	b := newTokenCache(dataDir, "pxt-b")
	if a.dir == b.dir {
		t.Fatalf("two tokens share the cache folder %s", a.dir)
	}
	if filepath.Dir(a.dir) != filepath.Join(dataDir, tokenCacheDir) {
		t.Fatalf("cache folder %s is not under %s", a.dir, filepath.Join(dataDir, tokenCacheDir))
	}
}
