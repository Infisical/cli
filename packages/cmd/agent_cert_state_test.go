package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func agentTestCertificate(t *testing.T, serial int64, expires time.Time) *api.CertificateData {
	t.Helper()
	publicKey, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "restart.example.test"},
		DNSNames: []string{"restart.example.test"}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, publicKey, key)
	require.NoError(t, err)
	certificatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return &api.CertificateData{
		CertificateID: fmt.Sprintf("cert-%d", serial), SerialNumber: fmt.Sprintf("%x", serial),
		Certificate: certificatePEM, CertificateChain: certificatePEM,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
	}
}

func agentTestRootCertificate(t *testing.T) string {
	t.Helper()
	publicKey, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, publicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func agentTestConfig(t *testing.T) *AgentCertificateConfig {
	t.Helper()
	dir := t.TempDir()
	certificate := &AgentCertificateConfig{
		ApplicationID: "application", ProfileID: "profile",
		Attributes: &CertificateAttributes{CommonName: "restart.example.test", AltNames: []string{"restart.example.test"}, TTL: "90d"},
		Lifecycle:  CertificateLifecycleConfig{RenewBeforeExpiry: "15d", StatusCheckInterval: "6h"},
	}
	certificate.FileConfig.Certificate.Path = filepath.Join(dir, "certificate.pem")
	certificate.FileConfig.PrivateKey.Path = filepath.Join(dir, "key.pem")
	certificate.FileConfig.Chain.Path = filepath.Join(dir, "chain.pem")
	return certificate
}

func agentTestManager(certificate *AgentCertificateConfig) *AgentManager {
	return &AgentManager{
		accessToken: "mock-token", certificates: []CertificateWithID{{ID: 1, Certificate: *certificate}},
		certificateStates: map[int]*CertificateState{1: {Status: "pending"}},
	}
}

type agentTestAPI struct {
	missingChain                                                           atomic.Bool
	pollFailed                                                             atomic.Bool
	onIssue                                                                func()
	issueError                                                             atomic.Int32
	issueCalls, renewCalls, pollCalls, listCalls, bundleCalls, statusCalls atomic.Int32
	pending, pollIssued, revoked                                           atomic.Bool
	statusError                                                            atomic.Int32
	old, next                                                              *api.CertificateData
}

func newAgentTestAPI(t *testing.T, old, next *api.CertificateData) *agentTestAPI {
	t.Helper()
	backend := &agentTestAPI{old: old, next: next}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		const prefix = "/v1/cert-manager/"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == prefix+"certificates":
			backend.issueCalls.Add(1)
			if backend.onIssue != nil {
				backend.onIssue()
			}
			if status := backend.issueError.Load(); status != 0 {
				w.WriteHeader(int(status))
				return
			}
			if backend.pending.Load() {
				_ = json.NewEncoder(w).Encode(api.CertificateResponse{CertificateRequestID: "request-1"})
			} else {
				_ = json.NewEncoder(w).Encode(api.CertificateResponse{Certificate: backend.next})
			}
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/renew"):
			backend.renewCalls.Add(1)
			if backend.pending.Load() {
				_ = json.NewEncoder(w).Encode(api.RenewCertificateResponse{CertificateRequestID: "request-1"})
			} else {
				_ = json.NewEncoder(w).Encode(api.RenewCertificateResponse{
					CertificateID: backend.next.CertificateID, SerialNumber: backend.next.SerialNumber,
					Certificate: backend.next.Certificate, CertificateChain: backend.next.CertificateChain, PrivateKey: backend.next.PrivateKey,
				})
			}
		case r.URL.Path == prefix+"certificates/certificate-requests/request-1":
			backend.pollCalls.Add(1)
			response := api.GetCertificateRequestResponse{Status: "pending"}
			if backend.pollFailed.Load() {
				response.Status = "failed"
				message := "provider rejected request"
				response.ErrorMessage = &message
			}
			if backend.pollIssued.Load() {
				response.Status = "issued"
				response.CertificateID = &backend.next.CertificateID
				response.SerialNumber = &backend.next.SerialNumber
				response.Certificate = &backend.next.Certificate
				response.CertificateChain = &backend.next.CertificateChain
				response.PrivateKey = &backend.next.PrivateKey
			}
			_ = json.NewEncoder(w).Encode(response)
		case r.URL.Path == prefix+"certificate-profiles/profile/certificates":
			backend.listCalls.Add(1)
			if r.URL.Query().Get("search") != backend.old.SerialNumber || r.URL.Query().Get("offset") != "0" || r.URL.Query().Get("limit") != "100" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"certificates": []any{map[string]string{"id": backend.old.CertificateID, "serialNumber": backend.old.SerialNumber}}})
		case strings.HasSuffix(r.URL.Path, "/bundle"):
			backend.bundleCalls.Add(1)
			certificate := backend.old
			if strings.Contains(r.URL.Path, backend.next.CertificateID+"/") {
				certificate = backend.next
			}
			chain := certificate.CertificateChain
			if backend.missingChain.Load() {
				chain = ""
			}
			_ = json.NewEncoder(w).Encode(api.CertificateBundleResponse{
				Certificate: certificate.Certificate, PrivateKey: certificate.PrivateKey,
				SerialNumber: certificate.SerialNumber, CertificateChain: chain,
			})
		case strings.HasPrefix(r.URL.Path, prefix+"certificates/"):
			backend.statusCalls.Add(1)
			if status := backend.statusError.Load(); status != 0 {
				w.WriteHeader(int(status))
				return
			}
			certificate := backend.old
			if strings.HasSuffix(r.URL.Path, backend.next.CertificateID) {
				certificate = backend.next
			}
			leaf, err := parseAgentCertificate([]byte(certificate.Certificate))
			if err != nil {
				w.WriteHeader(500)
				return
			}
			var response api.RetrieveCertificateResponse
			response.Certificate.ID, response.Certificate.SerialNumber = certificate.CertificateID, certificate.SerialNumber
			response.Certificate.Status = "active"
			if time.Now().After(leaf.NotAfter) {
				response.Certificate.Status = "expired"
			}
			if backend.revoked.Load() {
				response.Certificate.Status = "revoked"
			}
			response.Certificate.NotBefore, response.Certificate.NotAfter = leaf.NotBefore, leaf.NotAfter
			_ = json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)
	return backend
}

func seedAgentCertificate(t *testing.T, certificate *AgentCertificateConfig, data *api.CertificateData, saveState bool) {
	t.Helper()
	manager := agentTestManager(certificate)
	require.NoError(t, manager.WriteCertificateFiles(certificate, &api.CertificateResponse{Certificate: data}))
	if saveState {
		leaf, err := parseAgentCertificate([]byte(data.Certificate))
		require.NoError(t, err)
		state := &CertificateState{CertificateID: data.CertificateID}
		setManagedCertificateState(state, leaf, certificate)
		require.NoError(t, persistCertificateState(certificate, state))
	}
}

func runAgentMonitor(t *testing.T, certificate *AgentCertificateConfig, complete func(*AgentManager) bool) *AgentManager {
	t.Helper()
	manager := agentTestManager(certificate)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); manager.MonitorCertificates(ctx) }()
	t.Cleanup(cancel)
	require.Eventually(t, func() bool {
		manager.mutex.Lock()
		defer manager.mutex.Unlock()
		return complete(manager)
	}, 5*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("certificate monitor did not stop and release its state lock")
	}
	return manager
}

func TestManagedCertificateRestartReusesExistingCertificate(t *testing.T) {
	for _, saved := range []bool{false, true} {
		t.Run(fmt.Sprintf("persisted=%v", saved), func(t *testing.T) {
			certificate := agentTestConfig(t)
			old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
			backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
			seedAgentCertificate(t, certificate, old, saved)
			modTime := time.Now().Add(-time.Hour).Truncate(time.Second)
			require.NoError(t, os.Chtimes(certificate.FileConfig.Certificate.Path, modTime, modTime))
			for i := 0; i < 3; i++ {
				manager := runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
				assert.Equal(t, old.CertificateID, manager.certificateStates[1].CertificateID)
				assert.WithinDuration(t, time.Now().Add(90*24*time.Hour), manager.certificateStates[1].ExpiresAt, 2*time.Second)
			}
			assert.Zero(t, backend.issueCalls.Load())
			assert.Zero(t, backend.renewCalls.Load())
			info, err := os.Stat(certificate.FileConfig.Certificate.Path)
			require.NoError(t, err)
			assert.Equal(t, modTime, info.ModTime())
			if saved {
				assert.Zero(t, backend.listCalls.Load())
			} else {
				assert.EqualValues(t, 1, backend.listCalls.Load())
			}
		})
	}
}

func TestManagedCertificateStartupRenewsUsingActualExpiry(t *testing.T) {
	certificate := agentTestConfig(t)
	old := agentTestCertificate(t, 1, time.Now().Add(10*24*time.Hour))
	next := agentTestCertificate(t, 2, time.Now().Add(70*24*time.Hour))
	backend := newAgentTestAPI(t, old, next)
	seedAgentCertificate(t, certificate, old, true)
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool {
		return manager.certificateStates[1].CertificateID == next.CertificateID && manager.certificateStates[1].Status == "active"
	})
	manager := runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
	assert.Zero(t, backend.issueCalls.Load())
	assert.EqualValues(t, 1, backend.renewCalls.Load())
	leaf, err := parseAgentCertificate([]byte(next.Certificate))
	require.NoError(t, err)
	assert.Equal(t, leaf.NotAfter, manager.certificateStates[1].ExpiresAt)
}

func TestManagedCertificateRepairsOutputsWithoutIssuance(t *testing.T) {
	for _, broken := range []string{"missing certificate", "invalid certificate", "missing key", "invalid key", "mismatched key", "missing chain", "invalid chain"} {
		t.Run(broken, func(t *testing.T) {
			certificate := agentTestConfig(t)
			old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
			other := agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour))
			backend := newAgentTestAPI(t, old, other)
			seedAgentCertificate(t, certificate, old, true)
			output := certificate.FileConfig.Certificate.Path
			if strings.Contains(broken, "key") {
				output = certificate.FileConfig.PrivateKey.Path
			}
			if strings.Contains(broken, "chain") {
				output = certificate.FileConfig.Chain.Path
			}
			if strings.HasPrefix(broken, "missing") {
				require.NoError(t, os.Remove(output))
			} else if broken == "mismatched key" {
				require.NoError(t, os.WriteFile(output, []byte(other.PrivateKey), 0600))
			} else {
				require.NoError(t, os.WriteFile(output, []byte("corrupt"), 0600))
			}
			runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
			assert.Zero(t, backend.issueCalls.Load())
			assert.Zero(t, backend.renewCalls.Load())
			assert.EqualValues(t, 1, backend.bundleCalls.Load())
			certPEM, err := os.ReadFile(certificate.FileConfig.Certificate.Path)
			require.NoError(t, err)
			keyPEM, err := os.ReadFile(certificate.FileConfig.PrivateKey.Path)
			require.NoError(t, err)
			assert.Equal(t, old.Certificate, string(certPEM))
			assert.Equal(t, old.PrivateKey, string(keyPEM))
		})
	}
}

func TestManagedCertificateIssuesWhenMissingInvalidOrExpired(t *testing.T) {
	for _, condition := range []string{"missing", "invalid", "expired"} {
		t.Run(condition, func(t *testing.T) {
			certificate := agentTestConfig(t)
			old := agentTestCertificate(t, 1, time.Now().Add(-time.Hour))
			next := agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour))
			backend := newAgentTestAPI(t, old, next)
			if condition == "expired" {
				seedAgentCertificate(t, certificate, old, true)
			}
			if condition == "invalid" {
				require.NoError(t, os.WriteFile(certificate.FileConfig.Certificate.Path, []byte("invalid"), 0600))
			}
			for i := 0; i < 3; i++ {
				runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
			}
			assert.EqualValues(t, 1, backend.issueCalls.Load())
			assert.Zero(t, backend.renewCalls.Load())
			data, err := os.ReadFile(certificateStatePath(certificate))
			require.NoError(t, err)
			assert.NotContains(t, string(data), "PRIVATE KEY")
			info, err := os.Stat(certificateStatePath(certificate))
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
		})
	}
}

func TestManagedCertificateResumesPendingRequestsOnRestart(t *testing.T) {
	for _, renewal := range []bool{false, true} {
		t.Run(fmt.Sprintf("renewal=%v", renewal), func(t *testing.T) {
			certificate := agentTestConfig(t)
			old := agentTestCertificate(t, 1, time.Now().Add(10*24*time.Hour))
			next := agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour))
			backend := newAgentTestAPI(t, old, next)
			backend.pending.Store(true)
			if renewal {
				seedAgentCertificate(t, certificate, old, true)
			}
			runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return backend.pollCalls.Load() > 0 })
			backend.pollIssued.Store(true)
			runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
			runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
			if renewal {
				assert.Zero(t, backend.issueCalls.Load())
				assert.EqualValues(t, 1, backend.renewCalls.Load())
			} else {
				assert.EqualValues(t, 1, backend.issueCalls.Load())
				assert.Zero(t, backend.renewCalls.Load())
			}
			data, err := os.ReadFile(certificateStatePath(certificate))
			require.NoError(t, err)
			var saved persistedCertificateState
			require.NoError(t, json.Unmarshal(data, &saved))
			assert.Empty(t, saved.State.CertificateRequestID)
			assert.Equal(t, next.CertificateID, saved.State.CertificateID)
		})
	}
}

func TestManagedCertificateDoesNotIssueOnAmbiguousStateOrStatusErrors(t *testing.T) {
	for _, condition := range []string{"corrupt state", "requesting_issuance", "requesting_renewal", "revoked", "403", "500"} {
		t.Run(condition, func(t *testing.T) {
			certificate := agentTestConfig(t)
			old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
			backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
			seedAgentCertificate(t, certificate, old, true)
			switch condition {
			case "corrupt state":
				require.NoError(t, os.WriteFile(certificateStatePath(certificate), []byte("{"), 0600))
			case "requesting_issuance", "requesting_renewal":
				require.NoError(t, persistCertificateState(certificate, &CertificateState{Status: condition}))
			case "revoked":
				backend.revoked.Store(true)
			case "403":
				backend.statusError.Store(403)
			case "500":
				backend.statusError.Store(500)
			}
			manager := runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "failed" })
			assert.NotEmpty(t, manager.certificateStates[1].LastError)
			assert.Zero(t, backend.issueCalls.Load())
			assert.Zero(t, backend.renewCalls.Load())
		})
	}
}

func TestManagedCertificateStateLockPreventsConcurrentAgents(t *testing.T) {
	certificate := agentTestConfig(t)
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	unlock, err := lockCertificateState(certificate)
	require.NoError(t, err)
	defer unlock()
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "blocked" })
	assert.Zero(t, backend.issueCalls.Load())
}

func TestManagedCertificateRenewsDuringPeriodicCheck(t *testing.T) {
	certificate := agentTestConfig(t)
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	seedAgentCertificate(t, certificate, old, true)
	manager := agentTestManager(certificate)
	require.NoError(t, manager.initializeManagedCertificate(1, certificate))
	manager.certificateStates[1].NextRenewalCheck = time.Now().Add(-time.Hour)
	manager.CheckCertificateRenewals()
	assert.Zero(t, backend.renewCalls.Load())
	manager.certificates[0].Certificate.Lifecycle.RenewBeforeExpiry = "91d"
	manager.certificateStates[1].NextRenewalCheck = time.Now().Add(-time.Hour)
	manager.CheckCertificateRenewals()
	assert.EqualValues(t, 1, backend.renewCalls.Load())
	assert.Zero(t, backend.issueCalls.Load())
}

func TestManagedCertificateDoesNotDuplicateRequestsAfterServerErrors(t *testing.T) {
	certificate := agentTestConfig(t)
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	backend.issueError.Store(500)
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "failed" })
	backend.issueError.Store(0)
	manager := runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "failed" })
	assert.EqualValues(t, 1, backend.issueCalls.Load())
	assert.Contains(t, manager.certificateStates[1].LastError, "unknown outcome")
}

func TestManagedCertificateRetriesDefinitivelyRejectedRequests(t *testing.T) {
	certificate := agentTestConfig(t)
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	backend.issueError.Store(403)
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "failed" })
	backend.issueError.Store(0)
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
	assert.EqualValues(t, 2, backend.issueCalls.Load())
}

func TestManagedCertificateRecoversInterruptedFileDelivery(t *testing.T) {
	certificate := agentTestConfig(t)
	hookOutput := filepath.Join(t.TempDir(), "hook-ran")
	certificate.PostHooks.OnIssuance.Command = fmt.Sprintf("touch %q", hookOutput)
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	next := agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, next)
	backend.onIssue = func() { _ = os.Mkdir(certificate.FileConfig.Chain.Path, 0700) }
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "failed" })
	require.NoError(t, os.Remove(certificate.FileConfig.Chain.Path))
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
	assert.EqualValues(t, 1, backend.issueCalls.Load())
	assert.EqualValues(t, 1, backend.bundleCalls.Load())
	chain, err := os.ReadFile(certificate.FileConfig.Chain.Path)
	require.NoError(t, err)
	assert.Equal(t, next.CertificateChain, string(chain))
	require.Eventually(t, func() bool { _, err := os.Stat(hookOutput); return err == nil }, 2*time.Second, 10*time.Millisecond)
}

func TestManagedCertificateConfigChangesIssueOnlyOnce(t *testing.T) {
	certificate := agentTestConfig(t)
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	seedAgentCertificate(t, certificate, old, true)
	certificate.ProfileID = "other-profile"
	for i := 0; i < 3; i++ {
		runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
	}
	assert.EqualValues(t, 1, backend.issueCalls.Load())
}

func TestManagedCertificateDoesNotDiscardPendingRequestOnConfigChange(t *testing.T) {
	certificate := agentTestConfig(t)
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	backend.pending.Store(true)
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return backend.pollCalls.Load() > 0 })
	certificate.ProfileID = "other-profile"
	manager := runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "failed" })
	assert.EqualValues(t, 1, backend.issueCalls.Load())
	assert.Contains(t, manager.certificateStates[1].LastError, "configuration changed")
}

func TestCertificateStatePathValidation(t *testing.T) {
	certificate := agentTestConfig(t)
	certificate.Lifecycle.StatePath = certificate.FileConfig.PrivateKey.Path
	_, err := lockCertificateState(certificate)
	require.ErrorContains(t, err, "overlaps")
	certificate.Lifecycle.StatePath = certificate.FileConfig.Certificate.Path + ".state"
	require.NoError(t, validateCertificateStatePaths([]AgentCertificateConfig{*certificate}))
	require.ErrorContains(t, validateCertificateStatePaths([]AgentCertificateConfig{*certificate, *certificate}), "overlaps")
	certificate.CertificateID = "pinned"
	require.ErrorContains(t, validateCertificateStatePaths([]AgentCertificateConfig{*certificate}), "profile-based")
}

func TestManagedCertificateStateCanBeStoredInConfiguredDirectory(t *testing.T) {
	certificate := agentTestConfig(t)
	certificate.Lifecycle.StatePath = filepath.Join(t.TempDir(), "state.json")
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	seedAgentCertificate(t, certificate, old, false)
	for i := 0; i < 3; i++ {
		runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
	}
	assert.Zero(t, backend.issueCalls.Load())
	_, err := os.Stat(certificate.Lifecycle.StatePath)
	require.NoError(t, err)
	_, err = os.Stat(certificate.FileConfig.Certificate.Path + ".infisical-state.json")
	require.True(t, os.IsNotExist(err))
}

func TestManagedCertificateDoesNotIssueWhenCertificateIsUnreadable(t *testing.T) {
	certificate := agentTestConfig(t)
	require.NoError(t, os.Mkdir(certificate.FileConfig.Certificate.Path, 0700))
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	manager := runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "failed" })
	assert.Zero(t, backend.issueCalls.Load())
	assert.Contains(t, manager.certificateStates[1].LastError, "cannot read existing certificate")
}

func TestManagedCertificateRetriesFailedAsyncRequestAfterRetryInterval(t *testing.T) {
	certificate := agentTestConfig(t)
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	backend.pending.Store(true)
	backend.pollFailed.Store(true)
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "failed" })
	backend.pending.Store(false)
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "failed" })
	assert.EqualValues(t, 1, backend.issueCalls.Load())
	data, err := os.ReadFile(certificateStatePath(certificate))
	require.NoError(t, err)
	var saved persistedCertificateState
	require.NoError(t, json.Unmarshal(data, &saved))
	saved.State.LastRetry = time.Now().Add(-48 * time.Hour)
	require.NoError(t, persistCertificateState(certificate, &saved.State))
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
	assert.EqualValues(t, 2, backend.issueCalls.Load())
}

func TestManagedCertificateDoesNotRequestWhenOutputsAreUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks require an unprivileged user")
	}
	certificate := agentTestConfig(t)
	dir := t.TempDir()
	certificate.FileConfig.Chain.Path = filepath.Join(dir, "chain.pem")
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	manager := runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "failed" })
	assert.Zero(t, backend.issueCalls.Load())
	assert.Contains(t, manager.certificateStates[1].LastError, "cannot write certificate output")
}

func TestManagedCertificateRepairsValidButWrongChain(t *testing.T) {
	certificate := agentTestConfig(t)
	hookOutput := filepath.Join(t.TempDir(), "issuance-hook")
	certificate.PostHooks.OnIssuance.Command = fmt.Sprintf("touch %q", hookOutput)
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	seedAgentCertificate(t, certificate, old, true)
	wrong := agentTestCertificate(t, 99, time.Now().Add(90*24*time.Hour))
	require.NoError(t, os.WriteFile(certificate.FileConfig.Chain.Path, []byte(wrong.Certificate), 0600))
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
	chain, err := os.ReadFile(certificate.FileConfig.Chain.Path)
	require.NoError(t, err)
	assert.Equal(t, old.CertificateChain, string(chain))
	assert.Zero(t, backend.issueCalls.Load())
	assert.Never(t, func() bool { _, err := os.Stat(hookOutput); return err == nil }, 200*time.Millisecond, 10*time.Millisecond)
}

func TestManagedCertificateDoesNotEraseChainWhenBundleIsEmpty(t *testing.T) {
	certificate := agentTestConfig(t)
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	seedAgentCertificate(t, certificate, old, true)
	backend.missingChain.Store(true)
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "failed" })
	chain, err := os.ReadFile(certificate.FileConfig.Chain.Path)
	require.NoError(t, err)
	assert.Equal(t, old.CertificateChain, string(chain))
	assert.Zero(t, backend.issueCalls.Load())
}

func TestCertificateStatePathRejectsSymlinkAliasToOutput(t *testing.T) {
	certificate := agentTestConfig(t)
	aliasRoot := t.TempDir()
	alias := filepath.Join(aliasRoot, "outputs")
	require.NoError(t, os.Symlink(filepath.Dir(certificate.FileConfig.PrivateKey.Path), alias))
	certificate.Lifecycle.StatePath = filepath.Join(alias, filepath.Base(certificate.FileConfig.PrivateKey.Path))
	require.ErrorContains(t, validateCertificateStatePaths([]AgentCertificateConfig{*certificate}), "overlaps")
}

func TestManagedCertificateRetriesContendedStateLock(t *testing.T) {
	certificate := agentTestConfig(t)
	certificate.Lifecycle.FailureRetryInterval = "10ms"
	certificate.Lifecycle.StatusCheckInterval = "10ms"
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	seedAgentCertificate(t, certificate, old, true)
	unlock, err := lockCertificateState(certificate)
	require.NoError(t, err)
	released := false
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool {
		if !released && manager.certificateStates[1].Status == "blocked" {
			unlock()
			released = true
			return false
		}
		return manager.certificateStates[1].Status == "active"
	})
	assert.True(t, released)
	assert.Zero(t, backend.issueCalls.Load())
}

func TestManagedCertificateAppliesChangedChainRootPolicy(t *testing.T) {
	certificate := agentTestConfig(t)
	includeRoot := false
	certificate.FileConfig.Chain.OmitRoot = &includeRoot
	old := agentTestCertificate(t, 1, time.Now().Add(90*24*time.Hour))
	old.CertificateChain = agentTestRootCertificate(t)
	backend := newAgentTestAPI(t, old, agentTestCertificate(t, 2, time.Now().Add(90*24*time.Hour)))
	seedAgentCertificate(t, certificate, old, true)
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
	omitRoot := true
	certificate.FileConfig.Chain.OmitRoot = &omitRoot
	runAgentMonitor(t, certificate, func(manager *AgentManager) bool { return manager.certificateStates[1].Status == "active" })
	chain, err := os.ReadFile(certificate.FileConfig.Chain.Path)
	require.NoError(t, err)
	assert.Empty(t, chain)
	assert.Zero(t, backend.issueCalls.Load())
}
