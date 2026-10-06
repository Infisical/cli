package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const resumeTestCertificateID = "cert-uuid-1"

type resumeTestServer struct {
	mu         sync.Mutex
	id         string
	status     string
	serial     string
	notAfter   time.Time
	renewCalls int
	issueCalls int
}

func (s *resumeTestServer) start(t *testing.T, renewed *api.RenewCertificateResponse) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/cert-manager/certificates/"):
			var resp api.RetrieveCertificateResponse
			resp.Certificate.ID = strings.TrimPrefix(r.URL.Path, "/v1/cert-manager/certificates/")
			if s.id != "" {
				resp.Certificate.ID = s.id
			}
			resp.Certificate.Status = s.status
			resp.Certificate.SerialNumber = s.serial
			resp.Certificate.CommonName = "example.com"
			resp.Certificate.NotBefore = time.Now().Add(-time.Hour)
			resp.Certificate.NotAfter = s.notAfter
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/cert-manager/certificates/"+resumeTestCertificateID+"/renew":
			s.renewCalls++
			if renewed == nil {
				http.Error(w, "renewal failed", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(renewed)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/cert-manager/certificates":
			s.issueCalls++
			http.Error(w, "unexpected issuance", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)
}

func newResumeTestCertificatePEM(t *testing.T, serial int64, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func newResumeTestConfig(dir string) *AgentCertificateConfig {
	cfg := &AgentCertificateConfig{
		ProfileID:     "profile-uuid-1",
		ApplicationID: "app-uuid-1",
		Attributes:    &CertificateAttributes{CommonName: "example.com", TTL: "90d"},
		Lifecycle:     CertificateLifecycleConfig{RenewBeforeExpiry: "30d"},
	}
	cfg.FileConfig.Certificate.Path = filepath.Join(dir, "cert.pem")
	cfg.FileConfig.PrivateKey.Path = filepath.Join(dir, "key.pem")
	return cfg
}

func newResumeTestManager(cfg *AgentCertificateConfig) *AgentManager {
	return &AgentManager{
		accessToken:       "token",
		certificates:      []CertificateWithID{{ID: 1, Certificate: *cfg}},
		certificateStates: map[int]*CertificateState{1: {Status: "pending"}},
	}
}

// deliverCertificate writes files the same way a successful issuance does.
func deliverCertificate(t *testing.T, cfg *AgentCertificateConfig, serial int64, notAfter time.Time) {
	t.Helper()
	tm := &AgentManager{}
	require.NoError(t, tm.WriteCertificateFiles(cfg, &api.CertificateResponse{
		Certificate: &api.CertificateData{
			Certificate:   newResumeTestCertificatePEM(t, serial, notAfter),
			PrivateKey:    "key",
			SerialNumber:  big.NewInt(serial).Text(16),
			CertificateID: resumeTestCertificateID,
		},
	}))
}

func TestWriteCertificateFiles_SavesStateForProfileCertificates(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	deliverCertificate(t, cfg, 0x1234, time.Now().Add(90*24*time.Hour))

	record, err := readCertificateStateFile(cfg)
	require.NoError(t, err)
	assert.Equal(t, resumeTestCertificateID, record.CertificateID)
	assert.Equal(t, "1234", record.SerialNumber)
	assert.Equal(t, configFingerprint(cfg), record.ConfigFingerprint)

	info, err := os.Stat(certificateStateFilePath(cfg))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	leftovers, err := filepath.Glob(certificateStateFilePath(cfg) + ".tmp-*")
	require.NoError(t, err)
	assert.Empty(t, leftovers)
}

func TestWriteCertificateFiles_NoStateForCertificateIDDistribution(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	cfg.CertificateID = resumeTestCertificateID
	deliverCertificate(t, cfg, 0x1234, time.Now().Add(90*24*time.Hour))

	_, err := os.Stat(certificateStateFilePath(cfg))
	assert.True(t, os.IsNotExist(err))
}

func TestResumeCertificateFromDisk_ResumesValidCertificateOutsideRenewalWindow(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	notAfter := time.Now().Add(80 * 24 * time.Hour).Truncate(time.Second)
	deliverCertificate(t, cfg, 0x1234, notAfter)

	server := &resumeTestServer{status: "active", serial: "1234", notAfter: notAfter}
	server.start(t, nil)

	tm := newResumeTestManager(cfg)
	assert.True(t, tm.resumeCertificateFromDisk(1, cfg))

	state := tm.certificateStates[1]
	assert.Equal(t, "active", state.Status)
	assert.Equal(t, resumeTestCertificateID, state.CertificateID)
	assert.True(t, state.ExpiresAt.Equal(notAfter))
	assert.True(t, state.NextRenewalCheck.Equal(notAfter.Add(-30*24*time.Hour)))
	assert.Zero(t, server.renewCalls)
	assert.Zero(t, server.issueCalls)
}

func TestResumeCertificateFromDisk_RenewsWhenWithinRenewalWindow(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	notAfter := time.Now().Add(10 * 24 * time.Hour)
	deliverCertificate(t, cfg, 0x1234, notAfter)

	newNotAfter := time.Now().Add(90 * 24 * time.Hour)
	server := &resumeTestServer{status: "active", serial: "1234", notAfter: notAfter}
	server.start(t, &api.RenewCertificateResponse{
		Certificate:   newResumeTestCertificatePEM(t, 0x5678, newNotAfter),
		PrivateKey:    "key",
		SerialNumber:  "5678",
		CertificateID: "cert-uuid-2",
	})

	tm := newResumeTestManager(cfg)
	assert.True(t, tm.resumeCertificateFromDisk(1, cfg))

	assert.Equal(t, 1, server.renewCalls)
	assert.Zero(t, server.issueCalls)
	assert.Equal(t, "cert-uuid-2", tm.certificateStates[1].CertificateID)

	record, err := readCertificateStateFile(cfg)
	require.NoError(t, err)
	assert.Equal(t, "cert-uuid-2", record.CertificateID)
	assert.True(t, serialMatchesCertificateOnDisk(cfg, record.SerialNumber))
}

func TestResumeCertificateFromDisk_IssuesWhenThereIsNoSavedState(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	tm := newResumeTestManager(cfg)
	assert.False(t, tm.resumeCertificateFromDisk(1, cfg))
}

func TestResumeCertificateFromDisk_IssuesWhenCertificateFileIsMissing(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	notAfter := time.Now().Add(80 * 24 * time.Hour)
	deliverCertificate(t, cfg, 0x1234, notAfter)
	require.NoError(t, os.Remove(cfg.FileConfig.Certificate.Path))

	server := &resumeTestServer{status: "active", serial: "1234", notAfter: notAfter}
	server.start(t, nil)

	tm := newResumeTestManager(cfg)
	assert.False(t, tm.resumeCertificateFromDisk(1, cfg))
}

func TestResumeCertificateFromDisk_IssuesWhenCertificateOnDiskWasReplaced(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	notAfter := time.Now().Add(80 * 24 * time.Hour)
	deliverCertificate(t, cfg, 0x1234, notAfter)
	require.NoError(t, os.WriteFile(cfg.FileConfig.Certificate.Path, []byte(newResumeTestCertificatePEM(t, 0x9999, notAfter)), 0600))

	server := &resumeTestServer{status: "active", serial: "1234", notAfter: notAfter}
	server.start(t, nil)

	tm := newResumeTestManager(cfg)
	assert.False(t, tm.resumeCertificateFromDisk(1, cfg))
}

func TestResumeCertificateFromDisk_IssuesWhenConfigurationChanged(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	notAfter := time.Now().Add(80 * 24 * time.Hour)
	deliverCertificate(t, cfg, 0x1234, notAfter)

	server := &resumeTestServer{status: "active", serial: "1234", notAfter: notAfter}
	server.start(t, nil)

	cfg.Attributes.CommonName = "other.example.com"
	tm := newResumeTestManager(cfg)
	assert.False(t, tm.resumeCertificateFromDisk(1, cfg))
}

func TestResumeCertificateFromDisk_IssuesWhenCertificateIsRevoked(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	notAfter := time.Now().Add(80 * 24 * time.Hour)
	deliverCertificate(t, cfg, 0x1234, notAfter)

	server := &resumeTestServer{status: "revoked", serial: "1234", notAfter: notAfter}
	server.start(t, nil)

	tm := newResumeTestManager(cfg)
	assert.False(t, tm.resumeCertificateFromDisk(1, cfg))
}

func TestResumeCertificateFromDisk_IssuesWhenCertificateHasExpired(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	notAfter := time.Now().Add(-time.Minute)
	deliverCertificate(t, cfg, 0x1234, notAfter)

	server := &resumeTestServer{status: "active", serial: "1234", notAfter: notAfter}
	server.start(t, nil)

	tm := newResumeTestManager(cfg)
	assert.False(t, tm.resumeCertificateFromDisk(1, cfg))
}

func TestResumeCertificateFromDisk_IssuesCSRCertificateWithinRenewalWindow(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	cfg.CSR = "-----BEGIN CERTIFICATE REQUEST-----"
	notAfter := time.Now().Add(10 * 24 * time.Hour)
	deliverCertificate(t, cfg, 0x1234, notAfter)

	server := &resumeTestServer{status: "active", serial: "1234", notAfter: notAfter}
	server.start(t, nil)

	tm := newResumeTestManager(cfg)
	assert.False(t, tm.resumeCertificateFromDisk(1, cfg))
	assert.Zero(t, server.renewCalls)
	assert.Equal(t, "pending", tm.certificateStates[1].Status)
}

func TestResumeCertificateFromDisk_IssuesWhenInfisicalReturnsADifferentCertificate(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	notAfter := time.Now().Add(80 * 24 * time.Hour)
	deliverCertificate(t, cfg, 0x1234, notAfter)

	server := &resumeTestServer{id: "cert-uuid-other", status: "active", serial: "1234", notAfter: notAfter}
	server.start(t, nil)

	tm := newResumeTestManager(cfg)
	assert.False(t, tm.resumeCertificateFromDisk(1, cfg))
}

func TestResumeCertificateFromDisk_ResumesWhenNoKeyOrChainWasIssued(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	cfg.FileConfig.Chain.Path = filepath.Join(filepath.Dir(cfg.FileConfig.Certificate.Path), "chain.pem")
	notAfter := time.Now().Add(80 * 24 * time.Hour)

	// ACME and CSR issuance return no private key, and the chain can be empty.
	tm := &AgentManager{}
	require.NoError(t, tm.WriteCertificateFiles(cfg, &api.CertificateResponse{
		Certificate: &api.CertificateData{
			Certificate:   newResumeTestCertificatePEM(t, 0x1234, notAfter),
			SerialNumber:  "1234",
			CertificateID: resumeTestCertificateID,
		},
	}))

	server := &resumeTestServer{status: "active", serial: "1234", notAfter: notAfter}
	server.start(t, nil)

	tm = newResumeTestManager(cfg)
	assert.True(t, tm.resumeCertificateFromDisk(1, cfg))
	assert.Zero(t, server.issueCalls)
}

func TestResumeCertificateFromDisk_IssuesWhenWrittenPrivateKeyIsMissing(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	notAfter := time.Now().Add(80 * 24 * time.Hour)
	deliverCertificate(t, cfg, 0x1234, notAfter)
	require.NoError(t, os.Remove(cfg.FileConfig.PrivateKey.Path))

	server := &resumeTestServer{status: "active", serial: "1234", notAfter: notAfter}
	server.start(t, nil)

	tm := newResumeTestManager(cfg)
	assert.False(t, tm.resumeCertificateFromDisk(1, cfg))
}

func TestResumeCertificateFromDisk_IssuesWhenRenewalAtStartupFails(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	notAfter := time.Now().Add(10 * 24 * time.Hour)
	deliverCertificate(t, cfg, 0x1234, notAfter)

	server := &resumeTestServer{status: "active", serial: "1234", notAfter: notAfter}
	server.start(t, nil)

	tm := newResumeTestManager(cfg)
	assert.False(t, tm.resumeCertificateFromDisk(1, cfg))
	assert.Equal(t, 1, server.renewCalls)
	assert.Equal(t, "pending", tm.certificateStates[1].Status)
}

func TestWriteCertificateFiles_FailedWriteDropsSavedState(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write to read-only files")
	}
	cfg := newResumeTestConfig(t.TempDir())
	deliverCertificate(t, cfg, 0x1234, time.Now().Add(80*24*time.Hour))

	// The new key lands but the certificate write fails, leaving the old cert next to a new key.
	require.NoError(t, os.Chmod(cfg.FileConfig.Certificate.Path, 0400))
	tm := &AgentManager{}
	err := tm.WriteCertificateFiles(cfg, &api.CertificateResponse{
		Certificate: &api.CertificateData{
			Certificate:   newResumeTestCertificatePEM(t, 0x5678, time.Now().Add(90*24*time.Hour)),
			PrivateKey:    "new-key",
			SerialNumber:  "5678",
			CertificateID: "cert-uuid-2",
		},
	})
	require.Error(t, err)

	_, err = os.Stat(certificateStateFilePath(cfg))
	assert.True(t, os.IsNotExist(err))
	assert.False(t, newResumeTestManager(cfg).resumeCertificateFromDisk(1, cfg))
}

func TestWriteCertificateFiles_RefusedWriteKeepsSavedState(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	deliverCertificate(t, cfg, 0x1234, time.Now().Add(80*24*time.Hour))

	// A keyless replacement is refused before any output is touched.
	tm := &AgentManager{}
	err := tm.writeCertificateFiles(cfg, &api.CertificateResponse{
		Certificate: &api.CertificateData{
			Certificate:   newResumeTestCertificatePEM(t, 0x5678, time.Now().Add(90*24*time.Hour)),
			SerialNumber:  "5678",
			CertificateID: "cert-uuid-2",
		},
	}, true)
	require.Error(t, err)

	record, err := readCertificateStateFile(cfg)
	require.NoError(t, err)
	assert.Equal(t, resumeTestCertificateID, record.CertificateID)
}

func TestResumeCertificateFromDisk_IssuesWhenOutputPathChanged(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	deliverCertificate(t, cfg, 0x1234, time.Now().Add(80*24*time.Hour))

	cfg.FileConfig.Chain.Path = filepath.Join(filepath.Dir(cfg.FileConfig.Certificate.Path), "chain.pem")
	assert.False(t, newResumeTestManager(cfg).resumeCertificateFromDisk(1, cfg))
}

func TestResumeCertificateFromDisk_ResumesWhenOnlyPermissionsChanged(t *testing.T) {
	cfg := newResumeTestConfig(t.TempDir())
	notAfter := time.Now().Add(80 * 24 * time.Hour)
	deliverCertificate(t, cfg, 0x1234, notAfter)

	server := &resumeTestServer{status: "active", serial: "1234", notAfter: notAfter}
	server.start(t, nil)

	cfg.FileConfig.PrivateKey.Permission = "0640"
	assert.True(t, newResumeTestManager(cfg).resumeCertificateFromDisk(1, cfg))
}

// Covers the full lifecycle after a restart: the resumed certificate is left alone until
// its renewal window, the monitoring loop then renews it as usual (post-hook included),
// and the next restart resumes the renewed certificate.
func TestResumedCertificateIsRenewedByTheMonitoringLoop(t *testing.T) {
	dir := t.TempDir()
	cfg := newResumeTestConfig(dir)
	hookMarker := filepath.Join(dir, "renewal-hook-ran")
	cfg.PostHooks.OnRenewal.Command = "touch " + hookMarker
	deliverCertificate(t, cfg, 0x1234, time.Now().Add(80*24*time.Hour))

	server := &resumeTestServer{status: "active", serial: "1234", notAfter: time.Now().Add(80 * 24 * time.Hour)}
	server.start(t, &api.RenewCertificateResponse{
		Certificate:   newResumeTestCertificatePEM(t, 0x5678, time.Now().Add(90*24*time.Hour)),
		PrivateKey:    "renewed-key",
		SerialNumber:  "5678",
		CertificateID: "cert-uuid-2",
	})

	tm := newResumeTestManager(cfg)
	require.True(t, tm.resumeCertificateFromDisk(1, cfg))

	tm.CheckCertificateRenewals()
	assert.Zero(t, server.renewCalls, "nothing is due outside the renewal window")

	// Time passes: the certificate is now 10 days from expiry and its check is due.
	server.mu.Lock()
	server.notAfter = time.Now().Add(10 * 24 * time.Hour)
	server.mu.Unlock()
	tm.certificateStates[1].NextRenewalCheck = time.Now().Add(-time.Minute)

	tm.CheckCertificateRenewals()
	assert.Equal(t, 1, server.renewCalls)
	state := tm.certificateStates[1]
	assert.Equal(t, "active", state.Status)
	assert.Equal(t, "cert-uuid-2", state.CertificateID)
	assert.True(t, state.NextRenewalCheck.After(time.Now()))
	assert.True(t, serialMatchesCertificateOnDisk(cfg, "5678"))
	require.Eventually(t, func() bool {
		_, err := os.Stat(hookMarker)
		return err == nil
	}, 5*time.Second, 50*time.Millisecond, "on-renewal post-hook should run")

	// Restart again: the agent resumes the renewed certificate without issuing.
	server.mu.Lock()
	server.serial = "5678"
	server.notAfter = time.Now().Add(90 * 24 * time.Hour)
	server.mu.Unlock()

	restarted := newResumeTestManager(cfg)
	require.True(t, restarted.resumeCertificateFromDisk(1, cfg))
	assert.Equal(t, "cert-uuid-2", restarted.certificateStates[1].CertificateID)
	assert.Equal(t, 1, server.renewCalls)
	assert.Zero(t, server.issueCalls)
}
