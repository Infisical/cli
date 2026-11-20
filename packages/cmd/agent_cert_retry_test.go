package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type retryTestServer struct {
	retrieveStatus int
	issueStatus    int
	renewStatus    int
	notAfter       time.Time
	renewedBy      string
	status         string
	certificatePEM string
	retrieveCalls  atomic.Int32
	issueCalls     atomic.Int32
	renewCalls     atomic.Int32
}

func (s *retryTestServer) start(t *testing.T) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		issued := api.CertificateData{
			Certificate:   s.certificatePEM,
			PrivateKey:    "key",
			SerialNumber:  "02",
			CertificateID: "cert-renewed",
		}
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/cert-manager/certificates/"):
			s.retrieveCalls.Add(1)
			if s.retrieveStatus != 0 {
				w.WriteHeader(s.retrieveStatus)
				return
			}
			var resp api.RetrieveCertificateResponse
			resp.Certificate.ID = strings.TrimPrefix(r.URL.Path, "/v1/cert-manager/certificates/")
			resp.Certificate.Status = "active"
			if s.status != "" {
				resp.Certificate.Status = s.status
			}
			resp.Certificate.NotAfter = s.notAfter
			resp.Certificate.RenewedByCertificateID = s.renewedBy
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/renew"):
			s.renewCalls.Add(1)
			if s.renewStatus != 0 {
				w.WriteHeader(s.renewStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(api.RenewCertificateResponse{
				Certificate:   issued.Certificate,
				PrivateKey:    issued.PrivateKey,
				SerialNumber:  issued.SerialNumber,
				CertificateID: issued.CertificateID,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/cert-manager/certificates":
			s.issueCalls.Add(1)
			if s.issueStatus != 0 {
				w.WriteHeader(s.issueStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(api.CertificateResponse{Certificate: &issued})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)
}

func newRetryTestManager(t *testing.T, lifecycle CertificateLifecycleConfig, state *CertificateState) (*AgentManager, *AgentCertificateConfig) {
	t.Helper()
	dir := t.TempDir()
	cfg := &AgentCertificateConfig{
		ProfileID: "profile-uuid-1",
		Lifecycle: lifecycle,
	}
	cfg.FileConfig.Certificate.Path = filepath.Join(dir, "cert.pem")
	cfg.FileConfig.PrivateKey.Path = filepath.Join(dir, "key.pem")
	tm := &AgentManager{
		accessToken:       "token",
		retryConfig:       &RetryConfig{MaxRetries: intPtr(2), BaseDelay: "1ms", MaxDelay: "5ms"},
		certificates:      []CertificateWithID{{ID: 1, Certificate: *cfg}},
		certificateStates: map[int]*CertificateState{1: state},
	}
	return tm, &tm.certificates[0].Certificate
}

func TestCertificateClient_AppliesRetryStrategy(t *testing.T) {
	cases := []struct {
		name      string
		server    retryTestServer
		call      func(*resty.Client) error
		calls     func(*retryTestServer) int32
		wantCalls int32
	}{
		{
			name:      "retrieve retries a 503",
			server:    retryTestServer{retrieveStatus: http.StatusServiceUnavailable},
			call:      func(c *resty.Client) error { _, err := api.CallRetrieveCertificate(c, "cert-1"); return err },
			calls:     func(s *retryTestServer) int32 { return s.retrieveCalls.Load() },
			wantCalls: 3,
		},
		{
			name:   "issue is not replayed after a 503",
			server: retryTestServer{issueStatus: http.StatusServiceUnavailable},
			call: func(c *resty.Client) error {
				_, err := api.CallIssueCertificate(c, api.IssueCertificateRequest{})
				return err
			},
			calls:     func(s *retryTestServer) int32 { return s.issueCalls.Load() },
			wantCalls: 1,
		},
		{
			name:   "issue retries a 429",
			server: retryTestServer{issueStatus: http.StatusTooManyRequests},
			call: func(c *resty.Client) error {
				_, err := api.CallIssueCertificate(c, api.IssueCertificateRequest{})
				return err
			},
			calls:     func(s *retryTestServer) int32 { return s.issueCalls.Load() },
			wantCalls: 3,
		},
	}
	for i := range cases {
		tc := &cases[i]
		t.Run(tc.name, func(t *testing.T) {
			tc.server.start(t)
			tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{}, &CertificateState{})

			httpClient, err := tm.createAuthenticatedClient()
			require.NoError(t, err)

			require.Error(t, tc.call(httpClient))
			assert.Equal(t, tc.wantCalls, tc.calls(&tc.server))
		})
	}
}

func TestCheckCertificateRenewals_RetriesFailedIssuanceAfterInterval(t *testing.T) {
	server := &retryTestServer{certificatePEM: newResumeTestCertificatePEM(t, 2, time.Now().Add(90*24*time.Hour))}
	server.start(t)
	state := &CertificateState{Status: "failed", RetryCount: 1, LastRetry: time.Now()}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{FailureRetryInterval: "1m", RenewBeforeExpiry: "30d"}, state)

	tm.CheckCertificateRenewals()
	assert.Equal(t, int32(0), server.issueCalls.Load(), "retried before failure-retry-interval")

	state.LastRetry = time.Now().Add(-2 * time.Minute)
	tm.CheckCertificateRenewals()

	assert.Equal(t, int32(1), server.issueCalls.Load())
	assert.Equal(t, "active", state.Status)
	assert.Equal(t, 0, state.RetryCount)
}

func TestCheckCertificateRenewals_RetriesFailedRenewal(t *testing.T) {
	server := &retryTestServer{certificatePEM: newResumeTestCertificatePEM(t, 2, time.Now().Add(90*24*time.Hour))}
	server.start(t)
	state := &CertificateState{Delivered: true, Status: "failed", CertificateID: "cert-1", ExpiresAt: time.Now().Add(time.Hour), RetryCount: 1, LastRetry: time.Now().Add(-2 * time.Minute)}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{FailureRetryInterval: "1m", RenewBeforeExpiry: "30d"}, state)

	tm.CheckCertificateRenewals()

	assert.Equal(t, int32(1), server.renewCalls.Load())
	assert.Equal(t, int32(0), server.issueCalls.Load())
	assert.Equal(t, "active", state.Status)
	assert.Equal(t, "cert-renewed", state.CertificateID)
}

func TestCheckCertificateRenewals_StopsRetryingWhenBudgetIsExhausted(t *testing.T) {
	server := &retryTestServer{renewStatus: http.StatusInternalServerError}
	server.start(t)
	state := &CertificateState{Delivered: true, Status: "failed", CertificateID: "cert-1", ExpiresAt: time.Now().Add(time.Hour), LastRetry: time.Now().Add(-2 * time.Minute)}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{FailureRetryInterval: "1m", MaxFailureRetries: 2}, state)

	tm.CheckCertificateRenewals()
	require.Equal(t, 1, state.RetryCount)
	state.LastRetry = time.Now().Add(-2 * time.Minute)
	tm.CheckCertificateRenewals()
	require.Equal(t, 2, state.RetryCount)

	state.LastRetry = time.Now().Add(-2 * time.Minute)
	tm.CheckCertificateRenewals()

	assert.Equal(t, int32(2), server.renewCalls.Load(), "retried inside the cooldown")
}

func TestHandleFailedCertificateRenewal_SchedulesRetryAfterInterval(t *testing.T) {
	state := &CertificateState{Status: "renewing", CertificateID: "cert-1"}
	tm, cfg := newRetryTestManager(t, CertificateLifecycleConfig{FailureRetryInterval: "1m"}, state)

	tm.handleFailedCertificateRenewal(1, cfg, "external CA renewal failed")

	assert.Equal(t, "failed", state.Status)
	assert.Equal(t, 1, state.RetryCount)
	assert.False(t, claimFailureRetry(state, cfg, time.Now(), "test"), "retry scheduled before failure-retry-interval")
	assert.True(t, claimFailureRetry(state, cfg, time.Now().Add(2*time.Minute), "test"))
}

func TestCheckCertificateRenewals_AdvancesNextCheckWhenNotRenewing(t *testing.T) {
	server := &retryTestServer{notAfter: time.Now().Add(60 * 24 * time.Hour)}
	server.start(t)
	state := &CertificateState{
		Status:           "active",
		CertificateID:    "cert-1",
		ExpiresAt:        time.Now().Add(time.Hour),
		NextRenewalCheck: time.Now().Add(-time.Second),
	}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{RenewBeforeExpiry: "30d", StatusCheckInterval: "6h"}, state)

	tm.CheckCertificateRenewals()
	tm.CheckCertificateRenewals()

	assert.Equal(t, int32(1), server.retrieveCalls.Load())
	assert.Equal(t, int32(0), server.renewCalls.Load())
	assert.WithinDuration(t, time.Now().Add(6*time.Hour), state.NextRenewalCheck, time.Minute)
}

func TestShouldRenewCertificate_NeverWhenRenewBeforeExpiryUnset(t *testing.T) {
	state := &CertificateState{Status: "active", CertificateID: "cert-1", ExpiresAt: time.Now().Add(-time.Hour)}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{}, state)

	assert.False(t, tm.ShouldRenewCertificate(1))
}

func TestIssueCertificate_TakesExpiryFromIssuedCertificateWhenTTLUnset(t *testing.T) {
	notAfter := time.Now().Add(45 * 24 * time.Hour).Truncate(time.Second)
	server := &retryTestServer{certificatePEM: newResumeTestCertificatePEM(t, 2, notAfter)}
	server.start(t)
	state := &CertificateState{Status: "pending"}
	tm, cfg := newRetryTestManager(t, CertificateLifecycleConfig{RenewBeforeExpiry: "7d", StatusCheckInterval: "6h"}, state)

	require.NoError(t, tm.IssueCertificate(1, cfg))

	assert.True(t, notAfter.Equal(state.ExpiresAt), "expiresAt %s, want %s", state.ExpiresAt, notAfter)
	assert.WithinDuration(t, time.Now().Add(6*time.Hour), state.NextRenewalCheck, time.Minute)
}

func TestCheckCertificateRenewals_RepeatedWriteFailuresStopAtRetryBudget(t *testing.T) {
	server := &retryTestServer{certificatePEM: newResumeTestCertificatePEM(t, 2, time.Now().Add(90*24*time.Hour))}
	server.start(t)
	state := &CertificateState{Status: "failed", RetryCount: 1, LastRetry: time.Now().Add(-2 * time.Minute)}
	tm, cfg := newRetryTestManager(t, CertificateLifecycleConfig{FailureRetryInterval: "1m", MaxFailureRetries: 3, RenewBeforeExpiry: "30d"}, state)
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	cfg.FileConfig.Certificate.Path = filepath.Join(blocker, "cert.pem")

	for range 10 {
		tm.CheckCertificateRenewals()
		state.LastRetry = time.Now().Add(-2 * time.Minute)
	}

	assert.Equal(t, int32(2), server.issueCalls.Load()+server.renewCalls.Load())
	assert.Equal(t, "failed", state.Status)
}

func TestCheckCertificateRenewals_ReissuesWhenFailedCertificateHasExpired(t *testing.T) {
	server := &retryTestServer{notAfter: time.Now().Add(-time.Hour), certificatePEM: newResumeTestCertificatePEM(t, 2, time.Now().Add(90*24*time.Hour))}
	server.start(t)
	state := &CertificateState{Status: "failed", CertificateID: "cert-1", ExpiresAt: time.Now().Add(-time.Hour), LastRetry: time.Now().Add(-2 * time.Minute)}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{FailureRetryInterval: "1m", RenewBeforeExpiry: "30d"}, state)

	tm.CheckCertificateRenewals()

	assert.Equal(t, int32(1), server.issueCalls.Load())
	assert.Equal(t, int32(0), server.renewCalls.Load())
	assert.Equal(t, "active", state.Status)
}

func TestCheckCertificateStatus_ReportsExpiredPastNotAfter(t *testing.T) {
	server := &retryTestServer{notAfter: time.Now().Add(-time.Minute)}
	server.start(t)
	state := &CertificateState{Status: "active", CertificateID: "cert-1"}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{}, state)

	require.NoError(t, tm.CheckCertificateStatus(1, "cert-1"))

	assert.Equal(t, "expired", state.Status)
}

func TestValidateCertificateLifecycleConfig_RejectsMalformedRenewBeforeExpiryWithoutTTL(t *testing.T) {
	certificates := []AgentCertificateConfig{{ProfileID: "profile-uuid-1", Lifecycle: CertificateLifecycleConfig{RenewBeforeExpiry: "two weeks"}}}

	assert.ErrorContains(t, validateCertificateLifecycleConfig(&certificates), "invalid renew-before-expiry")
}

func TestCheckCertificateRenewals_ReissuesActiveCertificateFoundPastNotAfter(t *testing.T) {
	server := &retryTestServer{notAfter: time.Now().Add(-time.Minute), certificatePEM: newResumeTestCertificatePEM(t, 2, time.Now().Add(90*24*time.Hour))}
	server.start(t)
	state := &CertificateState{Status: "active", CertificateID: "cert-1", ExpiresAt: time.Now().Add(time.Hour), NextRenewalCheck: time.Now().Add(-time.Second)}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{RenewBeforeExpiry: "30d"}, state)

	tm.CheckCertificateRenewals()

	assert.Equal(t, int32(1), server.issueCalls.Load())
	assert.Equal(t, "active", state.Status)
	assert.Equal(t, "cert-renewed", state.CertificateID)
}

func TestCheckCertificateRenewals_LeavesExpiredCertificateWhenRenewalIsOff(t *testing.T) {
	server := &retryTestServer{notAfter: time.Now().Add(-time.Minute)}
	server.start(t)
	state := &CertificateState{Status: "active", CertificateID: "cert-1", ExpiresAt: time.Now().Add(time.Hour), NextRenewalCheck: time.Now().Add(-time.Second)}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{}, state)

	tm.CheckCertificateRenewals()
	tm.CheckCertificateRenewals()

	assert.Equal(t, int32(0), server.issueCalls.Load()+server.renewCalls.Load())
	assert.Equal(t, int32(1), server.retrieveCalls.Load())
	assert.Equal(t, "expired", state.Status)
}

func TestCheckCertificateRenewals_ReissuesWhenCertificateWasAlreadyRenewed(t *testing.T) {
	server := &retryTestServer{renewedBy: "cert-elsewhere", notAfter: time.Now().Add(time.Hour), certificatePEM: newResumeTestCertificatePEM(t, 2, time.Now().Add(90*24*time.Hour))}
	server.start(t)
	state := &CertificateState{Status: "failed", CertificateID: "cert-1", ExpiresAt: time.Now().Add(time.Hour), RetryCount: 1, LastRetry: time.Now().Add(-2 * time.Minute)}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{FailureRetryInterval: "1m", RenewBeforeExpiry: "30d"}, state)

	tm.CheckCertificateRenewals()

	assert.Equal(t, int32(0), server.renewCalls.Load())
	assert.Equal(t, int32(1), server.issueCalls.Load())
	assert.Equal(t, "active", state.Status)
}

func TestCheckCertificateRenewals_DoesNotRenewWhenWindowCoversWholeLifetime(t *testing.T) {
	server := &retryTestServer{notAfter: time.Now().Add(time.Hour)}
	server.start(t)
	state := &CertificateState{Status: "active", CertificateID: "cert-1", IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), NextRenewalCheck: time.Now().Add(-time.Second)}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{RenewBeforeExpiry: "2h", StatusCheckInterval: "6h"}, state)

	tm.CheckCertificateRenewals()
	tm.CheckCertificateRenewals()

	assert.Equal(t, int32(0), server.renewCalls.Load()+server.issueCalls.Load())
	assert.Equal(t, int32(1), server.retrieveCalls.Load())
	assert.Equal(t, "active", state.Status)
}

func TestCheckCertificateRenewals_StopsWhenFailedCertificateWasRevoked(t *testing.T) {
	server := &retryTestServer{status: "revoked", notAfter: time.Now().Add(time.Hour)}
	server.start(t)
	state := &CertificateState{Status: "failed", CertificateID: "cert-1", ExpiresAt: time.Now().Add(time.Hour), RetryCount: 1, LastRetry: time.Now().Add(-2 * time.Minute)}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{FailureRetryInterval: "1m", RenewBeforeExpiry: "30d"}, state)

	tm.CheckCertificateRenewals()
	state.LastRetry = time.Now().Add(-2 * time.Minute)
	tm.CheckCertificateRenewals()

	assert.Equal(t, int32(0), server.renewCalls.Load()+server.issueCalls.Load())
	assert.Equal(t, int32(1), server.retrieveCalls.Load())
	assert.Equal(t, "revoked", state.Status)
}

func intPtr(v int) *int { return &v }

func TestCertificateClient_ExplicitZeroDisablesRetries(t *testing.T) {
	t.Run("config", func(t *testing.T) {
		server := &retryTestServer{retrieveStatus: http.StatusServiceUnavailable}
		server.start(t)
		tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{}, &CertificateState{})
		tm.retryConfig.MaxRetries = intPtr(0)

		httpClient, err := tm.createAuthenticatedClient()
		require.NoError(t, err)
		_, err = api.CallRetrieveCertificate(httpClient, "cert-1")

		require.Error(t, err)
		assert.Equal(t, int32(1), server.retrieveCalls.Load())
	})
	t.Run("environment", func(t *testing.T) {
		t.Setenv(util.INFISICAL_RETRY_MAX_RETRIES_NAME, "0")
		server := &retryTestServer{retrieveStatus: http.StatusServiceUnavailable}
		server.start(t)
		tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{}, &CertificateState{})

		httpClient, err := tm.createAuthenticatedClient()
		require.NoError(t, err)
		_, err = api.CallRetrieveCertificate(httpClient, "cert-1")

		require.Error(t, err)
		assert.Equal(t, int32(1), server.retrieveCalls.Load())
	})
}

func TestCheckCertificateRenewals_StopsWhenExpiredOrCSRCertificateWasRevoked(t *testing.T) {
	cases := map[string]func(*AgentCertificateConfig, *CertificateState){
		"expired locally": func(_ *AgentCertificateConfig, s *CertificateState) { s.ExpiresAt = time.Now().Add(-time.Hour) },
		"csr":             func(c *AgentCertificateConfig, _ *CertificateState) { c.CSR = "csr" },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			server := &retryTestServer{status: "revoked", notAfter: time.Now().Add(time.Hour)}
			server.start(t)
			state := &CertificateState{Status: "failed", CertificateID: "cert-1", ExpiresAt: time.Now().Add(time.Hour), RetryCount: 1, LastRetry: time.Now().Add(-2 * time.Minute)}
			tm, cfg := newRetryTestManager(t, CertificateLifecycleConfig{FailureRetryInterval: "1m", RenewBeforeExpiry: "30d"}, state)
			setup(cfg, state)

			tm.CheckCertificateRenewals()

			assert.Equal(t, int32(0), server.renewCalls.Load()+server.issueCalls.Load())
			assert.Equal(t, "revoked", state.Status)
		})
	}
}

func TestCheckCertificateRenewals_ReplacementRunsTheRenewalHook(t *testing.T) {
	server := &retryTestServer{notAfter: time.Now().Add(-time.Minute), certificatePEM: newResumeTestCertificatePEM(t, 2, time.Now().Add(90*24*time.Hour))}
	server.start(t)
	state := &CertificateState{Delivered: true, Status: "active", CertificateID: "cert-1", ExpiresAt: time.Now().Add(time.Hour), NextRenewalCheck: time.Now().Add(-time.Second)}
	tm, cfg := newRetryTestManager(t, CertificateLifecycleConfig{RenewBeforeExpiry: "30d"}, state)
	require.NoError(t, os.WriteFile(cfg.FileConfig.Certificate.Path, []byte("old"), 0o600))
	dir := t.TempDir()
	cfg.PostHooks.OnRenewal.Command = "touch " + filepath.Join(dir, "renewal")
	cfg.PostHooks.OnIssuance.Command = "touch " + filepath.Join(dir, "issuance")

	tm.CheckCertificateRenewals()

	require.Equal(t, int32(1), server.issueCalls.Load())
	require.Eventually(t, func() bool { _, err := os.Stat(filepath.Join(dir, "renewal")); return err == nil }, 5*time.Second, 50*time.Millisecond)
	_, err := os.Stat(filepath.Join(dir, "issuance"))
	assert.True(t, os.IsNotExist(err), "a replacement must not run the issuance hook")
}

func TestIssuedCertificateValidity_StartsAtTheLaterOfNotBeforeAndTheRequest(t *testing.T) {
	tm, cfg := newRetryTestManager(t, CertificateLifecycleConfig{}, &CertificateState{})
	notAfter := time.Now().Add(2 * time.Hour).Truncate(time.Second)

	backdatedNotBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	requestedAt := time.Now().Add(-time.Minute)
	issuedAt, expiresAt := tm.issuedCertificateValidity(cfg, newTestCertificatePEM(t, 2, backdatedNotBefore, notAfter), requestedAt)
	assert.True(t, issuedAt.Equal(requestedAt), "a backdated NotBefore must not lengthen the lifetime")
	assert.True(t, expiresAt.Equal(notAfter))

	notBefore := time.Now().Add(-40 * time.Minute).Truncate(time.Second)
	issuedAt, _ = tm.issuedCertificateValidity(cfg, newTestCertificatePEM(t, 3, notBefore, notAfter), time.Now().Add(-45*time.Minute))
	assert.True(t, issuedAt.Equal(notBefore), "a late pickup starts the lifetime when the CA issued the certificate")
}

func TestCheckCertificateRenewals_UndeliveredCertificateIsReissuedWithTheIssuanceHook(t *testing.T) {
	server := &retryTestServer{notAfter: time.Now().Add(time.Hour), certificatePEM: newResumeTestCertificatePEM(t, 2, time.Now().Add(90*24*time.Hour))}
	server.start(t)
	state := &CertificateState{Status: "failed", CertificateID: "cert-1", ExpiresAt: time.Now().Add(time.Hour), RetryCount: 1, LastRetry: time.Now().Add(-2 * time.Minute)}
	tm, cfg := newRetryTestManager(t, CertificateLifecycleConfig{FailureRetryInterval: "1m", RenewBeforeExpiry: "30d"}, state)
	dir := t.TempDir()
	cfg.PostHooks.OnIssuance.Command = "touch " + filepath.Join(dir, "issuance")
	cfg.PostHooks.OnRenewal.Command = "touch " + filepath.Join(dir, "renewal")

	tm.CheckCertificateRenewals()

	assert.Equal(t, int32(1), server.issueCalls.Load())
	assert.Equal(t, int32(0), server.renewCalls.Load())
	require.Eventually(t, func() bool { _, err := os.Stat(filepath.Join(dir, "issuance")); return err == nil }, 5*time.Second, 50*time.Millisecond)
	_, err := os.Stat(filepath.Join(dir, "renewal"))
	assert.True(t, os.IsNotExist(err), "a first delivery must not run the renewal hook")
}

func TestCheckCertificateRenewals_ReissuesWhenCertificateWasDeletedInInfisical(t *testing.T) {
	server := &retryTestServer{retrieveStatus: http.StatusNotFound, certificatePEM: newResumeTestCertificatePEM(t, 2, time.Now().Add(90*24*time.Hour))}
	server.start(t)
	state := &CertificateState{Status: "failed", CertificateID: "cert-1", Delivered: true, ExpiresAt: time.Now().Add(time.Hour), RetryCount: 1, LastRetry: time.Now().Add(-2 * time.Minute)}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{FailureRetryInterval: "1m", RenewBeforeExpiry: "30d"}, state)

	tm.CheckCertificateRenewals()

	assert.Equal(t, int32(1), server.issueCalls.Load())
	assert.Equal(t, int32(0), server.renewCalls.Load())
}

func TestShouldRenewCertificate_WarnsOncePerCertificateWhenWindowCoversLifetime(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&logs)
	t.Cleanup(func() { log.Logger = previous })
	state := &CertificateState{Status: "active", CertificateID: "cert-1", IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
	tm, _ := newRetryTestManager(t, CertificateLifecycleConfig{RenewBeforeExpiry: "2h"}, state)

	for range 3 {
		assert.False(t, tm.ShouldRenewCertificate(1))
	}
	state.CertificateID = "cert-2"
	assert.False(t, tm.ShouldRenewCertificate(1))

	assert.Equal(t, 2, strings.Count(logs.String(), "longer than the certificate's lifetime"))
}

func TestExecutePostHook_RunsOneCertificatesHooksInOrder(t *testing.T) {
	out := filepath.Join(t.TempDir(), "order")
	tm := &AgentManager{}
	cfg := &AgentCertificateConfig{}

	tm.ExecutePostHook("sleep 0.3; echo failure >> "+out, 10, "failure", 1, cfg)
	tm.ExecutePostHook("echo renewal >> "+out, 10, "renewal", 1, cfg)

	require.Eventually(t, func() bool {
		data, _ := os.ReadFile(out)
		return strings.Count(string(data), "\n") == 2
	}, 5*time.Second, 50*time.Millisecond)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "failure\nrenewal\n", string(data))
}
