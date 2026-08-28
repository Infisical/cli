package util

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPolicy(maxRetries int) RetryPolicy {
	return RetryPolicy{
		MaxRetries: maxRetries,
		BaseDelay:  time.Millisecond,
		MaxDelay:   5 * time.Millisecond,
	}
}

// Attempts are counted client-side so failures that never reach a server still count.
func newTestClient(t *testing.T, policy RetryPolicy) (*resty.Client, *atomic.Int32) {
	t.Helper()

	var attempts atomic.Int32
	client := applyRetryPolicy(resty.New(), policy)
	client.OnBeforeRequest(func(_ *resty.Client, _ *resty.Request) error {
		attempts.Add(1)
		return nil
	})

	return client, &attempts
}

func TestRetryStatusCodes(t *testing.T) {
	const maxRetries = 2

	tests := []struct {
		name         string
		status       int
		wantAttempts int32
	}{
		{"429 too many requests is retried", http.StatusTooManyRequests, maxRetries + 1},
		{"502 bad gateway is retried", http.StatusBadGateway, maxRetries + 1},
		{"503 service unavailable is retried", http.StatusServiceUnavailable, maxRetries + 1},
		{"504 gateway timeout is retried", http.StatusGatewayTimeout, maxRetries + 1},

		{"400 bad request is not retried", http.StatusBadRequest, 1},
		{"401 unauthorized is not retried", http.StatusUnauthorized, 1},
		{"403 forbidden is not retried", http.StatusForbidden, 1},
		{"404 not found is not retried", http.StatusNotFound, 1},
		{"422 unprocessable is not retried", http.StatusUnprocessableEntity, 1},
		{"500 internal server error is not retried", http.StatusInternalServerError, 1},
		{"200 ok is not retried", http.StatusOK, 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
			}))
			defer server.Close()

			client, attempts := newTestClient(t, testPolicy(maxRetries))
			res, err := client.R().Get(server.URL)

			require.NoError(t, err, "a status-code failure should surface as a response, not an error")
			assert.Equal(t, test.status, res.StatusCode())
			assert.Equal(t, test.wantAttempts, attempts.Load())
		})
	}
}

// A 5xx on POST may have been committed server-side, so only 429 is safe to repeat there.
func TestRetryMethodSafety(t *testing.T) {
	const maxRetries = 2

	tests := []struct {
		method       string
		status       int
		wantAttempts int32
	}{
		{http.MethodGet, http.StatusGatewayTimeout, maxRetries + 1},
		{http.MethodPut, http.StatusGatewayTimeout, maxRetries + 1},
		{http.MethodDelete, http.StatusGatewayTimeout, maxRetries + 1},
		{http.MethodPost, http.StatusGatewayTimeout, 1},
		{http.MethodPost, http.StatusBadGateway, 1},
		{http.MethodPost, http.StatusServiceUnavailable, 1},
		{http.MethodPost, http.StatusTooManyRequests, maxRetries + 1},
		{http.MethodPatch, http.StatusGatewayTimeout, 1},
		{http.MethodPatch, http.StatusTooManyRequests, maxRetries + 1},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s %d", test.method, test.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
			}))
			defer server.Close()

			client, attempts := newTestClient(t, testPolicy(maxRetries))
			_, err := client.R().Execute(test.method, server.URL)

			require.NoError(t, err)
			assert.Equal(t, test.wantAttempts, attempts.Load())
		})
	}
}

func TestRetrySucceedsAfterTransientFailure(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, attempts := newTestClient(t, testPolicy(3))
	res, err := client.R().Get(server.URL)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode())
	assert.Equal(t, `{"ok":true}`, res.String())
	assert.Equal(t, int32(3), attempts.Load(), "should stop retrying as soon as a request succeeds")
}

func TestRetryDisabledWhenMaxRetriesIsZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client, attempts := newTestClient(t, testPolicy(0))
	_, err := client.R().Get(server.URL)

	require.NoError(t, err)
	assert.Equal(t, int32(1), attempts.Load())
}

func TestRetryOnTransportError(t *testing.T) {
	client, attempts := newTestClient(t, testPolicy(2))
	_, err := client.R().Get(deadAddress(t))

	require.Error(t, err)
	assert.Equal(t, int32(3), attempts.Load())
}

func TestNoRetryOnTLSTrustFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, attempts := newTestClient(t, testPolicy(3))
	_, err := client.R().Get(server.URL)

	require.Error(t, err)
	assert.Equal(t, int32(1), attempts.Load())
}

func TestNoRetryOnContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client, attempts := newTestClient(t, testPolicy(3))
	_, err := client.R().SetContext(ctx).Get(server.URL)

	require.Error(t, err)
	assert.LessOrEqual(t, attempts.Load(), int32(1))
}

func TestRetryHonorsRetryAfterHeader(t *testing.T) {
	const retryAfterSeconds = 1

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", fmt.Sprint(retryAfterSeconds))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// MaxDelay must exceed the header value or the request would not be retried at all.
	policy := RetryPolicy{MaxRetries: 2, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Second}
	client, _ := newTestClient(t, policy)

	start := time.Now()
	res, err := client.R().Get(server.URL)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode())
	assert.GreaterOrEqual(t, elapsed, retryAfterSeconds*time.Second,
		"should wait as long as the server asked rather than using its own backoff")
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Duration
		ok    bool
	}{
		{"empty header", "", 0, false},
		{"seconds", "30", 30 * time.Second, true},
		{"seconds with surrounding space", "  5  ", 5 * time.Second, true},
		{"zero seconds falls back to default backoff", "0", 0, false},
		{"negative seconds falls back to default backoff", "-5", 0, false},
		{"unparseable value falls back to default backoff", "soon", 0, false},
		// Uncapped, this multiplies into a negative Duration that would bypass the fail-fast.
		{"overflowing seconds are capped", "9999999999", maxRetryAfter, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := parseRetryAfter(test.value)
			assert.Equal(t, test.ok, ok)
			assert.Equal(t, test.want, got)
		})
	}

	t.Run("future http date", func(t *testing.T) {
		got, ok := parseRetryAfter(time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat))
		require.True(t, ok)
		// The header has second granularity and time passes during the call, so allow slack.
		assert.InDelta(t, (30 * time.Second).Seconds(), got.Seconds(), 2)
	})

	t.Run("far future http date is capped", func(t *testing.T) {
		got, ok := parseRetryAfter(time.Now().Add(100000 * time.Hour).UTC().Format(http.TimeFormat))
		require.True(t, ok)
		assert.Equal(t, maxRetryAfter, got)
	})

	t.Run("past http date falls back to default backoff", func(t *testing.T) {
		_, ok := parseRetryAfter(time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat))
		assert.False(t, ok)
	})
}

func TestRetryDelayFallsBackWithoutHeader(t *testing.T) {
	assert.Zero(t, retryDelay(nil), "a nil response should defer to resty's own backoff")

	res := &resty.Response{RawResponse: &http.Response{Header: http.Header{}}}
	assert.Zero(t, retryDelay(res), "an absent header should defer to resty's own backoff")
}

func TestRetryAfterBeyondMaxDelayFailsFast(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client, attempts := newTestClient(t, testPolicy(3))

	start := time.Now()
	res, err := client.R().Get(server.URL)

	require.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, res.StatusCode())
	assert.Equal(t, int32(1), attempts.Load())
	assert.Less(t, time.Since(start), time.Second)
}

func TestIsRetryableTransportError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		// Bare errnos satisfy net.Error, which is what makes an explicit errno list unnecessary.
		{"connection reset", syscall.ECONNRESET, true},
		{"broken pipe", syscall.EPIPE, true},
		{"dns failure", &net.DNSError{Err: "no such host", Name: "app.infisical.com"}, true},
		{"wrapped connection reset", fmt.Errorf("posting secret: %w", syscall.ECONNRESET), true},
		{"url-wrapped transport failure", &url.Error{Op: "Post", URL: "http://x", Err: &net.OpError{Op: "read", Err: syscall.ECONNRESET}}, true},

		{"untrusted certificate authority", x509.UnknownAuthorityError{}, false},
		{"certificate hostname mismatch", x509.HostnameError{Host: "app.infisical.com"}, false},
		{"json marshal failure", errors.New("json: unsupported type"), false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isRetryableTransportError(test.err))
		})
	}
}

func TestRetryPolicyEnvOverrides(t *testing.T) {
	t.Run("defaults apply when unset", func(t *testing.T) {
		t.Setenv(INFISICAL_RETRY_BASE_DELAY_NAME, "")
		t.Setenv(INFISICAL_RETRY_MAX_DELAY_NAME, "")
		t.Setenv(INFISICAL_RETRY_MAX_RETRIES_NAME, "")

		policy := DefaultRetryPolicy()
		assert.Equal(t, defaultRetryMaxRetries, policy.MaxRetries)
		assert.Equal(t, defaultRetryBaseDelay, policy.BaseDelay)
		assert.Equal(t, defaultRetryMaxDelay, policy.MaxDelay)
	})

	t.Run("env overrides are applied", func(t *testing.T) {
		t.Setenv(INFISICAL_RETRY_BASE_DELAY_NAME, "250ms")
		t.Setenv(INFISICAL_RETRY_MAX_DELAY_NAME, "45s")
		t.Setenv(INFISICAL_RETRY_MAX_RETRIES_NAME, "7")

		policy := DefaultRetryPolicy()
		assert.Equal(t, 7, policy.MaxRetries)
		assert.Equal(t, 250*time.Millisecond, policy.BaseDelay)
		assert.Equal(t, 45*time.Second, policy.MaxDelay)
	})

	t.Run("env overrides also apply to the agent policy", func(t *testing.T) {
		t.Setenv(INFISICAL_RETRY_BASE_DELAY_NAME, "")
		t.Setenv(INFISICAL_RETRY_MAX_DELAY_NAME, "")
		t.Setenv(INFISICAL_RETRY_MAX_RETRIES_NAME, "2")

		policy := AgentRetryPolicy()
		assert.Equal(t, 2, policy.MaxRetries, "env should win over the agent's higher default")
		assert.Equal(t, agentRetryMaxDelay, policy.MaxDelay)
	})

	t.Run("malformed values are ignored", func(t *testing.T) {
		t.Setenv(INFISICAL_RETRY_BASE_DELAY_NAME, "soon")
		t.Setenv(INFISICAL_RETRY_MAX_DELAY_NAME, "")
		t.Setenv(INFISICAL_RETRY_MAX_RETRIES_NAME, "lots")

		policy := DefaultRetryPolicy()
		assert.Equal(t, defaultRetryMaxRetries, policy.MaxRetries)
		assert.Equal(t, defaultRetryBaseDelay, policy.BaseDelay)
	})

	t.Run("best-effort policy ignores env overrides", func(t *testing.T) {
		t.Setenv(INFISICAL_RETRY_MAX_RETRIES_NAME, "50")

		assert.Equal(t, 1, BestEffortRetryPolicy().MaxRetries)
	})

	t.Run("base delay is clamped to max delay", func(t *testing.T) {
		t.Setenv(INFISICAL_RETRY_BASE_DELAY_NAME, "30s")
		t.Setenv(INFISICAL_RETRY_MAX_DELAY_NAME, "5s")
		t.Setenv(INFISICAL_RETRY_MAX_RETRIES_NAME, "")

		policy := DefaultRetryPolicy()
		assert.Equal(t, 5*time.Second, policy.BaseDelay)
		assert.Equal(t, 5*time.Second, policy.MaxDelay)
	})
}

func TestClientsAreBuiltThroughTheSharedConstructor(t *testing.T) {
	t.Setenv(INFISICAL_RETRY_MAX_RETRIES_NAME, "")

	client, err := GetRestyClientWithCustomHeaders()
	require.NoError(t, err)
	assert.Equal(t, defaultRetryMaxRetries, client.RetryCount)

	agentClient, err := GetRestyClientWithPolicy(AgentRetryPolicy())
	require.NoError(t, err)
	assert.Equal(t, agentRetryMaxRetries, agentClient.RetryCount)
}

// A direct resty.New() compiles and works but silently has no retry policy; add new clients via
// GetRestyClientWithCustomHeaders or GetRestyClientWithPolicy instead.
func TestNoDirectRestyConstruction(t *testing.T) {
	allowed := map[string]bool{
		filepath.Join("packages", "util", "common.go"): true,
	}

	packagesDir := filepath.Join("..", "..", "packages")
	repoRoot := filepath.Join("..", "..")

	var offenders []string

	err := filepath.WalkDir(packagesDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		relative, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		if allowed[relative] {
			return nil
		}

		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		for i, line := range strings.Split(string(contents), "\n") {
			if strings.Contains(line, "resty.New(") {
				offenders = append(offenders, fmt.Sprintf("%s:%d", relative, i+1))
			}
		}

		return nil
	})
	require.NoError(t, err)

	assert.Empty(t, offenders,
		"these sites construct a resty client directly and so have no retry policy; "+
			"use util.GetRestyClientWithCustomHeaders or util.GetRestyClientWithPolicy instead")
}

// newAbruptCloseServer simulates the ambiguous mid-flight failure: request delivered, connection
// dropped before any response.
func newAbruptCloseServer(t *testing.T) (serverURL string, connections func() int32) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	var count atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Read(make([]byte, 4096))
			_ = conn.Close()
		}
	}()

	return "http://" + listener.Addr().String(), count.Load
}

// deadAddress binds then releases a port, so dialing it is refused before anything is sent.
func deadAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	return "http://" + addr
}

func TestTransportErrorMethodSafety(t *testing.T) {
	const maxRetries = 2

	t.Run("mid-flight failure does not replay POST", func(t *testing.T) {
		serverURL, _ := newAbruptCloseServer(t)

		client, attempts := newTestClient(t, testPolicy(maxRetries))
		_, err := client.R().SetBody(`{"lease":"request"}`).Post(serverURL)

		require.Error(t, err)
		assert.Equal(t, int32(1), attempts.Load())
	})

	t.Run("mid-flight failure does not replay PATCH", func(t *testing.T) {
		serverURL, _ := newAbruptCloseServer(t)

		client, attempts := newTestClient(t, testPolicy(maxRetries))
		_, err := client.R().SetBody(`{}`).Patch(serverURL)

		require.Error(t, err)
		assert.Equal(t, int32(1), attempts.Load())
	})

	t.Run("mid-flight failure replays GET", func(t *testing.T) {
		serverURL, _ := newAbruptCloseServer(t)

		client, attempts := newTestClient(t, testPolicy(maxRetries))
		_, err := client.R().Get(serverURL)

		require.Error(t, err)
		assert.Equal(t, int32(maxRetries+1), attempts.Load())
	})

	t.Run("connection refused replays POST", func(t *testing.T) {
		client, attempts := newTestClient(t, testPolicy(maxRetries))
		_, err := client.R().SetBody(`{}`).Post(deadAddress(t))

		require.Error(t, err)
		assert.Equal(t, int32(maxRetries+1), attempts.Load())
	})

	t.Run("unresolvable host replays POST", func(t *testing.T) {
		client, attempts := newTestClient(t, testPolicy(maxRetries))
		_, err := client.R().SetBody(`{}`).Post("http://this-host-does-not-exist.invalid")

		require.Error(t, err)
		assert.Equal(t, int32(maxRetries+1), attempts.Load())
	})
}

func TestReplaySafePolicy(t *testing.T) {
	const maxRetries = 2

	replaySafe := testPolicy(maxRetries)
	replaySafe.ReplaySafe = true

	t.Run("mid-flight failure replays POST", func(t *testing.T) {
		serverURL, _ := newAbruptCloseServer(t)

		client, attempts := newTestClient(t, replaySafe)
		_, err := client.R().SetBody(`{"accessToken":"x"}`).Post(serverURL)

		require.Error(t, err)
		assert.Equal(t, int32(maxRetries+1), attempts.Load())
	})

	t.Run("503 on POST is retried", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		client, attempts := newTestClient(t, replaySafe)
		_, err := client.R().SetBody(`{}`).Post(server.URL)

		require.NoError(t, err)
		assert.Equal(t, int32(maxRetries+1), attempts.Load())
	})
}

func TestRequestNeverReachedServer(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		// Refused connections and dial timeouts arrive as OpError{Op: "dial"}, never bare errnos.
		{"refused connection", &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}, true},
		{"wrapped dial failure", fmt.Errorf("post: %w", &net.OpError{Op: "dial", Err: syscall.ETIMEDOUT}), true},
		{"dns failure", &net.DNSError{Err: "no such host", Name: "app.infisical.com"}, true},

		{"read failure mid-flight", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, false},
		{"write failure mid-flight", &net.OpError{Op: "write", Err: syscall.EPIPE}, false},
		{"bare errno lacks dial context", syscall.ECONNREFUSED, false},
		{"unexpected eof", io.ErrUnexpectedEOF, false},
		{"eof", io.EOF, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, requestNeverReachedServer(test.err))
		})
	}
}

func TestIsIdempotentMethod(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete} {
		assert.True(t, isIdempotentMethod(method), method)
	}
	for _, method := range []string{http.MethodPost, http.MethodPatch, "PROPFIND", ""} {
		assert.False(t, isIdempotentMethod(method), method)
	}
}
