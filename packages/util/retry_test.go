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

// testPolicy keeps the delays negligible so the suite exercises retry decisions rather than backoff.
func testPolicy(maxRetries int) RetryPolicy {
	return RetryPolicy{
		MaxRetries: maxRetries,
		BaseDelay:  time.Millisecond,
		MaxDelay:   5 * time.Millisecond,
	}
}

// newTestClient returns a client on testPolicy plus a counter of attempts actually dispatched.
// Counting client-side rather than in the handler also covers failures that never reach a server.
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

		// Permanent failures must surface on the first attempt. Retrying them multiplies the cost of
		// a bad token or a typo and delays the error the user needs to see.
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

// POST is not safely repeatable. A 502/503/504 can mean the server did process the write and only
// the response was lost, so replaying it risks double-applying, for instance minting a second
// dynamic secret lease. A 429 is safe because the server states it rejected the request outright.
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
	// Bind then release a port so the address is routable but nothing is listening, which is the
	// connection-refused case the CLI hits when an instance is down.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	deadURL := fmt.Sprintf("http://%s", listener.Addr().String())
	require.NoError(t, listener.Close())

	client, attempts := newTestClient(t, testPolicy(2))
	_, err = client.R().Get(deadURL)

	require.Error(t, err)
	assert.Equal(t, int32(3), attempts.Load())
}

// A TLS trust failure is deterministic, so retrying it only delays the real error. It satisfies
// net.Error, which is why the policy rules certificate errors out explicitly.
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

	// MaxDelay has to exceed Retry-After, otherwise the cap is what we would be measuring.
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

	t.Run("past http date falls back to default backoff", func(t *testing.T) {
		_, ok := parseRetryAfter(time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat))
		assert.False(t, ok)
	})
}

// A misconfigured or hostile Retry-After must not be able to park the CLI indefinitely.
func TestRetryDelayCapsRetryAfterAtMaxDelay(t *testing.T) {
	policy := RetryPolicy{MaxRetries: 3, BaseDelay: time.Second, MaxDelay: 10 * time.Second}

	res := &resty.Response{RawResponse: &http.Response{Header: http.Header{}}}
	res.RawResponse.Header.Set("Retry-After", "3600")

	assert.Equal(t, policy.MaxDelay, retryDelay(res, policy))
}

func TestRetryDelayFallsBackWithoutHeader(t *testing.T) {
	policy := RetryPolicy{MaxRetries: 3, BaseDelay: time.Second, MaxDelay: 10 * time.Second}

	assert.Zero(t, retryDelay(nil, policy), "a nil response should defer to resty's own backoff")

	res := &resty.Response{RawResponse: &http.Response{Header: http.Header{}}}
	assert.Zero(t, retryDelay(res, policy), "an absent header should defer to resty's own backoff")
}

func TestIsRetryableTransportError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"connection reset", syscall.ECONNRESET, true},
		{"connection refused", syscall.ECONNREFUSED, true},
		{"broken pipe", syscall.EPIPE, true},
		{"host unreachable", syscall.EHOSTUNREACH, true},
		{"network unreachable", syscall.ENETUNREACH, true},
		{"dns failure", &net.DNSError{Err: "no such host", Name: "app.infisical.com"}, true},
		{"wrapped connection reset", fmt.Errorf("posting secret: %w", syscall.ECONNRESET), true},

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

	// A bad value in the environment should not stop a command that would otherwise work.
	t.Run("malformed values are ignored", func(t *testing.T) {
		t.Setenv(INFISICAL_RETRY_BASE_DELAY_NAME, "soon")
		t.Setenv(INFISICAL_RETRY_MAX_DELAY_NAME, "")
		t.Setenv(INFISICAL_RETRY_MAX_RETRIES_NAME, "lots")

		policy := DefaultRetryPolicy()
		assert.Equal(t, defaultRetryMaxRetries, policy.MaxRetries)
		assert.Equal(t, defaultRetryBaseDelay, policy.BaseDelay)
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

// The constructors are only a single source of truth while nothing bypasses them, and a bypass is
// invisible in review: the client works, it just silently has no retries.
func TestClientsAreBuiltThroughTheSharedConstructor(t *testing.T) {
	t.Setenv(INFISICAL_RETRY_MAX_RETRIES_NAME, "")

	client, err := GetRestyClientWithCustomHeaders()
	require.NoError(t, err)
	assert.Equal(t, defaultRetryMaxRetries, client.RetryCount,
		"GetRestyClientWithCustomHeaders must apply the default retry policy")

	agentClient, err := GetRestyClientWithPolicy(AgentRetryPolicy())
	require.NoError(t, err)
	assert.Equal(t, agentRetryMaxRetries, agentClient.RetryCount)
}

// TestNoDirectRestyConstruction is the mechanism that keeps the retry policy single-sourced. A
// direct resty.New() compiles, runs, and looks correct in review; it just silently has no retries,
// which is exactly the bug this package exists to prevent. Add new clients via
// GetRestyClientWithCustomHeaders or GetRestyClientWithPolicy instead.
func TestNoDirectRestyConstruction(t *testing.T) {
	// Files allowed to construct a client directly, relative to the repo root.
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
		// Tests build throwaway clients on purpose and never talk to the real API.
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

// newAbruptCloseServer accepts connections, reads the request, then drops the connection without
// responding. That is the ambiguous mid-flight failure: the request was delivered, so the server may
// already have acted on it, and only the response was lost.
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

// deadAddress returns an address that is routable but has nothing listening, so dialing it is
// refused at connection establishment and the request provably never reaches a server.
func deadAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	return "http://" + addr
}

// Transport failures have to respect method safety too, but only when they are ambiguous. Treating
// every transport error as unsafe for POST would give up the case this feature mainly exists for:
// retrying across a backend that is briefly down.
func TestTransportErrorMethodSafety(t *testing.T) {
	const maxRetries = 2

	t.Run("mid-flight failure does not replay POST", func(t *testing.T) {
		serverURL, _ := newAbruptCloseServer(t)

		client, attempts := newTestClient(t, testPolicy(maxRetries))
		_, err := client.R().SetBody(`{"lease":"request"}`).Post(serverURL)

		require.Error(t, err)
		assert.Equal(t, int32(1), attempts.Load(),
			"an ambiguous mid-flight failure must not replay a write: the server may have committed it")
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
		assert.Equal(t, int32(maxRetries+1), attempts.Load(),
			"a read is idempotent, so an ambiguous failure is still safe to repeat")
	})

	t.Run("connection refused replays POST", func(t *testing.T) {
		client, attempts := newTestClient(t, testPolicy(maxRetries))
		_, err := client.R().SetBody(`{}`).Post(deadAddress(t))

		require.Error(t, err)
		assert.Equal(t, int32(maxRetries+1), attempts.Load(),
			"the dial never completed, so the server cannot have seen the write")
	})

	t.Run("unresolvable host replays POST", func(t *testing.T) {
		client, attempts := newTestClient(t, testPolicy(maxRetries))
		_, err := client.R().SetBody(`{}`).Post("http://this-host-does-not-exist.invalid")

		require.Error(t, err)
		assert.Equal(t, int32(maxRetries+1), attempts.Load(),
			"resolution never produced an address, so nothing was sent")
	})
}

func TestRequestNeverReachedServer(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"connection refused", syscall.ECONNREFUSED, true},
		{"wrapped connection refused", fmt.Errorf("post: %w", syscall.ECONNREFUSED), true},
		{"dns failure", &net.DNSError{Err: "no such host", Name: "app.infisical.com"}, true},
		{"dial failure", &net.OpError{Op: "dial", Err: syscall.ETIMEDOUT}, true},

		// Delivered, then the connection died. The server may already have committed the write.
		{"read failure mid-flight", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, false},
		{"write failure mid-flight", &net.OpError{Op: "write", Err: syscall.EPIPE}, false},
		{"bare connection reset", syscall.ECONNRESET, false},
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
