package util

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

// Retries live here so request sites don't configure them. Every resty client used to talk to the
// Infisical API is built by GetRestyClientWithCustomHeaders, which applies DefaultRetryPolicy, so a
// new api.Call* inherits retries without doing anything. Long-running commands that should ride out
// an outage instead of exiting use GetRestyClientWithPolicy(AgentRetryPolicy()).

const (
	defaultRetryMaxRetries = 3
	defaultRetryBaseDelay  = 500 * time.Millisecond
	defaultRetryMaxDelay   = 10 * time.Second

	// Long-running commands (agent, gateway, relay) keep trying for roughly a quarter hour so a
	// brief upstream outage doesn't take the process down with it.
	agentRetryMaxRetries = 30
	agentRetryMaxDelay   = 30 * time.Second
)

// retryableStatusCodes are the responses worth repeating. Deliberately narrow: a 401 or 404 does not
// improve on the third attempt, and retrying it just multiplies the cost of a bad token or a typo.
var retryableStatusCodes = map[int]bool{
	http.StatusTooManyRequests:    true, // 429
	http.StatusBadGateway:         true, // 502
	http.StatusServiceUnavailable: true, // 503
	http.StatusGatewayTimeout:     true, // 504
}

// RetryPolicy bounds how a resty client retries transient API failures. Time spent sleeping between
// attempts is at most MaxRetries * MaxDelay, so those two fields together decide how long a command
// keeps trying before it gives up.
type RetryPolicy struct {
	// MaxRetries counts attempts after the first, matching resty's SetRetryCount. Zero disables
	// retries.
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
}

// DefaultRetryPolicy suits one-shot commands, where a user or script is waiting on the result and
// would rather see the error than sit through a long backoff.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries: defaultRetryMaxRetries,
		BaseDelay:  defaultRetryBaseDelay,
		MaxDelay:   defaultRetryMaxDelay,
	}.withEnvOverrides()
}

// BestEffortRetryPolicy suits calls whose failure is tolerable and whose latency is not, such as
// usage reporting that also runs on the shutdown path. It absorbs a single blip without making the
// user wait on a full backoff for a result nobody reads.
func BestEffortRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries: 1,
		BaseDelay:  200 * time.Millisecond,
		MaxDelay:   time.Second,
	}.withEnvOverrides()
}

// AgentRetryPolicy suits processes expected to outlive a transient outage rather than exit on one.
func AgentRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries: agentRetryMaxRetries,
		BaseDelay:  defaultRetryBaseDelay,
		MaxDelay:   agentRetryMaxDelay,
	}.withEnvOverrides()
}

// withEnvOverrides applies the INFISICAL_RETRY_* variables on top of whichever defaults were chosen.
// A malformed value is reported and skipped rather than fatal, since this runs while building a
// client for a command that would otherwise work fine.
func (p RetryPolicy) withEnvOverrides() RetryPolicy {
	if raw := os.Getenv(INFISICAL_RETRY_BASE_DELAY_NAME); raw != "" {
		if delay, err := ParseTimeDurationString(raw, true); err == nil {
			p.BaseDelay = delay
		} else {
			log.Warn().Msgf("ignoring %s: %v", INFISICAL_RETRY_BASE_DELAY_NAME, err)
		}
	}

	if raw := os.Getenv(INFISICAL_RETRY_MAX_DELAY_NAME); raw != "" {
		if delay, err := ParseTimeDurationString(raw, true); err == nil {
			p.MaxDelay = delay
		} else {
			log.Warn().Msgf("ignoring %s: %v", INFISICAL_RETRY_MAX_DELAY_NAME, err)
		}
	}

	if raw := os.Getenv(INFISICAL_RETRY_MAX_RETRIES_NAME); raw != "" {
		if maxRetries, err := strconv.Atoi(raw); err == nil && maxRetries >= 0 {
			p.MaxRetries = maxRetries
		} else {
			log.Warn().Msgf("ignoring %s: must be a non-negative integer, got %q", INFISICAL_RETRY_MAX_RETRIES_NAME, raw)
		}
	}

	if p.MaxDelay > 0 && p.BaseDelay > p.MaxDelay {
		p.BaseDelay = p.MaxDelay
	}

	return p
}

// applyRetryPolicy installs the policy on a client. Safe to call on a client the caller will go on
// to configure further; only retry settings are touched.
func applyRetryPolicy(httpClient *resty.Client, policy RetryPolicy) *resty.Client {
	if policy.MaxRetries <= 0 {
		return httpClient
	}

	httpClient.
		SetRetryCount(policy.MaxRetries).
		SetRetryWaitTime(policy.BaseDelay).
		SetRetryMaxWaitTime(policy.MaxDelay).
		SetRetryAfter(func(_ *resty.Client, res *resty.Response) (time.Duration, error) {
			return retryDelay(res, policy), nil
		})

	// Resty drops its built-in "retry when err != nil" default as soon as a condition is added
	// (retry.go Backoff), so this one condition has to cover transport errors and status codes both.
	httpClient.AddRetryCondition(func(res *resty.Response, err error) bool {
		return shouldRetryRequest(res, err)
	})

	httpClient.AddRetryHook(retryLogger(policy))

	return httpClient
}

// shouldRetryRequest decides whether a failed attempt is worth repeating. It works from an allow
// list, so anything unrecognised falls through to "don't retry" and surfaces to the caller
// immediately.
func shouldRetryRequest(res *resty.Response, err error) bool {
	// The caller cancelled or its deadline passed. Further attempts cannot help and would ignore
	// what the caller asked for.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// A transport error means no usable response arrived. res may be nil here, so decide on the
	// error alone and do not touch res.
	if err != nil {
		return isRetryableTransportError(err)
	}

	if res == nil {
		return false
	}

	if !retryableStatusCodes[res.StatusCode()] {
		return false
	}

	return methodAllowsStatusRetry(res.Request.Method, res.StatusCode())
}

// methodAllowsStatusRetry gates status-code retries on whether repeating the request is safe.
//
// A 429 is always safe: the server is stating it rejected the request without acting on it. The 5xx
// codes are not, for methods that aren't idempotent. A 504 can mean the server did process the write
// and only the response was lost, so replaying a POST risks double-applying it, for instance minting
// a second dynamic secret lease. Those surface to the caller instead.
func methodAllowsStatusRetry(method string, statusCode int) bool {
	if statusCode == http.StatusTooManyRequests {
		return true
	}

	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete:
		return true
	default: // POST, PATCH, anything unrecognised
		return false
	}
}

// isRetryableTransportError reports whether a request failed in a way a retry could plausibly fix.
// Checks are on error types and syscall errnos rather than message substrings, so they don't depend
// on how the runtime happens to phrase things.
func isRetryableTransportError(err error) bool {
	if err == nil {
		return false
	}

	// TLS trust failures are deterministic. They satisfy net.Error below, so rule them out first;
	// otherwise a misconfigured CA bundle costs the user every attempt and every backoff before it
	// reports the real problem.
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return false
	}

	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return false
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return false
	}

	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return false
	}

	// Covers dial timeouts, DNS failures and refused connections: http.Client wraps transport
	// failures in *url.Error, which satisfies net.Error.
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	// Connection torn down mid-flight, most often a load balancer recycling a keep-alive connection.
	for _, errno := range []syscall.Errno{
		syscall.ECONNRESET,
		syscall.ECONNREFUSED,
		syscall.ECONNABORTED,
		syscall.EPIPE,
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
		syscall.ETIMEDOUT,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}

	// Keep-alive connection closed between our write and the server's response.
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// retryDelay returns how long to wait before the next attempt. Zero hands the decision back to
// resty's jittered exponential backoff, which is what we want whenever the server gave no guidance.
func retryDelay(res *resty.Response, policy RetryPolicy) time.Duration {
	if res == nil {
		return 0
	}

	wait, ok := parseRetryAfter(res.Header().Get("Retry-After"))
	if !ok {
		return 0
	}

	// The server told us exactly how long to wait, so prefer it over our own guess. Still cap it:
	// a misconfigured or hostile Retry-After shouldn't be able to park the CLI indefinitely.
	if policy.MaxDelay > 0 && wait > policy.MaxDelay {
		return policy.MaxDelay
	}

	return wait
}

// parseRetryAfter reads a Retry-After header in either RFC 9110 form, a delay in seconds or an
// absolute HTTP date. ok is false when the header is absent, unparseable, or already in the past,
// leaving the caller on its default backoff.
func parseRetryAfter(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}

	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}

	if deadline, err := http.ParseTime(value); err == nil {
		if wait := time.Until(deadline); wait > 0 {
			return wait, true
		}
	}

	return 0, false
}

// retryLogger records each retryable failure at debug level. Retries are routine on a flaky network
// and warning on every one would be noise for scripted use, so this stays behind --log-level debug.
func retryLogger(policy RetryPolicy) resty.OnRetryFunc {
	return func(res *resty.Response, err error) {
		event := log.Debug()
		exhausted := false

		if res != nil && res.Request != nil {
			// Attempt counts from 1, so the last one lands on MaxRetries+1. Resty runs retry hooks
			// on that attempt too, and calling it a retry there would be a lie.
			exhausted = res.Request.Attempt > policy.MaxRetries

			event = event.
				Str("method", res.Request.Method).
				Str("url", res.Request.URL).
				Int("attempt", res.Request.Attempt).
				Int("maxRetries", policy.MaxRetries)

			if res.StatusCode() != 0 {
				event = event.Int("status", res.StatusCode())
			}
		}

		if err != nil {
			event = event.Err(err)
		}

		if exhausted {
			event.Msg("request failed and retries are exhausted")
			return
		}

		event.Msg("request failed, retrying")
	}
}
