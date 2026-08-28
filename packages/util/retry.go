package util

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

const (
	defaultRetryMaxRetries = 3
	defaultRetryBaseDelay  = 500 * time.Millisecond
	defaultRetryMaxDelay   = 10 * time.Second

	agentRetryMaxRetries = 30
	agentRetryMaxDelay   = 30 * time.Second
)

var retryableStatusCodes = map[int]bool{
	http.StatusTooManyRequests:    true,
	http.StatusBadGateway:         true,
	http.StatusServiceUnavailable: true,
	http.StatusGatewayTimeout:     true,
}

// RetryPolicy bounds how a client retries transient failures.
type RetryPolicy struct {
	// MaxRetries counts attempts after the first. Zero disables retries.
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration

	// ReplaySafe asserts that every request sent through this client is safe to send more than
	// once, letting POST and PATCH retry like idempotent methods. Set it only where a replay
	// cannot double-apply a write.
	ReplaySafe bool
}

// DefaultRetryPolicy suits one-shot commands where a user or script is waiting on the result.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries: defaultRetryMaxRetries,
		BaseDelay:  defaultRetryBaseDelay,
		MaxDelay:   defaultRetryMaxDelay,
	}.withEnvOverrides()
}

// AgentRetryPolicy suits long-running processes that should ride out an outage rather than exit.
func AgentRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries: agentRetryMaxRetries,
		BaseDelay:  defaultRetryBaseDelay,
		MaxDelay:   agentRetryMaxDelay,
	}.withEnvOverrides()
}

// BestEffortRetryPolicy suits fire-and-forget calls. Not env-tunable so paths that run during
// shutdown stay time-bounded.
func BestEffortRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries: 1,
		BaseDelay:  200 * time.Millisecond,
		MaxDelay:   time.Second,
	}
}

// withEnvOverrides applies INFISICAL_RETRY_*, which affect every command run in the environment.
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

func applyRetryPolicy(httpClient *resty.Client, policy RetryPolicy) *resty.Client {
	httpClient.SetLogger(restyLogAdapter{})

	if policy.MaxRetries <= 0 {
		return httpClient
	}

	httpClient.
		SetRetryCount(policy.MaxRetries).
		SetRetryWaitTime(policy.BaseDelay).
		SetRetryMaxWaitTime(policy.MaxDelay).
		SetRetryAfter(func(_ *resty.Client, res *resty.Response) (time.Duration, error) {
			return retryDelay(res), nil
		})

	// The first AddRetryCondition replaces resty's built-in retry-on-error default, so this one
	// condition must cover transport errors and status codes both.
	httpClient.AddRetryCondition(func(res *resty.Response, err error) bool {
		return shouldRetryRequest(policy, res, err)
	})

	httpClient.AddRetryHook(retryLogger(policy))

	return httpClient
}

func shouldRetryRequest(policy RetryPolicy, res *resty.Response, err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	if err != nil {
		if !isRetryableTransportError(err) {
			return false
		}

		// Pre-delivery failures are safe to replay for any method. res is nil when resty failed
		// before sending; a non-nil response always carries its Request.
		if res == nil || requestNeverReachedServer(err) {
			return true
		}

		// Mid-flight failure: the server may have committed the request with only the response
		// lost, so replaying a non-idempotent method could double-apply it.
		return policy.ReplaySafe || isIdempotentMethod(res.Request.Method)
	}

	if res == nil || !retryableStatusCodes[res.StatusCode()] {
		return false
	}

	// Retrying sooner than the server asked for would only get rejected again.
	if wait, ok := parseRetryAfter(res.Header().Get("Retry-After")); ok && wait > policy.MaxDelay {
		return false
	}

	// A 429 was rejected before the server acted on it, so any method may repeat it.
	if res.StatusCode() == http.StatusTooManyRequests {
		return true
	}

	return policy.ReplaySafe || isIdempotentMethod(res.Request.Method)
}

// Per RFC 9110 9.2.2.
func isIdempotentMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace,
		http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func requestNeverReachedServer(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

func isRetryableTransportError(err error) bool {
	if err == nil {
		return false
	}

	// Deterministic, but wrapped in *url.Error like everything else, so this must come before the
	// net.Error check. crypto/tls wraps every x509 verification error in this type.
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	// A truncated response body surfaces as a bare io error, not a net.Error.
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// retryDelay returns the server-requested wait; zero tells resty to use its jittered backoff.
// No cap needed: shouldRetryRequest declines waits beyond MaxDelay.
func retryDelay(res *resty.Response) time.Duration {
	if res == nil {
		return 0
	}

	if wait, ok := parseRetryAfter(res.Header().Get("Retry-After")); ok {
		return wait
	}

	return 0
}

const maxRetryAfter = 24 * time.Hour

func parseRetryAfter(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}

	if seconds, err := strconv.Atoi(value); err == nil {
		switch {
		case seconds <= 0:
			return 0, false
		case seconds > int(maxRetryAfter/time.Second):
			return maxRetryAfter, true
		}
		return time.Duration(seconds) * time.Second, true
	}

	if deadline, err := http.ParseTime(value); err == nil {
		if wait := time.Until(deadline); wait > 0 {
			return min(wait, maxRetryAfter), true
		}
	}

	return 0, false
}

// restyLogAdapter routes resty's internal logging through zerolog. Everything maps to debug:
// resty's request-path warnings and errors duplicate retryLogger and the returned error.
type restyLogAdapter struct{}

func (restyLogAdapter) Errorf(format string, v ...any) {
	log.Debug().Str("component", "resty").Msgf(format, v...)
}

func (restyLogAdapter) Warnf(format string, v ...any) {
	log.Debug().Str("component", "resty").Msgf(format, v...)
}

func (restyLogAdapter) Debugf(format string, v ...any) {
	log.Debug().Str("component", "resty").Msgf(format, v...)
}

// Debug level: warning on every retry would be noise for scripted use.
func retryLogger(policy RetryPolicy) resty.OnRetryFunc {
	return func(res *resty.Response, err error) {
		event := log.Debug()
		exhausted := false

		if res != nil {
			// Resty runs retry hooks on the final attempt too.
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
