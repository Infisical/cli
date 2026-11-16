package agentvault

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// How often the proxy reports its brokered requests, and how many unsent reports it keeps (a day's worth) while
// Infisical can't be reached.
const (
	usageReportInterval    = time.Minute
	maxPendingUsageReports = 24 * 60
	// Infisical refuses a report above this, so a busier minute is split into several.
	maxBrokeredPerReport = 1_000_000
	// An Infisical without the route may be mid-upgrade, so the proxy asks again after this rather than giving up.
	usageRouteMissingPause = time.Hour
	// The last report on the way out gets this long in all, so it never holds up the shutdown.
	usageFinalTimeout = 5 * time.Second
)

// A sealed report never changes. Infisical bills each report once by its id and end time, so a resend that carried
// a different count would be dropped, and counts made after sealing go into the next report.
type usageReport struct {
	id       string
	endedAt  time.Time
	brokered int64
}

type usageSender func(ctx context.Context, report usageReport) error

type usageReporter struct {
	brokered atomic.Int64

	mu          sync.Mutex
	pending     []usageReport
	pausedUntil time.Time

	send      usageSender
	sendFinal usageSender
	now       func() time.Time
}

func newUsageReporter(send, sendFinal usageSender) *usageReporter {
	return &usageReporter{send: send, sendFinal: sendFinal, now: time.Now}
}

// Nil-safe, so a proxy built without a reporter (tests) still serves requests.
func (u *usageReporter) add(n int64) {
	if u == nil {
		return
	}
	u.brokered.Add(n)
}

func (u *usageReporter) seal(now time.Time) {
	n := u.brokered.Swap(0)
	if n <= 0 {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for n > 0 {
		part := min(n, maxBrokeredPerReport)
		u.pending = append(u.pending, usageReport{id: uuid.NewString(), endedAt: now.UTC(), brokered: part})
		n -= part
	}
	if over := len(u.pending) - maxPendingUsageReports; over > 0 {
		log.Warn().Int("reports", over).Msg("agent-vault: Infisical has been unreachable for a day, dropping the oldest usage reports")
		u.pending = append([]usageReport(nil), u.pending[over:]...)
	}
}

// Sends the pending reports oldest first, and stops at the first one that may still succeed later.
func (u *usageReporter) flush(ctx context.Context, send usageSender) {
	u.mu.Lock()
	if u.now().Before(u.pausedUntil) {
		u.mu.Unlock()
		return
	}
	reports := append([]usageReport(nil), u.pending...)
	u.mu.Unlock()

	done := map[string]bool{}
	for _, report := range reports {
		err := send(ctx, report)
		if err == nil {
			done[report.id] = true
			continue
		}
		var apiErr *api.APIError
		if errors.As(err, &apiErr) {
			if apiErr.StatusCode == http.StatusNotFound && apiErr.DocumentationURL != "" {
				log.Info().Msg("agent-vault: this Infisical doesn't take usage reports yet, trying again in an hour")
				u.mu.Lock()
				u.pausedUntil = u.now().Add(usageRouteMissingPause)
				u.mu.Unlock()
				break
			}
			// Only a refusal Infisical named is about the report itself, such as a clock too far off, so a resend would
			// be refused too. An unnamed one came from something in front of Infisical and may pass later.
			if apiErr.Name != "" && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 &&
				apiErr.StatusCode != http.StatusTooManyRequests && apiErr.StatusCode != http.StatusUnauthorized &&
				apiErr.StatusCode != http.StatusRequestTimeout {
				log.Warn().Err(err).Int64("brokered", report.brokered).Msg("agent-vault: Infisical refused a usage report, dropping it")
				done[report.id] = true
				continue
			}
		}
		log.Debug().Err(err).Msg("agent-vault: couldn't send a usage report, keeping it for the next try")
		break
	}

	if len(done) == 0 {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	kept := u.pending[:0]
	for _, report := range u.pending {
		if !done[report.id] {
			kept = append(kept, report)
		}
	}
	u.pending = kept
}

func (u *usageReporter) run(stop <-chan struct{}) {
	ticker := time.NewTicker(usageReportInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			u.seal(now)
			u.flush(context.Background(), u.send)
		}
	}
}

// One last report on the way out, without retries. Anything still unsent is lost with the process.
func (u *usageReporter) close() {
	u.seal(u.now())
	ctx, cancel := context.WithTimeout(context.Background(), usageFinalTimeout)
	defer cancel()
	u.flush(ctx, u.sendFinal)
}

func sendUsageReports(proxyToken func() string) usageSender {
	return func(ctx context.Context, report usageReport) error {
		httpClient, err := util.GetRestyClientWithCustomHeaders()
		if err != nil {
			return err
		}
		httpClient.SetAuthToken(proxyToken()).SetTimeout(controlPlaneTimeout)
		return reportUsage(ctx, httpClient, report)
	}
}

func sendFinalUsageReports(proxyToken func() string) usageSender {
	return func(ctx context.Context, report usageReport) error {
		httpClient, err := util.GetRestyClientWithPolicy(util.RetryPolicy{})
		if err != nil {
			return err
		}
		httpClient.SetAuthToken(proxyToken()).SetTimeout(usageFinalTimeout)
		return reportUsage(ctx, httpClient, report)
	}
}

func reportUsage(ctx context.Context, httpClient *resty.Client, report usageReport) error {
	return api.CallReportAgentVaultUsage(ctx, httpClient, api.ReportAgentVaultUsageRequest{
		ReportID: report.id,
		EndedAt:  report.endedAt,
		Brokered: report.brokered,
	})
}
