package agentvault

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// How often the proxy reports its brokered requests, and how many unsent reports it keeps (a day's worth) while
// Infisical can't be reached.
const (
	usageReportInterval    = time.Minute
	maxPendingUsageReports = 24 * 60
)

// A sealed report never changes. Infisical bills each report once by its id and end time, so a resend that carried
// a different count would be dropped, and counts made after sealing go into the next report.
type usageReport struct {
	id       string
	endedAt  time.Time
	brokered int64
}

type usageSender func(report usageReport) error

type usageReporter struct {
	brokered atomic.Int64
	disabled atomic.Bool

	mu      sync.Mutex
	pending []usageReport

	send usageSender
}

func newUsageReporter(send usageSender) *usageReporter {
	return &usageReporter{send: send}
}

// Nil-safe, so a proxy built without a reporter (tests) still serves requests.
func (u *usageReporter) add(n int64) {
	if u == nil || u.disabled.Load() {
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
	u.pending = append(u.pending, usageReport{id: uuid.NewString(), endedAt: now.UTC(), brokered: n})
	if over := len(u.pending) - maxPendingUsageReports; over > 0 {
		log.Warn().Int("reports", over).Msg("agent-vault: Infisical has been unreachable for a day, dropping the oldest usage reports")
		u.pending = append([]usageReport(nil), u.pending[over:]...)
	}
}

// Sends the pending reports oldest first, and stops at the first one that may still succeed later.
func (u *usageReporter) flush() {
	if u.disabled.Load() {
		return
	}
	u.mu.Lock()
	reports := append([]usageReport(nil), u.pending...)
	u.mu.Unlock()

	done := map[string]bool{}
	for _, report := range reports {
		err := u.send(report)
		if err == nil {
			done[report.id] = true
			continue
		}
		var apiErr *api.APIError
		if errors.As(err, &apiErr) {
			// An Infisical too old to have the route: nothing it could ever accept, so stop counting for this run.
			if apiErr.StatusCode == http.StatusNotFound && apiErr.DocumentationURL != "" {
				log.Info().Msg("agent-vault: this Infisical doesn't take usage reports, not sending them")
				u.disabled.Store(true)
				u.mu.Lock()
				u.pending = nil
				u.mu.Unlock()
				return
			}
			// Refused for what it says, such as a clock too far off, so a resend would be refused too.
			if apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 && apiErr.StatusCode != http.StatusTooManyRequests &&
				apiErr.StatusCode != http.StatusUnauthorized {
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
			u.flush()
		}
	}
}

// One last report on the way out. Anything still unsent is lost with the process.
func (u *usageReporter) close() {
	u.seal(time.Now())
	u.flush()
}

func sendUsageReports(proxyToken func() string) usageSender {
	return func(report usageReport) error {
		httpClient, err := util.GetRestyClientWithCustomHeaders()
		if err != nil {
			return err
		}
		httpClient.SetAuthToken(proxyToken()).SetTimeout(controlPlaneTimeout)
		return api.CallReportAgentVaultUsage(httpClient, api.ReportAgentVaultUsageRequest{
			ReportID: report.id,
			EndedAt:  report.endedAt,
			Brokered: report.brokered,
		})
	}
}
