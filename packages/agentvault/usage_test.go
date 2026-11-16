package agentvault

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
)

type recordingSender struct {
	mu   sync.Mutex
	sent []usageReport
	errs []error
}

func (r *recordingSender) send(_ context.Context, report usageReport) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, report)
	if len(r.errs) == 0 {
		return nil
	}
	err := r.errs[0]
	r.errs = r.errs[1:]
	return err
}

func TestUsageSealsTheCountIntoOneReport(t *testing.T) {
	sender := &recordingSender{}
	reporter := newUsageReporter(sender.send, sender.send)

	reporter.add(3)
	reporter.add(2)
	reporter.seal(time.Now())
	reporter.flush(context.Background(), reporter.send)

	if len(sender.sent) != 1 || sender.sent[0].brokered != 5 || sender.sent[0].id == "" {
		t.Fatalf("want one report of 5 with an id, got %+v", sender.sent)
	}
	reporter.seal(time.Now())
	reporter.flush(context.Background(), reporter.send)
	if len(sender.sent) != 1 {
		t.Fatalf("an empty minute sent a report: %+v", sender.sent)
	}
}

func TestAFailedReportIsResentUnchangedAndNewCountsGoToANewReport(t *testing.T) {
	sender := &recordingSender{errs: []error{errors.New("connection reset")}}
	reporter := newUsageReporter(sender.send, sender.send)

	reporter.add(5)
	reporter.seal(time.Now())
	reporter.flush(context.Background(), reporter.send)
	reporter.add(3)
	reporter.seal(time.Now())
	reporter.flush(context.Background(), reporter.send)

	if len(sender.sent) != 3 {
		t.Fatalf("want the failed report resent and then the new one, got %+v", sender.sent)
	}
	first, resent, next := sender.sent[0], sender.sent[1], sender.sent[2]
	if resent != first {
		t.Fatalf("a resend changed the report: first %+v, resent %+v", first, resent)
	}
	if next.id == first.id || next.brokered != 3 {
		t.Fatalf("new counts must go to a new report, got %+v", next)
	}
	if len(reporter.pending) != 0 {
		t.Fatalf("delivered reports are still pending: %+v", reporter.pending)
	}
}

func TestAReportInfisicalRefusesIsDroppedButAnOutageIsKept(t *testing.T) {
	sender := &recordingSender{errs: []error{
		&api.APIError{StatusCode: http.StatusBadRequest, Name: "BadRequest"},
		&api.APIError{StatusCode: http.StatusBadGateway},
	}}
	reporter := newUsageReporter(sender.send, sender.send)

	reporter.add(1)
	reporter.seal(time.Now())
	reporter.flush(context.Background(), reporter.send)
	reporter.add(1)
	reporter.seal(time.Now())
	reporter.flush(context.Background(), reporter.send)

	if len(reporter.pending) != 1 {
		t.Fatalf("want only the report that hit an outage kept, got %+v", reporter.pending)
	}
}

// Something in front of Infisical, such as a WAF or a load balancer, answers without Infisical's error name, and a
// 408 is a timeout whatever sent it, so neither is a verdict on the report.
func TestAnUnnamedRefusalOrATimeoutKeepsTheReport(t *testing.T) {
	for _, refusal := range []*api.APIError{
		{StatusCode: http.StatusForbidden},
		{StatusCode: http.StatusRequestTimeout},
		{StatusCode: http.StatusRequestTimeout, Name: "RequestTimeout"},
	} {
		sender := &recordingSender{errs: []error{refusal}}
		reporter := newUsageReporter(sender.send, sender.send)

		reporter.add(1)
		reporter.seal(time.Now())
		reporter.flush(context.Background(), reporter.send)
		if len(reporter.pending) != 1 {
			t.Fatalf("%d %q: the report was dropped", refusal.StatusCode, refusal.Name)
		}
		reporter.flush(context.Background(), reporter.send)
		if len(sender.sent) != 2 || len(reporter.pending) != 0 {
			t.Fatalf("%d %q: want the report resent and delivered, got sent %+v, pending %+v", refusal.StatusCode, refusal.Name, sender.sent, reporter.pending)
		}
	}
}

func TestAnInfisicalWithoutTheRouteIsAskedAgainAfterAnHour(t *testing.T) {
	sender := &recordingSender{errs: []error{&api.APIError{StatusCode: http.StatusNotFound, DocumentationURL: "https://infisical.com/docs"}}}
	reporter := newUsageReporter(sender.send, sender.send)
	now := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	reporter.now = func() time.Time { return now }

	reporter.add(1)
	reporter.seal(now)
	reporter.flush(context.Background(), reporter.send)
	now = now.Add(30 * time.Minute)
	reporter.add(2)
	reporter.seal(now)
	reporter.flush(context.Background(), reporter.send)

	if len(sender.sent) != 1 || len(reporter.pending) != 2 {
		t.Fatalf("want one attempt and both reports kept while paused, got sent %+v, pending %+v", sender.sent, reporter.pending)
	}

	now = now.Add(31 * time.Minute)
	reporter.flush(context.Background(), reporter.send)
	if len(sender.sent) != 3 || len(reporter.pending) != 0 {
		t.Fatalf("want both reports sent once the hour passed, got sent %+v, pending %+v", sender.sent, reporter.pending)
	}
	if sender.sent[1].brokered != 1 || sender.sent[2].brokered != 2 {
		t.Fatalf("the paused reports changed: %+v", sender.sent)
	}
}

func TestCloseSendsThroughTheFinalSender(t *testing.T) {
	steady, final := &recordingSender{}, &recordingSender{}
	reporter := newUsageReporter(steady.send, final.send)

	reporter.add(4)
	reporter.close()

	if len(steady.sent) != 0 || len(final.sent) != 1 || final.sent[0].brokered != 4 {
		t.Fatalf("want the last report on the final sender, got steady %+v, final %+v", steady.sent, final.sent)
	}
}

func TestShutdownClosesSessionLogsBeforeTheUsageReport(t *testing.T) {
	var order []string
	ps := &proxyServer{usage: newUsageReporter(nil, func(context.Context, usageReport) error {
		order = append(order, "usage")
		return nil
	})}
	ps.usage.add(1)

	ps.closeReporting(func() { order = append(order, "session logs") })

	if len(order) != 2 || order[0] != "session logs" || order[1] != "usage" {
		t.Fatalf("shutdown order = %v, want session logs then usage", order)
	}
}

func TestUnsentReportsAreBounded(t *testing.T) {
	reporter := newUsageReporter((&recordingSender{}).send, (&recordingSender{}).send)
	for i := 0; i < maxPendingUsageReports+5; i++ {
		reporter.add(1)
		reporter.seal(time.Now())
	}
	if len(reporter.pending) != maxPendingUsageReports {
		t.Fatalf("want %d pending reports, got %d", maxPendingUsageReports, len(reporter.pending))
	}
}

func TestANilReporterIgnoresCounts(t *testing.T) {
	var reporter *usageReporter
	reporter.add(1)
}

func TestAMinuteOverTheReportLimitIsSplit(t *testing.T) {
	reporter := newUsageReporter((&recordingSender{}).send, (&recordingSender{}).send)
	reporter.add(2*maxBrokeredPerReport + 5)
	reporter.seal(time.Now())

	if len(reporter.pending) != 3 {
		t.Fatalf("want 3 reports, got %+v", reporter.pending)
	}
	var total int64
	for _, report := range reporter.pending {
		if report.brokered > maxBrokeredPerReport {
			t.Fatalf("a report carries %d, over the limit", report.brokered)
		}
		total += report.brokered
	}
	if total != 2*maxBrokeredPerReport+5 {
		t.Fatalf("split lost requests: total %d", total)
	}
}
