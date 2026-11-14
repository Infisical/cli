package agentvault

import (
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

func (r *recordingSender) send(report usageReport) error {
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
	reporter := newUsageReporter(sender.send)

	reporter.add(3)
	reporter.add(2)
	reporter.seal(time.Now())
	reporter.flush()

	if len(sender.sent) != 1 || sender.sent[0].brokered != 5 || sender.sent[0].id == "" {
		t.Fatalf("want one report of 5 with an id, got %+v", sender.sent)
	}
	reporter.seal(time.Now())
	reporter.flush()
	if len(sender.sent) != 1 {
		t.Fatalf("an empty minute sent a report: %+v", sender.sent)
	}
}

func TestAFailedReportIsResentUnchangedAndNewCountsGoToANewReport(t *testing.T) {
	sender := &recordingSender{errs: []error{errors.New("connection reset")}}
	reporter := newUsageReporter(sender.send)

	reporter.add(5)
	reporter.seal(time.Now())
	reporter.flush()
	reporter.add(3)
	reporter.seal(time.Now())
	reporter.flush()

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
	sender := &recordingSender{errs: []error{&api.APIError{StatusCode: http.StatusBadRequest}, &api.APIError{StatusCode: http.StatusBadGateway}}}
	reporter := newUsageReporter(sender.send)

	reporter.add(1)
	reporter.seal(time.Now())
	reporter.flush()
	reporter.add(1)
	reporter.seal(time.Now())
	reporter.flush()

	if len(reporter.pending) != 1 {
		t.Fatalf("want only the report that hit an outage kept, got %+v", reporter.pending)
	}
}

func TestAnInfisicalWithoutTheRouteStopsReporting(t *testing.T) {
	sender := &recordingSender{errs: []error{&api.APIError{StatusCode: http.StatusNotFound, DocumentationURL: "https://infisical.com/docs"}}}
	reporter := newUsageReporter(sender.send)

	reporter.add(1)
	reporter.seal(time.Now())
	reporter.flush()
	reporter.add(1)
	reporter.seal(time.Now())
	reporter.flush()

	if len(sender.sent) != 1 || len(reporter.pending) != 0 {
		t.Fatalf("want one attempt and nothing kept, got sent %+v, pending %+v", sender.sent, reporter.pending)
	}
}

func TestUnsentReportsAreBounded(t *testing.T) {
	reporter := newUsageReporter((&recordingSender{}).send)
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
