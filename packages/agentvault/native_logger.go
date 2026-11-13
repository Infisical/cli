package agentvault

import (
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

// A statement or command, and what came back, are capped so one chatty connection can't overwrite the session's
// earlier rows in the spool or hold a large share of the proxy's memory. The spool also budgets bytes, not only
// rows, for the same reason: a few huge rows would otherwise fit under the row count.
const (
	nativeLogInputCap    = 8 << 10
	nativeLogOutputCap   = 64 << 10
	nativeLogShellWindow = 60 * time.Second
	// PAM's SSH handler can still flush a channel's last lines after it has called Close, so those are gathered
	// into one row for this long instead of a row each.
	nativeLogLateWindow = 500 * time.Millisecond
)

const nativeUnrecordedChannelNote = "Some input wasn't recorded, or a forwarded port or another channel was opened through this SSH connection"

// What a database or SSH connection did. A database row is one statement; an SSH row is one command, a stretch of
// what was piped into it and what it printed, one file operation, or a stretch of an interactive shell's screen.
type nativeDetail struct {
	Statement string `json:"statement,omitempty"`
	Command   string `json:"command,omitempty"`
	Stdin     string `json:"stdin,omitempty"`
	File      string `json:"file,omitempty"`
	Result    string `json:"result,omitempty"`
	Output    string `json:"output,omitempty"`
	Shell     bool   `json:"shell,omitempty"`
	Note      string `json:"note,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// A row still taking lines, written once its window ends, it fills, or the connection closes.
type nativeOpenRow struct {
	detail *nativeDetail
	since  time.Time
}

// One per connection, implementing PAM's session.SessionLogger. PAM's SSH handler logs from several goroutines
// and can log after it has called Close, so every method takes the lock and a late event is still recorded.
type nativeSessionLogger struct {
	ps  *proxyServer
	key string
	svc *resolvedService
	now func() time.Time

	mu    sync.Mutex
	grant *sessionLogGrant
	// The command's own row is written when it starts. What is piped into it and what it prints follow in rows
	// of their own, so a long command shows up while it runs. Its stdin and output are capped across those rows,
	// so one large dump can't push the session's earlier rows out of the spool.
	exec          nativeOpenRow
	execStdin     int
	execOutput    int
	execHasPipe   bool
	execStdinCut  bool
	execOutputCut bool
	shell         nativeOpenRow
	timer         *time.Timer
	unrecorded    bool
	closed        bool
}

func newNativeSessionLogger(ps *proxyServer, key string, grant *sessionLogGrant, svc *resolvedService) *nativeSessionLogger {
	return &nativeSessionLogger{ps: ps, key: key, grant: grant, svc: svc, now: time.Now}
}

func (l *nativeSessionLogger) LogEntry(entry session.SessionLogEntry) error {
	detail := &nativeDetail{}
	appendCapped(&detail.Statement, entry.Input, nativeLogInputCap, &detail.Truncated)
	appendCapped(&detail.Result, entry.Output, nativeLogOutputCap, &detail.Truncated)

	l.mu.Lock()
	defer l.mu.Unlock()
	// PAM stamps a statement when it was sent, so a long query still shows when it started.
	at := entry.Timestamp
	if at.IsZero() {
		at = l.now()
	}
	l.writeLocked(detail, at)
	return nil
}

func (l *nativeSessionLogger) LogSessionEvent(event session.SessionEvent) error {
	data := string(event.Data)

	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	switch event.ChannelType {
	case session.SessionChannelExec:
		l.logExecLocked(event.EventType, data, now)
	case session.SessionChannelSFTP:
		if event.EventType == session.SessionEventInput {
			detail := &nativeDetail{}
			appendCapped(&detail.File, data, nativeLogInputCap, &detail.Truncated)
			l.writeLocked(detail, now)
		}
	case session.SessionChannelShell:
		l.logShellLocked(data, now)
	case session.SessionChannelRDP:
	default:
		// PAM forwards channels it can't read, such as port forwarding, and labels them with no type. Stdin that arrives
		// before PAM has typed its channel comes here too, so the note covers both.
		if !l.unrecorded && l.loggingOnLocked() {
			l.unrecorded = true
			l.writeLocked(&nativeDetail{Note: nativeUnrecordedChannelNote}, now)
		}
	}
	l.armTimerLocked(now)
	return nil
}

// PAM reports an exec channel's command as "$ cmd", then each line of what the client pipes in as more input.
// Once a command has been piped something, a line starting with "$ " is more of that, or a file of shell
// examples piped into cat would read as commands the agent ran.
func (l *nativeSessionLogger) logExecLocked(eventType session.SessionEventType, data string, now time.Time) {
	if eventType == session.SessionEventInput {
		if command, ok := strings.CutPrefix(data, "$ "); ok && !l.execHasPipe {
			l.flushRowLocked(&l.exec)
			l.execStdin, l.execOutput = 0, 0
			l.execStdinCut, l.execOutputCut = false, false
			detail := &nativeDetail{}
			appendCapped(&detail.Command, command, nativeLogInputCap, &detail.Truncated)
			l.writeLocked(detail, now)
			return
		}
		l.execHasPipe = true
		l.appendExecLocked(&l.execStdin, &l.execStdinCut, "Input past 8 KiB wasn't recorded", data, nativeLogInputCap, now, func(d *nativeDetail) *string { return &d.Stdin })
		return
	}
	l.appendExecLocked(&l.execOutput, &l.execOutputCut, "Output past 64 KiB wasn't recorded", data, nativeLogOutputCap, now, func(d *nativeDetail) *string { return &d.Output })
}

// Adds a line to the command's open row. used counts what the command has recorded of this stream across all
// its rows; once that reaches max the row that hit it is written at once, and the rest of the stream is dropped.
// If that row was already written when the next line comes, a marker row says the stream was cut instead.
func (l *nativeSessionLogger) appendExecLocked(used *int, cut *bool, note string, line string, max int, now time.Time, field func(*nativeDetail) *string) {
	if !l.loggingOnLocked() {
		l.exec = nativeOpenRow{}
		return
	}
	if *used >= max {
		// The stream filled its share exactly, so this line is the first one left out.
		if line == "" || *cut {
			return
		}
		*cut = true
		if l.exec.detail != nil && *field(l.exec.detail) != "" {
			l.exec.detail.Truncated = true
			l.flushRowLocked(&l.exec)
			return
		}
		l.writeLocked(&nativeDetail{Note: note, Truncated: true}, now)
		return
	}
	l.rollIfStaleLocked(&l.exec, now)
	if l.exec.detail == nil {
		l.exec = nativeOpenRow{detail: &nativeDetail{}, since: now}
	}
	dst := field(l.exec.detail)
	before := len(*dst)
	room := len(*dst) + max - *used
	appendLine(dst, line, room, &l.exec.detail.Truncated)
	*used += len(*dst) - before
	if l.exec.detail.Truncated {
		*used = max
		*cut = true
		l.flushRowLocked(&l.exec)
	}
}

// A shell's input only appears when the shell didn't echo it, so the screen is recorded as it scrolls by, in rows
// that close at the output cap or after a minute.
func (l *nativeSessionLogger) logShellLocked(data string, now time.Time) {
	if !l.loggingOnLocked() {
		l.shell = nativeOpenRow{}
		return
	}
	l.rollIfStaleLocked(&l.shell, now)
	// A row that can't take the next line closes first, so only a single line longer than the cap is cut.
	if l.shell.detail != nil && len(l.shell.detail.Output)+1+len(data) > nativeLogOutputCap {
		l.flushRowLocked(&l.shell)
	}
	if l.shell.detail == nil {
		l.shell = nativeOpenRow{detail: &nativeDetail{Shell: true}, since: now}
	}
	appendLine(&l.shell.detail.Output, data, nativeLogOutputCap, &l.shell.detail.Truncated)
}

func (l *nativeSessionLogger) rollIfStaleLocked(row *nativeOpenRow, now time.Time) {
	if row.detail != nil && now.Sub(row.since) >= nativeLogShellWindow {
		l.flushRowLocked(row)
	}
}

// One timer for the connection, armed only while a row is open: for the oldest open row's window, or for the
// late window once the connection has closed.
func (l *nativeSessionLogger) armTimerLocked(now time.Time) {
	if l.timer != nil {
		return
	}
	var wait time.Duration
	switch {
	case l.exec.detail == nil && l.shell.detail == nil:
		return
	case l.closed:
		if !l.ps.lateNativeLogs.add(l) {
			l.flushLocked()
			return
		}
		wait = nativeLogLateWindow
	default:
		deadline := time.Time{}
		for _, row := range []nativeOpenRow{l.exec, l.shell} {
			if row.detail != nil && (deadline.IsZero() || row.since.Before(deadline)) {
				deadline = row.since
			}
		}
		wait = deadline.Add(nativeLogShellWindow).Sub(now)
	}
	l.timer = time.AfterFunc(wait, l.flushDue)
}

func (l *nativeSessionLogger) flushDue() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.timer = nil
	now := l.now()
	if l.closed {
		l.ps.lateNativeLogs.remove(l)
		l.flushLocked()
		return
	}
	l.rollIfStaleLocked(&l.exec, now)
	l.rollIfStaleLocked(&l.shell, now)
	l.armTimerLocked(now)
}

// Loggers holding late lines on their late window. Shutdown writes them before the session logs close, or the
// window would end after the recorder stopped taking rows and a connection's last lines would be lost. Take a
// logger's lock before mu, never the other way.
type lateNativeLogs struct {
	mu       sync.Mutex
	loggers  map[*nativeSessionLogger]struct{}
	shutDown bool
}

// Reports false once shutdown has flushed, so the caller writes its rows at once instead of waiting.
func (r *lateNativeLogs) add(l *nativeSessionLogger) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.shutDown {
		return false
	}
	if r.loggers == nil {
		r.loggers = map[*nativeSessionLogger]struct{}{}
	}
	r.loggers[l] = struct{}{}
	return true
}

func (r *lateNativeLogs) remove(l *nativeSessionLogger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.loggers, l)
}

// Called once the connections are closed and before the session logs close.
func (ps *proxyServer) flushLateNativeLogs() {
	r := &ps.lateNativeLogs
	r.mu.Lock()
	r.shutDown = true
	pending := r.loggers
	r.loggers = nil
	r.mu.Unlock()

	for l := range pending {
		l.mu.Lock()
		if l.timer != nil {
			l.timer.Stop()
			l.timer = nil
		}
		l.flushLocked()
		l.mu.Unlock()
	}
}

func (l *nativeSessionLogger) LogHttpEvent(session.HttpEvent) error { return nil }

func (l *nativeSessionLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
	// PAM closes the logger and so do we, and a late line between the two puts it on the late list.
	l.ps.lateNativeLogs.remove(l)
	l.flushLocked()
	return nil
}

func (l *nativeSessionLogger) flushLocked() {
	l.flushRowLocked(&l.exec)
	l.flushRowLocked(&l.shell)
}

func (l *nativeSessionLogger) flushRowLocked(row *nativeOpenRow) {
	if row.detail != nil {
		l.writeLocked(row.detail, row.since)
		*row = nativeOpenRow{}
	}
}

// The session's current grant, since logs can be switched off or on while a connection stays open. Once its cache
// entry is gone the last one known is used, so the final rows of an ended session are still kept. Checked on every
// SSH line too, and a row still open while logs are off is dropped, so nothing from that time is written once they
// are turned back on.
func (l *nativeSessionLogger) loggingOnLocked() bool {
	if grant, ok := l.ps.cache.currentGrant(l.key); ok {
		l.grant = grant
	}
	return l.grant != nil && l.ps.sessionLogs != nil
}

// recordOutcome writes a row for a connection that never reached the service, with the reason as its note.
func (l *nativeSessionLogger) recordOutcome(decision, reason string) {
	l.recordRefusal(decision, reason, nil)
}

func (l *nativeSessionLogger) recordRefusal(decision, reason string, hook *hookOutcome) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// The reasons are error text, which starts lowercase; a log row reads as a sentence.
	if r, size := utf8.DecodeRuneInString(reason); size > 0 {
		reason = string(unicode.ToUpper(r)) + reason[size:]
	}
	detail := &nativeDetail{}
	appendCapped(&detail.Note, reason, nativeLogInputCap, &detail.Truncated)
	l.writeDecisionLocked(decision, detail, l.now(), hook)
}

// at is when the row's activity started, which is the time it shows, however much later it is written.
func (l *nativeSessionLogger) writeLocked(detail *nativeDetail, at time.Time) {
	l.writeDecisionLocked(decisionBrokered, detail, at, nil)
}

func (l *nativeSessionLogger) writeDecisionLocked(decision string, detail *nativeDetail, at time.Time, hook *hookOutcome) {
	if !l.loggingOnLocked() {
		return
	}

	kind := l.svc.kind
	rec := sessionLogRecord{
		Method:      strings.ToUpper(kind),
		Host:        l.svc.native.host,
		Port:        strconv.Itoa(l.svc.native.port),
		Decision:    decision,
		Service:     &l.svc.name,
		ServiceType: &kind,
		Native:      detail,
		Hook:        hook,
		at:          at,
	}
	if l.svc.accessBundleName != "" {
		rec.AccessBundle = &l.svc.accessBundleName
	}
	l.ps.sessionLogs.record(l.grant, rec)
}

func appendCapped(dst *string, s string, max int, truncated *bool) {
	room := max - len(*dst)
	if room <= 0 {
		if s != "" {
			*truncated = true
		}
		return
	}
	if len(s) > room {
		// A copy, or the kept prefix would hold the whole original in memory while the spool counts only the prefix.
		s = strings.Clone(capText(s, room))
		*truncated = true
	}
	*dst += s
}

func appendLine(dst *string, line string, max int, truncated *bool) {
	if *dst != "" {
		appendCapped(dst, "\n", max, truncated)
	}
	appendCapped(dst, line, max, truncated)
}
