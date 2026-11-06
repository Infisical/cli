package agentvault

import (
	"strconv"
	"strings"
	"sync"
	"time"
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
)

const nativeUnrecordedChannelNote = "port forwarding or another channel was opened through this SSH connection; its traffic isn't recorded"

// What a database or SSH connection did. A database row is one statement; an SSH row is one command with its
// output, one file operation, or a stretch of an interactive shell's screen.
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

// One per connection, implementing PAM's session.SessionLogger. PAM's SSH handler logs from several goroutines
// and can log after it has called Close, so every method takes the lock and a late event is still recorded.
type nativeSessionLogger struct {
	ps  *proxyServer
	key string
	svc *resolvedService

	mu         sync.Mutex
	grant      *sessionLogGrant
	exec       *nativeDetail
	shell      *nativeDetail
	shellSince time.Time
	unrecorded bool
	closed     bool
}

func newNativeSessionLogger(ps *proxyServer, key string, grant *sessionLogGrant, svc *resolvedService) *nativeSessionLogger {
	return &nativeSessionLogger{ps: ps, key: key, grant: grant, svc: svc}
}

func (l *nativeSessionLogger) LogEntry(entry session.SessionLogEntry) error {
	detail := &nativeDetail{}
	appendCapped(&detail.Statement, entry.Input, nativeLogInputCap, &detail.Truncated)
	appendCapped(&detail.Result, entry.Output, nativeLogOutputCap, &detail.Truncated)

	l.mu.Lock()
	defer l.mu.Unlock()
	l.writeLocked(detail)
	return nil
}

func (l *nativeSessionLogger) LogSessionEvent(event session.SessionEvent) error {
	data := string(event.Data)

	l.mu.Lock()
	defer l.mu.Unlock()

	switch event.ChannelType {
	case session.SessionChannelExec:
		l.logExecLocked(event.EventType, data)
	case session.SessionChannelSFTP:
		if event.EventType == session.SessionEventInput {
			detail := &nativeDetail{}
			appendCapped(&detail.File, data, nativeLogInputCap, &detail.Truncated)
			l.writeLocked(detail)
		}
	case session.SessionChannelShell:
		l.logShellLocked(data)
	case session.SessionChannelRDP:
	default:
		// PAM forwards channels it can't read, such as port forwarding, and labels them with no type.
		if !l.unrecorded {
			l.unrecorded = true
			l.writeLocked(&nativeDetail{Note: nativeUnrecordedChannelNote})
		}
	}
	if l.closed {
		l.flushLocked()
	}
	return nil
}

// PAM reports an exec channel's command as "$ cmd", then each line of what the client pipes in as more input.
func (l *nativeSessionLogger) logExecLocked(eventType session.SessionEventType, data string) {
	if eventType == session.SessionEventInput {
		if command, ok := strings.CutPrefix(data, "$ "); ok {
			l.flushExecLocked()
			l.exec = &nativeDetail{}
			appendCapped(&l.exec.Command, command, nativeLogInputCap, &l.exec.Truncated)
			return
		}
		if l.exec == nil {
			l.exec = &nativeDetail{}
		}
		appendLine(&l.exec.Stdin, data, nativeLogInputCap, &l.exec.Truncated)
		return
	}
	if l.exec == nil {
		l.exec = &nativeDetail{}
	}
	appendLine(&l.exec.Output, data, nativeLogOutputCap, &l.exec.Truncated)
}

// A shell's input only appears when the shell didn't echo it, so the screen is recorded as it scrolls by, in rows
// that close at the output cap or after a minute.
func (l *nativeSessionLogger) logShellLocked(data string) {
	now := time.Now()
	if l.shell != nil && now.Sub(l.shellSince) >= nativeLogShellWindow {
		l.flushShellLocked()
	}
	// A row that can't take the next line closes first, so only a single line longer than the cap is cut.
	if l.shell != nil && len(l.shell.Output)+1+len(data) > nativeLogOutputCap {
		l.flushShellLocked()
	}
	if l.shell == nil {
		l.shell = &nativeDetail{Shell: true}
		l.shellSince = now
	}
	appendLine(&l.shell.Output, data, nativeLogOutputCap, &l.shell.Truncated)
}

func (l *nativeSessionLogger) LogHttpEvent(session.HttpEvent) error { return nil }

func (l *nativeSessionLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	l.flushLocked()
	return nil
}

func (l *nativeSessionLogger) flushLocked() {
	l.flushExecLocked()
	l.flushShellLocked()
}

func (l *nativeSessionLogger) flushExecLocked() {
	if l.exec != nil {
		l.writeLocked(l.exec)
		l.exec = nil
	}
}

func (l *nativeSessionLogger) flushShellLocked() {
	if l.shell != nil {
		l.writeLocked(l.shell)
		l.shell = nil
	}
}

func (l *nativeSessionLogger) writeLocked(detail *nativeDetail) {
	// The session's current grant, since logs can be switched off or on while a connection stays open. Once its
	// cache entry is gone the last one known is used, so the final rows of an ended session are still kept.
	if grant, ok := l.ps.cache.currentGrant(l.key); ok {
		l.grant = grant
	}
	if l.grant == nil || l.ps.sessionLogs == nil {
		return
	}

	kind := l.svc.kind
	rec := sessionLogRecord{
		Method:      strings.ToUpper(kind),
		Host:        l.svc.native.host,
		Port:        strconv.Itoa(l.svc.native.port),
		Decision:    decisionBrokered,
		Service:     &l.svc.name,
		ServiceType: &kind,
		Native:      detail,
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
		// Cut on a character boundary, so the record stays valid text.
		for room > 0 && !utf8.RuneStart(s[room]) {
			room--
		}
		s = s[:room]
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
