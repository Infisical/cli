package agentvault

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

func newLoggerUnderTest(t *testing.T) (*nativeSessionLogger, *proxyServer) {
	t.Helper()
	svc := nativeServiceAt(serviceKindSSH, "bastion", "10.0.0.5:22")
	ps := &proxyServer{}
	ps.cache = newSessionCache(grantingResolver{services: []*resolvedService{svc}}, ps.pollInterval)
	ps.sessionLogs = newSessionLogRecorder("proxy-1", &fakeShipper{})
	_, grant, err := ps.cache.lookup("agv_logger", nil)
	if err != nil {
		t.Fatal(err)
	}
	return newNativeSessionLogger(ps, sessionKey("agv_logger"), grant, svc), ps
}

func loggedRecords(ps *proxyServer) []sessionLogRecord {
	ps.sessionLogs.mu.Lock()
	defer ps.sessionLogs.mu.Unlock()
	spool := ps.sessionLogs.spools["s1"]
	if spool == nil {
		return nil
	}
	return spool.ring.drain(spool.ring.len())
}

func loggedRows(ps *proxyServer) []*nativeDetail {
	var rows []*nativeDetail
	for _, rec := range loggedRecords(ps) {
		rows = append(rows, rec.Native)
	}
	return rows
}

// A clock the test moves by hand, so a row's window can pass without waiting for it.
func fakeLoggerClock(logger *nativeSessionLogger) (start time.Time, advance func(time.Duration)) {
	start = time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	now := start
	var mu sync.Mutex
	logger.mu.Lock()
	logger.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	logger.mu.Unlock()
	return start, func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}
}

func event(channel session.SessionChannelType, kind session.SessionEventType, data string) session.SessionEvent {
	return session.SessionEvent{ChannelType: channel, EventType: kind, Data: []byte(data)}
}

func TestPipedStdinFollowsItsCommand(t *testing.T) {
	logger, ps := newLoggerUnderTest(t)
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "$ psql"))
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "SELECT 1;"))
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "SELECT 2;"))
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventOutput, "1"))
	_ = logger.Close()

	rows := loggedRows(ps)
	if len(rows) != 2 || rows[0].Command != "psql" || rows[1].Stdin != "SELECT 1;\nSELECT 2;" || rows[1].Output != "1" {
		t.Fatalf("rows = %+v, want the psql row, then its stdin and output", rows)
	}
}

// A file of shell examples piped into a command must not read as commands the agent ran.
func TestADollarLineInPipedStdinIsNotACommand(t *testing.T) {
	logger, ps := newLoggerUnderTest(t)
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "$ cat"))
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "# notes"))
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "$ rm -rf /x"))
	_ = logger.Close()

	rows := loggedRows(ps)
	var commands []string
	for _, row := range rows {
		if row.Command != "" {
			commands = append(commands, row.Command)
		}
	}
	if len(commands) != 1 || commands[0] != "cat" || rows[len(rows)-1].Stdin != "# notes\n$ rm -rf /x" {
		t.Fatalf("rows = %+v, want one command row for cat with the $ line kept as its stdin", rows)
	}
}

// A long command shows up while it runs, stamped with when it started, and its output follows in timed rows.
func TestACommandIsLoggedWhenItStartsAndItsOutputInTimedRows(t *testing.T) {
	logger, ps := newLoggerUnderTest(t)
	start, advance := fakeLoggerClock(logger)

	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "$ ./migrate.sh"))
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventOutput, "step 1"))
	records := loggedRecords(ps)
	if len(records) != 1 || records[0].Native.Command != "./migrate.sh" || records[0].Ts != start.Format(time.RFC3339Nano) {
		t.Fatalf("records = %+v, want the command written at once with its start time", records)
	}

	advance(nativeLogShellWindow)
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventOutput, "step 2"))
	advance(nativeLogShellWindow)
	logger.flushDue()

	records = loggedRecords(ps)
	if len(records) != 2 || records[0].Native.Output != "step 1" || records[1].Native.Output != "step 2" {
		t.Fatalf("records = %+v, want one output row per minute", records)
	}
	if records[0].Ts != start.Format(time.RFC3339Nano) || records[1].Ts != start.Add(nativeLogShellWindow).Format(time.RFC3339Nano) {
		t.Fatalf("output rows stamped %s and %s, want the time each one started", records[0].Ts, records[1].Ts)
	}
	_ = logger.Close()
}

// An idle shell's last screen must not wait for the next line or the end of the connection.
func TestTheTimerWritesAnIdleShellRow(t *testing.T) {
	logger, ps := newLoggerUnderTest(t)
	_, advance := fakeLoggerClock(logger)

	_ = logger.LogSessionEvent(event(session.SessionChannelShell, session.SessionEventOutput, "$ top"))
	logger.mu.Lock()
	armed := logger.timer != nil
	logger.mu.Unlock()
	if !armed {
		t.Fatal("no timer was armed for the open shell row")
	}
	logger.flushDue()
	if rows := loggedRows(ps); len(rows) != 0 {
		t.Fatalf("rows = %+v, want the row kept open inside its window", rows)
	}

	advance(nativeLogShellWindow)
	logger.flushDue()
	if rows := loggedRows(ps); len(rows) != 1 || !rows[0].Shell || rows[0].Output != "$ top" {
		t.Fatalf("rows = %+v, want the shell row written when its window ended", rows)
	}

	_ = logger.Close()
	logger.mu.Lock()
	defer logger.mu.Unlock()
	if logger.timer != nil {
		t.Fatal("Close left the timer running")
	}
}

// Rows written on a timer must not let one large dump push the session's earlier rows out of the spool.
func TestACommandsOutputIsCappedAcrossItsRows(t *testing.T) {
	logger, ps := newLoggerUnderTest(t)
	line := strings.Repeat("x", 1000)
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "$ cat big.log"))
	for i := 0; i < 200; i++ {
		_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventOutput, line))
	}
	_ = logger.Close()

	rows := loggedRows(ps)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want the command and one output row cut at the cap", len(rows))
	}
	if out := rows[1]; len(out.Output) != nativeLogOutputCap || !out.Truncated {
		t.Fatalf("output row holds %d bytes, truncated=%v, want %d and marked", len(out.Output), out.Truncated, nativeLogOutputCap)
	}
}

func TestAnEventAfterCloseIsStillRecorded(t *testing.T) {
	logger, ps := newLoggerUnderTest(t)
	_ = logger.Close()
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "$ uptime"))

	if rows := loggedRows(ps); len(rows) != 1 || rows[0].Command != "uptime" {
		t.Fatalf("rows = %+v, want the late command recorded", rows)
	}
}

// PAM can flush a channel's last lines after Close; they belong in one row, not a row each.
func TestLateOutputAfterCloseSharesARow(t *testing.T) {
	logger, ps := newLoggerUnderTest(t)
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "$ seq 3"))
	_ = logger.Close()
	for _, line := range []string{"1", "2", "3"} {
		_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventOutput, line))
	}

	var rows []*nativeDetail
	deadline := time.Now().Add(5 * time.Second)
	for len(rows) < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		rows = append(rows, loggedRows(ps)...)
	}
	if len(rows) != 2 || rows[0].Command != "seq 3" || rows[1].Output != "1\n2\n3" {
		t.Fatalf("rows = %+v, want the command and one row with the late output", rows)
	}
}

func TestAStatementShowsWhenItWasSent(t *testing.T) {
	logger, ps := newLoggerUnderTest(t)
	sent := time.Date(2026, 11, 7, 9, 30, 0, 0, time.UTC)
	_ = logger.LogEntry(session.SessionLogEntry{Timestamp: sent, Input: "SELECT pg_sleep(1800)", Output: "SELECT 1"})

	if records := loggedRecords(ps); len(records) != 1 || records[0].Ts != sent.Format(time.RFC3339Nano) {
		t.Fatalf("records = %+v, want the statement stamped when it was sent", records)
	}
}

func TestShellOutputIsRecordedInCappedChunks(t *testing.T) {
	logger, ps := newLoggerUnderTest(t)
	line := strings.Repeat("x", 1000)
	for i := 0; i < 100; i++ {
		_ = logger.LogSessionEvent(event(session.SessionChannelShell, session.SessionEventOutput, line))
	}
	_ = logger.Close()

	rows := loggedRows(ps)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 100 KB of output in two chunks", len(rows))
	}
	for _, row := range rows {
		if !row.Shell || len(row.Output) > nativeLogOutputCap || row.Truncated {
			t.Fatalf("chunk shell=%v len=%d truncated=%v", row.Shell, len(row.Output), row.Truncated)
		}
	}
}

func TestAForwardedChannelIsNotedOnce(t *testing.T) {
	logger, ps := newLoggerUnderTest(t)
	_ = logger.LogSessionEvent(event("", session.SessionEventOutput, "raw tunnel bytes"))
	_ = logger.LogSessionEvent(event("", session.SessionEventInput, "more"))
	_ = logger.Close()

	rows := loggedRows(ps)
	if len(rows) != 1 || rows[0].Note != nativeUnrecordedChannelNote || strings.Contains(rows[0].Output, "raw") {
		t.Fatalf("rows = %+v, want one note and none of the forwarded bytes", rows)
	}
}

func TestALongStatementIsCutAndMarked(t *testing.T) {
	logger, ps := newLoggerUnderTest(t)
	_ = logger.LogEntry(session.SessionLogEntry{Input: strings.Repeat("é", nativeLogInputCap), Output: "SELECT 0"})

	rows := loggedRows(ps)
	if len(rows) != 1 || len(rows[0].Statement) > nativeLogInputCap || !rows[0].Truncated || !strings.HasSuffix(rows[0].Statement, "é") {
		t.Fatalf("statement of %d bytes, truncated=%v, want at most %d cut on a character", len(rows[0].Statement), rows[0].Truncated, nativeLogInputCap)
	}
}

// One chatty session must not hold more than its byte budget: its oldest rows give way, as they do at the row cap.
func TestASessionsRowsAreBudgetedByBytes(t *testing.T) {
	log := newSessionLogRecorder("proxy-1", &fakeShipper{})
	grant := &sessionLogGrant{sessionID: "s1", key: make([]byte, 32)}
	output := strings.Repeat("y", nativeLogOutputCap)
	for i := 0; i < 200; i++ {
		log.record(grant, sessionLogRecord{Native: &nativeDetail{Output: output}})
	}

	log.mu.Lock()
	defer log.mu.Unlock()
	spool := log.spools["s1"]
	if spool.ring.bytes > sessionLogSpoolBytes || log.unsealedBytes != spool.ring.bytes {
		t.Fatalf("ring holds %d bytes (budget %d), recorder counts %d", spool.ring.bytes, sessionLogSpoolBytes, log.unsealedBytes)
	}
	if spool.ring.unreportedDrops == 0 {
		t.Fatal("rows dropped for the budget weren't counted")
	}
}

// A Postgres client speaks first, so a port check that connects and says nothing never makes the proxy log in.
func TestConnectWaitsForThePostgresClientsFirstByte(t *testing.T) {
	var tunnels atomic.Int32
	proxy := fakeConnectProxy(t, func() { tunnels.Add(1) })
	client := &ConnectClient{ProxyAddr: proxy, SessionToken: "agv_x"}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = client.ServeLocal(ctx, ln, NativeServiceInfo{Name: "db", Type: serviceKindPostgres}, func(error) {})
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	time.Sleep(200 * time.Millisecond)
	_ = conn.Close()
	time.Sleep(100 * time.Millisecond)
	if tunnels.Load() != 0 {
		t.Fatal("a silent port check opened a tunnel")
	}
}

// What an old proxy does with a TLS handshake on its HTTP port: it reads it as a bad request and says so in plain
// text, which the client must name as an old proxy rather than a TLS failure.
func TestAnOldProxyIsNamedAsSuch(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = bufio.NewReader(conn).Peek(1)
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}()

	client := &ConnectClient{ProxyAddr: ln.Addr().String(), SessionToken: "agv_x"}
	if _, err := client.ListNativeServices(context.Background()); err != ErrProxyTooOld {
		t.Fatalf("got %v, want ErrProxyTooOld", err)
	}
}

// Counts tunnel attempts without speaking TLS: the test only needs to see whether one was attempted.
func fakeConnectProxy(t *testing.T, onConnect func()) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			onConnect()
			_, _ = conn.Write([]byte("HTTP/1.1 " + http.StatusText(http.StatusBadRequest) + "\r\n\r\n"))
			_ = conn.Close()
		}
	}()
	return ln.Addr().String()
}

func TestASilentClientIsClosedWhenConnectStops(t *testing.T) {
	proxy := fakeConnectProxy(t, func() {})
	client := &ConnectClient{ProxyAddr: proxy, SessionToken: "agv_x"}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = client.ServeLocal(ctx, ln, NativeServiceInfo{Name: "db", Type: serviceKindPostgres}, func(error) {})
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(100 * time.Millisecond)
	cancel()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the silent client was left open after cancel: %v", err)
	}
}
