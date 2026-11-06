package agentvault

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
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

func loggedRows(ps *proxyServer) []*nativeDetail {
	ps.sessionLogs.mu.Lock()
	defer ps.sessionLogs.mu.Unlock()
	spool := ps.sessionLogs.spools["s1"]
	if spool == nil {
		return nil
	}
	var rows []*nativeDetail
	for _, rec := range spool.ring.drain(spool.ring.len()) {
		rows = append(rows, rec.Native)
	}
	return rows
}

func event(channel session.SessionChannelType, kind session.SessionEventType, data string) session.SessionEvent {
	return session.SessionEvent{ChannelType: channel, EventType: kind, Data: []byte(data)}
}

func TestPipedStdinStaysWithItsCommand(t *testing.T) {
	logger, ps := newLoggerUnderTest(t)
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "$ psql"))
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "SELECT 1;"))
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventInput, "SELECT 2;"))
	_ = logger.LogSessionEvent(event(session.SessionChannelExec, session.SessionEventOutput, "1"))
	_ = logger.Close()

	rows := loggedRows(ps)
	if len(rows) != 1 || rows[0].Command != "psql" || rows[0].Stdin != "SELECT 1;\nSELECT 2;" || rows[0].Output != "1" {
		t.Fatalf("rows = %+v, want one row for psql with its stdin and output", rows)
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
