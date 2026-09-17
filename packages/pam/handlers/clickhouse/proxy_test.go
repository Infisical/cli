package clickhouse

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type recordingLogger struct {
	entries []session.SessionLogEntry
}

func (r *recordingLogger) LogEntry(entry session.SessionLogEntry) error {
	r.entries = append(r.entries, entry)
	return nil
}
func (r *recordingLogger) LogSessionEvent(session.SessionEvent) error { return nil }
func (r *recordingLogger) LogHttpEvent(session.HttpEvent) error       { return nil }
func (r *recordingLogger) Close() error                               { return nil }

type capturedRequest struct {
	method  string
	path    string
	query   url.Values
	headers http.Header
	body    []byte
}

func newTestProxy(t *testing.T, upstream http.HandlerFunc, blocked ...string) (http.Handler, *recordingLogger, func()) {
	t.Helper()

	server := httptest.NewServer(upstream)

	patterns := make([]*regexp.Regexp, 0, len(blocked))
	for _, pattern := range blocked {
		patterns = append(patterns, regexp.MustCompile(pattern))
	}

	logger := &recordingLogger{}
	proxy := NewClickHouseProxy(ClickHouseProxyConfig{
		TargetAddr:      strings.TrimPrefix(server.URL, "http://"),
		Username:        "pam_svc",
		Password:        "s3cret", // ggignore
		Database:        "analytics",
		SessionID:       "session-1",
		SessionLogger:   logger,
		BlockedCommands: patterns,
	})

	return proxy.handler(zerolog.Nop()), logger, server.Close
}

func capturingUpstream(captured *capturedRequest, respond func(http.ResponseWriter)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*captured = capturedRequest{
			method:  r.Method,
			path:    r.URL.Path,
			query:   r.URL.Query(),
			headers: r.Header.Clone(),
			body:    body,
		}
		if respond != nil {
			respond(w)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func gzipped(t *testing.T, payload string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	_, err := writer.Write([]byte(payload))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return buffer.Bytes()
}

func TestReplacesClientCredentialsWithTheAccountsOwn(t *testing.T) {
	var captured capturedRequest
	handler, _, closeUpstream := newTestProxy(t, capturingUpstream(&captured, nil))
	defer closeUpstream()

	req := httptest.NewRequest(http.MethodPost, "/?user=attacker&password=guessed&query=SELECT+1", http.NoBody)
	req.Header.Set("Authorization", "Basic YXR0YWNrZXI6Z3Vlc3NlZA==") // ggignore
	req.Header.Set("X-ClickHouse-User", "attacker")
	req.Header.Set("X-ClickHouse-Key", "guessed")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	require.Equal(t, "pam_svc", captured.headers.Get("X-ClickHouse-User"))
	require.Equal(t, "s3cret", captured.headers.Get("X-ClickHouse-Key"))
	require.Empty(t, captured.headers.Get("Authorization"))
	require.Empty(t, captured.headers.Get("X-Forwarded-For"))
	require.Empty(t, captured.query.Get("user"))
	require.Empty(t, captured.query.Get("password"))
}

func TestStripsTheRoleParameterThatWouldActivateARoleWithoutAStatement(t *testing.T) {
	var captured capturedRequest
	handler, _, closeUpstream := newTestProxy(t, capturingUpstream(&captured, nil))
	defer closeUpstream()

	handler.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/?role=privileged&query=SELECT+1", http.NoBody))

	require.Empty(t, captured.query.Get("role"))
	require.Equal(t, "SELECT 1", captured.query.Get("query"))
}

func TestRefusesAPathOutsideTheQueryEndpoint(t *testing.T) {
	reached := false
	handler, _, closeUpstream := newTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})
	defer closeUpstream()

	// An SQL-backed custom handler can be mounted at any path, and its statement is never in the request
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/custom_handler", http.NoBody))

	require.False(t, reached)
	require.Equal(t, http.StatusNotFound, recorder.Code)
	require.Contains(t, recorder.Body.String(), "not available here")

	// The endpoints a driver actually needs still pass
	for _, path := range []string{"/", "/ping"} {
		reached = false
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, http.NoBody))
		require.True(t, reached, path)
	}
}

func TestReplacesWhateverDatabaseTheClientAsksFor(t *testing.T) {
	var captured capturedRequest
	handler, _, closeUpstream := newTestProxy(t, capturingUpstream(&captured, nil))
	defer closeUpstream()

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/?query=SELECT+1", http.NoBody))
	require.Equal(t, "analytics", captured.query.Get("database"))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/?database=other&query=SELECT+1", http.NoBody))
	require.Equal(t, "analytics", captured.query.Get("database"))
}

func TestBlocksAStatementInTheQueryParameter(t *testing.T) {
	reached := false
	handler, logger, closeUpstream := newTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}, `(?i)\bdrop\b`)
	defer closeUpstream()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/?query=DROP+TABLE+events", http.NoBody))

	require.False(t, reached)
	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.Equal(t, "497", recorder.Header().Get("X-ClickHouse-Exception-Code"))
	require.Contains(t, recorder.Body.String(), "Code: 497. DB::Exception:")
	require.Contains(t, recorder.Body.String(), "(ACCESS_DENIED)")

	require.Len(t, logger.entries, 1)
	require.Equal(t, "DROP TABLE events", logger.entries[0].Input)
	require.Contains(t, logger.entries[0].Output, "BLOCKED:")
}

func TestBlocksAStatementInsideAGzippedBody(t *testing.T) {
	reached := false
	handler, _, closeUpstream := newTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}, `(?i)\btruncate\b`)
	defer closeUpstream()

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(gzipped(t, "TRUNCATE TABLE events")))
	req.Header.Set("Content-Encoding", "gzip")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	require.False(t, reached)
	require.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestJoinsTheQueryParameterAndTheBodyTheWayClickHouseDoes(t *testing.T) {
	handler, logger, closeUpstream := newTestProxy(t, capturingUpstream(&capturedRequest{}, nil))
	defer closeUpstream()

	req := httptest.NewRequest(http.MethodPost, "/?query=SELECT+count()+FROM", strings.NewReader("events WHERE id > 5"))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	require.Len(t, logger.entries, 1)
	require.Equal(t, "SELECT count() FROM\nevents WHERE id > 5", logger.entries[0].Input)
}

func TestRefusesAPaddedBodyThatWouldPushAStatementPastTheInspectionWindow(t *testing.T) {
	reached := false
	handler, logger, closeUpstream := newTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}, `(?i)\bdrop\b`)
	defer closeUpstream()

	// A comment long enough to bury the statement behind the window the policy can see
	payload := "/*" + strings.Repeat("x", maxInspectBytes) + "*/ DROP TABLE events"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload)))

	require.False(t, reached)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Contains(t, recorder.Body.String(), "blocks commands")
	require.Empty(t, logger.entries)
}

func TestForwardsABodyLargerThanTheInspectionCapWhenNothingIsBlocked(t *testing.T) {
	var captured capturedRequest
	handler, _, closeUpstream := newTestProxy(t, capturingUpstream(&captured, nil))
	defer closeUpstream()

	payload := "INSERT INTO events FORMAT JSONEachRow\n" + strings.Repeat("x", maxInspectBytes+1024)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	require.Equal(t, len(payload), len(captured.body))
	require.Equal(t, payload, string(captured.body))
}

func TestTruncatesWhatALargeStatementWritesToTheRecording(t *testing.T) {
	handler, logger, closeUpstream := newTestProxy(t, capturingUpstream(&capturedRequest{}, nil))
	defer closeUpstream()

	payload := "INSERT INTO events VALUES " + strings.Repeat("a", maxLoggedStatementBytes*2)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload)))

	require.Len(t, logger.entries, 1)
	require.True(t, strings.HasSuffix(logger.entries[0].Input, "... [truncated]"))
	require.Less(t, len(logger.entries[0].Input), len(payload))
}

func TestRefusesACompressedBodyThatExpandsPastTheInspectionWindow(t *testing.T) {
	reached := false
	handler, _, closeUpstream := newTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}, `(?i)\bdrop\b`)
	defer closeUpstream()

	payload := "/*" + strings.Repeat("x", maxInspectBytes*2) + "*/ DROP TABLE events"
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(gzipped(t, payload)))
	req.Header.Set("Content-Encoding", "gzip")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	require.False(t, reached)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Contains(t, recorder.Body.String(), "blocks commands")
}

func TestRejectsABodyEncodingItCannotInspect(t *testing.T) {
	reached := false
	handler, _, closeUpstream := newTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})
	defer closeUpstream()

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("SELECT 1"))
	req.Header.Set("Content-Encoding", "zstd")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	require.False(t, reached)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Contains(t, recorder.Body.String(), "command blocking policy")

	req = httptest.NewRequest(http.MethodPost, "/?decompress=1", strings.NewReader("SELECT 1"))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	require.False(t, reached)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Contains(t, recorder.Body.String(), "decompress=1")
}

func TestRecordsTheRowCountsClickHouseReports(t *testing.T) {
	handler, logger, closeUpstream := newTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("X-ClickHouse-Summary", `{"read_rows":"120","written_rows":"0","result_rows":"7"}`)
		w.WriteHeader(http.StatusOK)
	})
	defer closeUpstream()

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/?query=SELECT+1", http.NoBody))

	require.Len(t, logger.entries, 1)
	require.Contains(t, logger.entries[0].Output, "7 row(s) returned")
	require.Contains(t, logger.entries[0].Output, "120 row(s) read")
	require.NotContains(t, logger.entries[0].Output, "row(s) written")
}

func TestRecordsAStreamingFailureAsInterruptedRatherThanSuccess(t *testing.T) {
	handler, logger, closeUpstream := newTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Length", "64")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))

		if hijacker, ok := w.(http.Hijacker); ok {
			conn, _, err := hijacker.Hijack()
			require.NoError(t, err)
			_ = conn.Close()
		}
	})
	defer closeUpstream()

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/?query=SELECT+1", http.NoBody))

	require.Len(t, logger.entries, 1)
	require.Contains(t, logger.entries[0].Output, "INTERRUPTED")
}

func TestRecordsAnUpstreamErrorAndStillReturnsItToTheClient(t *testing.T) {
	handler, logger, closeUpstream := newTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("X-ClickHouse-Exception-Code", "60")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Code: 60. DB::Exception: Table analytics.missing does not exist. (UNKNOWN_TABLE)\n"))
	})
	defer closeUpstream()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/?query=SELECT+1+FROM+missing", http.NoBody))

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Contains(t, recorder.Body.String(), "UNKNOWN_TABLE")

	require.Len(t, logger.entries, 1)
	require.Contains(t, logger.entries[0].Output, "ERROR:")
	require.Contains(t, logger.entries[0].Output, "UNKNOWN_TABLE")
}

func TestRecordsNothingForARequestThatCarriesNoStatement(t *testing.T) {
	handler, logger, closeUpstream := newTestProxy(t, capturingUpstream(&capturedRequest{}, nil))
	defer closeUpstream()

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ping", http.NoBody))

	require.Empty(t, logger.entries)
}

func TestReportsAnUnreachableTargetAsAClickHouseError(t *testing.T) {
	logger := &recordingLogger{}
	proxy := NewClickHouseProxy(ClickHouseProxyConfig{
		// Port 1 on loopback refuses immediately
		TargetAddr:    "127.0.0.1:1",
		Username:      "pam_svc",
		SessionID:     "session-1",
		SessionLogger: logger,
	})

	recorder := httptest.NewRecorder()
	proxy.handler(zerolog.Nop()).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/?query=SELECT+1", http.NoBody))

	require.Equal(t, http.StatusBadGateway, recorder.Code)
	require.Equal(t, "210", recorder.Header().Get("X-ClickHouse-Exception-Code"))
	require.Contains(t, recorder.Body.String(), "(NETWORK_ERROR)")
	require.Len(t, logger.entries, 1)
	require.Contains(t, logger.entries[0].Output, "ERROR:")
}
