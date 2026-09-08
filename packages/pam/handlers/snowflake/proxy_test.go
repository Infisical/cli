package snowflake

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
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

func newTestProxy(t *testing.T, blocked ...string) (*SnowflakeProxy, *recordingLogger) {
	t.Helper()

	patterns := make([]*regexp.Regexp, 0, len(blocked))
	for _, p := range blocked {
		patterns = append(patterns, regexp.MustCompile(p))
	}

	logger := &recordingLogger{}
	proxy := NewSnowflakeProxy(SnowflakeProxyConfig{
		Account:         "acme-test",
		Username:        "pam_svc",
		SessionID:       "session-1",
		SessionLogger:   logger,
		BlockedCommands: patterns,
	})
	proxy.token = sessionToken(proxy.config)

	return proxy, logger
}

func postJSON(t *testing.T, handler http.HandlerFunc, token string, sqlText string, gzipped bool) map[string]any {
	t.Helper()

	encoded, err := json.Marshal(map[string]any{"sqlText": sqlText})
	require.NoError(t, err)

	var payload bytes.Buffer
	if gzipped {
		writer := gzip.NewWriter(&payload)
		_, err = writer.Write(encoded)
		require.NoError(t, err)
		require.NoError(t, writer.Close())
	} else {
		payload.Write(encoded)
	}

	req := httptest.NewRequest(http.MethodPost, "/queries/v1/query-request", bytes.NewReader(payload.Bytes()))
	if gzipped {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if token != "" {
		req.Header.Set("Authorization", `Snowflake Token="`+token+`"`)
	}

	recorder := httptest.NewRecorder()
	handler(recorder, req)

	var decoded map[string]any
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&decoded))
	return decoded
}

func TestLoginHandsOutTheGatewayToken(t *testing.T) {
	proxy, _ := newTestProxy(t)

	recorder := httptest.NewRecorder()
	proxy.handleLogin(recorder, httptest.NewRequest(http.MethodPost, "/session/v1/login-request", nil))

	var body map[string]any
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&body))
	require.True(t, body["success"].(bool))
	// The client is never given a Snowflake token, so it cannot reach the account outside the session
	require.Equal(t, proxy.token, body["data"].(map[string]any)["token"])
}

func TestQueryRequiresTheToken(t *testing.T) {
	proxy, logger := newTestProxy(t)

	for _, token := range []string{"wrong", proxy.token[:len(proxy.token)-1], proxy.token + "x"} {
		body := postJSON(t, proxy.handleQuery(zeroLogger{}), token, "SELECT 1", false)
		require.False(t, body["success"].(bool))
	}
	require.Empty(t, logger.entries)
}

func TestBlockedStatementNeverReachesSnowflake(t *testing.T) {
	proxy, logger := newTestProxy(t, `(?i)^\s*drop\b`)

	// A nil driver connection proves the statement was refused before it would have run
	body := postJSON(t, proxy.handleQuery(zeroLogger{}), proxy.token, "  DROP TABLE orders", false)

	require.False(t, body["success"].(bool))
	require.Contains(t, body["message"].(string), "command blocking policy")
	require.Len(t, logger.entries, 1)
	require.Equal(t, "DROP TABLE orders", logger.entries[0].Input)
	require.Contains(t, logger.entries[0].Output, "BLOCKED:")
}

func TestBlockedStatementIsReadFromAGzippedBody(t *testing.T) {
	proxy, logger := newTestProxy(t, `(?i)\btruncate\b`)

	body := postJSON(t, proxy.handleQuery(zeroLogger{}), proxy.token, "TRUNCATE TABLE orders", true)

	require.False(t, body["success"].(bool))
	require.Len(t, logger.entries, 1)
	require.Equal(t, "TRUNCATE TABLE orders", logger.entries[0].Input)
}

func TestResultTranslation(t *testing.T) {
	result := &queryResult{
		columns: []column{{Name: "ID", Type: "text"}, {Name: "NAME", Type: "text"}},
		rows:    [][]any{{"1", "alice"}, {"2", nil}},
		queryID: "01b2-real",
		elapsed: 5 * time.Millisecond,
	}

	data := result.data()
	require.Equal(t, result.columns, data["rowtype"])
	require.Equal(t, [][]any{{"1", "alice"}, {"2", nil}}, data["rowset"])
	require.Equal(t, 2, data["total"])
	// Snowflake's own id, so a client that cancels or looks the query up names the right one
	require.Equal(t, "01b2-real", data["queryId"])
	require.Equal(t, "2 row(s), 5ms", result.summary())

	truncated := &queryResult{rows: make([][]any, 3), truncated: true}
	require.Contains(t, truncated.summary(), "truncated at")
}

// Snowflake reports the real row count even when only the first slice comes back inline
func TestQueryRecordsTruncationAgainstTheReportedTotal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":true,"data":{"queryResultFormat":"json","rowtype":[],"rowset":[["1"]],"total":42}}`)
	}))
	t.Cleanup(server.Close)

	client := newUpstream(SnowflakeProxyConfig{Account: "acme-test"})
	client.baseURL = server.URL

	result, err := client.query(t.Context(), "SELECT * FROM events", nil)

	require.NoError(t, err)
	require.True(t, result.truncated)
	require.Contains(t, result.summary(), "truncated at")
}

// A client on the official Go driver decodes sessionId as an int64 and fails the login on anything else
func TestLoginReportsANumericSessionID(t *testing.T) {
	data := loginData("token", SnowflakeProxyConfig{SessionID: "9f1c7a3e-0e3d-4d5a-8b21-1f2c3d4e5f60"}, nil, nil)

	id, ok := data["sessionId"].(int64)
	require.True(t, ok)
	require.Positive(t, id)
	require.Equal(t, id, loginData("t", SnowflakeProxyConfig{SessionID: "9f1c7a3e-0e3d-4d5a-8b21-1f2c3d4e5f60"}, nil, nil)["sessionId"])
}

// Cancelling has to reach Snowflake, or the statement runs on and the warehouse bills for it
func TestAbortForwardsTheStatementToSnowflake(t *testing.T) {
	var aborted string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		aborted = string(body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":true,"data":{}}`)
	}))
	t.Cleanup(server.Close)

	proxy, _ := newTestProxy(t)
	proxy.upstream = newUpstream(proxy.config)
	proxy.upstream.baseURL = server.URL
	proxy.upstream.requestID = "req-1"

	// The driver cancels on a second connection, so the lookup crosses proxies
	inflightQueries.Store(proxy.inflightKey("req-1"), &inflightQuery{upstream: proxy.upstream, cancel: func() {}})
	t.Cleanup(func() { inflightQueries.Delete(proxy.inflightKey("req-1")) })

	request := httptest.NewRequest(http.MethodPost, "/queries/v1/abort-request", strings.NewReader(`{"requestId":"req-1"}`))
	request.Header.Set("Authorization", `Snowflake Token="`+proxy.token+`"`)
	recorder := httptest.NewRecorder()
	proxy.handleAbort(zeroLogger{})(recorder, request)

	require.Contains(t, aborted, `"requestId":"req-1"`)
}

func TestCloseEndsTheSnowflakeSession(t *testing.T) {
	var deleted bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deleted = r.URL.Path == "/session" && r.URL.Query().Get("delete") == "true"
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":true,"data":{}}`)
	}))
	t.Cleanup(server.Close)

	proxy, _ := newTestProxy(t)
	proxy.upstream = newUpstream(proxy.config)
	proxy.upstream.baseURL = server.URL

	proxy.Close()

	require.True(t, deleted)
}

// Snowflake accepts a warehouse or role the credential can't use and just leaves it unset
func TestProbeRejectsAnUnusableWarehouse(t *testing.T) {
	proxy, _ := newTestProxy(t)
	proxy.config.Warehouse = "analytics_wh"
	proxy.sessionCtx = map[string]string{"warehouseName": ""}

	require.ErrorContains(t, proxy.Probe(t.Context()), "analytics_wh")

	// Snowflake upper-cases an unquoted identifier
	proxy.sessionCtx = map[string]string{"warehouseName": "ANALYTICS_WH"}
	proxy.upstream = newUpstream(proxy.config)
	proxy.upstream.baseURL = "http://127.0.0.1:1"
	require.NotContains(t, proxy.Probe(t.Context()).Error(), "analytics_wh")
}

// The gateway replaces http.DefaultTransport, so the upstream client must carry its own.
func TestUpstreamCarriesItsOwnTransport(t *testing.T) {
	client := newUpstream(SnowflakeProxyConfig{Account: "acme-test"})

	require.NotNil(t, client.client.Transport)
	require.NotEqual(t, http.DefaultTransport, client.client.Transport)
	require.Equal(t, "https://acme-test.snowflakecomputing.com", client.baseURL)
}

// A client hanging up has to end the session, or the recording is never flushed
func TestListenerUnblocksWhenTheConnectionCloses(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	listener := newSingleConnListener(server)
	conn, err := listener.Accept()
	require.NoError(t, err)

	require.NoError(t, conn.Close())

	_, err = listener.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

// Snowflake expires a session token roughly hourly, inside the length of a long PAM session
func TestQueryRenewsAnExpiredSessionToken(t *testing.T) {
	var renewals int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/session/token-request":
			renewals++
			require.Contains(t, r.Header.Get("Authorization"), "master-token")
			fmt.Fprint(w, `{"success":true,"data":{"sessionToken":"fresh-token","masterToken":"master-token"}}`)
		case "/queries/v1/query-request":
			if strings.Contains(r.Header.Get("Authorization"), "stale-token") {
				fmt.Fprintf(w, `{"success":false,"code":"%s","message":"session expired"}`, sessionExpiredCode)
				return
			}
			fmt.Fprint(w, `{"success":true,"data":{"queryResultFormat":"json","rowtype":[{"name":"N"}],"rowset":[["1"]]}}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	client := newUpstream(SnowflakeProxyConfig{Account: "acme-test"})
	client.baseURL = server.URL
	client.token, client.masterTok = "stale-token", "master-token"

	result, err := client.query(t.Context(), "SELECT 1", nil)

	require.NoError(t, err)
	require.Equal(t, 1, renewals)
	require.Equal(t, "fresh-token", client.token)
	require.Len(t, result.rows, 1)
}

func TestQueryForwardsBindings(t *testing.T) {
	var forwarded string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		forwarded = string(body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":true,"data":{"queryResultFormat":"json","rowtype":[],"rowset":[]}}`)
	}))
	t.Cleanup(server.Close)

	client := newUpstream(SnowflakeProxyConfig{Account: "acme-test"})
	client.baseURL = server.URL

	_, err := client.query(t.Context(), "SELECT ?", json.RawMessage(`{"1":{"type":"TEXT","value":"PUBLIC"}}`))

	require.NoError(t, err)
	require.Contains(t, forwarded, `"bindings":{"1":{"type":"TEXT","value":"PUBLIC"}}`)
}

// A passphrase left over from an earlier credential must not break an unencrypted key
func TestParsePrivateKeyIgnoresAStalePassphrase(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	plain := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	parsed, err := parsePrivateKey(plain, "left-over-passphrase")

	require.NoError(t, err)
	require.Equal(t, key.N, parsed.N)
}

// A query slower than about 45 seconds comes back "in progress" with a URL to poll
func TestQueryPollsAnInProgressResult(t *testing.T) {
	var polls int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/queries/v1/query-request" {
			fmt.Fprintf(w, `{"success":false,"code":"%s","data":{"getResultUrl":"/queries/v1/result"}}`, queryInProgressCode)
			return
		}
		polls++
		if polls < 2 {
			fmt.Fprintf(w, `{"success":false,"code":"%s","data":{"getResultUrl":"/queries/v1/result"}}`, queryInProgressCode)
			return
		}
		fmt.Fprint(w, `{"success":true,"data":{"queryResultFormat":"json","rowtype":[{"name":"N"}],"rowset":[["1"]]}}`)
	}))
	t.Cleanup(server.Close)

	client := newUpstream(SnowflakeProxyConfig{Account: "acme-test"})
	client.baseURL = server.URL

	result, err := client.query(t.Context(), "SELECT long_running()", nil)

	require.NoError(t, err)
	require.Equal(t, 2, polls)
	require.Len(t, result.rows, 1)
}

// Each client connection gets its own proxy, so a token minted by one must be accepted by the next
func TestSessionTokenIsStableAcrossConnections(t *testing.T) {
	config := SnowflakeProxyConfig{SessionID: "session-1", PrivateKey: "key-material"}

	require.Equal(t, sessionToken(config), sessionToken(config))
	require.NotEqual(t, sessionToken(config), sessionToken(SnowflakeProxyConfig{SessionID: "session-2", PrivateKey: "key-material"}))
	require.NotEqual(t, sessionToken(config), sessionToken(SnowflakeProxyConfig{SessionID: "session-1", PrivateKey: "other"}))
}

// The JDBC driver reads AUTOCOMMIT off the login response and panics when it is missing
func TestLoginForwardsSnowflakeSessionParameters(t *testing.T) {
	params := json.RawMessage(`[{"name":"AUTOCOMMIT","value":true}]`)

	data := loginData("token", SnowflakeProxyConfig{}, nil, params)
	require.Equal(t, params, data["parameters"])

	require.Equal(t, json.RawMessage("[]"), loginData("token", SnowflakeProxyConfig{}, nil, nil)["parameters"])
}

func TestGzippedRequestIsBoundedAfterDecompression(t *testing.T) {
	var payload bytes.Buffer
	writer := gzip.NewWriter(&payload)
	_, err := writer.Write([]byte(`{"sqlText":"` + strings.Repeat("A", 4<<20) + `"}`))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.Less(t, payload.Len(), maxRequestBytes)

	req := httptest.NewRequest(http.MethodPost, "/queries/v1/query-request", bytes.NewReader(payload.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")

	var out struct {
		SqlText string `json:"sqlText"`
	}
	require.Error(t, decodeRequest(httptest.NewRecorder(), req, &out))
}
