package clickhouse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSplitFormatClause(t *testing.T) {
	cases := []struct {
		name       string
		sql        string
		wantBody   string
		wantFormat string
	}{
		{
			name:       "the clause the node client appends",
			sql:        "SELECT 1 \nFORMAT JSON",
			wantBody:   "SELECT 1",
			wantFormat: "JSON",
		},
		{name: "trailing semicolon", sql: "SELECT 1 FORMAT JSONCompact;", wantBody: "SELECT 1", wantFormat: "JSONCompact"},
		{name: "no clause", sql: "SELECT 1", wantBody: "SELECT 1", wantFormat: ""},
		{
			// "format" inside the statement is not the clause, and peeling it off would corrupt the query.
			name:     "a call to formatDateTime is not a clause",
			sql:      "SELECT formatDateTime(now(), '%F')",
			wantBody: "SELECT formatDateTime(now(), '%F')",
		},
		{name: "a column named format", sql: "SELECT format FROM t", wantBody: "SELECT format FROM t"},
		{name: "format with no name", sql: "SELECT 1 FORMAT", wantBody: "SELECT 1 FORMAT"},
		// A trailing identifier that merely starts with "format" is not a clause, and splitting it would
		// throw away the operand in front of it.
		{name: "a table whose name starts with format", sql: "SELECT * FROM format_events", wantBody: "SELECT * FROM format_events"},
		{name: "an alias that starts with format", sql: "SELECT 1 AS format_id", wantBody: "SELECT 1 AS format_id"},
		{name: "ordering by a column called formatted", sql: "SELECT x FROM t ORDER BY formatted", wantBody: "SELECT x FROM t ORDER BY formatted"},
		{name: "lowercase clause", sql: "select 1 format json", wantBody: "select 1", wantFormat: "json"},
		{name: "mixed case clause", sql: "SELECT 1 FoRmAt JSONCompact", wantBody: "SELECT 1", wantFormat: "JSONCompact"},
		{name: "format alone is not a clause", sql: "FORMAT JSON", wantBody: "FORMAT JSON"},
		{name: "format inside a string literal", sql: "SELECT 'FORMAT JSON'", wantBody: "SELECT 'FORMAT JSON'"},
		{name: "several trailing semicolons", sql: "SELECT 1 ; ;", wantBody: "SELECT 1"},
		// A rune that shrinks when uppercased would shift byte offsets if the scan ran over a folded copy.
		{name: "a value whose uppercase form is shorter", sql: "SELECT 'ı' AS x FORMAT JSON", wantBody: "SELECT 'ı' AS x", wantFormat: "JSON"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, format := splitFormatClause(tc.sql)
			require.Equal(t, tc.wantBody, body)
			require.Equal(t, tc.wantFormat, format)
		})
	}
}

func TestIsWrappable(t *testing.T) {
	for _, body := range []string{"SELECT 1", "  select 1", "WITH x AS (SELECT 1) SELECT * FROM x", "EXPLAIN SELECT 1"} {
		require.True(t, isWrappable(body), body)
	}
	for _, body := range []string{"SHOW TABLES", "DESCRIBE TABLE t", "INSERT INTO t VALUES (1)", "CREATE TABLE t (a UInt8) ENGINE = Memory"} {
		require.False(t, isWrappable(body), body)
	}

	// Editors put comments and byte-order marks in front of perfectly ordinary statements.
	for _, body := range []string{"-- a note\nSELECT 1", "/* a note */ SELECT 1", "\ufeffSELECT 1", "/* a */ -- b\n  select 1"} {
		require.True(t, isWrappable(body), body)
	}
	// A prefix match is not a keyword match.
	require.False(t, isWrappable("SELECTFOO 1"))
	require.False(t, isWrappable("WITHOUT_ROWS()"))
}

func TestCheckSpliceable(t *testing.T) {
	ok := []string{
		"SELECT 1",
		"SELECT (1 + 2) AS x",
		"SELECT 'a;b) --' AS s",
		"SELECT \"col;)\" FROM t",
		"SELECT 1 -- a trailing ; comment",
		"SELECT 1 /* a ) comment */",
	}
	for _, body := range ok {
		require.NoError(t, checkSpliceable(body), body)
	}

	// Each of these would otherwise run something other than what was recorded and policy-checked.
	bad := []string{
		"SELECT 1) ; DROP TABLE users; --",
		"SELECT 1) UNION ALL (SELECT 2",
		"SELECT 1; SELECT 2",
		"SELECT (1",
		"SELECT 'unterminated",
	}
	for _, body := range bad {
		require.Error(t, checkSpliceable(body), body)
	}
}

// The bridge has to answer what ClickHouse's own HTTP interface answers, so both are asked the same thing
// and the envelopes compared.
func TestBridgeMatchesHTTPInterface(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	statements := []string{
		"SELECT 1 AS n, 'x' AS s",
		"SELECT map('a', 1::UInt64) AS m, tuple('p', 2) AS t",
		"SELECT number, toString(number) AS s FROM numbers(5)",
		"SELECT id, note FROM pam_write_test ORDER BY id LIMIT 3",
		"SELECT * FROM exotic ORDER BY id",
		"SELECT count() AS c FROM users",
		"SELECT NULL::Nullable(String) AS nothing",
		"WITH 2 AS x SELECT x * 3 AS y",
	}

	for _, format := range []string{formatJSON, formatJSONCompact} {
		for _, statement := range statements {
			t.Run(format+": "+statement, func(t *testing.T) {
				viaBridge := queryBridge(t, statement, format)
				viaHTTP := queryRealHTTP(t, statement, format)

				require.Equal(t, viaHTTP.Meta, viaBridge.Meta, "column metadata should match ClickHouse")
				require.Equal(t, viaHTTP.Rows, viaBridge.Rows, "row count should match ClickHouse")
				require.JSONEq(t, string(viaHTTP.Data), string(viaBridge.Data), "rows should match ClickHouse")
			})
		}
	}
}

func TestBridgeReportsClickHouseErrors(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	addr := startBridgeProxy(t, nil, &recordingLogger{})
	status, body := postStatement(t, addr, "SELECT * FROM table_that_is_not_there FORMAT JSON")

	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, body, "table_that_is_not_there")
	require.Contains(t, body, "DB::Exception")
}

func TestBridgeAppliesCommandBlocking(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	recorder := &recordingLogger{}
	addr := startBridgeProxy(t, []string{`(?i)\bdrop\b`}, recorder)

	status, body := postStatement(t, addr, "DROP TABLE pam_write_test FORMAT JSON")
	require.Equal(t, http.StatusForbidden, status)
	require.Contains(t, body, "blocked by the command blocking policy")
	require.True(t, recorder.contains("DROP TABLE pam_write_test"))
}

func TestBridgeRecordsStatements(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	recorder := &recordingLogger{}
	addr := startBridgeProxy(t, nil, recorder)

	status, _ := postStatement(t, addr, "SELECT 42 AS answer FORMAT JSON")
	require.Equal(t, http.StatusOK, status)
	require.True(t, recorder.contains("SELECT 42 AS answer"), recorder.dump())
	require.Contains(t, recorder.dump(), "1 row(s) returned")
}

// A native-only account has no HTTP upstream, so TargetAddr is deliberately empty.
func startBridgeProxy(t *testing.T, blocked []string, logger *recordingLogger) string {
	t.Helper()

	patterns := compileForTest(t, blocked)
	proxy := NewClickHouseProxy(ClickHouseProxyConfig{
		NativeAddr:      envOr("PAM_CLICKHOUSE_NATIVE", "127.0.0.1:9000"),
		Username:        envOr("PAM_CLICKHOUSE_USER", "default"),
		Password:        envOr("PAM_CLICKHOUSE_PASSWORD", "clickhouse"),
		Database:        envOr("PAM_CLICKHOUSE_DB", "analytics"),
		SessionID:       "bridge-test",
		SessionLogger:   logger,
		BlockedCommands: patterns,
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _ = proxy.HandleConnection(ctx, conn) }()
		}
	}()

	return listener.Addr().String()
}

func postStatement(t *testing.T, addr string, sql string) (int, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/", strings.NewReader(sql))
	require.NoError(t, err)

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func queryBridge(t *testing.T, statement string, format string) bridgeEnvelope {
	t.Helper()

	addr := startBridgeProxy(t, nil, &recordingLogger{})
	status, body := postStatement(t, addr, statement+" \nFORMAT "+format)
	require.Equal(t, http.StatusOK, status, body)

	var envelope bridgeEnvelope
	require.NoError(t, json.Unmarshal([]byte(body), &envelope), body)
	return envelope
}

func queryRealHTTP(t *testing.T, statement string, format string) bridgeEnvelope {
	t.Helper()

	target := fmt.Sprintf("http://%s/?database=%s",
		envOr("PAM_CLICKHOUSE_HTTP", "127.0.0.1:8123"), envOr("PAM_CLICKHOUSE_DB", "analytics"))

	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(statement+" \nFORMAT "+format))
	require.NoError(t, err)
	req.Header.Set("X-ClickHouse-User", envOr("PAM_CLICKHOUSE_USER", "default"))
	req.Header.Set("X-ClickHouse-Key", envOr("PAM_CLICKHOUSE_PASSWORD", "clickhouse"))

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	var envelope bridgeEnvelope
	require.NoError(t, json.Unmarshal(body, &envelope), string(body))
	return envelope
}

// The bridge exists for a server with HTTP genuinely turned off, so it is also exercised against one.
func TestBridgeAgainstHTTPDisabledServer(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	native := envOr("PAM_CLICKHOUSE_NOHTTP_NATIVE", "127.0.0.1:19001")
	probe, err := net.DialTimeout("tcp", native, 2*time.Second)
	if err != nil {
		t.Skipf("no HTTP-disabled ClickHouse on %s: %v", native, err)
	}
	probe.Close()

	bridged := NewClickHouseProxy(ClickHouseProxyConfig{
		NativeAddr:    native,
		Username:      "default",
		Password:      envOr("PAM_CLICKHOUSE_NOHTTP_PASSWORD", "clickhouse"),
		Database:      "default",
		SessionID:     "bridge-nohttp-test",
		SessionLogger: &recordingLogger{},
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() { _ = bridged.HandleConnection(ctx, conn) }()
		}
	}()

	status, body := postStatement(t, listener.Addr().String(),
		"SELECT 1 AS n, map('k', 'v') AS m \nFORMAT JSON")
	require.Equal(t, http.StatusOK, status, body)

	var envelope bridgeEnvelope
	require.NoError(t, json.Unmarshal([]byte(body), &envelope), body)
	require.Equal(t, 1, envelope.Rows)
	require.Equal(t, []bridgeColumn{{Name: "n", Type: "UInt8"}, {Name: "m", Type: "Map(String, String)"}}, envelope.Meta)
	require.JSONEq(t, `[{"n":1,"m":{"k":"v"}}]`, string(envelope.Data))
}

// The SQL editor asks for its format with the default_format setting rather than a FORMAT clause, which is
// a different code path and was returning nothing at all.
func TestBridgeHonoursDefaultFormatSetting(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	addr := startBridgeProxy(t, nil, &recordingLogger{})

	for _, format := range []string{formatJSON, formatJSONCompact} {
		t.Run(format, func(t *testing.T) {
			status, body := postGET(t, addr,
				"/?default_format="+format+"&max_execution_time=30&query="+
					urlEscape("SELECT id, tags FROM exotic ORDER BY id"))
			require.Equal(t, http.StatusOK, status, body)

			var envelope bridgeEnvelope
			require.NoError(t, json.Unmarshal([]byte(body), &envelope), body)
			require.Equal(t, 1, envelope.Rows)
			require.Equal(t, []bridgeColumn{
				{Name: "id", Type: "UInt64"},
				{Name: "tags", Type: "Map(String, UInt64)"},
			}, envelope.Meta)
		})
	}
}

// A statement whose last line is a comment would otherwise swallow the wrapper's closing parenthesis.
func TestBridgeHandlesATrailingComment(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	addr := startBridgeProxy(t, nil, &recordingLogger{})
	status, body := postStatement(t, addr, "SELECT 1 AS n\n-- a trailing note\nFORMAT JSON")
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, `"n":1`)
}

// A result bigger than one block used to fail because ch-go refuses a second block with no handler.
func TestBridgeHandlesAMultiBlockResult(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	addr := startBridgeProxy(t, nil, &recordingLogger{})

	// Comfortably more than one block (max_block_size defaults to ~65k) and under the row cap.
	const rows = 80000

	t.Run("with a format", func(t *testing.T) {
		status, body := postStatement(t, addr, fmt.Sprintf("SELECT number FROM numbers(%d) \nFORMAT JSONCompact", rows))
		require.Equal(t, http.StatusOK, status, body[:min(len(body), 400)])

		var envelope bridgeEnvelope
		require.NoError(t, json.Unmarshal([]byte(body), &envelope))
		require.Equal(t, rows, envelope.Rows)
	})

	t.Run("without a format", func(t *testing.T) {
		status, body := postStatement(t, addr, fmt.Sprintf("SELECT number FROM numbers(%d)", rows))
		require.Equal(t, http.StatusOK, status, body)
	})
}

func TestBridgeRefusesAResultBeyondTheRowCap(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	addr := startBridgeProxy(t, nil, &recordingLogger{})
	status, body := postStatement(t, addr,
		fmt.Sprintf("SELECT number FROM numbers(%d) \nFORMAT JSONCompact", maxBridgeRows+1000))

	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, body, "more than 100000 rows")
	// The refusal is the gateway's own, so it must not be dressed up as a network error.
	require.Contains(t, body, "TOO_MANY_ROWS")
	require.NotContains(t, body, "decode block", "ch-go's internal wrapping should not reach the client")
}

// /ping is a health check, and on a native-only account it used to be refused as an empty statement.
func TestBridgeAnswersPing(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	addr := startBridgeProxy(t, nil, &recordingLogger{})
	status, body := postGET(t, addr, "/ping")
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, body, "Ok.")
}

// A parameter is data. Values that are awkward to quote must survive unchanged.
func TestBridgeParameterRoundTrip(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	addr := startBridgeProxy(t, nil, &recordingLogger{})

	for _, value := range []string{"plain", "it's", `back\slash`, "a,b", "  spaced  ", "ünïcødé", "0", ""} {
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			status, body := postGET(t, addr,
				"/?param_v="+urlEscape(value)+"&query="+urlEscape("SELECT {v:String} AS got FORMAT JSON"))
			require.Equal(t, http.StatusOK, status, body)

			var envelope bridgeEnvelope
			require.NoError(t, json.Unmarshal([]byte(body), &envelope), body)

			var rows []struct {
				Got string `json:"got"`
			}
			require.NoError(t, json.Unmarshal(envelope.Data, &rows))
			require.Len(t, rows, 1)
			require.Equal(t, value, rows[0].Got)
		})
	}
}

// @clickhouse/client.insert() sends `INSERT INTO t FORMAT JSONEachRow` with the rows in the body, which goes
// down the no-format path as one native query carrying inline data. It must complete rather than sit until
// the server's receive timeout, and the rows have to actually land.
func TestBridgeInsertWithInlineData(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	addr := startBridgeProxy(t, nil, &recordingLogger{})
	marker := fmt.Sprintf("bridge-insert-%d", time.Now().UnixNano())

	type result struct {
		status int
		body   string
	}
	done := make(chan result, 1)
	go func() {
		status, body, err := postStatementE(addr,
			fmt.Sprintf("INSERT INTO pam_write_test (id, note) FORMAT JSONEachRow\n{\"id\":9100,\"note\":%q}", marker))
		if err != nil {
			done <- result{status: -1, body: err.Error()}
			return
		}
		done <- result{status: status, body: body}
	}()

	select {
	case got := <-done:
		require.Equal(t, http.StatusOK, got.status, got.body)
	case <-time.After(45 * time.Second):
		t.Fatal("the bridge hung on an INSERT carrying inline data")
	}

	// An empty 200 that quietly inserted nothing would be worse than hanging.
	require.Equal(t, "1", queryDirect(t, fmt.Sprintf("SELECT count() FROM pam_write_test WHERE note = '%s'", marker)))
}
