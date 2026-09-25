package clickhouse

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func itOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}
}

func startProxy(t *testing.T, config ClickHouseProxyConfig) string {
	t.Helper()

	proxy := NewClickHouseProxy(config)

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() { _ = proxy.HandleConnection(ctx, conn) }()
		}
	}()

	return fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
}

func baseConfig(logger *recordingLogger, blocked ...string) ClickHouseProxyConfig {
	patterns := make([]*regexp.Regexp, 0, len(blocked))
	for _, p := range blocked {
		patterns = append(patterns, regexp.MustCompile(p))
	}
	return ClickHouseProxyConfig{
		TargetAddr:      envOr("PAM_CLICKHOUSE_HTTP", "127.0.0.1:8123"),
		NativeAddr:      envOr("PAM_CLICKHOUSE_NATIVE", "127.0.0.1:9000"),
		Username:        envOr("PAM_CLICKHOUSE_USER", "default"),
		Password:        envOr("PAM_CLICKHOUSE_PASSWORD", "clickhouse"),
		Database:        envOr("PAM_CLICKHOUSE_DB", "analytics"),
		SessionID:       "edge-test",
		SessionLogger:   logger,
		BlockedCommands: patterns,
	}
}

func TestNativeCompressionBothWays(t *testing.T) {
	itOnly(t)

	for _, compression := range []string{"1", "0"} {
		t.Run("compression="+compression, func(t *testing.T) {
			recorder := &recordingLogger{}
			port := startProxy(t, baseConfig(recorder, `(?i)\bdrop\b`))

			out, err := runClient(t, port, "SELECT 1;\nSELECT 'second';\nDROP TABLE pam_write_test;",
				"--compression", compression)
			t.Logf("%s", out)

			require.Error(t, err, "the blocked statement should fail the client")
			require.Contains(t, out, "second", "earlier statements should still run")
			require.Contains(t, out, "blocked by the command blocking policy")
			require.True(t, recorder.contains("SELECT 'second'"), recorder.dump())
		})
	}
}

func TestNativeInsertWithCompressionBothWays(t *testing.T) {
	itOnly(t)

	for _, compression := range []string{"1", "0"} {
		t.Run("compression="+compression, func(t *testing.T) {
			port := startProxy(t, baseConfig(&recordingLogger{}))
			marker := fmt.Sprintf("edge-%s-%d", compression, time.Now().UnixNano())

			out, err := runClient(t, port,
				fmt.Sprintf("INSERT INTO pam_write_test (id, note) VALUES (7001, '%s');\nSELECT note FROM pam_write_test WHERE note = '%s';", marker, marker),
				"--compression", compression)
			require.NoError(t, err, out)
			require.Contains(t, out, marker)
		})
	}
}

// A column type ch-go cannot infer can only appear in the client direction on an INSERT.
func TestNativeInsertIntoUnreadableColumnFailsClosed(t *testing.T) {
	itOnly(t)

	recorder := &recordingLogger{}
	port := startProxy(t, baseConfig(recorder))

	out, _ := runClient(t, port,
		"INSERT INTO exotic (id, tags, pair, arr, lc, dec, ts, en) VALUES (99, {'x':1}, ('p',2), ['a'], 'low', 1.0, '2026-01-01 00:00:00.000', 'a');")
	t.Logf("%s", out)

	require.Contains(t, out, "could not read the data block",
		"an unreadable INSERT should be refused with an explanation")
	require.Contains(t, out, "Map(String, UInt64)", "the message should name the offending type")
	require.Contains(t, out, "HTTP interface", "the message should point at the way that works")

	// Refusing has to mean the rows never reach ClickHouse.
	require.Equal(t, 0, countExotic(t, 99), "the refused rows should not have been written")
}

func countExotic(t *testing.T, id int) int {
	t.Helper()

	target := fmt.Sprintf("http://%s/?database=%s",
		envOr("PAM_CLICKHOUSE_HTTP", "127.0.0.1:8123"), envOr("PAM_CLICKHOUSE_DB", "analytics"))

	req, err := http.NewRequest(http.MethodPost, target,
		strings.NewReader(fmt.Sprintf("SELECT count() FROM exotic WHERE id = %d", id)))
	require.NoError(t, err)
	req.Header.Set("X-ClickHouse-User", envOr("PAM_CLICKHOUSE_USER", "default"))
	req.Header.Set("X-ClickHouse-Key", envOr("PAM_CLICKHOUSE_PASSWORD", "clickhouse"))

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	count, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, err, string(raw))
	return count
}

func TestBlockedStatementEndsTheSession(t *testing.T) {
	itOnly(t)

	recorder := &recordingLogger{}
	port := startProxy(t, baseConfig(recorder, `(?i)\bdrop\b`))

	before := countWriteTest(t)

	out, err := runClient(t, port,
		"SELECT 1;\nDROP TABLE pam_write_test;\nINSERT INTO pam_write_test (id, note) VALUES (7777, 'after-block');")
	t.Logf("%s", out)
	require.Error(t, err)
	require.Contains(t, out, "blocked by the command blocking policy")

	// Neither the blocked DROP nor the statement behind it may have run.
	require.Equal(t, before, countWriteTest(t), "nothing after a refusal should reach ClickHouse")
	require.NotContains(t, out, "after-block")
}

func countWriteTest(t *testing.T) int {
	t.Helper()

	target := fmt.Sprintf("http://%s/?database=%s",
		envOr("PAM_CLICKHOUSE_HTTP", "127.0.0.1:8123"), envOr("PAM_CLICKHOUSE_DB", "analytics"))

	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader("SELECT count() FROM pam_write_test"))
	require.NoError(t, err)
	req.Header.Set("X-ClickHouse-User", envOr("PAM_CLICKHOUSE_USER", "default"))
	req.Header.Set("X-ClickHouse-Key", envOr("PAM_CLICKHOUSE_PASSWORD", "clickhouse"))

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	count, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, err, string(raw))
	return count
}

func tlsConfigFor(t *testing.T, insecure bool) *tls.Config {
	t.Helper()
	config := &tls.Config{ServerName: "localhost", InsecureSkipVerify: insecure}
	if insecure {
		return config
	}
	pem, err := os.ReadFile(os.Getenv("PAM_CLICKHOUSE_TLS_CERT"))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pem))
	config.RootCAs = pool
	return config
}

func tlsConfigSkipOrConfig(t *testing.T) (ClickHouseProxyConfig, bool) {
	t.Helper()
	native := os.Getenv("PAM_CLICKHOUSE_TLS_NATIVE")
	httpAddr := os.Getenv("PAM_CLICKHOUSE_TLS_HTTP")
	if native == "" || httpAddr == "" {
		return ClickHouseProxyConfig{}, false
	}
	return ClickHouseProxyConfig{
		TargetAddr:    httpAddr,
		NativeAddr:    native,
		Username:      "default",
		Password:      "clickhouse",
		Database:      "analytics",
		EnableTLS:     true,
		TLSConfig:     tlsConfigFor(t, true),
		SessionID:     "edge-tls-test",
		SessionLogger: &recordingLogger{},
	}, true
}

func TestTLSUpstream(t *testing.T) {
	itOnly(t)

	config, ok := tlsConfigSkipOrConfig(t)
	if !ok {
		t.Skip("set PAM_CLICKHOUSE_TLS_NATIVE and PAM_CLICKHOUSE_TLS_HTTP to run")
	}

	t.Run("native client over TLS to the server", func(t *testing.T) {
		port := startProxy(t, config)
		out, err := runClient(t, port, "SELECT note FROM t ORDER BY id;")
		require.NoError(t, err, out)
		require.Contains(t, out, "tls-one")
	})

	t.Run("http client over TLS to the server", func(t *testing.T) {
		port := startProxy(t, config)
		status, body := postStatement(t, "127.0.0.1:"+port, "SELECT count() AS c FROM t")
		require.Equal(t, http.StatusOK, status, body)
		require.Contains(t, body, "2")
	})

	t.Run("connection tests reach both interfaces over TLS", func(t *testing.T) {
		require.NoError(t, TestConnection(context.Background(), config))
		require.NoError(t, TestNativeConnection(context.Background(), config))
	})

	t.Run("bridging over TLS for a server with no HTTP", func(t *testing.T) {
		bridged := config
		bridged.TargetAddr = ""
		port := startProxy(t, bridged)

		status, body := postStatement(t, "127.0.0.1:"+port, "SELECT id, note FROM t ORDER BY id \nFORMAT JSON")
		require.Equal(t, http.StatusOK, status, body)

		var envelope bridgeEnvelope
		require.NoError(t, json.Unmarshal([]byte(body), &envelope), body)
		require.Equal(t, 2, envelope.Rows)
		require.JSONEq(t, `[{"id":1,"note":"tls-one"},{"id":2,"note":"tls-two"}]`, string(envelope.Data))
	})

	t.Run("a pinned CA verifies rather than skipping", func(t *testing.T) {
		if os.Getenv("PAM_CLICKHOUSE_TLS_CERT") == "" {
			t.Skip("set PAM_CLICKHOUSE_TLS_CERT to run")
		}
		verified := config
		verified.TLSConfig = tlsConfigFor(t, false)
		require.NoError(t, TestNativeConnection(context.Background(), verified))
	})

	t.Run("an untrusted certificate is refused when verification is on", func(t *testing.T) {
		strict := config
		strict.TLSConfig = &tls.Config{ServerName: "localhost"}
		err := TestNativeConnection(context.Background(), strict)
		require.Error(t, err, "a self-signed certificate should not verify")
		require.Contains(t, strings.ToLower(err.Error()), "certificate")
	})
}

func TestAccountWithoutNativePortRefusesNativeClients(t *testing.T) {
	itOnly(t)

	config := baseConfig(&recordingLogger{})
	config.NativeAddr = ""
	port := startProxy(t, config)

	out, err := runClient(t, port, "SELECT 1;")
	t.Logf("%s", out)
	require.Error(t, err)
	require.Contains(t, out, "native port")

	// The HTTP interface has to keep working on the same account.
	status, body := postStatement(t, "127.0.0.1:"+port, "SELECT 1")
	require.Equal(t, http.StatusOK, status, body)
}

func TestAccountWithoutHTTPPortStillServesBothClients(t *testing.T) {
	itOnly(t)

	config := baseConfig(&recordingLogger{})
	config.TargetAddr = ""
	port := startProxy(t, config)

	out, err := runClient(t, port, "SELECT 'native-on-bridged-account';")
	require.NoError(t, err, out)
	require.Contains(t, out, "native-on-bridged-account")

	status, body := postStatement(t, "127.0.0.1:"+port, "SELECT 1 AS n \nFORMAT JSON")
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, `"n":1`)
}

func TestAccountWithNeitherPortFailsClearly(t *testing.T) {
	itOnly(t)

	config := baseConfig(&recordingLogger{})
	config.TargetAddr = ""
	config.NativeAddr = ""
	port := startProxy(t, config)

	// The session layer rejects this config before a handler ever runs, so the handler's own guard simply...
	_, _, err := postStatementE("127.0.0.1:"+port, "SELECT 1")
	require.Error(t, err, "a session with neither port must not serve anything")
}

func TestBridgeEdgeCases(t *testing.T) {
	itOnly(t)

	config := baseConfig(&recordingLogger{})
	config.TargetAddr = ""

	cases := []struct {
		name       string
		sql        string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "a statement shape that cannot be wrapped says so",
			sql:        "SHOW TABLES \nFORMAT JSON",
			wantStatus: http.StatusBadRequest,
			wantBody:   "SELECT, WITH or EXPLAIN",
		},
		{
			name:       "a format the bridge does not produce says so",
			sql:        "SELECT 1 \nFORMAT TabSeparated",
			wantStatus: http.StatusBadRequest,
			wantBody:   "JSON and JSONCompact",
		},
		{
			name:       "a statement with no format runs and returns nothing to parse",
			sql:        "CREATE TABLE IF NOT EXISTS bridge_ddl (a UInt8) ENGINE = Memory",
			wantStatus: http.StatusOK,
		},
		{
			name:       "an empty statement is refused",
			sql:        "",
			wantStatus: http.StatusBadRequest,
			wantBody:   "No statement was sent",
		},
		{
			name:       "a syntax error comes back as ClickHouse wrote it",
			sql:        "SELECT FROM WHERE \nFORMAT JSON",
			wantStatus: http.StatusBadRequest,
			wantBody:   "Syntax error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := startProxy(t, config)
			status, body := postStatement(t, "127.0.0.1:"+port, tc.sql)
			require.Equal(t, tc.wantStatus, status, body)
			if tc.wantBody != "" {
				require.Contains(t, body, tc.wantBody)
			}
		})
	}
}

func TestBridgePassesQueryParameters(t *testing.T) {
	itOnly(t)

	recorder := &recordingLogger{}
	config := baseConfig(recorder)
	config.TargetAddr = ""
	port := startProxy(t, config)

	status, body := postGET(t, "127.0.0.1:"+port,
		"/?param_wanted=7&query="+urlEscape("SELECT {wanted:UInt8} AS got FORMAT JSON"))
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, `"got":7`)
	require.Contains(t, recorder.dump(), "wanted=7", "the parameter belongs in the recording")
}

func TestCompressedRequestBodies(t *testing.T) {
	itOnly(t)

	for _, native := range []bool{false, true} {
		name := "http interface"
		if native {
			name = "bridged to native"
		}
		t.Run(name, func(t *testing.T) {
			config := baseConfig(&recordingLogger{})
			if native {
				config.TargetAddr = ""
			}
			port := startProxy(t, config)

			status, body := postGzipped(t, "127.0.0.1:"+port, "SELECT 5 AS five \nFORMAT JSON")
			require.Equal(t, http.StatusOK, status, body)

			// ClickHouse pretty-prints its JSON and the bridge writes it compact, so the rows are compared rather than...
			var envelope bridgeEnvelope
			require.NoError(t, json.Unmarshal([]byte(body), &envelope), body)
			require.JSONEq(t, `[{"five":5}]`, string(envelope.Data))
		})
	}
}

func TestSnifferEdgeCases(t *testing.T) {
	itOnly(t)

	port := startProxy(t, baseConfig(&recordingLogger{}))

	t.Run("a client that connects and says nothing is eventually dropped", func(t *testing.T) {
		conn, err := net.Dial("tcp", "127.0.0.1:"+port)
		require.NoError(t, err)
		defer conn.Close()

		// The sniff deadline is what guarantees this; without it the handler would hold the session open.
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(sniffTimeout+10*time.Second)))
		buf := make([]byte, 64)
		_, err = conn.Read(buf)
		require.Error(t, err, "the gateway should close a connection that never says anything")
		require.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the gateway held the connection open past the sniff timeout")
	})

	t.Run("garbage is not mistaken for either protocol", func(t *testing.T) {
		conn, err := net.Dial("tcp", "127.0.0.1:"+port)
		require.NoError(t, err)
		defer conn.Close()
		_, err = conn.Write([]byte{0xFF, 0xFE, 0xFD, 0xFC})
		require.NoError(t, err)
		// Bytes that are not a request line leave net/http waiting for headers, so the bound here is its...
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(45*time.Second)))

		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		require.NotErrorIs(t, err, os.ErrDeadlineExceeded, "garbage must not leave the handler hanging")
		if err == nil || n > 0 {
			require.Contains(t, string(buf[:n]), "400", "garbage should be answered as a bad HTTP request")
		} else {
			require.ErrorIs(t, err, io.EOF)
		}
	})

	t.Run("the /ping path answers", func(t *testing.T) {
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://127.0.0.1:" + port + "/ping")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("a path outside the query endpoint is refused", func(t *testing.T) {
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://127.0.0.1:" + port + "/play")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestConcurrentMixedProtocolSessions(t *testing.T) {
	itOnly(t)

	recorder := &recordingLogger{}
	port := startProxy(t, baseConfig(recorder))

	var wg sync.WaitGroup
	errs := make(chan error, 16)

	for i := range 6 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			marker := fmt.Sprintf("concurrent-native-%d", n)
			out, err := runClient(t, port, fmt.Sprintf("SELECT '%s';", marker))
			if err != nil {
				errs <- fmt.Errorf("native %d: %v\n%s", n, err, out)
				return
			}
			if !strings.Contains(out, marker) {
				errs <- fmt.Errorf("native %d: missing marker in %s", n, out)
			}
		}(i)
	}

	for i := range 6 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			status, body, err := postStatementE("127.0.0.1:"+port, fmt.Sprintf("SELECT %d AS n", n))
			if err != nil {
				errs <- fmt.Errorf("http %d: %v", n, err)
				return
			}
			if status != http.StatusOK {
				errs <- fmt.Errorf("http %d: status %d: %s", n, status, body)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestNativeLargeResultSet(t *testing.T) {
	itOnly(t)

	port := startProxy(t, baseConfig(&recordingLogger{}))
	// The rows have to actually cross the proxy, or none of the multi-block relay is exercised.
	out, err := runClient(t, port, "SELECT number FROM numbers(300000);")
	require.NoError(t, err, out)

	lines := strings.Count(strings.TrimSpace(out), "\n") + 1
	require.Equal(t, 300000, lines, "every row should reach the client")
	require.Contains(t, out, "299999", "the last row should survive the relay")
}

func TestNativeWideRowsStreamThrough(t *testing.T) {
	itOnly(t)

	port := startProxy(t, baseConfig(&recordingLogger{}))

	direct := queryDirect(t, "SELECT sum(length(payload)) FROM wide_blobs")
	require.NotEqual(t, "0", direct, "wide_blobs must be seeded for this to test anything")

	out, err := runClient(t, port, "SELECT sum(length(payload)) FROM wide_blobs;")
	require.NoError(t, err, out)
	require.Equal(t, direct, strings.TrimSpace(out), "the proxied total must match the server's")
}

func queryDirect(t *testing.T, sql string) string {
	t.Helper()

	target := fmt.Sprintf("http://%s/?database=%s",
		envOr("PAM_CLICKHOUSE_HTTP", "127.0.0.1:8123"), envOr("PAM_CLICKHOUSE_DB", "analytics"))
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(sql))
	require.NoError(t, err)
	req.Header.Set("X-ClickHouse-User", envOr("PAM_CLICKHOUSE_USER", "default"))
	req.Header.Set("X-ClickHouse-Key", envOr("PAM_CLICKHOUSE_PASSWORD", "clickhouse"))

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return strings.TrimSpace(string(raw))
}

func TestUpstreamUnreachable(t *testing.T) {
	itOnly(t)

	t.Run("native client gets a native exception", func(t *testing.T) {
		config := baseConfig(&recordingLogger{})
		config.NativeAddr = "127.0.0.1:1"
		port := startProxy(t, config)

		out, err := runClient(t, port, "SELECT 1;")
		t.Logf("%s", out)
		require.Error(t, err)
		require.Contains(t, out, "could not reach ClickHouse")
	})

	t.Run("bridge reports a bad gateway", func(t *testing.T) {
		config := baseConfig(&recordingLogger{})
		config.TargetAddr = ""
		config.NativeAddr = "127.0.0.1:1"
		port := startProxy(t, config)

		status, body := postStatement(t, "127.0.0.1:"+port, "SELECT 1 \nFORMAT JSON")
		require.Equal(t, http.StatusBadGateway, status)
		require.Contains(t, body, "could not reach ClickHouse")
	})
}

func TestWrongAccountCredentialsSurfaceCleanly(t *testing.T) {
	itOnly(t)

	config := baseConfig(&recordingLogger{})
	config.Password = "definitely-not-the-password"
	port := startProxy(t, config)

	out, err := runClient(t, port, "SELECT 1;")
	t.Logf("%s", out)
	require.Error(t, err)
	require.Contains(t, out, "refused the account")
}

func TestNativeRecordingCapturesOutcomes(t *testing.T) {
	itOnly(t)

	recorder := &recordingLogger{}
	port := startProxy(t, baseConfig(recorder))

	out, err := runClient(t, port, "SELECT 1;\nSELECT * FROM nope_not_here;")
	t.Logf("%s", out)
	require.Error(t, err)

	waitFor(t, func() bool { return strings.Contains(recorder.dump(), "ERROR:") })
	dump := recorder.dump()
	require.Contains(t, dump, "SELECT 1")
	require.Contains(t, dump, "nope_not_here")
	require.Equal(t, 1, strings.Count(dump, "=> OK"), "exactly the one successful statement keeps its outcome")
	require.Equal(t, 1, strings.Count(dump, "ERROR:"), "the failed statement is recorded once")
}

func TestNativeRevisionPinning(t *testing.T) {
	itOnly(t)

	port := startProxy(t, baseConfig(&recordingLogger{}))

	// The server is newer than ch-go, so this only passes if the pinned revision is honoured end to end.
	out, err := runClient(t, port, "SELECT version();")
	require.NoError(t, err, out)
	require.Equal(t, queryDirect(t, "SELECT version()"), strings.TrimSpace(out))
}

func TestQuoteFieldDump(t *testing.T) {
	cases := []struct{ in, want string }{
		{"7", `'7'`},
		{"plain", `'plain'`},
		{"it's", `'it\'s'`},
		{`back\slash`, `'back\\slash'`},
		{`'; DROP TABLE users; --`, `'\'; DROP TABLE users; --'`},
		{"", `''`},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, quoteFieldDump(tc.in), tc.in)
	}
}

// A parameter is data, so a value full of quotes has to come back as that value rather than changing the...
func TestBridgeParameterCannotEscapeItsQuotes(t *testing.T) {
	itOnly(t)

	config := baseConfig(&recordingLogger{})
	config.TargetAddr = ""
	port := startProxy(t, config)

	hostile := `'; DROP TABLE pam_write_test; --`
	status, body := postGET(t, "127.0.0.1:"+port,
		"/?param_v="+urlEscape(hostile)+"&query="+urlEscape("SELECT {v:String} AS got FORMAT JSON"))

	require.Equal(t, http.StatusOK, status, body)

	var envelope bridgeEnvelope
	require.NoError(t, json.Unmarshal([]byte(body), &envelope), body)

	var rows []struct {
		Got string `json:"got"`
	}
	require.NoError(t, json.Unmarshal(envelope.Data, &rows))
	require.Len(t, rows, 1)
	require.Equal(t, hostile, rows[0].Got, "the value should survive intact, not be executed")

	// The table the payload tried to drop is still there.
	okStatus, okBody := postStatement(t, "127.0.0.1:"+port, "SELECT count() AS c FROM pam_write_test \nFORMAT JSON")
	require.Equal(t, http.StatusOK, okStatus, okBody)
}
