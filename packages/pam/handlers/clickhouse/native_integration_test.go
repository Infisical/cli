package clickhouse

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Exercises the native handler against a real ClickHouse over the real clickhouse-client, which is the only way
// to cover revision pinning, the addendum and block framing. Opt in with PAM_CLICKHOUSE_NATIVE_IT=1.
//
//	docker run -d --name pam-clickhouse-target -p 8123:8123 -p 9000:9000 \
//	  -e CLICKHOUSE_PASSWORD=clickhouse -e CLICKHOUSE_DB=analytics clickhouse/clickhouse-server:24.8
func TestNativeIntegration(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	type testCase struct {
		name        string
		sql         string
		blocked     []string
		wantOutput  []string
		wantFailure string
	}

	cases := []testCase{
		{
			name:       "multiple statements on one connection",
			sql:        "SELECT 1;\nSELECT 2;\nSELECT 3;",
			wantOutput: []string{"1", "2", "3"},
		},
		{
			name:       "credentials come from the account, not the client",
			sql:        "SELECT currentUser();",
			wantOutput: []string{"default"},
		},
		{
			name:       "column types ch-go cannot infer still stream back",
			sql:        "SELECT map('a', 1::UInt64) AS m, tuple('p', 2) AS t;",
			wantOutput: []string{"{'a':1}", "('p',2)"},
		},
		{
			// A fixed marker would be satisfied by a previous run's row even if the insert path regressed.
			name:       "insert pushes a client data block",
			sql:        insertMarkerSQL(),
			wantOutput: []string{insertMarker},
		},
		{
			name:        "a blocked statement is refused as a native exception",
			sql:         "DROP TABLE pam_write_test;",
			blocked:     []string{`(?i)\bdrop\b`},
			wantFailure: "blocked by the command blocking policy",
		},
		{
			name:        "blocking still applies after an earlier statement on the same connection",
			sql:         "SELECT 1;\nDROP TABLE pam_write_test;",
			blocked:     []string{`(?i)\bdrop\b`},
			wantFailure: "blocked by the command blocking policy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &recordingLogger{}
			addr := startNativeProxy(t, tc.blocked, recorder)

			out, err := runClient(t, addr, tc.sql)
			t.Logf("client output:\n%s", out)

			if tc.wantFailure != "" {
				if err == nil {
					t.Fatalf("expected the client to fail, got success:\n%s", out)
				}
				if !strings.Contains(out, tc.wantFailure) {
					t.Fatalf("expected %q in the client output, got:\n%s", tc.wantFailure, out)
				}
				return
			}

			if err != nil {
				t.Fatalf("clickhouse-client failed: %v\n%s", err, out)
			}
			for _, want := range tc.wantOutput {
				if !strings.Contains(out, want) {
					t.Fatalf("expected %q in the client output, got:\n%s", want, out)
				}
			}
		})
	}
}

// TestNativeRecordsEveryStatement proves the packet loop keeps inspecting after the first statement, which a
// handler that degrades into a raw relay would silently stop doing.
func TestNativeRecordsEveryStatement(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	recorder := &recordingLogger{}
	addr := startNativeProxy(t, nil, recorder)

	if out, err := runClient(t, addr, "SELECT 1;\nSELECT 2;\nSELECT 3;"); err != nil {
		t.Fatalf("clickhouse-client failed: %v\n%s", err, out)
	}

	for _, want := range []string{"SELECT 1", "SELECT 2", "SELECT 3"} {
		if !recorder.contains(want) {
			t.Fatalf("expected %q in the session recording, got:\n%s", want, recorder.dump())
		}
	}

	if !strings.Contains(recorder.dump(), "=> OK") {
		t.Fatalf("expected the outcome of each statement to be recorded, got:\n%s", recorder.dump())
	}
}

// TestNativeRecordsFailedStatement proves a statement ClickHouse rejects is recorded with its error rather
// than as a success.
func TestNativeRecordsFailedStatement(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	recorder := &recordingLogger{}
	addr := startNativeProxy(t, nil, recorder)

	if _, err := runClient(t, addr, "SELECT * FROM does_not_exist;"); err == nil {
		t.Fatal("expected the statement to fail")
	}

	waitFor(t, func() bool { return strings.Contains(recorder.dump(), "ERROR:") })

	if !strings.Contains(recorder.dump(), "does_not_exist") {
		t.Fatalf("expected the failed statement in the recording, got:\n%s", recorder.dump())
	}
}

// A column type ch-go cannot infer costs the outcome of that statement, never the statement or the session.
func TestNativeDegradesOnUnreadableResultBlock(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	recorder := &recordingLogger{}
	addr := startNativeProxy(t, []string{`(?i)\bdrop\b`}, recorder)

	out, err := runClient(t, addr,
		"SELECT map('a', 1::UInt64) AS m;\nSELECT 'after-the-map';\nDROP TABLE pam_write_test;")
	t.Logf("client output:\n%s", out)

	if err == nil {
		t.Fatalf("expected the blocked statement to fail the client:\n%s", out)
	}
	if !strings.Contains(out, "{'a':1}") {
		t.Fatalf("expected the unreadable column type to still reach the client:\n%s", out)
	}
	if !strings.Contains(out, "after-the-map") {
		t.Fatalf("expected the session to survive the unreadable block:\n%s", out)
	}
	// The security control has to keep working after the recorder degrades.
	if !strings.Contains(out, "blocked by the command blocking policy") {
		t.Fatalf("expected blocking to still apply after degrading:\n%s", out)
	}
	if !recorder.contains("after-the-map") {
		t.Fatalf("expected statements to still be recorded after degrading, got:\n%s", recorder.dump())
	}
	if !strings.Contains(recorder.dump(), "outcome could not be read") {
		t.Fatalf("expected the recording to say outcomes stopped, got:\n%s", recorder.dump())
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	for range 100 {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the session recording")
}

var insertMarker = fmt.Sprintf("native-it-%d", time.Now().UnixNano())

func insertMarkerSQL() string {
	return fmt.Sprintf(
		"INSERT INTO pam_write_test (id, note) VALUES (4242, '%s');\nSELECT note FROM pam_write_test WHERE note = '%s';",
		insertMarker, insertMarker)
}

func compileForTest(t *testing.T, blocked []string) []*regexp.Regexp {
	t.Helper()
	patterns := make([]*regexp.Regexp, 0, len(blocked))
	for _, p := range blocked {
		patterns = append(patterns, regexp.MustCompile(p))
	}
	return patterns
}

func startNativeProxy(t *testing.T, blocked []string, logger *recordingLogger) string {
	t.Helper()

	patterns := compileForTest(t, blocked)

	proxy := NewClickHouseProxy(ClickHouseProxyConfig{
		TargetAddr:      envOr("PAM_CLICKHOUSE_HTTP", "127.0.0.1:8123"),
		NativeAddr:      envOr("PAM_CLICKHOUSE_NATIVE", "127.0.0.1:9000"),
		Username:        envOr("PAM_CLICKHOUSE_USER", "default"),
		Password:        envOr("PAM_CLICKHOUSE_PASSWORD", "clickhouse"),
		Database:        envOr("PAM_CLICKHOUSE_DB", "analytics"),
		SessionID:       "native-integration-test",
		SessionLogger:   logger,
		BlockedCommands: patterns,
	})

	// The client runs in a container, so the listener has to be reachable from outside the loopback.
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
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

	return fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
}

func envOr(name string, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func TestNativeConnectionTest(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	native := envOr("PAM_CLICKHOUSE_NATIVE", "127.0.0.1:9000")

	cases := []struct {
		name     string
		addr     string
		username string
		password string
		wantErr  string
	}{
		{name: "valid account", addr: native, username: "default", password: "clickhouse"},
		{
			name: "wrong password is an auth failure, not a timeout",
			addr: native, username: "default", password: "wrong",
			wantErr: "clickhouse rejected the connection",
		},
		{
			name: "unknown user is reported as ClickHouse reported it",
			addr: native, username: "nobody", password: "x",
			wantErr: "clickhouse rejected the connection",
		},
		{
			name: "a port with nothing on it fails to dial",
			addr: "127.0.0.1:1", username: "default", password: "clickhouse",
			wantErr: "connect",
		},
		{
			// The HTTP port answers, so this proves the check is a real handshake rather than a dial.
			name: "pointing the native check at the HTTP port fails",
			addr: envOr("PAM_CLICKHOUSE_HTTP", "127.0.0.1:8123"), username: "default", password: "clickhouse",
			wantErr: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := TestNativeConnection(context.Background(), ClickHouseProxyConfig{
				NativeAddr: tc.addr,
				Username:   tc.username,
				Password:   tc.password,
				Database:   envOr("PAM_CLICKHOUSE_DB", "analytics"),
			})

			if tc.name == "pointing the native check at the HTTP port fails" {
				if err == nil {
					t.Fatal("expected the HTTP port to fail a native handshake")
				}
				t.Logf("got: %v", err)
				return
			}

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q, got success", tc.wantErr)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
				t.Fatalf("expected %q in %v", tc.wantErr, err)
			}
		})
	}
}
