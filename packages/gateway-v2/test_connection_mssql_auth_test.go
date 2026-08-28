package gatewayv2

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
)

// hangupPort accepts connections and immediately closes them, so the probe's reachability dial succeeds and the
// protocol client still fails. A closed port would be rejected before either path runs.
func hangupPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestSQLConnectionTestRoutesWindowsAuthToProxy(t *testing.T) {
	port := hangupPort(t)

	for _, authMethod := range []string{"ntlm", "kerberos"} {
		t.Run(authMethod, func(t *testing.T) {
			err := doSQLConnectionTest(context.Background(), "127.0.0.1", port, sqlTestParams{
				Dialect:    "mssql",
				Username:   "svc_app",
				Password:   "pw",
				Database:   "master",
				AuthMethod: authMethod,
				Domain:     "CORP",
				Realm:      "CORP.EXAMPLE.COM",
				Spn:        "MSSQLSvc/sql.corp.example.com:" + strconv.Itoa(port),
			})
			if err == nil {
				t.Fatal("expected a failure against a target that hangs up")
			}
			if !strings.Contains(err.Error(), "server prelogin") {
				t.Fatalf("expected the proxy handshake to run, got: %v", err)
			}
		})
	}
}

func TestSQLConnectionTestKeepsSqlLoginOnDriverPath(t *testing.T) {
	port := hangupPort(t)

	err := doSQLConnectionTest(context.Background(), "127.0.0.1", port, sqlTestParams{
		Dialect:    "mssql",
		Username:   "sa",
		Password:   "pw",
		Database:   "master",
		AuthMethod: "sql-login",
	})
	if err == nil {
		t.Fatal("expected a failure against a target that hangs up")
	}
	if strings.Contains(err.Error(), "server prelogin") {
		t.Fatalf("sql-login should stay on the driver path, got: %v", err)
	}
}
