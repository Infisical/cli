package gatewayv2

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
)

func closedPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func TestSQLConnectionTestRoutesWindowsAuthToProxy(t *testing.T) {
	port := closedPort(t)

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
				t.Fatal("expected a connection failure against a closed port")
			}
			if !strings.Contains(err.Error(), "dial server") {
				t.Fatalf("expected the proxy handshake to run, got: %v", err)
			}
		})
	}
}

func TestSQLConnectionTestKeepsSqlLoginOnDriverPath(t *testing.T) {
	port := closedPort(t)

	err := doSQLConnectionTest(context.Background(), "127.0.0.1", port, sqlTestParams{
		Dialect:    "mssql",
		Username:   "sa",
		Password:   "pw",
		Database:   "master",
		AuthMethod: "sql-login",
	})
	if err == nil {
		t.Fatal("expected a connection failure against a closed port")
	}
	if strings.Contains(err.Error(), "dial server") {
		t.Fatalf("sql-login should stay on the driver path, got: %v", err)
	}
}
