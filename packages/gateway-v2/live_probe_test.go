//go:build liveprobe

package gatewayv2

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

// Live classification checks against real targets. Run with:
//
//	go test -tags liveprobe ./packages/gateway-v2/ -run TestLive -v
//
// Each case runs the real probe against a real server and asserts the phase the control plane will act on:
// auth stops the heartbeat schedule, transport keeps it retrying.
func expectKind(t *testing.T, name string, err error, want testConnFailureKind) {
	t.Helper()
	got := classifyTestConnFailure(err)
	if got != want {
		t.Errorf("%s: got %q, want %q (err: %v)", name, got, want, err)
		return
	}
	t.Logf("%-34s %-10s %v", name, got, err)
}

func expectOk(t *testing.T, name string, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: expected success, got: %v", name, err)
		return
	}
	t.Logf("%-34s ok", name)
}

func liveCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func deadPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func TestLivePostgres(t *testing.T) {
	ctx := liveCtx(t)
	base := sqlTestParams{Dialect: "postgres", Username: "pamadmin", Password: "adminpass", Database: "appdb"}

	expectOk(t, "postgres/valid", doSQLConnectionTest(ctx, "127.0.0.1", 15432, base))

	bad := base
	bad.Password = "wrong-password"
	expectKind(t, "postgres/wrong password", doSQLConnectionTest(ctx, "127.0.0.1", 15432, bad), failureKindAuth)

	noDB := base
	noDB.Database = "does-not-exist"
	expectKind(t, "postgres/missing database", doSQLConnectionTest(ctx, "127.0.0.1", 15432, noDB), failureKindAuth)

	expectKind(t, "postgres/port closed", doSQLConnectionTest(ctx, "127.0.0.1", deadPort(t), base), failureKindTransport)
	expectKind(t, "postgres/host unresolvable", doSQLConnectionTest(ctx, "no-such-host.invalid", 5432, base), failureKindTransport)
}

func TestLiveMysql(t *testing.T) {
	ctx := liveCtx(t)
	base := sqlTestParams{Dialect: "mysql", Username: "root", Password: "Live!Test123", Database: "appdb"}

	expectOk(t, "mysql/valid", doSQLConnectionTest(ctx, "127.0.0.1", 13306, base))

	bad := base
	bad.Password = "wrong-password"
	expectKind(t, "mysql/wrong password", doSQLConnectionTest(ctx, "127.0.0.1", 13306, bad), failureKindAuth)

	expectKind(t, "mysql/port closed", doSQLConnectionTest(ctx, "127.0.0.1", deadPort(t), base), failureKindTransport)
}

func TestLiveMssql(t *testing.T) {
	ctx := liveCtx(t)
	base := sqlTestParams{Dialect: "mssql", Username: "sa", Password: "Heartbeat!Test123", Database: "master", AuthMethod: "sql-login"}

	expectOk(t, "mssql/valid", doSQLConnectionTest(ctx, "127.0.0.1", 11433, base))

	bad := base
	bad.Password = "wrong-password"
	expectKind(t, "mssql/wrong password", doSQLConnectionTest(ctx, "127.0.0.1", 11433, bad), failureKindAuth)

	noDB := base
	noDB.Database = "does-not-exist"
	expectKind(t, "mssql/missing database", doSQLConnectionTest(ctx, "127.0.0.1", 11433, noDB), failureKindAuth)

	expectKind(t, "mssql/port closed", doSQLConnectionTest(ctx, "127.0.0.1", deadPort(t), base), failureKindTransport)
}

func TestLiveRedis(t *testing.T) {
	ctx := liveCtx(t)

	expectOk(t, "redis/valid default user", doRedisConnectionTest(ctx, "127.0.0.1", 6380, redisTestParams{Password: "default-pass-123"}))
	expectOk(t, "redis/valid acl user", doRedisConnectionTest(ctx, "127.0.0.1", 6380, redisTestParams{Username: "pamuser", Password: "pam-pass-123"}))

	expectKind(t, "redis/wrong password",
		doRedisConnectionTest(ctx, "127.0.0.1", 6380, redisTestParams{Password: "wrong-password"}), failureKindAuth)
	expectKind(t, "redis/unknown acl user",
		doRedisConnectionTest(ctx, "127.0.0.1", 6380, redisTestParams{Username: "ghost", Password: "pam-pass-123"}), failureKindAuth)
	expectKind(t, "redis/no password supplied",
		doRedisConnectionTest(ctx, "127.0.0.1", 6380, redisTestParams{}), failureKindAuth)
	expectKind(t, "redis/port closed",
		doRedisConnectionTest(ctx, "127.0.0.1", deadPort(t), redisTestParams{Password: "default-pass-123"}), failureKindTransport)
}

func TestLiveMongo(t *testing.T) {
	ctx := liveCtx(t)
	base := mongoTestParams{Username: "pamadmin", Password: "Live!Test123", AuthSource: "admin"}

	expectOk(t, "mongo/valid", doMongoConnectionTest(ctx, "127.0.0.1", 27018, base))

	bad := base
	bad.Password = "wrong-password"
	expectKind(t, "mongo/wrong password", doMongoConnectionTest(ctx, "127.0.0.1", 27018, bad), failureKindAuth)

	expectKind(t, "mongo/port closed", doMongoConnectionTest(ctx, "127.0.0.1", deadPort(t), base), failureKindTransport)
}

func TestLiveLdap(t *testing.T) {
	ctx := liveCtx(t)
	base := ldapTestParams{Username: "cn=admin,dc=example,dc=org", Password: "LiveTest123"}

	expectOk(t, "ldap/valid bind", doLdapConnectionTest(ctx, "127.0.0.1", 1389, base))

	bad := base
	bad.Password = "wrong-password"
	expectKind(t, "ldap/wrong password", doLdapConnectionTest(ctx, "127.0.0.1", 1389, bad), failureKindAuth)

	unknown := base
	unknown.Username = "cn=ghost,dc=example,dc=org"
	expectKind(t, "ldap/unknown dn", doLdapConnectionTest(ctx, "127.0.0.1", 1389, unknown), failureKindAuth)

	expectKind(t, "ldap/port closed", doLdapConnectionTest(ctx, "127.0.0.1", deadPort(t), base), failureKindTransport)
}

func TestLiveSSH(t *testing.T) {
	run := func(params sshTestParams, host string, port int) error {
		_, err := doSSHExec(host, port, sshExecEnvelope{
			Command: "true", AuthMethod: params.AuthMethod, Username: params.Username,
			Password: params.Password, PrivateKey: params.PrivateKey, TimeoutMs: 15000,
		})
		return err
	}

	expectOk(t, "ssh/valid password",
		run(sshTestParams{AuthMethod: "password", Username: "pamuser", Password: "LiveTest123"}, "127.0.0.1", 2225))
	expectKind(t, "ssh/wrong password",
		run(sshTestParams{AuthMethod: "password", Username: "pamuser", Password: "wrong-password"}, "127.0.0.1", 2225),
		failureKindAuth)
	expectKind(t, "ssh/unknown user",
		run(sshTestParams{AuthMethod: "password", Username: "ghost", Password: "LiveTest123"}, "127.0.0.1", 2225),
		failureKindAuth)
	expectKind(t, "ssh/port closed",
		run(sshTestParams{AuthMethod: "password", Username: "pamuser", Password: "whatever"}, "127.0.0.1", deadPort(t)),
		failureKindTransport)
	// A plain TCP service that is not SSH: the handshake fails before any credential is offered.
	expectKind(t, "ssh/not an ssh server",
		run(sshTestParams{AuthMethod: "password", Username: "pamuser", Password: "whatever"}, "127.0.0.1", 15432),
		failureKindTransport)
	// The server offers only publickey, so the password is never sent and nothing counts toward a lockout.
	expectKind(t, "ssh/method not offered",
		run(sshTestParams{AuthMethod: "password", Username: "pamuser", Password: "whatever"}, "127.0.0.1", 2223),
		failureKindTransport)
}

// Windows-auth MSSQL against the real SQL Server on EC2, which routes through the proxy handshake rather than
// the database/sql driver. Skipped unless PAM_MSSQL_NTLM_PASSWORD is set.
func TestLiveMssqlNtlm(t *testing.T) {
	password := os.Getenv("PAM_MSSQL_NTLM_PASSWORD")
	if password == "" {
		t.Skip("PAM_MSSQL_NTLM_PASSWORD not set")
	}
	ctx := liveCtx(t)
	const host = "18.220.191.145"
	base := sqlTestParams{
		Dialect: "mssql", Username: "pamsql", Password: password, Database: "master",
		AuthMethod: "ntlm", Domain: "EC2AMAZ-DG3116F",
	}

	expectOk(t, "mssql-ntlm/valid", doSQLConnectionTest(ctx, host, 1433, base))

	bad := base
	bad.Password = "wrong-password"
	expectKind(t, "mssql-ntlm/wrong password", doSQLConnectionTest(ctx, host, 1433, bad), failureKindAuth)

	expectKind(t, "mssql-ntlm/port closed", doSQLConnectionTest(ctx, "127.0.0.1", deadPort(t), base), failureKindTransport)
}

func TestLiveTCP(t *testing.T) {
	ctx := liveCtx(t)
	expectOk(t, "tcp/reachable", doTCPReachabilityTest(ctx, "127.0.0.1", 15432))
	expectKind(t, "tcp/port closed", doTCPReachabilityTest(ctx, "127.0.0.1", deadPort(t)), failureKindTransport)
}
