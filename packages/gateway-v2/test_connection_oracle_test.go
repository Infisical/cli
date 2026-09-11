package gatewayv2

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	go_ora "github.com/sijms/go-ora/v2"
)

func TestSQLVerifyQuery(t *testing.T) {
	if got := sqlVerifyQuery("oracle"); got != "SELECT 1 FROM DUAL" {
		t.Fatalf("oracle verify query = %q", got)
	}
	for _, dialect := range []string{"postgres", "mysql", "mssql"} {
		if got := sqlVerifyQuery(dialect); got != "SELECT 1" {
			t.Fatalf("%s verify query = %q", dialect, got)
		}
	}
}

func TestOracleDialectReachesTheDriver(t *testing.T) {
	port := hangupPort(t)

	err := doSQLConnectionTest(context.Background(), "127.0.0.1", port, sqlTestParams{
		Dialect:  "oracle",
		Username: "system",
		Password: "pw",
		Database: "freepdb1",
	})
	if err == nil {
		t.Fatal("expected a failure against a target that hangs up")
	}
	if strings.Contains(err.Error(), "unsupported SQL dialect") {
		t.Fatalf("oracle should be routed to the driver, got: %v", err)
	}
}

func TestUnknownSQLDialectIsRejected(t *testing.T) {
	port := hangupPort(t)

	err := doSQLConnectionTest(context.Background(), "127.0.0.1", port, sqlTestParams{
		Dialect:  "db2",
		Username: "u",
		Password: "pw",
		Database: "d",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported SQL dialect") {
		t.Fatalf("expected an unsupported-dialect error, got: %v", err)
	}
}

func TestOracleUnparseableCAFailsAsTransport(t *testing.T) {
	port := hangupPort(t)
	reject := true

	err := doSQLConnectionTest(context.Background(), "127.0.0.1", port, sqlTestParams{
		Dialect:               "oracle",
		Username:              "system",
		Password:              "pw",
		Database:              "freepdb1",
		SslEnabled:            true,
		SslCertificate:        "not a certificate",
		SslRejectUnauthorized: &reject,
	})
	if err == nil {
		t.Fatal("expected a failure")
	}
	if got := classifyTestConnFailure(err); got != failureKindTransport {
		t.Fatalf("kind = %q, want transport (err=%v)", got, err)
	}
}

func TestOracleConnStringNeverLeaksPassword(t *testing.T) {
	const pw = `S3cr3t#Pw%x/y`

	params := sqlTestParams{
		Dialect:  "oracle",
		Username: "system",
		Password: pw,
		Database: "FREEPDB1",
	}

	_, err := openSQLTestDB("fe80::1%lo0", 1521, params)
	if err == nil {
		t.Fatal("expected an error from an unparseable DSN")
	}
	if strings.Contains(err.Error(), pw) || strings.Contains(err.Error(), url.PathEscape(pw)) {
		t.Fatalf("raw error leaked the password: %s", err.Error())
	}

	for _, form := range []string{pw, url.PathEscape(pw), url.QueryEscape(pw)} {
		msg := redactProbeSecrets("connect failed: oracle://system:"+form+"@host:1521/FREEPDB1", pw)
		if strings.Contains(msg, form) {
			t.Fatalf("redaction missed %q in %q", form, msg)
		}
	}
}

func TestRedactProbeSecretsRemovesCredentials(t *testing.T) {
	long := "S3cr3t#Pw%x"
	withSecret := "connect failed for " + long
	if got := redactProbeSecrets(withSecret, long); strings.Contains(got, long) {
		t.Fatalf("a full-length secret must be redacted, got %q", got)
	}

	dsn := `parse "oracle://system:` + url.PathEscape("ab") + `@host:1521/FREEPDB1": bad`
	got := redactProbeSecrets(dsn, "ab")
	if strings.Contains(got, "system:ab@") {
		t.Fatalf("URL userinfo must be stripped even for a short secret, got %q", got)
	}
	if !strings.Contains(got, "******@") {
		t.Fatalf("expected redacted userinfo, got %q", got)
	}
}

func TestAlterPasswordStatement(t *testing.T) {
	base := sqlRotateParams{TargetUsername: "APP_USER", NewPassword: "NewPw_123"}
	base.Dialect = "oracle"

	delegated := base
	delegated.Username = "ROTATOR"
	delegated.Password = "RotPw_1"
	got, err := alterPasswordStatement(delegated)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "REPLACE") {
		t.Fatalf("delegated rotation must not restate a password it does not own: %q", got)
	}

	self := base
	self.Username = "APP_USER"
	self.Password = "OldPw_1"
	got, err = alterPasswordStatement(self)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `REPLACE "OldPw_1"`) {
		t.Fatalf("self-rotation must restate the old password: %q", got)
	}

	caseDiffers := base
	caseDiffers.Username = "app_user"
	caseDiffers.Password = "OldPw_1"
	got, err = alterPasswordStatement(caseDiffers)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "REPLACE") {
		t.Fatalf("a username differing only in case is a different Oracle account: %q", got)
	}

	bad := self
	bad.TargetUsername = `BAD"NAME`
	if _, err := alterPasswordStatement(bad); err == nil {
		t.Fatal("a username containing a double quote must be rejected")
	}
}

func TestRedactionSurvivesAtSignInPassword(t *testing.T) {
	pw := "p@ssw0rd"
	dsn := go_ora.BuildUrl("host", 1521, "svc", "user", pw, nil)
	got := redactProbeSecrets(`parse "`+dsn+`": bad`, pw)

	for _, leak := range []string{pw, "ssw0rd", "p@"} {
		if strings.Contains(got, leak) {
			t.Fatalf("redacted message still contains %q: %s", leak, got)
		}
	}
}

func TestAlterPasswordStatementRejectsNonOracleDialect(t *testing.T) {
	for _, d := range []string{"", "mysql", "postgres"} {
		p := sqlRotateParams{TargetUsername: "app", NewPassword: "NewPw_1"}
		p.Dialect = d
		if _, err := alterPasswordStatement(p); err == nil {
			t.Fatalf("dialect %q must be rejected: the statement also parses as valid MySQL", d)
		}
	}
}

func TestOracleListenerErrorsClassifyAsTransport(t *testing.T) {
	for _, msg := range []string{
		"ORA-12514: TNS:listener does not currently know of service requested in connect descriptor",
		"ORA-12541: TNS:no listener",
		"ORA-12537: TNS:connection closed",
		"ORA-01033: ORACLE initialization or shutdown in progress",
	} {
		err := sqlAuthFailure("oracle", errors.New(msg))
		if got := classifyTestConnFailure(err); got != failureKindTransport {
			t.Fatalf("%q classified as %q, want transport", msg, got)
		}
	}
}

func TestOracleRejectedCredentialStillClassifiesAsAuth(t *testing.T) {
	err := sqlAuthFailure("oracle", errors.New("ORA-01017: invalid username/password; logon denied"))
	if got := classifyTestConnFailure(err); got != failureKindAuth {
		t.Fatalf("kind = %q, want auth", got)
	}
}

func TestRedactionStripsUserinfoContainingAtSign(t *testing.T) {
	got := redactProbeSecrets(`dial "mongodb://user:p@ss@host:27017/db" failed`)

	for _, leak := range []string{"p@ss", "ss@host"} {
		if strings.Contains(got, leak) {
			t.Fatalf("userinfo with an @ was only half redacted: %s", got)
		}
	}
	if !strings.Contains(got, "mongodb://******@host:27017") {
		t.Fatalf("expected the whole userinfo redacted, got %s", got)
	}
}
