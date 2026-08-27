package gatewayv2

import (
	"errors"
	"net"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	mssql "github.com/microsoft/go-mssqldb"
)

// Whether the target refused the credential or we never got far enough to ask. The control plane needs these
// apart: a refused credential stops the schedule, while an unreachable target keeps retrying. Only the gateway
// holds the driver error, so the classification happens here rather than by matching strings upstream.
type testConnFailureKind string

const (
	failureKindAuth      testConnFailureKind = "auth"
	failureKindTransport testConnFailureKind = "transport"
	failureKindUnknown   testConnFailureKind = "unknown"
)

// SQLSTATE 28xxx is "invalid authorization specification", which Postgres uses for a rejected password.
const pgInvalidAuthorizationClass = "28"

func classifyTestConnFailure(err error) testConnFailureKind {
	if err == nil {
		return failureKindUnknown
	}

	// Anything that never completed a connection is transport, whatever the protocol said afterwards.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return failureKindTransport
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return failureKindTransport
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return failureKindTransport
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return failureKindTransport
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if strings.HasPrefix(pgErr.Code, pgInvalidAuthorizationClass) {
			return failureKindAuth
		}
		return failureKindUnknown
	}

	var myErr *mysql.MySQLError
	if errors.As(err, &myErr) {
		// 1045 access denied, 1044 access denied to database, 1698 auth plugin rejected the credential.
		switch myErr.Number {
		case 1044, 1045, 1698:
			return failureKindAuth
		default:
			return failureKindUnknown
		}
	}

	var msErr mssql.Error
	if errors.As(err, &msErr) {
		// 18456 login failed, 18452 untrusted domain, 4060 cannot open database for this login.
		switch msErr.Number {
		case 4060, 18452, 18456:
			return failureKindAuth
		default:
			return failureKindUnknown
		}
	}

	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultInvalidCredentials, ldap.LDAPResultInsufficientAccessRights:
			return failureKindAuth
		default:
			return failureKindUnknown
		}
	}

	return classifyTestConnFailureByMessage(err.Error())
}

// Drivers without typed errors (SSH, Redis, MongoDB, and the MSSQL proxy handshake) only report a string.
var authFailureSubstrings = []string{
	"unable to authenticate",      // golang.org/x/crypto/ssh
	"no supported methods remain", // golang.org/x/crypto/ssh
	"ssh: handshake failed",       // golang.org/x/crypto/ssh
	"ntlm authentication failed",  // MSSQL proxy handshake
	"kerberos authentication failed",
	"authentication failed",
	"auth failed",
	"invalid password",
	"wrong password",
	"access denied",
	"permission denied",
	"wrongpassword",                  // Redis
	"noauth",                         // Redis
	"invalid username-password pair", // MongoDB
	"authentication error",
}

var transportFailureSubstrings = []string{
	"connection refused",
	"connection reset",
	"no such host",
	"i/o timeout",
	"timed out",
	"deadline exceeded",
	"network is unreachable",
	"host is unreachable",
	"broken pipe",
	"eof",
}

func classifyTestConnFailureByMessage(message string) testConnFailureKind {
	lowered := strings.ToLower(message)
	for _, needle := range authFailureSubstrings {
		if strings.Contains(lowered, needle) {
			return failureKindAuth
		}
	}
	for _, needle := range transportFailureSubstrings {
		if strings.Contains(lowered, needle) {
			return failureKindTransport
		}
	}
	return failureKindUnknown
}
