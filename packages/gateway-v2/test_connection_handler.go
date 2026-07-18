package gatewayv2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	maxTestConnRequestBytes = 64 * 1024
	testConnDefaultTimeout  = 15 * time.Second
	testConnMaxTimeout      = 60 * time.Second
)

const (
	testConnModePostgres = "postgres"
	testConnModeSSH      = "ssh"
	testConnModeTCP      = "tcp"
)

// testConnectionEnvelope is the request body for a connection test. The target host/port come from the signed
// gateway certificate; mode selects which client validates it, and the remaining fields are read per mode.
type testConnectionEnvelope struct {
	Mode      string `json:"mode"` // "postgres" | "ssh" | "tcp"
	TimeoutMs int    `json:"timeoutMs"`

	// ssh
	AuthMethod  string `json:"authMethod"`
	PrivateKey  string `json:"privateKey"`
	Certificate string `json:"certificate"`

	// postgres + ssh
	Username string `json:"username"`
	Password string `json:"password"`

	// postgres
	Database              string `json:"database"`
	SslEnabled            bool   `json:"sslEnabled"`
	SslRejectUnauthorized *bool  `json:"sslRejectUnauthorized"`
	SslCertificate        string `json:"sslCertificate"`
}

type testConnectionResult struct {
	Ok bool `json:"ok"`
}

type testConnectionResponse struct {
	Result testConnectionResult `json:"result"`
}

// doPostgresConnectionTest authenticates against the target Postgres and runs a trivial query.
func doPostgresConnectionTest(ctx context.Context, host string, port int, env testConnectionEnvelope) error {
	config, err := pgx.ParseConfig("")
	if err != nil {
		return fmt.Errorf("failed to build connection config: %w", err)
	}
	config.Host = host
	config.Port = uint16(port)
	config.User = env.Username
	config.Password = env.Password
	config.Database = env.Database

	if env.SslEnabled {
		rejectUnauthorized := env.SslRejectUnauthorized == nil || *env.SslRejectUnauthorized
		tlsConfig := &tls.Config{ServerName: host, InsecureSkipVerify: !rejectUnauthorized}
		if env.SslCertificate != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(env.SslCertificate)) {
				return fmt.Errorf("failed to parse SSL certificate")
			}
			tlsConfig.RootCAs = pool
		}
		config.TLSConfig = tlsConfig
	} else {
		config.TLSConfig = nil
	}

	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	var result int
	return conn.QueryRow(ctx, "SELECT 1").Scan(&result)
}

// doTCPReachabilityTest confirms the target host:port accepts a TCP connection. It's the fallback for targets we
// can't authenticate at rest (RDP, SSH certificate auth), so at least a bad host/port is rejected.
func doTCPReachabilityTest(ctx context.Context, host string, port int) error {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	return conn.Close()
}

func handleTestConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, "Only POST is supported")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTestConnRequestBytes))
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	var env testConnectionEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		writeRPCError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	timeout := testConnDefaultTimeout
	if env.TimeoutMs > 0 {
		if timeout = time.Duration(env.TimeoutMs) * time.Millisecond; timeout > testConnMaxTimeout {
			timeout = testConnMaxTimeout
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	target, _ := r.Context().Value(rpcTargetContextKey{}).(rpcTarget)

	var testErr error
	switch env.Mode {
	case testConnModePostgres:
		testErr = doPostgresConnectionTest(ctx, target.host, target.port, env)
	case testConnModeSSH:
		_, testErr = doSSHExec(target.host, target.port, sshExecEnvelope{
			Command:     "true",
			AuthMethod:  env.AuthMethod,
			Username:    env.Username,
			Password:    env.Password,
			PrivateKey:  env.PrivateKey,
			Certificate: env.Certificate,
			TimeoutMs:   env.TimeoutMs,
		})
	case testConnModeTCP:
		testErr = doTCPReachabilityTest(ctx, target.host, target.port)
	default:
		writeRPCError(w, http.StatusBadRequest, fmt.Sprintf("unsupported test-connection mode: %q", env.Mode))
		return
	}

	if testErr != nil {
		writeRPCError(w, http.StatusBadGateway, testErr.Error())
		return
	}
	writeRPCJSON(w, http.StatusOK, testConnectionResponse{Result: testConnectionResult{Ok: true}})
}
