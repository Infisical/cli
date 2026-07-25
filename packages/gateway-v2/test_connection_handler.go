package gatewayv2

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	maxTestConnRequestBytes   = 64 * 1024
	testConnDefaultTimeout    = 15 * time.Second
	testConnMaxTimeout        = 60 * time.Second
	connectionTestReqDeadline = 90 * time.Second
)

func serveConnectionTestOverTLS(ctx context.Context, conn *tls.Conn, reader *bufio.Reader, forwardConfig *ForwardConfig) error {
	return serveRPCOverTLS(ctx, conn, reader, forwardConfig, connectionTestMux(), connectionTestReqDeadline, "connection-test")
}

var connectionTestMux = sync.OnceValue(func() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/test-connection", handleTestConnection)
	return mux
})

const (
	testConnModePostgres = "postgres"
	testConnModeSSH      = "ssh"
	testConnModeTCP      = "tcp"
)

// testConnectionEnvelope carries the fields common to every connection test; mode selects which client validates
// it and which per-mode params struct the body is decoded into. The target host/port come from the signed cert.
type testConnectionEnvelope struct {
	Mode      string `json:"mode"` // "postgres" | "ssh" | "tcp"
	TimeoutMs int    `json:"timeoutMs"`
}

type postgresTestParams struct {
	Username              string `json:"username"`
	Password              string `json:"password"`
	Database              string `json:"database"`
	SslEnabled            bool   `json:"sslEnabled"`
	SslRejectUnauthorized *bool  `json:"sslRejectUnauthorized"`
	SslCertificate        string `json:"sslCertificate"`
}

type sshTestParams struct {
	AuthMethod  string `json:"authMethod"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	PrivateKey  string `json:"privateKey"`
	Certificate string `json:"certificate"`
}

type testConnectionResult struct {
	Ok bool `json:"ok"`
}

type testConnectionResponse struct {
	Result testConnectionResult `json:"result"`
}

// doPostgresConnectionTest authenticates against the target Postgres and runs a trivial query.
func doPostgresConnectionTest(ctx context.Context, host string, port int, params postgresTestParams) error {
	config, err := pgx.ParseConfig("")
	if err != nil {
		return fmt.Errorf("failed to build connection config: %w", err)
	}
	config.Host = host
	config.Fallbacks = nil
	config.Port = uint16(port)
	config.User = params.Username
	config.Password = params.Password
	config.Database = params.Database

	if params.SslEnabled {
		rejectUnauthorized := params.SslRejectUnauthorized == nil || *params.SslRejectUnauthorized
		tlsConfig := &tls.Config{ServerName: host, InsecureSkipVerify: !rejectUnauthorized}
		if params.SslCertificate != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(params.SslCertificate)) {
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
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
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
		var params postgresTestParams
		if err := json.Unmarshal(body, &params); err != nil {
			writeRPCError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		testErr = doPostgresConnectionTest(ctx, target.host, target.port, params)
	case testConnModeSSH:
		var params sshTestParams
		if err := json.Unmarshal(body, &params); err != nil {
			writeRPCError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		_, testErr = doSSHExec(target.host, target.port, sshExecEnvelope{
			Command:     "true",
			AuthMethod:  params.AuthMethod,
			Username:    params.Username,
			Password:    params.Password,
			PrivateKey:  params.PrivateKey,
			Certificate: params.Certificate,
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
