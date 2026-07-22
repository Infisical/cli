package gatewayv2

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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
	testConnModeSQL        = "sql"
	testConnModeMongoDB    = "mongodb"
	testConnModeLDAP       = "ldap"
	testConnModeKubernetes = "kubernetes"
	testConnModeSSH        = "ssh"
	testConnModeTCP        = "tcp"
)

// testConnectionEnvelope carries the fields common to every connection test; mode selects which client validates
// it and which per-mode params struct the body is decoded into. The target host/port come from the signed cert.
type testConnectionEnvelope struct {
	Mode      string `json:"mode"`
	TimeoutMs int    `json:"timeoutMs"`
}

type sqlTestParams struct {
	Dialect               string `json:"dialect"` // "postgres" | "mysql" | "mssql"
	Username              string `json:"username"`
	Password              string `json:"password"`
	Database              string `json:"database"`
	SslEnabled            bool   `json:"sslEnabled"`
	SslRejectUnauthorized *bool  `json:"sslRejectUnauthorized"`
	SslCertificate        string `json:"sslCertificate"`
}

type mongoTestParams struct {
	Username              string `json:"username"`
	Password              string `json:"password"`
	Database              string `json:"database"`
	SslEnabled            bool   `json:"sslEnabled"`
	SslRejectUnauthorized *bool  `json:"sslRejectUnauthorized"`
	SslCertificate        string `json:"sslCertificate"`
}

type ldapTestParams struct {
	Username               string `json:"username"`
	Password               string `json:"password"`
	UseLdaps               bool   `json:"useLdaps"`
	LdapRejectUnauthorized *bool  `json:"ldapRejectUnauthorized"`
	LdapCaCert             string `json:"ldapCaCert"`
	LdapTlsServerName      string `json:"ldapTlsServerName"`
}

type kubernetesTestParams struct {
	Token                 string `json:"token"`
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

// buildTestTLSConfig verifies the server by default; an explicit CA pins it, and rejectUnauthorized=false disables it
func buildTestTLSConfig(serverName, caCertificate string, rejectUnauthorized *bool) (*tls.Config, error) {
	reject := rejectUnauthorized == nil || *rejectUnauthorized
	tlsConfig := &tls.Config{ServerName: serverName, InsecureSkipVerify: !reject}
	if caCertificate != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caCertificate)) {
			return nil, fmt.Errorf("failed to parse SSL certificate")
		}
		tlsConfig.RootCAs = pool
	}
	return tlsConfig, nil
}

// openSQLTestDB builds a lazily-connecting *sql.DB for the target using the dialect's driver and a shared TLS config
func openSQLTestDB(host string, port int, params sqlTestParams) (*sql.DB, error) {
	var tlsConfig *tls.Config
	if params.SslEnabled {
		var err error
		if tlsConfig, err = buildTestTLSConfig(host, params.SslCertificate, params.SslRejectUnauthorized); err != nil {
			return nil, err
		}
	}

	switch params.Dialect {
	case "postgres":
		config, err := pgx.ParseConfig("")
		if err != nil {
			return nil, fmt.Errorf("failed to build connection config: %w", err)
		}
		config.Host = host
		config.Port = uint16(port)
		config.User = params.Username
		config.Password = params.Password
		config.Database = params.Database
		config.TLSConfig = tlsConfig
		config.Fallbacks = nil
		return stdlib.OpenDB(*config), nil
	case "mysql":
		config := mysql.NewConfig()
		config.Net = "tcp"
		config.Addr = net.JoinHostPort(host, strconv.Itoa(port))
		config.User = params.Username
		config.Passwd = params.Password
		config.DBName = params.Database
		config.TLS = tlsConfig
		connector, err := mysql.NewConnector(config)
		if err != nil {
			return nil, err
		}
		return sql.OpenDB(connector), nil
	case "mssql":
		query := url.Values{}
		query.Set("database", params.Database)
		if params.SslEnabled {
			query.Set("encrypt", "true")
		} else {
			query.Set("encrypt", "disable")
		}
		dsn := (&url.URL{
			Scheme:   "sqlserver",
			User:     url.UserPassword(params.Username, params.Password),
			Host:     net.JoinHostPort(host, strconv.Itoa(port)),
			RawQuery: query.Encode(),
		}).String()
		config, err := msdsn.Parse(dsn)
		if err != nil {
			return nil, err
		}
		if tlsConfig != nil {
			config.TLSConfig = tlsConfig
		}
		return sql.OpenDB(mssql.NewConnectorConfig(config)), nil
	default:
		return nil, fmt.Errorf("unsupported SQL dialect: %q", params.Dialect)
	}
}

// doSQLConnectionTest authenticates against the target SQL server and runs a trivial query
func doSQLConnectionTest(ctx context.Context, host string, port int, params sqlTestParams) error {
	db, err := openSQLTestDB(host, port, params)
	if err != nil {
		return err
	}
	defer db.Close()

	var result int
	return db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
}

// doMongoConnectionTest authenticates against the target MongoDB and pings it
func doMongoConnectionTest(ctx context.Context, host string, port int, params mongoTestParams) error {
	opts := options.Client().SetHosts([]string{net.JoinHostPort(host, strconv.Itoa(port))})
	if params.Username != "" {
		opts.SetAuth(options.Credential{
			Username:   params.Username,
			Password:   params.Password,
			AuthSource: params.Database,
		})
	}
	if params.SslEnabled {
		tlsConfig, err := buildTestTLSConfig(host, params.SslCertificate, params.SslRejectUnauthorized)
		if err != nil {
			return err
		}
		opts.SetTLSConfig(tlsConfig)
	}

	client, err := mongo.Connect(opts)
	if err != nil {
		return err
	}
	defer func() { _ = client.Disconnect(ctx) }()

	return client.Ping(ctx, nil)
}

// doLdapConnectionTest binds to the target directory with the supplied credentials (the Windows AD auth check)
func doLdapConnectionTest(ctx context.Context, host string, port int, params ldapTestParams) error {
	timeout := testConnDefaultTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	scheme := "ldap"
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: timeout})}
	if params.UseLdaps {
		scheme = "ldaps"
		serverName := params.LdapTlsServerName
		if serverName == "" {
			serverName = host
		}
		tlsConfig, err := buildTestTLSConfig(serverName, params.LdapCaCert, params.LdapRejectUnauthorized)
		if err != nil {
			return err
		}
		opts = append(opts, ldap.DialWithTLSConfig(tlsConfig))
	}

	conn, err := ldap.DialURL(fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, strconv.Itoa(port))), opts...)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetTimeout(timeout)

	return conn.Bind(params.Username, params.Password)
}

// doKubernetesConnectionTest confirms the API server is reachable and accepts the token (401 = bad credentials)
func doKubernetesConnectionTest(ctx context.Context, host string, port int, params kubernetesTestParams) error {
	tlsConfig, err := buildTestTLSConfig(host, params.SslCertificate, params.SslRejectUnauthorized)
	if err != nil {
		return err
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	url := fmt.Sprintf("https://%s/api", net.JoinHostPort(host, strconv.Itoa(port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if params.Token != "" {
		req.Header.Set("Authorization", "Bearer "+params.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("kubernetes API rejected the credentials (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("kubernetes API returned HTTP %d", resp.StatusCode)
	}
	return nil
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

// runWithContext bounds op by ctx even when the underlying driver ignores context cancellation
func runWithContext(ctx context.Context, op func() error) error {
	done := make(chan error, 1)
	go func() { done <- op() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("connection test timed out")
	}
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

	decode := func(params any) bool {
		if err := json.Unmarshal(body, params); err != nil {
			writeRPCError(w, http.StatusBadRequest, "Invalid request body")
			return false
		}
		return true
	}

	var op func() error
	switch env.Mode {
	case testConnModeSQL:
		var params sqlTestParams
		if !decode(&params) {
			return
		}
		op = func() error { return doSQLConnectionTest(ctx, target.host, target.port, params) }
	case testConnModeMongoDB:
		var params mongoTestParams
		if !decode(&params) {
			return
		}
		op = func() error { return doMongoConnectionTest(ctx, target.host, target.port, params) }
	case testConnModeLDAP:
		var params ldapTestParams
		if !decode(&params) {
			return
		}
		op = func() error { return doLdapConnectionTest(ctx, target.host, target.port, params) }
	case testConnModeKubernetes:
		var params kubernetesTestParams
		if !decode(&params) {
			return
		}
		op = func() error { return doKubernetesConnectionTest(ctx, target.host, target.port, params) }
	case testConnModeSSH:
		var params sshTestParams
		if !decode(&params) {
			return
		}
		op = func() error {
			_, err := doSSHExec(target.host, target.port, sshExecEnvelope{
				Command:     "true",
				AuthMethod:  params.AuthMethod,
				Username:    params.Username,
				Password:    params.Password,
				PrivateKey:  params.PrivateKey,
				Certificate: params.Certificate,
				TimeoutMs:   env.TimeoutMs,
			})
			return err
		}
	case testConnModeTCP:
		op = func() error { return doTCPReachabilityTest(ctx, target.host, target.port) }
	default:
		writeRPCError(w, http.StatusBadRequest, fmt.Sprintf("unsupported test-connection mode: %q", env.Mode))
		return
	}

	if testErr := runWithContext(ctx, op); testErr != nil {
		writeRPCError(w, http.StatusBadGateway, testErr.Error())
		return
	}
	writeRPCJSON(w, http.StatusOK, testConnectionResponse{Result: testConnectionResult{Ok: true}})
}
