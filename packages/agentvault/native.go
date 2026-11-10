package agentvault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	pamhandlers "github.com/Infisical/infisical-merge/packages/pam/handlers"
	pammysql "github.com/Infisical/infisical-merge/packages/pam/handlers/mysql"
	pamssh "github.com/Infisical/infisical-merge/packages/pam/handlers/ssh"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

const (
	serviceKindPostgres = "postgres"
	serviceKindMySQL    = "mysql"
	serviceKindSSH      = "ssh"

	credentialSSHKey = "ssh-key"

	// A CONNECT target under this suffix names a service, not a host. The suffix never resolves, so a
	// named-service tunnel can never be confused with one to a real host.
	NativeServiceSuffix = ".svc.agent-vault"
	// The port is required by CONNECT syntax and means nothing for a named service.
	NativeServicePort = "1"
	// A CONNECT with this header only asks whether the service would be served: the proxy answers and opens nothing.
	NativeProbeHeader = "Agent-Vault-Probe"
	// The name the proxy's TLS door presents and `connect` verifies. It never resolves; trust comes from the pinned CA.
	ProxyTLSServerName = "agent-vault-proxy.internal"
)

// Where a database or SSH service's connection goes. The account comes from the service's credential.
type nativeTarget struct {
	host     string
	port     int
	database string
	// The proxy's own leg to the server. Off still uses TLS when a Postgres server offers it, without verifying.
	tlsEnabled bool
	tlsVerify  bool
	ca         string
}

func (t nativeTarget) equal(other nativeTarget) bool {
	return t == other
}

func (t nativeTarget) addr() string {
	return net.JoinHostPort(t.host, strconv.Itoa(t.port))
}

func isNativeKind(kind string) bool {
	return kind == serviceKindPostgres || kind == serviceKindMySQL || kind == serviceKindSSH
}

func nativeServiceName(hostname string) (string, bool) {
	name, ok := strings.CutSuffix(hostname, NativeServiceSuffix)
	return name, ok && name != ""
}

// A service sent inline with the session wins over a bundle service of the same name: the inline one is what the
// session was started with, and a bundle edit made since must not send `connect db` to another database.
func findNativeService(services []*resolvedService, name string) *resolvedService {
	var fromBundle *resolvedService
	for _, svc := range services {
		if svc.native == nil || !isNativeKind(svc.kind) || !strings.EqualFold(svc.name, name) {
			continue
		}
		if svc.accessBundleName == "" {
			return svc
		}
		if fromBundle == nil {
			fromBundle = svc
		}
	}
	return fromBundle
}

// nativeServices lists the session's database and SSH services, one per name, preferring inline ones.
func nativeServices(services []*resolvedService) []*resolvedService {
	var out []*resolvedService
	seen := map[string]bool{}
	for _, svc := range services {
		if svc.native == nil || !isNativeKind(svc.kind) {
			continue
		}
		name := strings.ToLower(svc.name)
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, findNativeService(services, svc.name))
	}
	return out
}

// Checked when a connection is requested, not when the key was saved, so the agent's `connect` reports it
// instead of the SSH login failing with no reason.
func checkSSHKey(svc *resolvedService) error {
	if svc.credential.kind != credentialSSHKey {
		return nil
	}
	signer, err := ssh.ParsePrivateKey(svc.credential.privateKey)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return fmt.Errorf("the SSH key stored on service %q can't be used: it is protected by a passphrase. Ask an admin to update the service", svc.name)
		}
		return fmt.Errorf("the SSH key stored on service %q can't be used: it isn't a private key the proxy can read. Ask an admin to update the service", svc.name)
	}
	if svc.credential.certificate != "" {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(svc.credential.certificate))
		cert, isCert := pub.(*ssh.Certificate)
		if err != nil || !isCert {
			return fmt.Errorf("the SSH certificate stored on service %q can't be used: it isn't an SSH certificate. Ask an admin to update the service", svc.name)
		}
		if _, err := ssh.NewCertSigner(cert, signer); err != nil {
			return fmt.Errorf("the SSH certificate stored on service %q doesn't match its private key. Ask an admin to update the service", svc.name)
		}
	}
	return nil
}

// handleNativeConnect serves a CONNECT that names a database or SSH service. Every refusal happens before the
// tunnel opens, as a status `connect` can show. After the 200 the connection goes to PAM's handler for the
// protocol, which logs in with the service's account and relays everything else.
func (ps *proxyServer) handleNativeConnect(w http.ResponseWriter, r *http.Request, sessionToken, serviceName string) {
	// The database leg after this is plaintext, so the tunnel to it is only offered over TLS.
	if r.TLS == nil {
		http.Error(w, "database and SSH services are reached with `infisical agent-vault connect`, which talks to the proxy over TLS", http.StatusForbidden)
		return
	}

	services, grant, err := ps.cache.lookup(sessionToken, nil)
	if err != nil {
		ps.denyAtGate(w, sessionToken, serviceName+NativeServiceSuffix, NativeServicePort, err)
		return
	}

	svc := findNativeService(services, serviceName)
	if svc == nil {
		ps.refuseNative(w, sessionToken, serviceName, fmt.Sprintf("this session has no database or SSH service named %q", serviceName))
		return
	}
	// A probe only checks the service for `connect`, which says why it was refused, so only a real connection is
	// recorded.
	isProbe := r.Header.Get(NativeProbeHeader) != ""
	refuse := func(body string) {
		if isProbe {
			ps.refuseNative(w, sessionToken, serviceName, body)
			return
		}
		ps.refuseNativeService(w, sessionToken, grant, svc, body)
	}
	if svc.personalValuesMissing {
		refuse(errPersonalValuesMissing(svc).Error())
		return
	}
	if err := checkSSHKey(svc); err != nil {
		refuse(err.Error())
		return
	}
	tlsConfig, err := nativeTLSConfig(*svc.native)
	if err != nil {
		refuse(fmt.Sprintf("the certificate authority stored on service %q can't be used: %s. Ask an admin to update the service", svc.name, err))
		return
	}
	if isProbe {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if ps.nativeTunnels.Add(1) > int64(maxNativeTunnels) {
		ps.nativeTunnels.Add(-1)
		refuse(errNativeTunnelsFull.Error())
		return
	}
	defer ps.nativeTunnels.Add(-1)

	conn, err := ps.cache.registerNative(sessionToken, svc)
	if errors.Is(err, errSessionGone) {
		ps.denyAtGate(w, sessionToken, serviceName+NativeServiceSuffix, NativeServicePort, err)
		return
	}
	if err != nil {
		refuse(err.Error())
		return
	}
	defer ps.cache.releaseNative(conn)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connection hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	// PAM's handlers don't all watch the context, so closing the connection is what ends them.
	// TODO: this only cuts the agent off. PAM's MySQL handler ignores the context, so a query already running when
	// the service is removed or the session ends keeps its server connection and runs to completion. The Postgres
	// handler drops its server connection, but the database can still finish the query. Stopping it needs PAM's
	// handlers to cancel the query (KILL QUERY for MySQL, a cancel request for Postgres).
	stop := context.AfterFunc(conn.ctx, func() { _ = clientConn.Close() })
	defer stop()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	logger := newNativeSessionLogger(ps, conn.key, grant, svc)
	defer logger.Close()

	log.Info().Str("service", svc.name).Str("kind", svc.kind).Str("sessionKey", conn.key).
		Msg("agent-vault: native connection opened")
	// TODO: when PAM's handler can't log in to the server (a wrong password, a certificate it doesn't trust, a host it
	// can't reach), the agent's client only sees the connection close. The reason reaches this log and the session
	// log. Fix in PAM's handlers by sending the client an error in its own protocol before closing.
	client := &hangUpConn{Conn: clientConn}
	err = serveNative(conn.ctx, client, svc, tlsConfig, logger)
	if err != nil && conn.ctx.Err() == nil && !isClientHangUp(err) && !client.hungUp.Load() {
		log.Warn().Err(err).Str("service", svc.name).Str("sessionKey", conn.key).Msg("agent-vault: native connection ended with an error")
		logger.recordOutcome(decisionError, "The proxy couldn't connect to the service: "+err.Error())
		return
	}
	log.Info().Str("service", svc.name).Str("sessionKey", conn.key).Msg("agent-vault: native connection closed")
}

var errNativeTunnelsFull = errors.New("the proxy is serving as many database and SSH connections as it can. Close some and try again, or run another proxy")

// PAM's handlers return a bare EOF when the client hangs up, which is how most connections end. A failure to reach or
// log in to the server comes back wrapped with what failed.
func isClientHangUp(err error) bool {
	return err == io.EOF || err == io.ErrUnexpectedEOF
}

// hangUpConn records the client hanging up. PAM's handlers wrap the client's EOF in the same way as a server's
// (a dropped MySQL client reads as a bad connection, a Postgres one as a failed startup), so which side closed
// first is the only reliable way to tell an ordinary end from a failure.
type hangUpConn struct {
	net.Conn
	hungUp atomic.Bool
}

func (c *hangUpConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET)) {
		c.hungUp.Store(true)
	}
	return n, err
}

func (ps *proxyServer) refuseNative(w http.ResponseWriter, sessionToken, serviceName, body string) {
	log.Warn().Str("service", serviceName).Str("sessionKey", sessionKey(sessionToken)).Str("reason", body).
		Msg("agent-vault: refused a database or SSH connection")
	writeProxyError(w, http.StatusForbidden, decisionBlocked, errorCodeServiceRefused, body)
}

// refuseNativeService refuses a connection to a service the session has, and records it so the session log shows
// the attempt.
func (ps *proxyServer) refuseNativeService(w http.ResponseWriter, sessionToken string, grant *sessionLogGrant, svc *resolvedService, body string) {
	newNativeSessionLogger(ps, sessionKey(sessionToken), grant, svc).recordOutcome(decisionBlocked, body)
	ps.refuseNative(w, sessionToken, svc.name, body)
}

func nativeTLSConfig(target nativeTarget) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: target.host}
	if !target.tlsEnabled || !target.tlsVerify {
		cfg.InsecureSkipVerify = true
		return cfg, nil
	}
	if target.ca != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(target.ca)) {
			return nil, errors.New("it isn't a PEM certificate")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func serveNative(ctx context.Context, conn net.Conn, svc *resolvedService, tlsConfig *tls.Config, logger *nativeSessionLogger) error {
	target := *svc.native
	cred := svc.credential

	switch svc.kind {
	case serviceKindPostgres:
		// TODO: PAM's Postgres handler builds its pgproto3 Backend and Frontend without SetMaxBodyLen, so a session
		// holder can declare a huge message in a 5-byte header and make the proxy allocate it before any body arrives.
		// Fix in PAM's handler by calling SetMaxBodyLen on both sides. That alone isn't enough: before forwarding,
		// trackClientMessage builds the executable SQL for every Bind (buildExecutableSQL replaces each $n with the
		// bound value), so a Parse that repeats $1 many times with one large parameter allocates far more than any
		// message cap. Fix by also capping the expanded SQL.
		// It also dials the server with no timeout, so a host or port that drops packets keeps the agent waiting until
		// the operating system gives up, about 75 seconds. Fix by dialing with a timeout, as its SSH handler does (10s).
		// It also never removes a prepared statement on Close, so a long-lived connection keeps the SQL of every
		// named statement it has prepared. Fix by handling Close and capping the map.
		// It pairs replies with requests through an unordered map and drops a Query's request at its first reply, so
		// a multi-statement Query or pipelined requests can log the wrong result or lose an error. Fix by pairing
		// replies in the order the requests were sent.
		return pamhandlers.NewPostgresProxy(pamhandlers.PostgresProxyConfig{
			TargetAddr:     target.addr(),
			InjectUsername: cred.username,
			InjectPassword: string(cred.password),
			InjectDatabase: target.database,
			EnableTLS:      target.tlsEnabled,
			TLSConfig:      tlsConfig,
			SessionID:      svc.id,
			SessionLogger:  logger,
		}).HandleConnection(ctx, conn)
	case serviceKindMySQL:
		// TODO: PAM's MySQL handler offers the client only mysql_native_password, so clients built without that plugin
		// (the current Homebrew mysql) fail to log in. MySQL 8, the official mysql:9 image and MariaDB clients work.
		// Fix in PAM's handler by also offering caching_sha2_password.
		// TODO: PAM's MySQL handler logs a statement the database refused as NO_RESPONSE, so the session log doesn't
		// say it was denied. Fix in PAM's handler by recording MySQL's error instead.
		// TODO: PAM's MySQL handler doesn't log the database a client names at login or switches to with COM_INIT_DB
		// (both reach RelayHandler.UseDB), so the session log doesn't show which database later statements ran in.
		// Fix in PAM's handler by logging UseDB.
		return pammysql.NewMysqlProxy(pammysql.MysqlProxyConfig{
			TargetAddr:     target.addr(),
			InjectUsername: cred.username,
			InjectPassword: string(cred.password),
			InjectDatabase: target.database,
			EnableTLS:      target.tlsEnabled,
			TLSConfig:      tlsConfig,
			SessionID:      svc.id,
			SessionLogger:  logger,
		}).HandleConnection(ctx, conn)
	case serviceKindSSH:
		config := pamssh.SSHProxyConfig{
			TargetAddr:     target.addr(),
			AuthMethod:     "password",
			InjectUsername: cred.username,
			InjectPassword: string(cred.password),
			SessionID:      svc.id,
			SessionLogger:  logger,
		}
		if cred.kind == credentialSSHKey {
			config.AuthMethod = "public-key"
			config.InjectPassword = ""
			config.InjectPrivateKey = string(cred.privateKey)
			if cred.certificate != "" {
				config.AuthMethod = "certificate"
				config.InjectCertificate = cred.certificate
			}
		}
		// TODO: PAM's SSH handler never reads the server's stderr, so the agent doesn't see error output and a command
		// writing a lot to stderr can stall its channel. The fix belongs in PAM's handler.
		// TODO: PAM's SFTP parser panics on a zero-length packet (parseOnePacket in sftp_parser.go), in a goroutine with
		// no recover, so one packet from an agent crashes the whole proxy and every session on it. The parser is set
		// up before the subsystem request is answered, so even a refused sftp request reaches it. Fix in PAM by
		// rejecting packetLen < 1 and recovering in the channel goroutines.
		// TODO: PAM's SSH handler sets a channel's type in its request goroutine while proxyData reads it for every
		// chunk, so stdin sent right after the exec request, as OpenSSH sends piped input, can arrive untyped and is
		// dropped from the session log (the command still gets it). Fix in PAM by holding a session channel's data
		// until its first request sets the type.
		// TODO: PAM's SSH handler can close the client's channel before it replies to `exec`, so a command that
		// finishes fast can fail with "exec request failed" even though it ran. The fix belongs in PAM's handler.
		// TODO: PAM's SSH handler closes an exec channel about 6 seconds after the client's stdin ends (proxy.go waits
		// 3s for output, then 3s for exit-status), so `ssh -n host 'long command'`, the usual way agents run
		// commands, is cut off with exit 255, and whatever it wrote to stderr never reaches the agent. The fix belongs
		// in PAM's handler (wait for the server's channel to close, and copy stderr) and must keep scp working.
		// TODO: PAM's SSH handler writes every exec command to the proxy's own log at info, and its Postgres handler
		// every query at debug, whether or not session logs are on, so a secret in a command line reaches that log.
		// The fix belongs in PAM's handlers: leave the command and query out of those lines.
		return pamssh.NewSSHProxy(config).HandleConnection(ctx, conn)
	}
	return fmt.Errorf("service kind %q has no native handler", svc.kind)
}

// NativeServicesPath lists the session's database and SSH services for `infisical agent-vault connect`, so it can
// open a port for each and print the command that reaches it.
const NativeServicesPath = "/_agent-vault/native-services"

type NativeServiceInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Database string `json:"database,omitempty"`
}

type NativeServicesResponse struct {
	Services []NativeServiceInfo `json:"services"`
}

// Only over the TLS door, the one `connect` uses, and only with the session's token, as the tunnels themselves.
func (ps *proxyServer) serveNativeServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil {
		http.Error(w, "database and SSH services are listed only over the proxy's TLS door, which `infisical agent-vault connect` uses", http.StatusForbidden)
		return
	}
	sessionToken, ok := requestSessionToken(r)
	if !ok {
		writeProxyAuthChallenge(w)
		return
	}
	services, err := ps.cache.get(sessionToken)
	if err != nil {
		ps.denyAtGate(w, sessionToken, "native-services", NativeServicePort, err)
		return
	}

	out := NativeServicesResponse{Services: []NativeServiceInfo{}}
	for _, svc := range nativeServices(services) {
		out.Services = append(out.Services, NativeServiceInfo{Name: svc.name, Type: svc.kind, Database: svc.native.database})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
