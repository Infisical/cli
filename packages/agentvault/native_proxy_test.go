package agentvault

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"golang.org/x/crypto/ssh"
)

// A proxy behind the real door listener, so tests go through the TLS door the way `connect` does.
func newNativeProxy(t *testing.T, services []*resolvedService) (*proxyServer, *ConnectClient, string) {
	t.Helper()
	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	ps := &proxyServer{transport: newUpstreamTransport(), ca: newCaManager(key, cert)}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts})
	ps.cache = newSessionCache(grantingResolver{services: services}, ps.pollInterval)
	ps.sessionLogs = newSessionLogRecorder("proxy-1", &fakeShipper{})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	door := newDoorListener(ln, proxyDoorTLSConfig(ps.ca), time.Second)
	srv := &http.Server{
		Handler:      http.HandlerFunc(ps.dispatch),
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	go func() { _ = srv.Serve(door) }()
	t.Cleanup(func() {
		ps.cache.closeNative(time.Second)
		_ = srv.Close()
	})

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return ps, &ConnectClient{ProxyAddr: ln.Addr().String(), SessionToken: "agv_test-token", RootCAs: pool}, ln.Addr().String()
}

func nativeServiceAt(kind, name, addr string) *resolvedService {
	host, port, _ := net.SplitHostPort(addr)
	portNumber, _ := strconv.Atoi(port)
	return &resolvedService{
		id:               "id-" + name,
		name:             name,
		kind:             kind,
		accessBundleName: "bundle",
		native:           &nativeTarget{host: host, port: portNumber, database: "app"},
		credential:       credential{kind: credentialBasic, username: "agent", password: []byte("secret")},
	}
}

func nativeRecords(t *testing.T, ps *proxyServer, want int) []sessionLogRecord {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		ps.sessionLogs.mu.Lock()
		spool := ps.sessionLogs.spools["s1"]
		n := 0
		if spool != nil {
			n = spool.ring.len()
		}
		if n >= want || time.Now().After(deadline) {
			var records []sessionLogRecord
			if spool != nil {
				records = spool.ring.drain(n)
			}
			ps.sessionLogs.mu.Unlock()
			return records
		}
		ps.sessionLogs.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTheDoorServesPlainHTTPAndTLSOnOnePort(t *testing.T) {
	_, client, addr := newNativeProxy(t, nil)

	resp, err := http.Get("http://" + addr + "/_agent-vault/ca")
	if err != nil {
		t.Fatalf("plain request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("plain door answered %d", resp.StatusCode)
	}

	services, err := client.ListNativeServices(context.Background())
	if err != nil || len(services) != 0 {
		t.Fatalf("TLS door: services=%v err=%v", services, err)
	}
}

func TestATLSConnectionIdleLongerThanThePeekIsNotCut(t *testing.T) {
	_, client, _ := newNativeProxy(t, nil)
	conn, err := client.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(1500 * time.Millisecond)

	if _, err := io.WriteString(conn, "GET "+NativeServicesPath+" HTTP/1.1\r\nHost: x\r\nProxy-Authorization: "+client.proxyAuthorization()+"\r\n\r\n"); err != nil {
		t.Fatalf("write after idling: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("a TLS connection idle past the peek deadline was cut: %v", err)
	}
	resp.Body.Close()
}

func TestANativeConnectOnThePlainDoorIsRefused(t *testing.T) {
	_, client, addr := newNativeProxy(t, []*resolvedService{nativeServiceAt(serviceKindPostgres, "db", "127.0.0.1:1")})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "CONNECT db"+NativeServiceSuffix+":1 HTTP/1.1\r\nHost: db"+NativeServiceSuffix+":1\r\nProxy-Authorization: "+client.proxyAuthorization()+"\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a plaintext native CONNECT got %d, want 403", resp.StatusCode)
	}
}

func TestNativeRefusalsHappenBeforeTheTunnel(t *testing.T) {
	missingValues := nativeServiceAt(serviceKindPostgres, "members", "127.0.0.1:1")
	missingValues.personalValuesMissing = true
	badKey := nativeServiceAt(serviceKindSSH, "bastion", "127.0.0.1:1")
	badKey.credential = credential{kind: credentialSSHKey, username: "agent", privateKey: []byte("not a key")}
	_, client, _ := newNativeProxy(t, []*resolvedService{missingValues, badKey})

	for _, tc := range []struct{ service, want string }{
		{"nope", `no database or SSH service named "nope"`},
		{"members", "needs your own credential or sign-in"},
		{"bastion", `the SSH key stored on service "bastion" can't be used`},
	} {
		err := client.Probe(context.Background(), tc.service)
		var refused *ProxyRefusedError
		if !errors.As(err, &refused) || refused.Status != http.StatusForbidden || !strings.Contains(refused.Message, tc.want) {
			t.Errorf("probe %s: %v, want a 403 containing %q", tc.service, err, tc.want)
		}
	}
}

func TestANativeServiceNeverMatchesAnHTTPRequest(t *testing.T) {
	svc := nativeServiceAt(serviceKindPostgres, "db", "127.0.0.1:5432")
	svc.hostPattern = "127.0.0.1:5432"
	if bestMatch([]*resolvedService{svc}, "127.0.0.1", "5432") != nil {
		t.Fatal("a database service matched an HTTP request to its host")
	}
}

func TestAnInlineServiceWinsOverABundleServiceOfTheSameName(t *testing.T) {
	bundle := nativeServiceAt(serviceKindPostgres, "db", "10.0.0.1:5432")
	inline := nativeServiceAt(serviceKindPostgres, "db", "10.0.0.2:5432")
	inline.accessBundleName = ""
	if got := findNativeService([]*resolvedService{bundle, inline}, "db"); got != inline {
		t.Fatal("the bundle's service was picked over the session's own")
	}
}

func TestPostgresThroughTheProxyLogsInAsTheServiceAccountAndIsRecorded(t *testing.T) {
	upstream := startFakePostgres(t, "agent", "secret")
	ps, client, _ := newNativeProxy(t, []*resolvedService{nativeServiceAt(serviceKindPostgres, "db", upstream)})

	tunnel, err := client.OpenTunnel(context.Background(), "db")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	_ = tunnel.SetDeadline(time.Now().Add(5 * time.Second))

	frontend := pgproto3.NewFrontend(tunnel, tunnel)
	frontend.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "whoever", "database": "other"}})
	if err := frontend.Flush(); err != nil {
		t.Fatal(err)
	}
	waitFor[*pgproto3.ReadyForQuery](t, frontend)
	frontend.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := frontend.Flush(); err != nil {
		t.Fatal(err)
	}
	waitFor[*pgproto3.ReadyForQuery](t, frontend)
	frontend.Send(&pgproto3.Terminate{})
	_ = frontend.Flush()

	records := nativeRecords(t, ps, 1)
	if len(records) != 1 || records[0].Native == nil || records[0].Native.Statement != "SELECT 1" || records[0].Method != "POSTGRES" {
		t.Fatalf("records = %+v, want one POSTGRES row for SELECT 1", records)
	}
}

func TestSSHExecThroughTheProxyRecordsTheCommandAndItsOutput(t *testing.T) {
	upstream := startFakeSSH(t, "agent", "secret")
	ps, client, _ := newNativeProxy(t, []*resolvedService{nativeServiceAt(serviceKindSSH, "bastion", upstream)})

	tunnel, err := client.OpenTunnel(context.Background(), "bastion")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(tunnel, "bastion", &ssh.ClientConfig{
		User:            "anyone",
		Auth:            []ssh.AuthMethod{ssh.Password("ignored")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh through the proxy: %v", err)
	}
	client2 := ssh.NewClient(sshConn, chans, reqs)
	defer client2.Close()
	exec := func() ([]byte, error) {
		session, err := client2.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		return session.Output("whoami")
	}
	// PAM's SSH handler can close the channel before it replies to a fast exec (see the TODO in native.go), which
	// shows here as EOF or "exec request failed". The connection stays usable, so the exec is tried again on a new
	// channel. One retry still lost it twice in a row within 60 runs with -race -cpu=1, hence a few.
	out, err := exec()
	for attempt := 1; attempt < 5 && err != nil && (errors.Is(err, io.EOF) || strings.Contains(err.Error(), "exec request failed")); attempt++ {
		out, err = exec()
	}
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if strings.TrimSpace(string(out)) != "agent" {
		t.Fatalf("the command ran as %q, want the service account", out)
	}
	_ = client2.Close()

	// The command's row is written when it starts and its output follows in a row of its own.
	var command, output bool
	records := nativeRecords(t, ps, 2)
	for _, record := range records {
		if record.Native == nil {
			continue
		}
		command = command || record.Native.Command == "whoami"
		output = output || strings.Contains(record.Native.Output, "agent")
	}
	if !command || !output {
		t.Fatalf("records = %+v, want a row for whoami and its output", records)
	}
}

func waitFor[T pgproto3.BackendMessage](t *testing.T, frontend *pgproto3.Frontend) T {
	t.Helper()
	for {
		msg, err := frontend.Receive()
		if err != nil {
			t.Fatalf("waiting for %T: %v", *new(T), err)
		}
		if typed, ok := msg.(T); ok {
			return typed
		}
		if errResp, ok := msg.(*pgproto3.ErrorResponse); ok {
			t.Fatalf("server error: %s", errResp.Message)
		}
	}
}

// A Postgres server just big enough for PAM's handler: refuses TLS, asks for a cleartext password, answers a query.
func startFakePostgres(t *testing.T, user, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakePostgres(conn, user, password)
		}
	}()
	return ln.Addr().String()
}

func serveFakePostgres(conn net.Conn, user, password string) {
	defer conn.Close()
	backend := pgproto3.NewBackend(conn, conn)
	for {
		startup, err := backend.ReceiveStartupMessage()
		if err != nil {
			return
		}
		if _, isSSL := startup.(*pgproto3.SSLRequest); isSSL {
			_, _ = conn.Write([]byte("N"))
			continue
		}
		msg, ok := startup.(*pgproto3.StartupMessage)
		if !ok || msg.Parameters["user"] != user {
			return
		}
		break
	}
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	_ = backend.Flush()
	// The startup is read, so the backend now expects regular messages.
	backend.SetAuthType(pgproto3.AuthTypeCleartextPassword)
	msg, err := backend.Receive()
	if err != nil {
		return
	}
	if pw, ok := msg.(*pgproto3.PasswordMessage); !ok || pw.Password != password {
		backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"})
		_ = backend.Flush()
		return
	}
	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	_ = backend.Flush()
	for {
		msg, err := backend.Receive()
		if err != nil {
			return
		}
		switch msg.(type) {
		case *pgproto3.Query:
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			_ = backend.Flush()
		case *pgproto3.Terminate:
			return
		}
	}
}

// An SSH server that accepts one account by password and answers `whoami` on an exec channel.
func startFakeSSH(t *testing.T, user, password string) string {
	t.Helper()
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if meta.User() == user && string(pw) == password {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeSSH(conn, config)
		}
	}()
	return ln.Addr().String()
}

func serveFakeSSH(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	server, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer server.Close()
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		go func() {
			defer channel.Close()
			for req := range requests {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				_ = req.Reply(true, nil)
				command := string(req.Payload[4:])
				if command == "whoami" {
					_, _ = io.Copy(channel, bytes.NewBufferString(server.User()+"\n"))
				}
				// As OpenSSH does: end of output, then the exit status, then close.
				_ = channel.CloseWrite()
				status := make([]byte, 4)
				binary.BigEndian.PutUint32(status, 0)
				_, _ = channel.SendRequest("exit-status", false, status)
				return
			}
		}()
	}
}
