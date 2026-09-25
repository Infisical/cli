package clickhouse

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// fakeClickHouse stands in for a server so the security-critical parts of the handshake and packet loop...
type fakeClickHouse struct {
	listener net.Listener

	mu       sync.Mutex
	hello    proto.ClientHello
	quotaKey string
	queries  []proto.Query
	// Bytes seen after the handshake, which is what proves nothing was relayed once a refusal happened.
	bytesAfterHandshake int
	done                chan struct{}

	// Non-zero caps what this server claims to speak, standing in for a ClickHouse older than ch-go.
	serverRevision int
	// Non-empty answers the handshake with an exception instead of a hello.
	refuseWith string
}

func startFakeClickHouse(t *testing.T, serverRevision ...int) *fakeClickHouse {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	f := &fakeClickHouse{listener: listener, done: make(chan struct{})}
	if len(serverRevision) > 0 {
		f.serverRevision = serverRevision[0]
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		defer close(f.done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		f.serve(conn)
	}()

	return f
}

func (f *fakeClickHouse) addr() string { return f.listener.Addr().String() }

func (f *fakeClickHouse) serve(conn net.Conn) {
	r := proto.NewReader(newTap(conn))

	code, err := r.UVarInt()
	if err != nil || proto.ClientCode(code) != proto.ClientCodeHello {
		return
	}

	var hello proto.ClientHello
	if err := hello.Decode(r); err != nil {
		return
	}

	f.mu.Lock()
	f.hello = hello
	f.mu.Unlock()

	rev := min(hello.ProtocolVersion, proto.Version)
	if f.serverRevision > 0 {
		rev = min(rev, f.serverRevision)
	}

	var b proto.Buffer
	if f.refuseWith != "" {
		exception := proto.Exception{Code: 516, Name: "AUTHENTICATION_FAILED", Message: f.refuseWith}
		proto.ServerCodeException.Encode(&b)
		exception.EncodeAware(&b, rev)
		_, _ = conn.Write(b.Buf)
		return
	}
	serverHello := proto.ServerHello{Name: "FakeClickHouse", Major: 24, Minor: 8, Revision: rev}
	serverHello.EncodeAware(&b, rev)
	if _, err := conn.Write(b.Buf); err != nil {
		return
	}

	if proto.FeatureAddendum.In(rev) {
		quotaKey, err := r.Str()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.quotaKey = quotaKey
		f.mu.Unlock()
	}

	for {
		packet, err := r.UVarInt()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.bytesAfterHandshake++
		f.mu.Unlock()

		if proto.ClientCode(packet) != proto.ClientCodeQuery {
			continue
		}
		var q proto.Query
		if err := q.DecodeAware(r, rev); err != nil {
			return
		}
		f.mu.Lock()
		f.queries = append(f.queries, q)
		f.mu.Unlock()
	}
}

func (f *fakeClickHouse) snapshot() (proto.ClientHello, string, []proto.Query, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hello, f.quotaKey, append([]proto.Query(nil), f.queries...), f.bytesAfterHandshake
}

func dialProxy(t *testing.T, config ClickHouseProxyConfig) net.Conn {
	t.Helper()

	proxy := NewClickHouseProxy(config)
	client, server := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	handled := make(chan struct{})

	// Cleanup runs last-registered-first, so this waits only after the conn is closed and ctx cancelled.
	t.Cleanup(func() {
		select {
		case <-handled:
		case <-time.After(5 * time.Second):
			t.Error("the handler did not finish")
		}
	})
	t.Cleanup(cancel)
	t.Cleanup(func() { client.Close() })

	go func() {
		defer close(handled)
		_ = proxy.HandleConnection(ctx, server)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))
	return client
}

func clientHandshake(t *testing.T, conn net.Conn, user, password string) *proto.Reader {
	t.Helper()

	var b proto.Buffer
	proto.ClientHello{
		Name:            "unit-test client",
		Major:           24,
		Minor:           8,
		ProtocolVersion: proto.Version,
		Database:        "whatever-the-client-wants",
		User:            user,
		Password:        password,
	}.Encode(&b)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)

	r := proto.NewReader(newTap(conn))
	code, err := r.UVarInt()
	require.NoError(t, err)
	require.Equal(t, proto.ServerCodeHello, proto.ServerCode(code))

	var serverHello proto.ServerHello
	require.NoError(t, serverHello.DecodeAware(r, proto.Version))

	if proto.FeatureAddendum.In(proto.Version) {
		b.Reset()
		b.PutString("the-client-quota-key")
		_, err = conn.Write(b.Buf)
		require.NoError(t, err)
	}
	return r
}

func TestNativeHandshakeInjectsAccountCredentials(t *testing.T) {
	upstream := startFakeClickHouse(t)

	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr: upstream.addr(),
		Username:   "the-account",
		Password:   "the-account-password",
		Database:   "the-account-database",
		SessionID:  "unit",
	})
	clientHandshake(t, conn, "attacker", "attacker-password")

	require.Eventually(t, func() bool {
		hello, _, _, _ := upstream.snapshot()
		return hello.User != ""
	}, 5*time.Second, 20*time.Millisecond)

	hello, quotaKey, _, _ := upstream.snapshot()
	require.Equal(t, "the-account", hello.User)
	require.Equal(t, "the-account-password", hello.Password)
	require.Equal(t, "the-account-database", hello.Database)
	require.NotEqual(t, "attacker", hello.User)
	require.Empty(t, quotaKey, "the client's quota key is not the account's to choose")
}

func TestNativeUnreadablePacketFailsClosed(t *testing.T) {
	upstream := startFakeClickHouse(t)

	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr: upstream.addr(),
		Username:   "account",
		SessionID:  "unit",
	})
	reader := clientHandshake(t, conn, "someone", "")

	var b proto.Buffer
	b.PutUVarInt(99)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)

	code, message := decodeException(t, reader)
	require.Equal(t, codeNotImplemented, code)
	require.Contains(t, message, "could not read ClickHouse client packet 99")

	_, _, queries, seen := upstream.snapshot()
	require.Empty(t, queries)
	require.Zero(t, seen, "no packet may reach ClickHouse after a refusal")
}

func TestNativeBlockedStatementNeverReachesUpstream(t *testing.T) {
	upstream := startFakeClickHouse(t)
	recorder := &recordingLogger{}

	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr:      upstream.addr(),
		Username:        "account",
		SessionID:       "unit",
		SessionLogger:   recorder,
		BlockedCommands: []*regexp.Regexp{regexp.MustCompile(`(?i)\bdrop\b`)},
	})
	reader := clientHandshake(t, conn, "someone", "")

	writeQuery(t, conn, proto.Query{Body: "DROP TABLE important"})

	code, message := decodeException(t, reader)
	require.Equal(t, codeAccessDenied, code)
	require.Contains(t, message, "blocked by the command blocking policy")

	_, _, queries, _ := upstream.snapshot()
	require.Empty(t, queries, "a blocked statement must not reach ClickHouse")
	require.True(t, recorder.contains("DROP TABLE important"))
	require.Contains(t, recorder.dump(), "BLOCKED")
}

func TestNativeStripsTheClientQuotaKeyFromTheQuery(t *testing.T) {
	upstream := startFakeClickHouse(t)

	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr: upstream.addr(),
		Username:   "account",
		SessionID:  "unit",
	})
	clientHandshake(t, conn, "someone", "")

	writeQuery(t, conn, proto.Query{
		Body: "SELECT 1",
		Info: proto.ClientInfo{QuotaKey: "quota-the-client-picked"},
	})

	require.Eventually(t, func() bool {
		_, _, queries, _ := upstream.snapshot()
		return len(queries) == 1
	}, 5*time.Second, 20*time.Millisecond)

	_, _, queries, _ := upstream.snapshot()
	require.Equal(t, "SELECT 1", queries[0].Body)
	require.Empty(t, queries[0].Info.QuotaKey)
}

func TestNativeHandshakePinsTheRevision(t *testing.T) {
	upstream := startFakeClickHouse(t)

	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr: upstream.addr(),
		Username:   "account",
		SessionID:  "unit",
	})

	var b proto.Buffer
	proto.ClientHello{
		Name:            "a client newer than ch-go",
		Major:           99,
		Minor:           9,
		ProtocolVersion: proto.Version + 500,
		Database:        "db",
		User:            "someone",
	}.Encode(&b)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)

	r := proto.NewReader(newTap(conn))
	code, err := r.UVarInt()
	require.NoError(t, err)
	require.Equal(t, proto.ServerCodeHello, proto.ServerCode(code))

	var serverHello proto.ServerHello
	require.NoError(t, serverHello.DecodeAware(r, proto.Version))
	require.Equal(t, maxNativeRevision, serverHello.Revision,
		"the client must be told the pinned revision, not the server's")

	require.Eventually(t, func() bool {
		hello, _, _, _ := upstream.snapshot()
		return hello.ProtocolVersion != 0
	}, 5*time.Second, 20*time.Millisecond)

	hello, _, _, _ := upstream.snapshot()
	require.Equal(t, maxNativeRevision, hello.ProtocolVersion)
}

func writeQuery(t *testing.T, conn net.Conn, q proto.Query) {
	writeQueryAt(t, conn, q, proto.Version)
}

func writeQueryAt(t *testing.T, conn net.Conn, q proto.Query, rev int) {
	t.Helper()

	q.Info.ProtocolVersion = rev
	q.Info.Major, q.Info.Minor = 24, 8
	q.Info.Interface = proto.InterfaceTCP
	q.Info.Query = proto.ClientQueryInitial
	q.Info.InitialAddress = "127.0.0.1:0"
	q.Stage = proto.StageComplete

	var b proto.Buffer
	q.EncodeAware(&b, rev)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)
}

func decodeException(t *testing.T, r *proto.Reader) (int, string) {
	t.Helper()

	code, err := r.UVarInt()
	require.NoError(t, err)
	require.Equal(t, proto.ServerCodeException, proto.ServerCode(code))

	var e proto.Exception
	require.NoError(t, e.DecodeAware(r, proto.Version))
	return int(e.Code), e.Message
}

// ch-go trailing the server is the reason the handshake pins a revision at all.
func TestChGoRevisionIsStillBehindTheServers(t *testing.T) {
	require.LessOrEqual(t, maxNativeRevision, 54469,
		"ch-go has caught up with ClickHouse; revision pinning needs revisiting")
}

// A server older than ch-go reads no addendum, so pinning above what it speaks desynchronises the stream.
func TestNativeHandshakeClampsToAnOlderServer(t *testing.T) {
	const oldRevision = 54455 // ClickHouse 22.3 LTS, below FeatureAddendum (54458)
	require.False(t, proto.FeatureAddendum.In(oldRevision))

	upstream := startFakeClickHouse(t, oldRevision)

	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr: upstream.addr(),
		Username:   "account",
		SessionID:  "unit",
	})

	var b proto.Buffer
	proto.ClientHello{
		Name:            "a modern client",
		Major:           24,
		Minor:           8,
		ProtocolVersion: proto.Version,
		Database:        "db",
		User:            "someone",
	}.Encode(&b)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)

	r := proto.NewReader(newTap(conn))
	code, err := r.UVarInt()
	require.NoError(t, err)
	require.Equal(t, proto.ServerCodeHello, proto.ServerCode(code))

	var serverHello proto.ServerHello
	require.NoError(t, serverHello.DecodeAware(r, oldRevision))
	require.Equal(t, oldRevision, serverHello.Revision,
		"the client must be told the upstream's revision, not one it cannot parse")

	// The fake reads no quota key at this revision, so a query must land as the next packet it sees.
	writeQueryAt(t, conn, proto.Query{Body: "SELECT 1"}, oldRevision)

	require.Eventually(t, func() bool {
		_, _, queries, _ := upstream.snapshot()
		return len(queries) == 1
	}, 5*time.Second, 20*time.Millisecond, "the upstream stream desynchronised")

	_, quotaKey, queries, _ := upstream.snapshot()
	require.Equal(t, "SELECT 1", queries[0].Body)
	require.Empty(t, quotaKey, "no addendum may be written to a server that does not read one")
}

func TestNativeHandshakeRefusesAnOversizedField(t *testing.T) {
	upstream := startFakeClickHouse(t)

	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr: upstream.addr(),
		Username:   "account",
		SessionID:  "unit",
	})

	var b proto.Buffer
	proto.ClientCodeHello.Encode(&b)
	b.PutUVarInt(uint64(maxHandshakeStringLen) + 1)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	answer, _ := io.ReadAll(conn)
	require.Empty(t, answer, "an oversized handshake field must not be answered")

	hello, _, _, bytesAfterHandshake := upstream.snapshot()
	require.Empty(t, hello.Name, "nothing may reach the upstream")
	require.Zero(t, bytesAfterHandshake)
}

// The server direction must stop writing once a statement has been refused, or the client sees bytes
// trailing the exception the proxy just sent it.
func newRefusedSession(t *testing.T, client net.Conn, upstream net.Conn) *nativeSession {
	t.Helper()

	proxy := NewClickHouseProxy(ClickHouseProxyConfig{SessionID: "unit", SessionLogger: &recordingLogger{}})
	s := &nativeSession{
		proxy:    newNativeProxy(proxy),
		log:      zerolog.Nop(),
		client:   client,
		upstream: upstream,
		rev:      maxNativeRevision,
		outcomes: newOutcomeRecorder(proxy),
	}
	s.upstreamTap = newTap(upstream)
	s.upstreamReader = proto.NewReader(s.upstreamTap)
	s.refused.Store(true)
	return s
}

func TestRefusedSessionRelaysNoServerBytes(t *testing.T) {
	// A packet the loop can parse leaves by the per-iteration guard; one it cannot leaves by the relay.
	for name, packet := range map[string][]byte{
		"a parseable packet": func() []byte {
			var b proto.Buffer
			proto.ServerCodePong.Encode(&b)
			return b.Buf
		}(),
		"a packet the loop cannot read": func() []byte {
			var b proto.Buffer
			b.PutUVarInt(250)
			b.PutString(strings.Repeat("x", 512))
			return b.Buf
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			client, clientPeer := net.Pipe()
			upstream, upstreamPeer := net.Pipe()
			t.Cleanup(func() {
				client.Close()
				clientPeer.Close()
				upstream.Close()
				upstreamPeer.Close()
			})

			s := newRefusedSession(t, client, upstream)

			go func() {
				_, _ = upstreamPeer.Write(packet)
				upstreamPeer.Close()
			}()

			done := make(chan struct{})
			go func() {
				defer close(done)
				s.serverLoop()
			}()

			require.NoError(t, clientPeer.SetReadDeadline(time.Now().Add(2*time.Second)))
			buf := make([]byte, 64)
			n, err := clientPeer.Read(buf)
			require.Error(t, err, "a refused session must write nothing further to the client")
			require.Zero(t, n)

			client.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("serverLoop did not return")
			}
		})
	}
}

func TestRefusalAwareWriterRefusesAfterARefusal(t *testing.T) {
	client, clientPeer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		clientPeer.Close()
		upstream.Close()
		upstreamPeer.Close()
	})

	s := newRefusedSession(t, client, upstream)

	n, err := newRefusalAwareWriter(s).Write([]byte("server bytes"))
	require.ErrorIs(t, err, errSessionRefused)
	require.Zero(t, n)
}

func TestNativeConnectionTestClassifiesFailures(t *testing.T) {
	t.Run("an http port is named as a handshake timeout, not a rejected credential", func(t *testing.T) {
		// An HTTP server accepts the connection and then waits for a request, which is exactly what a
		// misconfigured native port looks like.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		t.Cleanup(server.Close)

		// The probe's own deadline bounds the handshake, so this does not wait out nativeHandshakeTimeout.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		err := TestNativeConnection(ctx, ClickHouseProxyConfig{
			NativeAddr: strings.TrimPrefix(server.URL, "http://"),
			Username:   "account",
			Database:   "analytics",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "did not answer ClickHouse's native handshake")
		require.Contains(t, err.Error(), "within 1s", "the message must name the budget that was applied")
		// The heartbeat stops scheduling on a rejected credential, so a silent port has to stay a
		// transport failure rather than being read as one.
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	})

	t.Run("a refused credential surfaces the server's own message", func(t *testing.T) {
		upstream := startFakeClickHouse(t)
		upstream.refuseWith = "Authentication failed: password is incorrect"

		err := TestNativeConnection(context.Background(), ClickHouseProxyConfig{
			NativeAddr: upstream.addr(),
			Username:   "account",
			Database:   "analytics",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "password is incorrect")
		require.NotErrorIs(t, err, os.ErrDeadlineExceeded)
	})

	t.Run("an unreachable port fails as a dial error", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := listener.Addr().String()
		require.NoError(t, listener.Close())

		err = TestNativeConnection(context.Background(), ClickHouseProxyConfig{
			NativeAddr: addr,
			Username:   "account",
			Database:   "analytics",
		})
		require.Error(t, err)
		require.NotContains(t, err.Error(), "did not answer ClickHouse's native handshake")
	})
}

func TestNativeAnchoredRuleStillBlocksAStatementCarryingParameters(t *testing.T) {
	upstream := startFakeClickHouse(t)

	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr:      upstream.addr(),
		Username:        "account",
		SessionID:       "unit",
		SessionLogger:   &recordingLogger{},
		BlockedCommands: []*regexp.Regexp{regexp.MustCompile(`(?i)^DROP TABLE important$`)},
	})
	r := clientHandshake(t, conn, "someone", "whatever")

	writeQuery(t, conn, proto.Query{
		Body:       "DROP TABLE important",
		Parameters: []proto.Parameter{{Key: "who", Value: "someone"}},
	})

	code, message := decodeException(t, r)
	require.Equal(t, codeAccessDenied, code)
	require.Contains(t, message, "blocked by the command blocking policy")

	_, _, queries, _ := upstream.snapshot()
	require.Empty(t, queries, "the blocked statement must not reach the upstream")
}
