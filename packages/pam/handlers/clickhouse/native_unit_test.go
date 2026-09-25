package clickhouse

import (
	"context"
	"net"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/stretchr/testify/require"
)

// fakeClickHouse stands in for a server so the security-critical parts of the handshake and packet loop can
// be tested without docker: what the gateway sends upstream is recorded, and nothing needs a real database.
type fakeClickHouse struct {
	listener net.Listener

	mu       sync.Mutex
	hello    proto.ClientHello
	quotaKey string
	queries  []proto.Query
	// Bytes seen after the handshake, which is what proves nothing was relayed once a refusal happened.
	bytesAfterHandshake int
	done                chan struct{}
}

func startFakeClickHouse(t *testing.T) *fakeClickHouse {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	f := &fakeClickHouse{listener: listener, done: make(chan struct{})}
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

	var b proto.Buffer
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

// dialProxy runs one session against a proxy configured to reach the fake server.
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

// The whole point of the proxy: what the client presents is dropped and the account's own identity is used.
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

// A packet the loop cannot read must end the session, and nothing may reach the server after it.
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

// A blocked statement must be refused before it is forwarded, and must end the session.
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

// The client's quota key rides on the Query packet as well as the addendum, and both are the account's.
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

// The revision is pinned to what ch-go can parse, and the client has to be told the pinned one so it
// encodes to match.
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
	t.Helper()

	q.Info.ProtocolVersion = proto.Version
	q.Info.Major, q.Info.Minor = 24, 8
	q.Info.Interface = proto.InterfaceTCP
	q.Info.Query = proto.ClientQueryInitial
	q.Info.InitialAddress = "127.0.0.1:0"
	q.Stage = proto.StageComplete

	var b proto.Buffer
	q.EncodeAware(&b, proto.Version)
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

// ch-go trailing the server is the reason the handshake pins a revision at all. If ch-go ever catches up,
// the pinning becomes a no-op and this is the reminder to re-check it.
func TestChGoRevisionIsStillBehindTheServers(t *testing.T) {
	require.LessOrEqual(t, maxNativeRevision, 54469,
		"ch-go has caught up with ClickHouse; revision pinning needs revisiting")
}
