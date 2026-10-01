package clickhouse

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type fakeClickHouse struct {
	listener net.Listener

	mu                  sync.Mutex
	hello               proto.ClientHello
	quotaKey            string
	queries             []proto.Query
	bytesAfterHandshake int
	done                chan struct{}

	serverRevision int
	refuseWith     string
	conn           net.Conn
	answerQueries  bool
	answerWith     []byte
	events         []string
	dataPackets    [][]byte
}

func (f *fakeClickHouse) disconnect() {
	f.mu.Lock()
	conn := f.conn
	f.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
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
		f.mu.Lock()
		f.conn = conn
		f.mu.Unlock()
		f.serve(conn)
	}()

	return f
}

func (f *fakeClickHouse) addr() string { return f.listener.Addr().String() }

func (f *fakeClickHouse) serve(conn net.Conn) {
	tp := newTap(conn)
	r := proto.NewReader(tp)

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

	compressed := false
	for {
		tp.discard()
		packet, err := r.UVarInt()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.bytesAfterHandshake++
		f.mu.Unlock()

		switch proto.ClientCode(packet) {
		case proto.ClientCodeQuery:
			var q proto.Query
			if err := q.DecodeAware(r, rev); err != nil {
				return
			}
			compressed = q.Compression == proto.CompressionEnabled
			f.mu.Lock()
			f.queries = append(f.queries, q)
			f.events = append(f.events, "query: "+q.Body)
			f.mu.Unlock()

			if f.answerWith != nil {
				if _, err := conn.Write(f.answerWith); err != nil {
					return
				}
			}

			if f.answerQueries {
				var reply proto.Buffer
				proto.ServerCodeProgress.Encode(&reply)
				proto.Progress{Rows: 7}.EncodeAware(&reply, rev)
				proto.ServerCodeEndOfStream.Encode(&reply)
				if _, err := conn.Write(reply.Buf); err != nil {
					return
				}
			}

		case proto.ClientCodeData:
			if _, err := r.Str(); err != nil {
				return
			}
			if compressed {
				r.EnableCompression()
			}
			var (
				block   proto.Block
				results proto.Results
			)
			err := block.DecodeBlock(r, rev, results.Auto())
			r.DisableCompression()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.events = append(f.events, fmt.Sprintf("data: %d rows", block.Rows))
			f.dataPackets = append(f.dataPackets, tp.take())
			f.mu.Unlock()
		}
	}
}

func (f *fakeClickHouse) received() ([]string, [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...), append([][]byte(nil), f.dataPackets...)
}

func (f *fakeClickHouse) snapshot() (proto.ClientHello, string, []proto.Query, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hello, f.quotaKey, append([]proto.Query(nil), f.queries...), f.bytesAfterHandshake
}

func dialProxy(t *testing.T, config ClickHouseProxyConfig) net.Conn {
	return dialProxyOver(t, config, func(c net.Conn) net.Conn { return c })
}

type deadlineDeafConn struct{ net.Conn }

func (deadlineDeafConn) SetDeadline(time.Time) error      { return nil }
func (deadlineDeafConn) SetReadDeadline(time.Time) error  { return nil }
func (deadlineDeafConn) SetWriteDeadline(time.Time) error { return nil }

func dialProxyOver(t *testing.T, config ClickHouseProxyConfig, wrap func(net.Conn) net.Conn) net.Conn {
	t.Helper()

	proxy := NewClickHouseProxy(config)
	client, rawServer := net.Pipe()
	server := wrap(rawServer)

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

func TestChGoRevisionIsStillBehindTheServers(t *testing.T) {
	require.LessOrEqual(t, maxNativeRevision, 54469,
		"ch-go has caught up with ClickHouse; revision pinning needs revisiting")
}

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
	b.PutUVarInt(uint64(maxPacketBytes) + 1)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	answer, _ := io.ReadAll(conn)
	require.Empty(t, answer, "an oversized handshake field must not be answered")

	hello, _, _, bytesAfterHandshake := upstream.snapshot()
	require.Empty(t, hello.Name, "nothing may reach the upstream")
	require.Zero(t, bytesAfterHandshake)
}

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
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		t.Cleanup(server.Close)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		err := TestNativeConnection(ctx, ClickHouseProxyConfig{
			NativeAddr: strings.TrimPrefix(server.URL, "http://"),
			Username:   "account",
			Database:   "analytics",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "did not answer ClickHouse's native handshake")
		require.Contains(t, err.Error(), "left of the connection test's budget")
		require.NotContains(t, err.Error(), "entered as the native one")
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

func TestNativeRefusesAnOversizedQueryBody(t *testing.T) {
	upstream := startFakeClickHouse(t)

	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr:    upstream.addr(),
		Username:      "account",
		SessionID:     "unit",
		SessionLogger: &recordingLogger{},
	})
	r := clientHandshake(t, conn, "someone", "whatever")

	var q proto.Query
	q.ID = "id"
	q.Info.Query = proto.ClientQueryInitial
	q.Info.Interface = proto.InterfaceTCP
	q.Info.InitialAddress = "127.0.0.1:0"
	q.Info.Major, q.Info.Minor, q.Info.ProtocolVersion = 24, 8, proto.Version
	q.Stage = proto.StageComplete
	q.Body = "SELECT 1"

	var full proto.Buffer
	q.EncodeAware(&full, proto.Version)

	var b proto.Buffer
	b.Buf = append(b.Buf, full.Buf[:bytes.LastIndex(full.Buf, []byte("SELECT 1"))-1]...)
	b.PutUVarInt(1 << 40)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)

	code, message := decodeException(t, r)
	require.Equal(t, codeNotImplemented, code)
	require.Contains(t, message, "could not read the query packet")

	_, _, queries, _ := upstream.snapshot()
	require.Empty(t, queries, "nothing may be forwarded from a packet the gateway refused")
}

func TestUpstreamDisconnectEndsTheClientSession(t *testing.T) {
	upstream := startFakeClickHouse(t)

	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr:    upstream.addr(),
		Username:      "account",
		SessionID:     "unit",
		SessionLogger: &recordingLogger{},
	})
	clientHandshake(t, conn, "someone", "whatever")

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))

	upstream.disconnect()

	buf := make([]byte, 16)
	started := time.Now()
	_, err := conn.Read(buf)
	require.Error(t, err, "the client must not be left waiting once the upstream is gone")
	require.Less(t, time.Since(started), 3*time.Second, "the session should end promptly, not on a timeout")
}

func TestNativeConnectionTestDoesNotBlameThePortWhenTheBudgetRanOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(server.Close)

	for _, budget := range []time.Duration{20 * time.Millisecond, 100 * time.Millisecond, 400 * time.Millisecond} {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		err := TestNativeConnection(ctx, ClickHouseProxyConfig{
			NativeAddr: strings.TrimPrefix(server.URL, "http://"),
			Username:   "account",
			Database:   "analytics",
		})
		cancel()

		require.Error(t, err, "budget=%s", budget)
		require.NotContains(t, err.Error(), "within 0s", "budget=%s: a rounded-to-zero duration is nonsense", budget)
		require.NotContains(t, err.Error(), "entered as the native one",
			"budget=%s: an exhausted budget must not be reported as a misconfigured port", budget)
		require.Contains(t, err.Error(), "ran out of time", "budget=%s", budget)
	}
}

func TestNativeHandshakeDoesNotAllocateWhatItRefuses(t *testing.T) {
	upstream := startFakeClickHouse(t)
	conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"})

	var b proto.Buffer
	proto.ClientCodeHello.Encode(&b)
	b.PutString("unit-test client")
	b.PutInt(24)
	b.PutInt(8)
	b.PutInt(proto.Version)
	b.PutString("db")
	b.PutUVarInt(512 << 20)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	answer, _ := io.ReadAll(conn)
	runtime.ReadMemStats(&after)

	require.Empty(t, answer, "an oversized handshake field must not be answered")
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(16<<20),
		"a claimed 512MB must not be allocated before it arrives")
}

func TestNativeStalledSessionsDoNotStarveAnother(t *testing.T) {
	const stalled = 8
	for i := 0; i < stalled; i++ {
		upstream := startFakeClickHouse(t)
		conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"})
		clientHandshake(t, conn, "someone", "")

		var b proto.Buffer
		proto.ClientCodeQuery.Encode(&b)
		_, err := conn.Write(b.Buf)
		require.NoError(t, err)
	}

	upstream := startFakeClickHouse(t)
	upstream.answerQueries = true
	conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"})
	reader := clientHandshake(t, conn, "someone", "")
	writeQuery(t, conn, proto.Query{Body: "SELECT 1"})

	code, err := reader.UVarInt()
	require.NoError(t, err)
	require.Equal(t, proto.ServerCodeProgress, proto.ServerCode(code),
		"a session must be served while others sit mid-packet")
}

func TestNativeStalledSessionsHoldNoMemory(t *testing.T) {
	before := nativeBytesInFlight.Load()
	for i := 0; i < 8; i++ {
		upstream := startFakeClickHouse(t)
		conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"})
		clientHandshake(t, conn, "someone", "")
		startPartialQuery(t, conn, 1<<10)
	}
	require.Less(t, nativeBytesInFlight.Load()-before, int64(1<<20),
		"a session mid-packet must hold what it sent, not what it might send")
}

func TestNativeChargesAndReleasesAHalfSentPacket(t *testing.T) {
	const declared = 8 << 20

	before := nativeBytesInFlight.Load()
	upstream := startFakeClickHouse(t)
	conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"})
	clientHandshake(t, conn, "someone", "")
	startPartialQuery(t, conn, declared)

	waitForBytesInFlight(t, func(held int64) bool { return held >= declared },
		"the bytes a packet declared must be charged before they are allocated")

	require.NoError(t, conn.Close())
	waitForBytesInFlight(t, func(held int64) bool { return held <= before },
		"a packet that never arrived must give its charge back")
}

func TestNativeCutsOffAStalledPacketWithoutDeadlines(t *testing.T) {
	restore := packetIdleTimeout
	packetIdleTimeout = 150 * time.Millisecond
	t.Cleanup(func() { packetIdleTimeout = restore })

	before := nativeBytesInFlight.Load()
	upstream := startFakeClickHouse(t)
	conn := dialProxyOver(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"},
		func(c net.Conn) net.Conn { return deadlineDeafConn{c} })
	clientHandshake(t, conn, "someone", "")
	startPartialQuery(t, conn, 8<<20)

	waitForBytesInFlight(t, func(held int64) bool { return held >= 8<<20 },
		"the bytes a packet declared must be charged before they are allocated")
	waitForBytesInFlight(t, func(held int64) bool { return held <= before },
		"a stalled packet must be cut off even when the transport ignores deadlines")
}

func startPartialQuery(t *testing.T, conn net.Conn, declared int) {
	t.Helper()

	var b proto.Buffer
	proto.ClientCodeQuery.Encode(&b)
	b.PutUVarInt(uint64(declared))
	b.Buf = append(b.Buf, 'q')
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)
}

func waitForBytesInFlight(t *testing.T, ok func(held int64) bool, message string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok(nativeBytesInFlight.Load()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s (holding %d)", message, nativeBytesInFlight.Load())
}

func TestNativeRefusesWhatTheGatewayIsAlreadyHolding(t *testing.T) {
	nativeBytesInFlight.Add(maxNativeBytesInFlight)
	t.Cleanup(func() { nativeBytesInFlight.Add(-maxNativeBytesInFlight) })

	upstream := startFakeClickHouse(t)
	conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"})

	var b proto.Buffer
	proto.ClientHello{Name: "unit-test client", Major: 24, Minor: 8, ProtocolVersion: proto.Version}.Encode(&b)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	answer, _ := io.ReadAll(conn)
	require.Empty(t, answer, "a session the gateway has no memory for must not be answered")

	hello, _, _, _ := upstream.snapshot()
	require.Empty(t, hello.Name, "nothing may reach the upstream")
}

func TestNativeRefusesAPacketTheGatewayHasNoRoomFor(t *testing.T) {
	upstream := startFakeClickHouse(t)
	conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"})
	reader := clientHandshake(t, conn, "someone", "")

	const spare = 64 << 10
	nativeBytesInFlight.Add(maxNativeBytesInFlight - spare)
	t.Cleanup(func() { nativeBytesInFlight.Add(-(maxNativeBytesInFlight - spare)) })

	startPartialQuery(t, conn, 1<<20)

	code, message := decodeException(t, reader)
	require.Equal(t, codeNotImplemented, code)
	require.Contains(t, message, "already holding its share")

	_, _, queries, _ := upstream.snapshot()
	require.Empty(t, queries, "a refused packet must not reach ClickHouse")
}

// The target is configured, not chosen by the client, but a compromised one must not be able to
// take the gateway's memory with a size it merely claims.
func TestNativeBoundsWhatTheUpstreamDeclares(t *testing.T) {
	upstream := startFakeClickHouse(t)

	var answer proto.Buffer
	proto.ServerCodeData.Encode(&answer)
	answer.PutString("")
	proto.BlockInfo{BucketNum: -1}.Encode(&answer)
	answer.PutUVarInt(1)
	answer.PutUVarInt(1)
	answer.PutString("c")
	answer.PutString("String")
	answer.PutBool(false)
	answer.PutUVarInt(uint64(maxServerPacketBytes) + 1)
	answer.Buf = append(answer.Buf, []byte("short")...)
	upstream.answerWith = append([]byte{}, answer.Buf...)

	conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"})
	reader := clientHandshake(t, conn, "someone", "")
	writeQuery(t, conn, proto.Query{Body: "SELECT 1"})

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	relayed, err := reader.ReadRaw(len(upstream.answerWith))
	runtime.ReadMemStats(&after)

	require.NoError(t, err)
	require.Equal(t, upstream.answerWith, relayed,
		"a block the gateway gave up on must still reach the client untouched")
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(maxServerPacketBytes),
		"a declared size must not be allocated before it is read")
}

// Bytes waiting on a slow client are still memory the gateway is holding, so the charge has to
// outlive the decode that brought them in.
func TestNativeHoldsAServerPacketsChargeUntilItIsWritten(t *testing.T) {
	var col proto.ColStr
	for i := 0; i < 20000; i++ {
		col.Append(strings.Repeat("y", 100))
	}
	var answer proto.Buffer
	proto.ServerCodeData.Encode(&answer)
	answer.PutString("")
	block := proto.Block{Rows: col.Rows(), Columns: 1}
	require.NoError(t, block.EncodeBlock(&answer, proto.Version, []proto.InputColumn{{Name: "c", Data: &col}}))

	upstream := startFakeClickHouse(t)
	upstream.answerWith = append([]byte{}, answer.Buf...)

	before := nativeBytesInFlight.Load()
	conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"})
	reader := clientHandshake(t, conn, "someone", "")
	writeQuery(t, conn, proto.Query{Body: "SELECT c FROM t"})

	// One byte proves the write has begun, so the decode that charged it is over. The rest of the
	// packet is still in the gateway's hands, waiting on a client that is not reading.
	head, err := reader.ReadRaw(1)
	require.NoError(t, err)
	require.Equal(t, upstream.answerWith[:1], head)
	require.Greater(t, nativeBytesInFlight.Load()-before, int64(1<<20),
		"a packet waiting on the client must still be charged")

	relayed, err := reader.ReadRaw(len(upstream.answerWith) - 1)
	require.NoError(t, err)
	require.Equal(t, upstream.answerWith[1:], relayed)
	waitForBytesInFlight(t, func(held int64) bool { return held <= before },
		"the charge must go back once the bytes are gone")
}
