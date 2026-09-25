package clickhouse

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/rs/zerolog"
)

// Native brokers ClickHouse's TCP protocol on 9000/9440, which the HTTP interface cannot serve: clickhouse-client,
// clickhouse-driver and clickhouse-go all speak it exclusively. A statement arrives length-prefixed in its own
// Query packet, so unlike HTTP there is no inspection window to overrun and an INSERT's rows never reach the policy.
//
// Only the client direction is parsed. The server direction is relayed byte for byte, because nothing in it is
// inspected and decoding it would make a SELECT fail on any column type ch-go cannot infer.

const (
	// ch-go decodes up to its own revision, and a newer server sends Hello fields it cannot read. Both sides are
	// pinned to what we can parse, which downgrades the client too.
	maxNativeRevision = proto.Version

	nativeDialTimeout  = 30 * time.Second
	nativeWriteTimeout = 60 * time.Second
	// A port that accepts TCP and then says nothing is the symptom of the HTTP port entered as the native one,
	// so the handshake gives up well before the dial would.
	nativeHandshakeTimeout = 10 * time.Second
	// Long enough that a slow client is not dropped mid-statement, short enough to reap an abandoned session.
	nativeIdleTimeout = 12 * time.Hour
)

type nativeProxy struct {
	*ClickHouseProxy
}

func newNativeProxy(owner *ClickHouseProxy) *nativeProxy {
	return &nativeProxy{ClickHouseProxy: owner}
}

// tap records every byte a decoder consumes so the exact wire bytes can be replayed upstream. Reads are handed
// out one at a time: proto.Reader buffers 128 KB, which would swallow packets we have not parsed yet.
type tap struct {
	src *bufio.Reader
	buf []byte
}

func newTap(r io.Reader) *tap {
	return &tap{src: bufio.NewReaderSize(r, 64<<10)}
}

func (t *tap) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b, err := t.src.ReadByte()
	if err != nil {
		return 0, err
	}
	p[0] = b
	t.buf = append(t.buf, b)
	return 1, nil
}

// take returns the bytes consumed since the last call and starts a new run.
func (t *tap) take() []byte {
	b := t.buf
	t.buf = nil
	return b
}

// rest is the reader the tap is draining, buffered bytes included. Relaying from the socket directly would
// silently drop whatever the buffer already holds.
func (t *tap) rest() io.Reader {
	return t.src
}

func (t *tap) discard() {
	t.buf = nil
}

// Writing an exception ends the session. The client's stream is mid-packet once a refusal happens, so
// carrying on would parse garbage, and anything still in the tap could be flushed upstream by a later
// packet: a refused statement would reach ClickHouse after being refused.
var errSessionRefused = errors.New("the session was refused")

type nativeSession struct {
	proxy    *nativeProxy
	log      zerolog.Logger
	client   net.Conn
	upstream net.Conn
	rev      int

	// One tap over the upstream, shared by the handshake and the server loop. A second tap would start its
	// own buffer and lose whatever the first had already read off the socket.
	upstreamTap    *tap
	upstreamReader *proto.Reader

	outcomes *outcomeRecorder

	// Both directions write to the client, so a refusal must not land inside a packet the server loop is
	// still writing. Once refused, the server loop stops writing entirely.
	writeMu sync.Mutex
	refused atomic.Bool

	// Set by the Query packet and read by the data-block decoder
	compressed atomic.Bool
}

// writeToClient serialises the two directions and bounds a client that has stopped reading.
func (s *nativeSession) writeToClient(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	_ = s.client.SetWriteDeadline(time.Now().Add(nativeWriteTimeout))
	defer func() { _ = s.client.SetWriteDeadline(time.Time{}) }()

	_, err := s.client.Write(payload)
	return err
}

func (s *nativeSession) writeToUpstream(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	_ = s.upstream.SetWriteDeadline(time.Now().Add(nativeWriteTimeout))
	defer func() { _ = s.upstream.SetWriteDeadline(time.Time{}) }()

	_, err := s.upstream.Write(payload)
	return err
}

func (p *nativeProxy) HandleConnection(ctx context.Context, clientConn net.Conn, l zerolog.Logger) error {
	defer clientConn.Close()
	// A malformed packet must not take the gateway, and every other session with it, down.
	defer func() {
		if r := recover(); r != nil {
			l.Error().Interface("panic", r).Msg("Recovered from a panic in the ClickHouse native handler")
		}
	}()

	upstream, err := p.dialUpstream(ctx)
	if err != nil {
		l.Error().Err(err).Msg("Failed to reach ClickHouse over the native protocol")
		return writeNativeError(clientConn, maxNativeRevision, codeNetworkError,
			fmt.Sprintf("The gateway could not reach ClickHouse: %v", err))
	}
	defer upstream.Close()

	stop := context.AfterFunc(ctx, func() {
		clientConn.Close()
		upstream.Close()
	})
	defer stop()

	s := &nativeSession{proxy: p, log: l, client: clientConn, upstream: upstream}
	s.outcomes = newOutcomeRecorder(p.ClickHouseProxy)
	s.upstreamTap = newTap(upstream)
	s.upstreamReader = proto.NewReader(s.upstreamTap)

	clientTap := newTap(clientConn)
	clientReader := proto.NewReader(clientTap)

	// A port that accepts TCP and then says nothing is the symptom of the HTTP port entered as the native
	// one, so the handshake gives up rather than holding both sockets until the session expires.
	deadline := time.Now().Add(nativeHandshakeTimeout)
	_ = clientConn.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)

	if err := s.handshake(clientTap, clientReader); err != nil {
		l.Debug().Err(err).Msg("ClickHouse native handshake ended")
		return nil
	}

	_ = clientConn.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	// Nothing in the server direction gates a statement, so a packet it cannot read costs only the outcome of
	// that statement: it flushes what it read and streams the rest untouched.
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer func() {
			if r := recover(); r != nil {
				l.Error().Interface("panic", r).Msg("Recovered from a panic reading the ClickHouse server direction")
			}
		}()
		s.serverLoop()
	}()

	if err := s.clientLoop(clientTap, clientReader); err != nil {
		l.Debug().Err(err).Msg("ClickHouse native session ended")
	}

	// Closing the upstream unblocks the server loop. Its outcomes have to land before the recorder drains,
	// or a statement that finished is written to the recording as interrupted.
	upstream.Close()
	select {
	case <-serverDone:
	case <-time.After(nativeWriteTimeout):
		l.Warn().Msg("The ClickHouse server direction did not stop in time")
	}
	s.outcomes.finish()
	return nil
}

// refuse reports the refusal to the client and ends the session.
func (s *nativeSession) refuse(t *tap, code int, message string) error {
	if t != nil {
		t.discard()
	}
	// Set before writing, so the server loop cannot interleave a packet with the exception.
	s.refused.Store(true)

	if err := s.writeToClient(nativeErrorPacket(s.rev, code, message)); err != nil {
		return err
	}
	return errSessionRefused
}

func (p *nativeProxy) dialUpstream(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: nativeDialTimeout}
	if !p.config.EnableTLS {
		return dialer.DialContext(ctx, "tcp", p.config.NativeAddr)
	}
	return (&tls.Dialer{NetDialer: dialer, Config: p.config.TLSConfig}).DialContext(ctx, "tcp", p.config.NativeAddr)
}

// handshake swaps the client's credentials for the account's, so nothing the client holds works outside a
// recorded session, and pins the protocol revision both ways.
func (s *nativeSession) handshake(t *tap, r *proto.Reader) error {
	code, err := r.UVarInt()
	if err != nil {
		return fmt.Errorf("read client packet code: %w", err)
	}
	if proto.ClientCode(code) != proto.ClientCodeHello {
		return fmt.Errorf("expected Hello, got client packet %d", code)
	}

	var hello proto.ClientHello
	if err := hello.Decode(r); err != nil {
		return fmt.Errorf("decode client hello: %w", err)
	}
	t.discard()

	// The revision drives feature gating on both sides, and it is unvalidated client input: a huge uvarint
	// decodes to a negative int, which would be re-encoded upstream as an enormous revision.
	if hello.ProtocolVersion <= 0 {
		return s.refuse(t, codeNotImplemented,
			fmt.Sprintf("This session could not read the protocol revision %d the client asked for.",
				hello.ProtocolVersion))
	}
	s.rev = min(hello.ProtocolVersion, maxNativeRevision)

	var b proto.Buffer
	proto.ClientHello{
		Name:            hello.Name,
		Major:           hello.Major,
		Minor:           hello.Minor,
		ProtocolVersion: s.rev,
		Database:        s.proxy.config.Database,
		User:            s.proxy.config.Username,
		Password:        s.proxy.config.Password,
	}.Encode(&b)
	if err := s.writeToUpstream(b.Buf); err != nil {
		return fmt.Errorf("write upstream hello: %w", err)
	}

	serverReader := s.upstreamReader
	serverCode, err := serverReader.UVarInt()
	if err != nil {
		return fmt.Errorf("read server packet code: %w", err)
	}

	if proto.ServerCode(serverCode) == proto.ServerCodeException {
		var e proto.Exception
		if err := e.DecodeAware(serverReader, s.rev); err != nil {
			return fmt.Errorf("decode upstream exception: %w", err)
		}
		s.log.Warn().Str("upstreamError", e.Message).Msg("ClickHouse refused the account credentials")
		return s.refuse(t, codeAccessDenied,
			fmt.Sprintf("ClickHouse refused the account this session uses: %s", e.Message))
	}
	if proto.ServerCode(serverCode) != proto.ServerCodeHello {
		return fmt.Errorf("expected server Hello, got packet %d", serverCode)
	}

	var serverHello proto.ServerHello
	if err := serverHello.DecodeAware(serverReader, s.rev); err != nil {
		return fmt.Errorf("decode server hello: %w", err)
	}
	// The client keys its own encoding off the revision it is told, so it has to see the pinned one.
	serverHello.Revision = s.rev

	s.upstreamTap.discard()

	b.Reset()
	serverHello.EncodeAware(&b, s.rev)
	if err := s.writeToClient(b.Buf); err != nil {
		return fmt.Errorf("write client hello response: %w", err)
	}

	// At rev >= 54458 the client follows the handshake with its quota key, written as a bare string rather than
	// a coded packet. Ours is empty: the account's quota is not the client's to choose.
	if proto.FeatureAddendum.In(s.rev) {
		if _, err := r.Str(); err != nil {
			return fmt.Errorf("read client addendum: %w", err)
		}
		t.discard()

		b.Reset()
		b.PutString("")
		if err := s.writeToUpstream(b.Buf); err != nil {
			return fmt.Errorf("write upstream addendum: %w", err)
		}
	}

	s.log.Info().
		Str("clientName", hello.Name).
		Int("revision", s.rev).
		Msg("ClickHouse native session established")
	return nil
}

// clientLoop parses every packet the client sends. A statement that is never parsed is a statement the policy
// never sees, so an unreadable stream ends the session rather than being relayed blind.
func (s *nativeSession) clientLoop(t *tap, r *proto.Reader) error {
	for {
		_ = s.client.SetReadDeadline(time.Now().Add(nativeIdleTimeout))

		code, err := r.UVarInt()
		if err != nil {
			return fmt.Errorf("client hung up: %w", err)
		}

		switch proto.ClientCode(code) {
		case proto.ClientCodePing, proto.ClientCodeCancel:
			if err := s.forward(t.take()); err != nil {
				return err
			}

		case proto.ClientTablesStatusRequest:
			// This one carries a table list the loop does not decode. Forwarding just the code would leave
			// the stream one packet out of step and every later statement unreadable.
			return s.refuse(t, codeNotImplemented,
				"This session does not support ClickHouse's tables-status request.")

		case proto.ClientCodeQuery:
			if err := s.handleQuery(t, r); err != nil {
				return err
			}

		case proto.ClientCodeData:
			if err := s.handleData(t, r); err != nil {
				return err
			}

		default:
			s.log.Warn().Uint64("packetCode", code).Msg("Refused an unreadable ClickHouse client packet")
			return s.refuse(t, codeNotImplemented,
				fmt.Sprintf("This session could not read ClickHouse client packet %d, so the command blocking "+
					"policy could not be applied to it.", code))
		}
	}
}

func (s *nativeSession) handleQuery(t *tap, r *proto.Reader) error {
	var q proto.Query
	if err := q.DecodeAware(r, s.rev); err != nil {
		s.log.Warn().Err(err).Msg("Could not read a ClickHouse query packet")
		return s.refuse(t, codeNotImplemented,
			"This session could not read the query packet, so the command blocking policy could not be "+
				"applied to it.")
	}
	t.discard()

	// EncodeAware always writes StageComplete, so a client asking for a partial stage would have its query
	// silently upgraded to a full execution. Refusing is the honest answer.
	if q.Stage != proto.StageComplete {
		return s.refuse(t, codeNotImplemented,
			fmt.Sprintf("This session only runs statements to completion, and this client asked for stage %d.",
				int(q.Stage)))
	}

	s.compressed.Store(q.Compression == proto.CompressionEnabled)

	statement := q.Body + nativeParameterSuffix(q.Parameters)

	if blocked := s.proxy.blockedBy(statement); blocked != nil {
		s.proxy.logStatement(statement, fmt.Sprintf("BLOCKED: %s", blocked.String()))
		s.log.Info().Str("pattern", blocked.String()).Msg("Blocked a statement by policy")
		return s.refuse(t, codeAccessDenied,
			"This statement is blocked by the command blocking policy on this account.")
	}

	s.outcomes.begin(statement)

	// The identities a client could otherwise choose for itself, matching the set the HTTP interface strips.
	// An inter-server secret in particular must never be something a session gets to pick.
	// InitialUser and InitialAddress are deliberately left alone: forcing the query kind to Initial already
	// makes ClickHouse authorise as the account, and it asserts on an empty initial address.
	q.Info.QuotaKey = ""
	q.Info.Query = proto.ClientQueryInitial
	q.Secret = ""

	var b proto.Buffer
	q.EncodeAware(&b, s.rev)
	return s.forward(b.Buf)
}

// handleData decodes a block only far enough to find where it ends, then replays the client's own bytes. The
// decoded values are discarded: re-encoding them would have to reproduce a serialization we do not own.
func (s *nativeSession) handleData(t *tap, r *proto.Reader) error {
	table, err := r.Str()
	if err != nil {
		s.log.Warn().Err(err).Msg("Could not read a ClickHouse data packet")
		return s.refuse(t, codeNotImplemented,
			"This session could not read the data packet that followed this statement.")
	}

	compressed := s.compressed.Load()
	if compressed {
		r.EnableCompression()
	}
	var (
		block   proto.Block
		discard proto.Results
	)
	decodeErr := block.DecodeBlock(r, s.rev, discard.Auto())
	if compressed {
		r.DisableCompression()
	}

	if decodeErr != nil {
		s.log.Warn().Err(decodeErr).Str("table", table).Msg("Could not read a ClickHouse data block")
		return s.refuse(t, codeNotImplemented,
			fmt.Sprintf("This session could not read the data block sent with this statement, so it was not "+
				"forwarded: %v. Sending this data over ClickHouse's HTTP interface avoids the limitation.", decodeErr))
	}

	return s.forward(t.take())
}

// serverLoop reads the server direction for the sake of the recording only. Every packet is replayed to the
// client byte for byte, and the first one it cannot read ends the parsing rather than the session.
func (s *nativeSession) serverLoop() {
	t := s.upstreamTap
	r := s.upstreamReader

	relayRest := func(reason string) {
		s.outcomes.degrade(reason)
		if s.refused.Load() {
			return
		}
		if err := s.writeToClient(t.take()); err != nil {
			return
		}
		// Reading the socket directly here would skip whatever the tap has already buffered off it, which
		// is most of the in-flight response.
		_, _ = io.Copy(newRefusalAwareWriter(s), t.rest())
	}

	for {
		code, err := r.UVarInt()
		if err != nil {
			return
		}

		switch proto.ServerCode(code) {
		case proto.ServerCodePong:

		case proto.ServerCodeEndOfStream:
			s.outcomes.complete("OK")

		case proto.ServerCodeException:
			var e proto.Exception
			if err := e.DecodeAware(r, s.rev); err != nil {
				relayRest(err.Error())
				return
			}
			message := firstLine(e.Message, e.Name)
			if len(message) > maxLoggedErrorBytes {
				message = message[:maxLoggedErrorBytes] + "... [truncated]"
			}
			s.outcomes.complete(fmt.Sprintf("ERROR: Code %d: %s", e.Code, message))

		case proto.ServerCodeProgress:
			var p proto.Progress
			if err := p.DecodeAware(r, s.rev); err != nil {
				relayRest(err.Error())
				return
			}
			s.outcomes.progress(p.Rows, p.Bytes)

		case proto.ServerCodeProfile:
			var p proto.Profile
			if err := p.DecodeAware(r, s.rev); err != nil {
				relayRest(err.Error())
				return
			}

		case proto.ServerCodeTableColumns:
			if _, err := r.Str(); err != nil {
				relayRest(err.Error())
				return
			}
			if _, err := r.Str(); err != nil {
				relayRest(err.Error())
				return
			}

		case proto.ServerCodeData, proto.ServerCodeTotals, proto.ServerCodeExtremes, proto.ServerCodeLog,
			proto.ServerProfileEvents:
			if err := s.skipServerBlock(r, proto.ServerCode(code)); err != nil {
				relayRest(err.Error())
				return
			}

		default:
			relayRest(fmt.Sprintf("unreadable server packet %d", code))
			return
		}

		if s.refused.Load() {
			return
		}
		if err := s.writeToClient(t.take()); err != nil {
			return
		}
	}
}

// refusalAwareWriter stops relaying once the client loop has refused the session, so a raw relay cannot
// append bytes after the exception the client was just sent.
type refusalAwareWriter struct{ s *nativeSession }

func newRefusalAwareWriter(s *nativeSession) io.Writer { return refusalAwareWriter{s: s} }

func (w refusalAwareWriter) Write(p []byte) (int, error) {
	if w.s.refused.Load() {
		return 0, errSessionRefused
	}
	if err := w.s.writeToClient(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Log and profile-event blocks are never compressed, whatever the query asked for.
func (s *nativeSession) skipServerBlock(r *proto.Reader, code proto.ServerCode) error {
	if _, err := r.Str(); err != nil {
		return fmt.Errorf("read block table name: %w", err)
	}

	compressed := s.compressed.Load() &&
		code != proto.ServerCodeLog && code != proto.ServerProfileEvents
	if compressed {
		r.EnableCompression()
		defer r.DisableCompression()
	}

	var (
		block   proto.Block
		discard proto.Results
	)
	return block.DecodeBlock(r, s.rev, discard.Auto())
}

func (s *nativeSession) forward(payload []byte) error {
	if err := s.writeToUpstream(payload); err != nil {
		return fmt.Errorf("forward to ClickHouse: %w", err)
	}
	return nil
}

// nativeParameterSuffix mirrors the HTTP handler, so a parameterized statement reads the same in a recording
// whichever interface ran it.
func nativeParameterSuffix(parameters []proto.Parameter) string {
	if len(parameters) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(parameters))
	for _, p := range parameters {
		pairs = append(pairs, p.Key+"="+p.Value)
	}
	return "\n-- parameters: " + strings.Join(pairs, " ")
}

// writeNativeError reports a gateway refusal the way ClickHouse reports its own, so a driver surfaces it as a
// server exception rather than a broken connection.
func writeNativeError(w io.Writer, revision int, code int, message string) error {
	if _, err := w.Write(nativeErrorPacket(revision, code, message)); err != nil {
		return fmt.Errorf("write native exception: %w", err)
	}
	return nil
}

// nativeErrorPacket builds the exception and the end-of-stream that closes it out.
func nativeErrorPacket(revision int, code int, message string) []byte {
	if revision <= 0 {
		revision = maxNativeRevision
	}

	var b proto.Buffer
	proto.ServerCodeException.Encode(&b)
	exception := proto.Exception{
		Code:    proto.Error(code),
		Name:    "DB::Exception",
		Message: message,
	}
	exception.EncodeAware(&b, revision)
	proto.ServerCodeEndOfStream.Encode(&b)
	return b.Buf
}

// TestNativeConnection proves the account can log in over the native port. ClickHouse validates credentials
// during the handshake, so a successful Hello exchange is a real auth check rather than a reachability probe.
func TestNativeConnection(ctx context.Context, config ClickHouseProxyConfig) error {
	dialCtx, cancel := context.WithTimeout(ctx, nativeDialTimeout)
	defer cancel()

	conn, err := (&nativeProxy{ClickHouseProxy: &ClickHouseProxy{config: config}}).dialUpstream(dialCtx)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(nativeHandshakeTimeout))

	var b proto.Buffer
	proto.ClientHello{
		Name:            "Infisical PAM",
		Major:           1,
		Minor:           0,
		ProtocolVersion: maxNativeRevision,
		Database:        config.Database,
		User:            config.Username,
		Password:        config.Password,
	}.Encode(&b)
	if _, err := conn.Write(b.Buf); err != nil {
		return fmt.Errorf("write hello: %w", err)
	}

	r := proto.NewReader(newTap(conn))
	code, err := r.UVarInt()
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return fmt.Errorf("the port accepted the connection but did not answer ClickHouse's native "+
				"handshake within %s, which is what the HTTP port does when it is entered as the native one",
				nativeHandshakeTimeout)
		}
		return fmt.Errorf("read hello response: %w", err)
	}

	switch proto.ServerCode(code) {
	case proto.ServerCodeHello:
		var hello proto.ServerHello
		if err := hello.DecodeAware(r, maxNativeRevision); err != nil {
			return fmt.Errorf("decode hello response: %w", err)
		}
		return nil
	case proto.ServerCodeException:
		var e proto.Exception
		if err := e.DecodeAware(r, maxNativeRevision); err != nil {
			return fmt.Errorf("decode exception: %w", err)
		}
		return fmt.Errorf("clickhouse rejected the connection: %s", e.Message)
	default:
		return fmt.Errorf("unexpected server packet %d during the native handshake", code)
	}
}
