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

	"github.com/ClickHouse/ch-go/compress"
	"github.com/ClickHouse/ch-go/proto"
	"github.com/rs/zerolog"
)

const (
	// A newer server sends Hello fields ch-go cannot read, so both sides are pinned to what we can parse.
	maxNativeRevision = proto.Version

	nativeDialTimeout      = 30 * time.Second
	nativeWriteTimeout     = 60 * time.Second
	nativeHandshakeTimeout = 10 * time.Second
	nativeIdleTimeout      = 12 * time.Hour
)

type nativeProxy struct {
	*ClickHouseProxy
}

func newNativeProxy(owner *ClickHouseProxy) *nativeProxy {
	return &nativeProxy{ClickHouseProxy: owner}
}

// One byte at a time, or proto.Reader buffers past the packet.
type tap struct {
	src *bufio.Reader
	buf []byte

	// Set while a packet is being read, to push its deadline out as bytes arrive.
	refresh      func()
	sinceRefresh int
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
	if t.refresh != nil {
		if t.sinceRefresh++; t.sinceRefresh >= deadlineRefreshBytes {
			t.sinceRefresh = 0
			t.refresh()
		}
	}
	return 1, nil
}

func (t *tap) take() []byte {
	b := t.buf
	t.buf = nil
	return b
}

// Relaying from the socket instead would drop whatever the tap's buffer already holds.
func (t *tap) rest() io.Reader {
	return t.src
}

func (t *tap) discard() {
	t.buf = nil
}

// A refusal ends the session: the stream is mid-packet.
var errSessionRefused = errors.New("the session was refused")

type nativeSession struct {
	proxy    *nativeProxy
	log      zerolog.Logger
	client   net.Conn
	upstream net.Conn
	rev      int

	// One tap for both the handshake and the server loop; a second would lose what the first buffered.
	upstreamTap    *tap
	upstreamReader *proto.Reader

	outcomes *outcomeRecorder

	// Both directions write to the client, so a refusal must not land inside a packet mid-write.
	writeMu sync.Mutex
	refused atomic.Bool

	compressed atomic.Bool
	compressor *compress.Writer

	// A rejected statement's data blocks still arrive, and ClickHouse would reject them outside a query.
	droppingData bool
}

func (s *nativeSession) writeToClient(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.writeClientLocked(payload)
}

// Checked under the lock, or a packet cleared just before a refusal trails it.
func (s *nativeSession) writeToClientUnlessRefused(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.refused.Load() {
		return errSessionRefused
	}
	return s.writeClientLocked(payload)
}

func (s *nativeSession) writeClientLocked(payload []byte) error {
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

	// The HTTP port entered as the native one usually never answers the handshake.
	deadline := time.Now().Add(nativeHandshakeTimeout)
	_ = clientConn.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)

	// The handshake decodes client-declared strings too, so it is bounded like any other packet.
	handshake := &packetAccount{}
	clientReader.SetLimit(maxPacketBytes)
	clientReader.SetOnTake(handshake.charge)
	s.upstreamReader.SetLimit(maxPacketBytes)
	s.upstreamReader.SetOnTake(handshake.charge)
	err = s.handshake(clientTap, clientReader)
	clientReader.SetOnTake(nil)
	clientReader.SetLimit(0)
	s.upstreamReader.SetOnTake(nil)
	s.upstreamReader.SetLimit(0)
	handshake.release()
	if err != nil {
		l.Debug().Err(err).Msg("ClickHouse native handshake ended")
		return nil
	}

	_ = clientConn.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		// Upstream gone: end the session rather than block until the idle deadline.
		defer func() {
			if !s.refused.Load() {
				_ = clientConn.Close()
			}
		}()
		defer func() {
			if r := recover(); r != nil {
				l.Error().Interface("panic", r).Msg("Recovered from a panic reading the ClickHouse server direction")
			}
		}()
		s.serverLoop()
	}()

	// Deferred so a panic still drains the recorder.
	defer func() {
		// Outcomes must land before the recorder drains, or a finished statement is recorded as interrupted.
		upstream.Close()
		select {
		case <-serverDone:
		case <-time.After(nativeWriteTimeout):
			l.Warn().Msg("The ClickHouse server direction did not stop in time")
		}
		s.outcomes.finish()
	}()

	if err := s.clientLoop(clientTap, clientReader); err != nil {
		l.Debug().Err(err).Msg("ClickHouse native session ended")
	}
	return nil
}

// refuseDecode names the gateway running out of room rather than blaming the packet for it.
func (s *nativeSession) refuseDecode(t *tap, err error, message string) error {
	if errors.Is(err, errGatewayFull) {
		return s.refuse(t, codeNotImplemented, errGatewayFull.Error())
	}
	return s.refuse(t, codeNotImplemented, message)
}

func (s *nativeSession) refuse(t *tap, code int, message string) error {
	if t != nil {
		t.discard()
	}
	s.refused.Store(true)

	if err := s.writeToClient(nativeErrorPacket(s.rev, code, message)); err != nil {
		return err
	}
	return errSessionRefused
}

// For a fully read statement: the stream is still in sync, so the session carries on as ClickHouse's would.
func (s *nativeSession) reject(t *tap, code int, message string) error {
	t.discard()
	s.droppingData = true
	return s.writeToClient(nativeExceptionPacket(s.rev, code, message))
}

func (p *nativeProxy) dialUpstream(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: nativeDialTimeout}
	if !p.config.EnableTLS {
		return dialer.DialContext(ctx, "tcp", p.config.NativeAddr)
	}
	return (&tls.Dialer{NetDialer: dialer, Config: p.config.TLSConfig}).DialContext(ctx, "tcp", p.config.NativeAddr)
}

// handshake swaps the client's credentials for the account's and pins the revision both ways.
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

	// Unvalidated client input: a huge uvarint decodes negative and would be re-encoded as an enormous revision.
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
		s.log.Warn().Uint64("packetCode", serverCode).Msg("ClickHouse's native port did not answer the handshake")
		return s.refuse(t, codeNetworkError, "The native port on this account did not complete ClickHouse's "+
			"native handshake: "+unexpectedHandshakeReply(serverCode)+".")
	}

	var serverHello proto.ServerHello
	if err := serverHello.DecodeAware(serverReader, s.rev); err != nil {
		return fmt.Errorf("decode server hello: %w", err)
	}
	// Clamp to the upstream's revision so it never gets fields it can't read.
	if serverHello.Revision > 0 && serverHello.Revision < s.rev {
		s.rev = serverHello.Revision
	}
	serverHello.Revision = s.rev

	s.upstreamTap.discard()

	b.Reset()
	serverHello.EncodeAware(&b, s.rev)
	if err := s.writeToClient(b.Buf); err != nil {
		return fmt.Errorf("write client hello response: %w", err)
	}

	// At rev >= 54458 the quota key follows the handshake as a bare string. Ours is empty: not the client's to pick.
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

// A statement that is never parsed is one the policy never sees, so an unreadable stream ends the session.
func (s *nativeSession) clientLoop(t *tap, r *proto.Reader) error {
	for {
		_ = s.client.SetReadDeadline(time.Now().Add(nativeIdleTimeout))

		code, err := r.UVarInt()
		if err != nil {
			return fmt.Errorf("client hung up: %w", err)
		}

		// A half-sent packet must not hold what it allocated for as long as an idle session may
		// sit, and a slow one must still finish, so the deadline moves with the bytes.
		pushDeadline := func() { _ = s.client.SetReadDeadline(time.Now().Add(packetIdleTimeout)) }
		pushDeadline()
		t.refresh, t.sinceRefresh = pushDeadline, 0

		account := &packetAccount{}
		r.SetLimit(maxPacketBytes)
		r.SetOnTake(account.charge)
		err = s.handlePacket(t, r, code)
		r.SetOnTake(nil)
		r.SetLimit(0)
		account.release()
		t.refresh = nil
		if err != nil {
			return err
		}
	}
}

func (s *nativeSession) handlePacket(t *tap, r *proto.Reader, code uint64) error {
	{
		switch proto.ClientCode(code) {
		case proto.ClientCodeCancel:
			if s.droppingData {
				t.discard()
				return nil
			}
			if err := s.forward(t.take()); err != nil {
				return err
			}

		case proto.ClientCodePing:
			if err := s.forward(t.take()); err != nil {
				return err
			}

		case proto.ClientTablesStatusRequest:
			// Carries a table list the loop does not decode; forwarding just the code would desync the stream.
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
	return nil
}

func (s *nativeSession) handleQuery(t *tap, r *proto.Reader) error {
	var q proto.Query
	if err := q.DecodeAware(r, s.rev); err != nil {
		s.log.Warn().Err(err).Msg("Could not read a ClickHouse query packet")
		return s.refuseDecode(t, err,
			"This session could not read the query packet, so the command blocking policy could not be "+
				"applied to it.")
	}
	t.discard()
	s.droppingData = false
	s.compressed.Store(q.Compression == proto.CompressionEnabled)

	// EncodeAware always writes StageComplete, so a partial stage would be silently upgraded to a full run.
	if q.Stage != proto.StageComplete {
		return s.reject(t, codeNotImplemented,
			fmt.Sprintf("This session only runs statements to completion, and this client asked for stage %d.",
				int(q.Stage)))
	}

	statement := q.Body + nativeParameterSuffix(q.Parameters)

	if blocked := s.proxy.blockedBy(q.Body, statement); blocked != nil {
		s.proxy.logStatement(statement, fmt.Sprintf("BLOCKED: %s", blocked.String()))
		s.log.Info().Str("pattern", blocked.String()).Msg("Blocked a statement by policy")
		return s.reject(t, codeAccessDenied,
			"This statement is blocked by the command blocking policy on this account.")
	}

	s.outcomes.begin(statement)

	// InitialAddress stays set: ClickHouse asserts on an empty one.
	q.Info.QuotaKey = ""
	q.Info.Query = proto.ClientQueryInitial
	q.Secret = ""

	var b proto.Buffer
	q.EncodeAware(&b, s.rev)
	return s.forward(b.Buf)
}

// Re-encoded from what was parsed, so ClickHouse never reads bytes whose extent only it understood.
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
		decoded proto.Results
	)
	decodeErr := block.DecodeBlock(r, s.rev, decoded.Auto())
	if compressed {
		r.DisableCompression()
	}

	if decodeErr != nil {
		s.log.Warn().Err(decodeErr).Str("table", table).Msg("Could not read a ClickHouse data block")
		s.outcomes.complete("INTERRUPTED: a data block could not be read, so the rest was not forwarded")
		return s.refuseDecode(t, decodeErr,
			fmt.Sprintf("This session could not read the data block sent with this statement, so it was not "+
				"forwarded: %v. Sending this data over ClickHouse's HTTP interface avoids the limitation.", decodeErr))
	}
	t.discard()

	if s.droppingData {
		return nil
	}

	var compressor *compress.Writer
	if compressed {
		if s.compressor == nil {
			s.compressor = compress.NewWriter(compress.Level(0), compress.LZ4)
		}
		compressor = s.compressor
	}
	packet, err := encodeDataPacket(s.rev, table, block, decoded, compressor)
	if err != nil {
		s.log.Warn().Err(err).Str("table", table).Msg("Could not re-encode a ClickHouse data block")
		return s.refuse(nil, codeNotImplemented,
			fmt.Sprintf("This session could not re-encode the data block sent with this statement, so it was "+
				"not forwarded: %v. Sending this data over ClickHouse's HTTP interface avoids the limitation.", err))
	}
	return s.forward(packet)
}

// Read for the recording only: the first packet it cannot read ends the parsing, not the session.
func (s *nativeSession) serverLoop() {
	t := s.upstreamTap
	r := s.upstreamReader

	relayRest := func(reason string) {
		s.outcomes.degrade(reason)
		if err := s.writeToClientUnlessRefused(t.take()); err != nil {
			return
		}
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

		if err := s.writeToClientUnlessRefused(t.take()); err != nil {
			return
		}
	}
}

// Stops the raw relay appending bytes after the exception the client was just sent.
type refusalAwareWriter struct{ s *nativeSession }

func newRefusalAwareWriter(s *nativeSession) io.Writer { return refusalAwareWriter{s: s} }

func (w refusalAwareWriter) Write(p []byte) (int, error) {
	if err := w.s.writeToClientUnlessRefused(p); err != nil {
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

// Mirrors the HTTP handler, so a parameterized statement reads the same in either recording.
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

// Reports a gateway refusal as ClickHouse would, so a driver surfaces it rather than a broken connection.
func writeNativeError(w io.Writer, revision int, code int, message string) error {
	if _, err := w.Write(nativeErrorPacket(revision, code, message)); err != nil {
		return fmt.Errorf("write native exception: %w", err)
	}
	return nil
}

func nativeErrorPacket(revision int, code int, message string) []byte {
	var b proto.Buffer
	b.Buf = nativeExceptionPacket(revision, code, message)
	proto.ServerCodeEndOfStream.Encode(&b)
	return b.Buf
}

// No trailing EndOfStream: on a session that carries on, the client would read it as the next statement's end.
func nativeExceptionPacket(revision int, code int, message string) []byte {
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
	return b.Buf
}

// A Hello that happens to hold a blank line gets "HTTP/1.1 400" from the HTTP port, read as packet 72.
const httpResponseFirstByte = 'H'

func unexpectedHandshakeReply(code uint64) string {
	if code == httpResponseFirstByte {
		return "it answered with HTTP, which looks like ClickHouse's HTTP port entered as the native one"
	}
	return fmt.Sprintf("it answered with packet %d, which is not ClickHouse's native protocol", code)
}

// ClickHouse validates credentials during the handshake, so a Hello exchange is a real auth check.
func TestNativeConnection(ctx context.Context, config ClickHouseProxyConfig) error {
	return nativeHandshakeCheck(ctx, config, false)
}

// Sends no credential: any answer in the native protocol, a refused login included, proves the port.
func ProbeNativeProtocol(ctx context.Context, config ClickHouseProxyConfig) error {
	config.Username, config.Password = "", ""
	return nativeHandshakeCheck(ctx, config, true)
}

func nativeHandshakeCheck(ctx context.Context, config ClickHouseProxyConfig, exceptionProvesPort bool) error {
	dialCtx, cancel := context.WithTimeout(ctx, nativeDialTimeout)
	defer cancel()

	conn, err := (&nativeProxy{ClickHouseProxy: &ClickHouseProxy{config: config}}).dialUpstream(dialCtx)
	if err != nil {
		return err
	}
	defer conn.Close()

	// The probe's own budget wins when it is shorter, so a slow handshake cannot outlive the test.
	budget := nativeHandshakeTimeout
	budgetWasCapped := false
	if probeDeadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(probeDeadline); remaining < budget {
			budget, budgetWasCapped = remaining, true
		}
	}
	// Too little left to tell a silent port from a probe that simply ran out of time.
	if budget < time.Second {
		return fmt.Errorf("the connection test ran out of time before ClickHouse's native port could be "+
			"checked; %s remained of the budget", budget.Round(time.Millisecond))
	}
	_ = conn.SetDeadline(time.Now().Add(budget))

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
			if budgetWasCapped {
				return fmt.Errorf("the port accepted the connection but did not answer ClickHouse's native "+
					"handshake in the %s left of the connection test's budget: %w", budget.Round(time.Millisecond), err)
			}
			return fmt.Errorf("the port accepted the connection but did not answer ClickHouse's native "+
				"handshake within %s, which is what the HTTP port usually does when it is entered as the native one: %w",
				budget.Round(time.Second), err)
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
		if exceptionProvesPort {
			return nil
		}
		return fmt.Errorf("clickhouse rejected the connection: %s", e.Message)
	default:
		return errors.New(unexpectedHandshakeReply(code))
	}
}
