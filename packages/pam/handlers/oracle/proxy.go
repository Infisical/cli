package oracle

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

// prependedConn lets us push bytes we've already read back "in front" of a net.Conn's
// read stream, so downstream code can read them normally.
type prependedConn struct {
	net.Conn
	buf []byte
}

func (p *prependedConn) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// SetReadDeadline forwards to the wrapped conn; our prepended buf reads are synchronous
// so no deadline is needed for them.
func (p *prependedConn) SetReadDeadline(t time.Time) error {
	type withDeadline interface{ SetReadDeadline(time.Time) error }
	if d, ok := p.Conn.(withDeadline); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

// OracleProxyConfig mirrors the shape used by other PAM database handlers so the
// dispatch in pam-proxy.go stays templatized. Oracle-specific extras (the upstream
// TLS pinning fields) sit on top of the common eight.
type OracleProxyConfig struct {
	TargetAddr     string // "host:port"
	InjectUsername string
	InjectPassword string
	InjectDatabase string
	EnableTLS      bool
	TLSConfig      *tls.Config // provided by dispatcher but not used on the upstream leg
	SessionID      string
	SessionLogger  session.SessionLogger

	SSLRejectUnauthorized bool
	SSLCertificate        string
}

type OracleProxy struct {
	config OracleProxyConfig
}

func NewOracleProxy(config OracleProxyConfig) *OracleProxy {
	return &OracleProxy{config: config}
}

// HandleConnection runs one end-to-end PAM session for a connecting Oracle client.
// Flow:
//  1. Dial+auth upstream with real credentials so we fail cleanly if the backend is down.
//  2. Read the client's CONNECT, send an ACCEPT.
//  3. Drive server-side TCPNego + DataTypeNego.
//  4. Handle (and refuse) ANO if the client sent it.
//  5. Run server-side O5Logon verifying ProxyPasswordPlaceholder.
//  6. Relay raw bytes both directions with a passive TTC tap for query logging.
func (p *OracleProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	// New proxied-auth flow: forward client pre-auth bytes verbatim to upstream, intercept
	// only at O5Logon boundary. This keeps client and upstream in matching cap state, so
	// post-auth byte relay works for clients whose caps differ from go-ora's (notably JDBC
	// thin — sqlcl, SQL Developer, DBeaver).
	return p.handleConnectionProxied(ctx, clientConn)
}

// handleConnectionLegacy is the original impersonation flow (go-ora upstream dial +
// server-side handshake). Kept for reference; not currently routed.
func (p *OracleProxy) handleConnectionLegacy(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	defer func() {
		if err := p.config.SessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionID", p.config.SessionID).Msg("Failed to close session logger")
		}
	}()

	log.Info().Str("sessionID", p.config.SessionID).Str("target", p.config.TargetAddr).Msg("Oracle PAM session started")

	host, port, err := splitHostPort(p.config.TargetAddr)
	if err != nil {
		return fmt.Errorf("invalid target addr: %w", err)
	}

	upstream, err := DialUpstream(ctx, UpstreamCredentials{
		Host:                  host,
		Port:                  port,
		Service:               p.config.InjectDatabase,
		Username:              p.config.InjectUsername,
		Password:              p.config.InjectPassword,
		SSLEnabled:            p.config.EnableTLS,
		SSLRejectUnauthorized: p.config.SSLRejectUnauthorized,
		SSLCertificate:        p.config.SSLCertificate,
	})
	if err != nil {
		log.Error().Err(err).Str("sessionID", p.config.SessionID).Msg("Failed to authenticate to Oracle upstream")
		_ = WriteRefuseToClient(clientConn, "(DESCRIPTION=(ERR=12564)(VSNNUM=0)(ERROR_STACK=(ERROR=(CODE=12564)(EMFI=4))))")
		return fmt.Errorf("upstream auth failed: %w", err)
	}
	defer upstream.Close()

	// Read client CONNECT (16-bit length framing until ACCEPT completes + v315 negotiation).
	connectRaw, err := ReadFullPacket(clientConn, false)
	if err != nil {
		return fmt.Errorf("read client CONNECT: %w", err)
	}
	if PacketTypeOf(connectRaw) == PacketTypeResend {
		// Rare fall-back: client may re-send; accept and read again.
		connectRaw, err = ReadFullPacket(clientConn, false)
		if err != nil {
			return fmt.Errorf("re-read CONNECT: %w", err)
		}
	}
	if PacketTypeOf(connectRaw) != PacketTypeConnect {
		return fmt.Errorf("expected CONNECT, got type=%d", connectRaw[4])
	}
	connectPkt, err := ParseConnectPacket(connectRaw)
	if err != nil {
		return fmt.Errorf("parse CONNECT: %w", err)
	}

	log.Info().
		Str("sessionID", p.config.SessionID).
		Uint16("clientVersion", connectPkt.Version).
		Uint16("clientLoVersion", connectPkt.LoVersion).
		Uint32("clientSDU", connectPkt.SessionDataUnit).
		Uint32("clientTDU", connectPkt.TransportDataUnit).
		Uint16("clientOptions", connectPkt.Options).
		Uint8("clientFlag", connectPkt.Flag).
		Uint8("clientACFL0", connectPkt.ACFL0).
		Uint8("clientACFL1", connectPkt.ACFL1).
		Int("connectDataLen", len(connectPkt.ConnectData)).
		Str("connectRawHex", fmt.Sprintf("% X", connectRaw[:min(80, len(connectRaw))])).
		Msg("Oracle CONNECT received")

	accept := AcceptFromConnect(connectPkt)
	acceptBytes := accept.Bytes()
	if _, err := clientConn.Write(acceptBytes); err != nil {
		return fmt.Errorf("write ACCEPT: %w", err)
	}
	// From ACCEPT onward, use 32-bit length framing if negotiated >= 315.
	use32Bit := accept.Version >= 315
	log.Info().
		Str("sessionID", p.config.SessionID).
		Uint16("acceptVersion", accept.Version).
		Bool("use32BitLen", use32Bit).
		Int("acceptLen", len(acceptBytes)).
		Str("acceptHex", fmt.Sprintf("% X", acceptBytes)).
		Msg("Oracle ACCEPT sent")

	// Peek what the client sends next: if it's an empty read/EOF, the client rejected
	// our ACCEPT and closed the socket. Otherwise feed the bytes back into nego.
	peekBuf := make([]byte, 256)
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, peekErr := clientConn.Read(peekBuf)
	_ = clientConn.SetReadDeadline(time.Time{})
	log.Info().
		Str("sessionID", p.config.SessionID).
		Int("peekBytes", n).
		Err(peekErr).
		Str("peekHex", fmt.Sprintf("% X", peekBuf[:n])).
		Msg("Post-ACCEPT peek")
	if peekErr != nil && n == 0 {
		return fmt.Errorf("client closed after ACCEPT without sending nego: %w", peekErr)
	}

	peeked := append([]byte(nil), peekBuf[:n]...)

	// Connect-data supplement: some clients (notably go-ora) send the DESCRIPTION string
	// as a follow-up 16-bit-framed DATA packet right after the ACCEPT, before any nego
	// traffic. We recognise it by the 16-bit framing pattern (length high byte in [0],
	// length low byte in [1], bytes [2:4] zero, bytes[4] == 0x06 for DATA) and drain it.
	// Only after this supplement is consumed does the client switch to 32-bit framing.
	if supplementLen := detectConnectDataSupplement(peeked); supplementLen > 0 {
		log.Info().
			Str("sessionID", p.config.SessionID).
			Int("supplementLen", supplementLen).
			Msg("Draining connect-data supplement (16-bit framed DATA)")
		if supplementLen > len(peeked) {
			// Supplement extends past what we peeked — read the rest.
			remaining := make([]byte, supplementLen-len(peeked))
			if _, err := io.ReadFull(clientConn, remaining); err != nil {
				return fmt.Errorf("read connect-data supplement tail: %w", err)
			}
			peeked = nil
		} else {
			peeked = peeked[supplementLen:]
		}
	}

	clientConn = &prependedConn{Conn: clientConn, buf: peeked}

	// Pre-auth: client may send ANO / TCPNego / DataTypeNego in various orders.
	// RunPreAuthExchange dispatches per-payload and returns once it sees the auth-request
	// opcode (0x03), returning that payload so we can feed it to O5Logon phase 1.
	p1Payload, err := RunPreAuthExchange(clientConn, use32Bit)
	if err != nil {
		return fmt.Errorf("pre-auth exchange: %w", err)
	}
	log.Info().Str("sessionID", p.config.SessionID).Msg("Oracle pre-auth exchange complete")

	if _, err := ParseAuthPhaseOne(p1Payload); err != nil {
		_ = WriteErrorToClient(clientConn, ORA1017InvalidCredentials, "ORA-01017: invalid username/password; logon denied", use32Bit)
		return fmt.Errorf("parse auth phase 1: %w", err)
	}
	state, err := NewO5LogonServerState()
	if err != nil {
		return fmt.Errorf("init O5Logon state: %w", err)
	}
	p1Resp := BuildAuthPhaseOneResponse(state)
	log.Info().
		Str("sessionID", p.config.SessionID).
		Int("p1RespLen", len(p1Resp)).
		Str("p1RespHex", fmt.Sprintf("% X", p1Resp)).
		Msg("Auth phase 1 response")
	if err := writeDataPayload(clientConn, p1Resp, use32Bit); err != nil {
		return fmt.Errorf("write auth phase 1 response: %w", err)
	}

	p2Payload, err := readDataPayload(clientConn, use32Bit)
	if err != nil {
		return fmt.Errorf("read auth phase 2: %w", err)
	}
	p2, err := ParseAuthPhaseTwo(p2Payload)
	if err != nil {
		_ = WriteErrorToClient(clientConn, ORA1017InvalidCredentials, "ORA-01017: invalid username/password; logon denied", use32Bit)
		return fmt.Errorf("parse auth phase 2: %w", err)
	}
	if _, encKey, verr := state.VerifyClientPassword(p2.EClientSessKey, p2.EPassword); verr != nil {
		_ = WriteErrorToClient(clientConn, ORA1017InvalidCredentials, "ORA-01017: invalid username/password; logon denied", use32Bit)
		return fmt.Errorf("verify client password: %w", verr)
	} else {
		svr, err := BuildSvrResponse(encKey)
		if err != nil {
			return fmt.Errorf("build SVR response: %w", err)
		}
		// Mirror upstream's phase-2 KVPs (session IDs, NLS, db info etc.) so the client's
		// view of the session matches what upstream actually issued — otherwise subsequent
		// RPCs reference IDs upstream will reject.
		p2Resp := BuildAuthPhaseTwoResponseFromUpstream(svr, upstream.Phase2KVPs)
		if err := writeDataPayload(clientConn, p2Resp, use32Bit); err != nil {
			return fmt.Errorf("write auth phase 2 response: %w", err)
		}
	}

	log.Info().Str("sessionID", p.config.SessionID).Msg("Client authenticated; starting relay")

	c2u, u2c := NewQueryExtractorPair(p.config.SessionLogger, p.config.SessionID, use32Bit)
	defer c2u.Stop()
	defer u2c.Stop()

	errCh := make(chan error, 2)
	go relayWithTap(clientConn, upstream.Conn, c2u, errCh)
	go relayWithTap(upstream.Conn, clientConn, u2c, errCh)

	select {
	case rerr := <-errCh:
		if rerr != nil && rerr != io.EOF {
			log.Debug().Err(rerr).Str("sessionID", p.config.SessionID).Msg("Oracle relay ended")
		}
	case <-ctx.Done():
		log.Info().Str("sessionID", p.config.SessionID).Msg("Oracle session cancelled by context")
	}

	log.Info().Str("sessionID", p.config.SessionID).Msg("Oracle PAM session ended")
	return nil
}

// detectConnectDataSupplement returns the length of a 16-bit-framed DATA packet at the
// start of buf, or 0 if buf doesn't look like one. Pattern: bytes[0:2] = length (16-bit
// BE, plausible 8..64K), bytes[2:4] = 0 (packet checksum), bytes[4] = 0x06 (DATA type).
func detectConnectDataSupplement(buf []byte) int {
	if len(buf) < 8 {
		return 0
	}
	length := int(buf[0])<<8 | int(buf[1])
	if length < 8 || length > 64*1024 {
		return 0
	}
	// Reject if the length field LOOKS like the high bytes of a 32-bit length
	// (i.e. bytes[2:4] are non-zero would imply a 32-bit length). A 16-bit framed
	// packet MUST have bytes[2:4] zero because that's the checksum field.
	if buf[2] != 0 || buf[3] != 0 {
		return 0
	}
	if buf[4] != 0x06 {
		return 0
	}
	return length
}

// relayWithTap copies src → dst byte-for-byte, Feed()'ing a copy of each read into the
// tap extractor. This is the hot path — it must not parse or log per-packet.
func relayWithTap(src, dst net.Conn, tap *QueryExtractor, errCh chan<- error) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				errCh <- werr
				return
			}
			tap.Feed(buf[:n])
		}
		if err != nil {
			errCh <- err
			return
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q: %w", portStr, err)
	}
	return host, port, nil
}
