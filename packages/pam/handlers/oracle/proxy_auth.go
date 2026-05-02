package oracle

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// handleConnectionProxied is the cap-aligned implementation of the Oracle PAM handler.
// Instead of dialling upstream via go-ora (which negotiates upstream state with go-ora's
// own caps), we open a raw TCP connection to upstream and forward the client's CONNECT /
// ANO / TCPNego / DataTypeNego bytes verbatim. Upstream therefore negotiates with the
// CLIENT's caps — making post-auth byte relay possible.
//
// The only interception happens at the O5Logon boundary: we decrypt the client's key
// material with the placeholder password, re-encrypt with the real password before
// forwarding to upstream; and we substitute upstream's password-derived fields with
// placeholder-derived equivalents when forwarding to the client.
func (p *OracleProxy) handleConnectionProxied(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	defer func() {
		if err := p.config.SessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionID", p.config.SessionID).Msg("Failed to close session logger")
		}
	}()

	log.Info().Str("sessionID", p.config.SessionID).Str("target", p.config.TargetAddr).Msg("Oracle PAM session started (proxied auth)")

	// 1. Dial upstream. For TCPS targets we get back both the raw TCP conn and
	// the first TLS session wrapping it. Oracle's TCPS flow may ask us to do
	// a SECOND TLS handshake on the raw conn partway through (see the
	// RESEND+flag=0x08 branch below), so we keep both references.
	rawUpstream, tlsUpstream, err := dialUpstreamRaw(ctx, p.config)
	if err != nil {
		log.Error().Err(err).Str("sessionID", p.config.SessionID).Msg("Failed to dial Oracle upstream")
		_ = WriteRefuseToClient(clientConn, "(DESCRIPTION=(ERR=12564)(VSNNUM=0)(ERROR_STACK=(ERROR=(CODE=12564)(EMFI=4))))")
		return fmt.Errorf("upstream dial: %w", err)
	}
	// upstreamConn starts as the first TLS session (when TLS) or the raw conn
	// (when not). It may be reassigned to a fresh *tls.Conn on a flag-0x08
	// RESEND. The deferred close acts on whatever it points to at exit time.
	var upstreamConn net.Conn
	if tlsUpstream != nil {
		upstreamConn = tlsUpstream
	} else {
		upstreamConn = rawUpstream
	}
	defer func() { upstreamConn.Close() }()

	// 2. Forward client CONNECT → upstream, then upstream ACCEPT → client.
	connectRaw, err := ReadFullPacket(clientConn, false)
	if err != nil {
		return fmt.Errorf("read client CONNECT: %w", err)
	}
	if PacketTypeOf(connectRaw) != PacketTypeConnect {
		return fmt.Errorf("expected CONNECT, got type=%d", connectRaw[4])
	}
	if _, err := upstreamConn.Write(connectRaw); err != nil {
		return fmt.Errorf("forward CONNECT: %w", err)
	}

	// Read upstream packets until we see ACCEPT. The listener may send intermediate
	// packets first — notably NSPTRS (type 0x0B, "RESEND") which tells the client to
	// re-transmit its DESCRIPTION as a follow-up packet because it didn't fit inline
	// in the CONNECT. We forward these intermediates to the client transparently, and
	// if we see NSPTRS specifically we also read the client's follow-up packet and
	// forward it back to upstream — otherwise upstream stalls waiting for it.
	//
	// A REFUSE / REDIRECT ends the flow with an error.
	var acceptRaw []byte
	for attempt := 0; acceptRaw == nil; attempt++ {
		pkt, err := ReadFullPacket(upstreamConn, false)
		if err != nil {
			return fmt.Errorf("read upstream handshake packet (attempt %d): %w", attempt, err)
		}
		pktType := PacketTypeOf(pkt)
		var origFlag byte
		if len(pkt) > 5 {
			origFlag = pkt[5]
		}
		log.Info().Str("sessionID", p.config.SessionID).Uint8("pktType", uint8(pktType)).Int("pktLen", len(pkt)).Uint8("flag", origFlag).Msg("Proxy: upstream handshake packet")

		// Oracle TCPS in-band "restart TLS" signal: RESEND with byte-5 flag
		// 0x08 tells the client to abandon the current TLS session and run a
		// FRESH TLS handshake on the raw TCP socket (bypassing the already-
		// established first-round TLS). The server does the same on its end.
		// go-ora handles this in network/session.go readPacket's RESEND branch
		// by calling session.negotiate() again — which creates a new
		// tls.Client(session.conn, ...) wrapping the raw conn. We do the
		// equivalent here.
		if p.config.EnableTLS && pktType == PacketTypeResend && origFlag&0x08 != 0 {
			tc, terr := upgradeToTLS(ctx, rawUpstream, p.config)
			if terr != nil {
				return fmt.Errorf("upstream TLS upgrade after RESEND(flag=0x08): %w", terr)
			}
			upstreamConn = tc
			log.Info().Str("sessionID", p.config.SessionID).Str("tlsVersion", tlsVersionString(tc.ConnectionState().Version)).Str("cipher", tls.CipherSuiteName(tc.ConnectionState().CipherSuite)).Msg("Proxy: upstream TLS re-handshook on RESEND(flag=0x08)")
		}

		// Byte-5 masking: thin clients (JDBC thin, python-oracledb thin) read
		// byte 5 from the RESEND to decide whether their local socket is
		// TCPS-shaped and try to cast their NT adapter to TcpsNTAdapter. Our
		// client-facing socket is plain TCP, so the cast would fail. Strip
		// the flag on the packet going to the client.
		if p.config.EnableTLS && len(pkt) > 5 {
			pkt[5] = 0x00
		}
		if _, werr := clientConn.Write(pkt); werr != nil {
			return fmt.Errorf("forward upstream handshake packet: %w", werr)
		}
		switch pktType {
		case PacketTypeAccept:
			acceptRaw = pkt
		case PacketTypeRefuse:
			return fmt.Errorf("upstream REFUSE during handshake")
		case PacketTypeRedirect:
			return fmt.Errorf("upstream REDIRECT during handshake (not supported)")
		case PacketTypeResend:
			// Read the client's follow-up packet (typically the DESCRIPTION supplement
			// as a 16-bit-framed DATA packet) and forward to upstream. If we upgraded
			// to TLS above, this write flows through the new TLS session.
			supplement, err := ReadFullPacket(clientConn, false)
			if err != nil {
				return fmt.Errorf("read client supplement after RESEND: %w", err)
			}
			log.Info().Str("sessionID", p.config.SessionID).Int("supplementLen", len(supplement)).Uint8("supplType", uint8(PacketTypeOf(supplement))).Msg("Proxy: forwarding client supplement after RESEND")
			if _, werr := upstreamConn.Write(supplement); werr != nil {
				return fmt.Errorf("forward client supplement: %w", werr)
			}
		}
	}

	// Parse ACCEPT to learn negotiated version → framing mode.
	// Layout: bytes[8:10] = version (u16BE).
	var acceptVersion uint16
	if len(acceptRaw) >= 10 {
		acceptVersion = binary.BigEndian.Uint16(acceptRaw[8:10])
	}
	use32Bit := acceptVersion >= 315
	log.Info().Str("sessionID", p.config.SessionID).Uint16("acceptVersion", acceptVersion).Bool("use32Bit", use32Bit).Msg("Proxy: ACCEPT forwarded")

	// 3. Post-ACCEPT: peek for go-ora's 16-bit-framed connect-data supplement.
	peekBuf := make([]byte, 256)
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := clientConn.Read(peekBuf)
	_ = clientConn.SetReadDeadline(time.Time{})
	peeked := append([]byte(nil), peekBuf[:n]...)
	if slen := detectConnectDataSupplement(peeked); slen > 0 {
		log.Info().Int("supplementLen", slen).Msg("Proxy: draining connect-data supplement, forwarding to upstream")
		if slen > len(peeked) {
			rest := make([]byte, slen-len(peeked))
			if _, err := io.ReadFull(clientConn, rest); err != nil {
				return fmt.Errorf("read supplement tail: %w", err)
			}
			// Forward full supplement to upstream.
			if _, err := upstreamConn.Write(peeked); err != nil {
				return fmt.Errorf("forward supplement head: %w", err)
			}
			if _, err := upstreamConn.Write(rest); err != nil {
				return fmt.Errorf("forward supplement tail: %w", err)
			}
			peeked = nil
		} else {
			if _, err := upstreamConn.Write(peeked[:slen]); err != nil {
				return fmt.Errorf("forward supplement: %w", err)
			}
			peeked = peeked[slen:]
		}
	}
	if len(peeked) > 0 {
		clientConn = &prependedConn{Conn: clientConn, buf: peeked}
	}

	// 4. Pre-auth turn-taking loop: each client packet → forward to upstream → read
	//    upstream response → forward to client. Break when we see the auth request.
	p1Payload, err := proxyUntilAuthRequest(clientConn, upstreamConn, use32Bit, p.config.SessionID)
	if err != nil {
		return fmt.Errorf("pre-auth proxy: %w", err)
	}
	log.Info().Str("sessionID", p.config.SessionID).Int("p1Len", len(p1Payload)).Msg("Proxy: auth-request boundary reached")

	// 5. Rewrite the phase-1 auth-request username to match the configured account,
	// then forward to upstream. Same net effect as how the postgres/mysql/mssql
	// handlers overwrite the client's startup-packet user: whatever the client
	// types is inert; upstream always looks up the configured account's verifier.
	p1Forward := p1Payload
	if p.config.InjectUsername != "" {
		rewritten, rerr := rewritePhase1User(p1Payload, p.config.InjectUsername)
		if rerr != nil {
			return fmt.Errorf("rewrite phase 1 username: %w", rerr)
		}
		p1Forward = rewritten
	}
	if err := writeDataPayload(upstreamConn, p1Forward, use32Bit); err != nil {
		return fmt.Errorf("forward phase 1 request: %w", err)
	}

	// 6. Read upstream's phase-1 response. Extract fields, translate, forward to client.
	p1RespUpstream, err := readDataPayload(upstreamConn, use32Bit)
	if err != nil {
		return fmt.Errorf("read upstream phase 1 response: %w", err)
	}
	state, p1RespTranslated, err := translatePhase1Response(p1RespUpstream, p.config.InjectPassword)
	if err != nil {
		_ = WriteErrorToClient(clientConn, ORA1017InvalidCredentials, "ORA-01017: invalid username/password; logon denied", use32Bit)
		return fmt.Errorf("translate phase 1 response: %w", err)
	}
	if err := writeDataPayload(clientConn, p1RespTranslated, use32Bit); err != nil {
		return fmt.Errorf("write translated phase 1 response: %w", err)
	}
	log.Info().Str("sessionID", p.config.SessionID).Msg("Proxy: phase-1 response translated and forwarded")

	// 7. Read client's phase-2 request. Decrypt with placeholder keys, re-encrypt with
	//    real-password keys, forward to upstream.
	p2ReqClient, err := readDataPayload(clientConn, use32Bit)
	if err != nil {
		return fmt.Errorf("read client phase 2 request: %w", err)
	}
	p2ReqTranslated, err := translatePhase2Request(p2ReqClient, state, p.config.InjectPassword)
	if err != nil {
		_ = WriteErrorToClient(clientConn, ORA1017InvalidCredentials, "ORA-01017: invalid username/password; logon denied", use32Bit)
		return fmt.Errorf("translate phase 2 request: %w", err)
	}
	// Upstream Oracle cross-checks the phase-2 username against phase-1; we rewrote
	// phase-1 above, so phase-2 has to agree or auth fails.
	if p.config.InjectUsername != "" {
		rewritten, rerr := rewritePhase2User(p2ReqTranslated, p.config.InjectUsername)
		if rerr != nil {
			return fmt.Errorf("rewrite phase 2 username: %w", rerr)
		}
		p2ReqTranslated = rewritten
	}
	if err := writeDataPayload(upstreamConn, p2ReqTranslated, use32Bit); err != nil {
		return fmt.Errorf("forward phase 2 request: %w", err)
	}
	log.Info().Str("sessionID", p.config.SessionID).Msg("Proxy: phase-2 request translated and forwarded")

	// 8. Read upstream's phase-2 response. Substitute AUTH_SVR_RESPONSE with a
	//    placeholder-derived one so the client verifies successfully.
	p2RespUpstream, err := readDataPayload(upstreamConn, use32Bit)
	if err != nil {
		return fmt.Errorf("read upstream phase 2 response: %w", err)
	}
	p2RespTranslated, err := translatePhase2Response(p2RespUpstream, state)
	if err != nil {
		return fmt.Errorf("translate phase 2 response: %w", err)
	}
	if err := writeDataPayload(clientConn, p2RespTranslated, use32Bit); err != nil {
		return fmt.Errorf("write translated phase 2 response: %w", err)
	}
	log.Info().Str("sessionID", p.config.SessionID).Msg("Proxy: phase-2 response translated; client authenticated")

	// 9. Byte relay.
	c2u, u2c := NewQueryExtractorPair(p.config.SessionLogger, p.config.SessionID, use32Bit)
	defer c2u.Stop()
	defer u2c.Stop()

	errCh := make(chan error, 2)
	go relayWithTap(clientConn, upstreamConn, c2u, errCh)
	go relayWithTap(upstreamConn, clientConn, u2c, errCh)

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

// oracleUpstreamCiphers is the set of TLS cipher suites we advertise to Oracle
// TCPS listeners. Oracle 19c (including AWS RDS's SSL option) only offers
// legacy RSA-CBC cipher suites — they are not in Go's crypto/tls defaults, so
// we list them explicitly. Modern AEAD suites are kept first so newer Oracle
// versions still use them.
var oracleUpstreamCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

// buildOracleTLSConfig clones the shared TLS config and augments it with the
// settings Oracle TCPS needs: legacy cipher suites (Oracle 19c only offers
// RSA-CBC), TLS 1.0 floor (the second-round handshake against RDS negotiates
// down to 1.0 in practice), and 1.2 ceiling (TLS 1.3 has no handshake-restart
// mechanism). Only the Oracle-upstream leg relaxes versions this way; the
// relay mTLS and other handlers stay on defaults.
func buildOracleTLSConfig(base *tls.Config, host string) *tls.Config {
	cfg := base.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	cfg.MinVersion = tls.VersionTLS10
	cfg.MaxVersion = tls.VersionTLS12
	cfg.CipherSuites = oracleUpstreamCiphers
	return cfg
}

// dialUpstreamRaw opens the upstream connection. Returns the raw TCP conn
// and — when TLS is enabled — the first TLS session wrapping it.
//
// Oracle TCPS on port 2484 requires a TLS handshake from byte zero (we tested
// this — plaintext CONNECT is met with an immediate connection reset). That
// first TLS session carries the initial CONNECT and the server's RESEND. If
// the RESEND's byte-5 flag has 0x08 set, Oracle's protocol requires a SECOND
// TLS handshake on the SAME underlying TCP socket (bypassing the first TLS
// session) before the next CONNECT supplement can flow. go-ora does this
// same two-handshake dance in network/session.go readPacket's RESEND branch.
// That second handshake is performed by upgradeToTLS below, reusing the raw
// conn returned here.
func dialUpstreamRaw(ctx context.Context, cfg OracleProxyConfig) (rawConn net.Conn, tlsConn *tls.Conn, err error) {
	host, _, err := splitHostPort(cfg.TargetAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid target addr: %w", err)
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	rawConn, err = d.DialContext(ctx, "tcp", cfg.TargetAddr)
	if err != nil {
		return nil, nil, err
	}
	if !cfg.EnableTLS {
		return rawConn, nil, nil
	}
	if cfg.TLSConfig == nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("upstream TLS requested but no TLSConfig provided")
	}
	tlsCfg := buildOracleTLSConfig(cfg.TLSConfig, host)
	tc := tls.Client(rawConn, tlsCfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("upstream TLS handshake: %w", err)
	}
	return rawConn, tc, nil
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// upgradeToTLS performs a TLS handshake on an existing upstream TCP socket.
// Called mid-flow when Oracle's RESEND packet signals the socket should switch
// to TLS. The returned *tls.Conn replaces the raw conn from that point on.
func upgradeToTLS(ctx context.Context, rawConn net.Conn, cfg OracleProxyConfig) (*tls.Conn, error) {
	host, _, err := splitHostPort(cfg.TargetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target addr: %w", err)
	}
	tlsCfg := buildOracleTLSConfig(cfg.TLSConfig, host)
	tc := tls.Client(rawConn, tlsCfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("upstream TLS handshake: %w", err)
	}
	return tc, nil
}

// proxyUntilAuthRequest runs a bidirectional packet-level proxy between client and
// upstream during pre-auth. Two goroutines read from each side and forward to the other,
// synchronously with no turn-taking assumption. The client-side reader inspects DATA
// packets for the phase-1 auth request (opcode 0x03 0x76); when seen, it signals the
// main routine to stop and returns the auth-request payload WITHOUT forwarding it.
// All other packets (control, marker, data) flow through transparently.
//
// The caller takes over O5Logon translation from here.
func proxyUntilAuthRequest(client, upstream net.Conn, use32Bit bool, sessionID string) ([]byte, error) {
	type result struct {
		payload []byte
		err     error
	}
	done := make(chan result, 2)
	stop := make(chan struct{})

	// Upstream → client: forward every packet unchanged. Exit when stop is signalled.
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			pkt, err := ReadFullPacket(upstream, use32Bit)
			if err != nil {
				select {
				case done <- result{err: fmt.Errorf("read upstream: %w", err)}:
				default:
				}
				return
			}
			if _, werr := client.Write(pkt); werr != nil {
				select {
				case done <- result{err: fmt.Errorf("write client: %w", werr)}:
				default:
				}
				return
			}
			log.Debug().Str("sessionID", sessionID).Uint8("type", uint8(PacketTypeOf(pkt))).Int("len", len(pkt)).Msg("Proxy pre-auth: upstream → client")
		}
	}()

	// Client → upstream: forward packets, but watch DATA packets for auth-request.
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			pkt, err := ReadFullPacket(client, use32Bit)
			if err != nil {
				select {
				case done <- result{err: fmt.Errorf("read client: %w", err)}:
				default:
				}
				return
			}
			pktType := PacketTypeOf(pkt)
			// Check for auth-request on DATA packets.
			if pktType == PacketTypeData {
				payload, perr := extractDataPayload(pkt)
				if perr == nil && len(payload) >= 2 &&
					payload[0] == TTCMsgAuthRequest && payload[1] == AuthSubOpPhaseOne {
					// Don't forward — caller takes over.
					select {
					case done <- result{payload: payload}:
					default:
					}
					return
				}
			}
			if _, werr := upstream.Write(pkt); werr != nil {
				select {
				case done <- result{err: fmt.Errorf("write upstream: %w", werr)}:
				default:
				}
				return
			}
			log.Debug().Str("sessionID", sessionID).Uint8("type", uint8(pktType)).Int("len", len(pkt)).Msg("Proxy pre-auth: client → upstream")
		}
	}()

	res := <-done
	close(stop)
	// Force the other goroutine out of its blocked ReadFullPacket by setting a past
	// deadline on the upstream connection. If we don't, that goroutine would steal
	// the upstream's phase-1 response when we try to read it directly.
	if uc, ok := upstream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = uc.SetReadDeadline(time.Now().Add(-1 * time.Second))
	}
	// Give it a beat to exit, then reset the deadline.
	time.Sleep(50 * time.Millisecond)
	if uc, ok := upstream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = uc.SetReadDeadline(time.Time{})
	}
	if res.err != nil {
		return nil, res.err
	}
	return res.payload, nil
}

// extractDataPayload returns the TTC payload body of a DATA packet. Assumes caller has
// verified the packet is indeed DATA. The 2-byte data_flags follow the 8-byte TNS header
// in both 16-bit and 32-bit framing modes, so body always starts at offset 10.
func extractDataPayload(pkt []byte) ([]byte, error) {
	const headerLen = 10
	if len(pkt) < headerLen {
		return nil, fmt.Errorf("packet too short: %d", len(pkt))
	}
	return pkt[headerLen:], nil
}

// rewriteAuthRequestUser replaces the username field in a client-sent auth request
// (phase-1 or phase-2 — same layout, different sub-op) with `newUser`, leaving every
// other field verbatim. Upstream Oracle uses the username we forward here to look up
// the account's verifier in phase 1 and to validate the same user in phase 2 — so
// rewriting both drives the whole crypto path to operate on `newUser`'s credentials,
// regardless of what the client originally typed.
//
// Layout (identical for phase-1 sub-op 0x76 and phase-2 sub-op 0x73):
//
//	u8 0x03, u8 subOp, u8 0, u8 hasUser, [u32 compressed userLen OR single 0 byte],
//	u32 compressed mode, u8 1, u32 compressed count, u8 1, u8 1,
//	[optional u8 CLR-length prefix (go-ora) | no prefix (JDBC thin)] + user bytes,
//	<count KVPs>
//
// Username encoding varies by client: go-ora emits a CLR-length byte before the raw
// bytes; JDBC thin omits it. We detect which form the client used with the same peek
// heuristic as ParseAuthPhaseTwo (if the next byte equals userLen and is below 0x20,
// it's a length prefix) and mirror that form when emitting `newUser`.
func rewriteAuthRequestUser(payload []byte, expectedSubOp byte, newUser string) ([]byte, error) {
	r := NewTTCReader(payload)
	op, err := r.GetByte()
	if err != nil {
		return nil, fmt.Errorf("opcode: %w", err)
	}
	if op != TTCMsgAuthRequest {
		return nil, fmt.Errorf("unexpected opcode 0x%02X", op)
	}
	sub, err := r.GetByte()
	if err != nil {
		return nil, err
	}
	if sub != expectedSubOp {
		return nil, fmt.Errorf("unexpected sub-op 0x%02X (want 0x%02X)", sub, expectedSubOp)
	}
	if _, err := r.GetByte(); err != nil { // the 0x00 separator
		return nil, err
	}

	hasUser, err := r.GetByte()
	if err != nil {
		return nil, err
	}
	// Client sent no username — nothing to rewrite; forward verbatim.
	if hasUser != 1 {
		return payload, nil
	}
	origUserLen, err := r.GetInt(4, true, true)
	if err != nil {
		return nil, fmt.Errorf("userLen: %w", err)
	}
	if origUserLen <= 0 {
		return payload, nil
	}

	// Capture the offset just after the userLen compressed-int. Everything from here
	// up to the start of the user bytes (mode / markers / count) is copied verbatim.
	middleStart := r.Pos()

	// Walk mode + markers + count + 1 + 1 (identical to ParseAuthPhaseTwo).
	if _, err := r.GetInt(4, true, true); err != nil {
		return nil, fmt.Errorf("mode: %w", err)
	}
	if _, err := r.GetByte(); err != nil {
		return nil, fmt.Errorf("marker after mode: %w", err)
	}
	if _, err := r.GetInt(4, true, true); err != nil {
		return nil, fmt.Errorf("count: %w", err)
	}
	if _, err := r.GetByte(); err != nil {
		return nil, fmt.Errorf("marker 1: %w", err)
	}
	if _, err := r.GetByte(); err != nil {
		return nil, fmt.Errorf("marker 2: %w", err)
	}
	middleEnd := r.Pos()

	// The next bytes are either <CLR-len> <user bytes> (go-ora) or just <user bytes>
	// (JDBC thin). Peek to distinguish.
	peek, perr := r.PeekByte()
	if perr != nil {
		return nil, fmt.Errorf("peek user: %w", perr)
	}
	usedCLRPrefix := int(peek) == origUserLen && peek < 0x20
	if usedCLRPrefix {
		if _, err := r.GetByte(); err != nil {
			return nil, fmt.Errorf("consume user CLR length: %w", err)
		}
	}
	if _, err := r.GetBytes(origUserLen); err != nil {
		return nil, fmt.Errorf("user bytes: %w", err)
	}
	userEnd := r.Pos()

	// Rebuild: header [0..3) + hasUser(1) + new userLen compressed + original middle
	// (mode/marker/count/1/1) + [optional CLR-len byte] + new user bytes + tail.
	newUserBytes := []byte(newUser)
	newUserLen := len(newUserBytes)

	out := make([]byte, 0, len(payload)+16)
	out = append(out, payload[:3]...) // opcode + sub + 0x00
	out = append(out, 0x01)           // hasUser = 1
	// Emit newUserLen as a compressed int. Reuse TTCBuilder to avoid reimplementing
	// the 0xFE/size-byte prefix rules.
	lb := NewTTCBuilder()
	lb.PutInt(int64(newUserLen), 4, true, true)
	out = append(out, lb.Bytes()...)
	out = append(out, payload[middleStart:middleEnd]...)
	if usedCLRPrefix {
		out = append(out, byte(newUserLen))
	}
	out = append(out, newUserBytes...)
	out = append(out, payload[userEnd:]...)
	return out, nil
}

// rewritePhase1User rewrites AUTH_USER on a phase-1 auth request.
func rewritePhase1User(payload []byte, newUser string) ([]byte, error) {
	return rewriteAuthRequestUser(payload, AuthSubOpPhaseOne, newUser)
}

// rewritePhase2User rewrites AUTH_USER on a phase-2 auth request.
func rewritePhase2User(payload []byte, newUser string) ([]byte, error) {
	return rewriteAuthRequestUser(payload, AuthSubOpPhaseTwo, newUser)
}

// ProxyAuthState carries session material extracted during phase-1 so phase-2 translation
// and SVR_RESPONSE regeneration have access to what they need.
type ProxyAuthState struct {
	Salt              []byte // raw salt (decoded from AUTH_VFR_DATA hex)
	Pbkdf2CSKSalt     string // hex string
	Pbkdf2VGenCount   int
	Pbkdf2SDerCount   int
	RealKey           []byte // AUTH_SESSKEY key derived from real password + salt
	PlaceholderKey    []byte // AUTH_SESSKEY key derived from placeholder password + salt
	ServerSessKey     []byte // raw server session key (decrypted from upstream)
	placeholderEncKey []byte // password-encryption key (session-keyed; independent of password itself)
}

// translatePhase1Response decodes upstream's phase-1 response, substitutes AUTH_SESSKEY
// so the client can decrypt it with the placeholder password (instead of the real one),
// and returns the modified payload plus state for phase-2.
func translatePhase1Response(payload []byte, realPassword string) (*ProxyAuthState, []byte, error) {
	// Parse payload into an ordered list of KVPs so we can rebuild with modifications.
	kvs, trailer, err := parseAuthRespKVPList(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("parse upstream phase 1: %w", err)
	}

	// Extract fields we need.
	var eSessKey, vfrData, cskSalt, vGenStr, sDerStr string
	for _, kv := range kvs {
		switch kv.Key {
		case "AUTH_SESSKEY":
			eSessKey = kv.Value
		case "AUTH_VFR_DATA":
			vfrData = kv.Value
		case "AUTH_PBKDF2_CSK_SALT":
			cskSalt = kv.Value
		case "AUTH_PBKDF2_VGEN_COUNT":
			vGenStr = kv.Value
		case "AUTH_PBKDF2_SDER_COUNT":
			sDerStr = kv.Value
		}
	}
	if eSessKey == "" || vfrData == "" {
		return nil, nil, fmt.Errorf("upstream phase 1 missing AUTH_SESSKEY or AUTH_VFR_DATA")
	}
	salt, err := hex.DecodeString(vfrData)
	if err != nil {
		return nil, nil, fmt.Errorf("decode salt: %w", err)
	}
	vGen, _ := strconv.Atoi(vGenStr)
	if vGen == 0 {
		vGen = 4096
	}
	sDer, _ := strconv.Atoi(sDerStr)
	if sDer == 0 {
		sDer = 3
	}

	// Derive both keys (real password → decrypt upstream's SESSKEY; placeholder → re-encrypt).
	realKey, _, err := deriveServerKey(realPassword, salt, vGen)
	if err != nil {
		return nil, nil, fmt.Errorf("derive real key: %w", err)
	}
	placeholderKey, _, err := deriveServerKey(ProxyPasswordPlaceholder, salt, vGen)
	if err != nil {
		return nil, nil, fmt.Errorf("derive placeholder key: %w", err)
	}

	// Decrypt upstream's server session key with real key.
	serverSessKey, err := decryptSessionKey(false, realKey, eSessKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt upstream server session key: %w", err)
	}
	// Re-encrypt with placeholder key so client can decrypt.
	newESessKey, err := encryptSessionKey(false, placeholderKey, serverSessKey)
	if err != nil {
		return nil, nil, fmt.Errorf("re-encrypt server session key: %w", err)
	}

	// Substitute AUTH_SESSKEY in the KVP list.
	for i := range kvs {
		if kvs[i].Key == "AUTH_SESSKEY" {
			kvs[i].Value = newESessKey
			break
		}
	}

	// Rebuild payload.
	rebuilt := rebuildAuthRespPayload(kvs, trailer)

	state := &ProxyAuthState{
		Salt:            salt,
		Pbkdf2CSKSalt:   cskSalt,
		Pbkdf2VGenCount: vGen,
		Pbkdf2SDerCount: sDer,
		RealKey:         realKey,
		PlaceholderKey:  placeholderKey,
		ServerSessKey:   serverSessKey,
	}
	return state, rebuilt, nil
}

// translatePhase2Request takes the client's phase-2 payload (where AUTH_SESSKEY and
// AUTH_PASSWORD were encrypted with the placeholder-derived keys) and substitutes them
// with values keyed for the real password, so upstream Oracle can verify.
func translatePhase2Request(payload []byte, state *ProxyAuthState, realPassword string) ([]byte, error) {
	// Phase-2 request uses the same "PutKeyVal" layout as phase-1 response but with a
	// different leading opcode frame (0x03 0x73 0 plus header fields). We parse the
	// header prefix up to the KVP dictionary, modify the KVP dictionary, and rebuild.
	p2, err := ParseAuthPhaseTwo(payload)
	if err != nil {
		return nil, fmt.Errorf("parse client phase 2: %w", err)
	}

	if p2.EClientSessKey == "" || p2.EPassword == "" {
		return nil, fmt.Errorf("client phase 2 missing AUTH_SESSKEY or AUTH_PASSWORD")
	}

	// Decrypt client's sess key with placeholder key.
	clientSessKey, err := decryptSessionKey(false, state.PlaceholderKey, p2.EClientSessKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt client session key: %w", err)
	}
	if len(clientSessKey) != len(state.ServerSessKey) {
		return nil, fmt.Errorf("client session key length mismatch: got %d want %d", len(clientSessKey), len(state.ServerSessKey))
	}
	// Re-encrypt with real key for upstream.
	newEClientSessKey, err := encryptSessionKey(false, state.RealKey, clientSessKey)
	if err != nil {
		return nil, fmt.Errorf("re-encrypt client session key: %w", err)
	}

	// Compute password-encryption keys: one using placeholder password, one using real.
	placeholderEncKey, err := deriveProxyPasswordEncKey(clientSessKey, state.ServerSessKey, state.Pbkdf2CSKSalt, state.Pbkdf2SDerCount)
	if err != nil {
		return nil, fmt.Errorf("derive placeholder enc key: %w", err)
	}
	realEncKey := placeholderEncKey // same computation: encKey is derived from session keys + pbkdf2 salt, NOT password
	// Verify client's password equals placeholder.
	decoded, err := decryptSessionKey(true, placeholderEncKey, p2.EPassword)
	if err != nil {
		return nil, fmt.Errorf("decrypt client password: %w", err)
	}
	if len(decoded) <= 16 {
		return nil, fmt.Errorf("decoded password too short")
	}
	if string(decoded[16:]) != ProxyPasswordPlaceholder {
		// Do not embed the decrypted plaintext — it could be a real password the
		// client typed by mistake, and the error chain bubbles to gateway logs.
		return nil, fmt.Errorf("password mismatch")
	}
	// Encrypt REAL password with the real encKey (which equals placeholderEncKey here
	// because the computation uses session keys + CSK salt only, not the password).
	newEPassword, err := encryptPassword([]byte(realPassword), realEncKey, true)
	if err != nil {
		return nil, fmt.Errorf("encrypt real password: %w", err)
	}

	// Rebuild the phase-2 payload with substituted AUTH_SESSKEY and AUTH_PASSWORD.
	rebuilt, err := rebuildPhase2Request(payload, newEClientSessKey, newEPassword)
	if err != nil {
		return nil, fmt.Errorf("rebuild phase 2: %w", err)
	}
	// Also stash encKey for SVR_RESPONSE regen.
	state.placeholderEncKey = placeholderEncKey
	return rebuilt, nil
}

// translatePhase2Response substitutes AUTH_SVR_RESPONSE in upstream's phase-2 response
// with one the client can verify (derived from the placeholder-keyed encKey instead of
// the real-password-keyed one). All other fields are forwarded verbatim.
func translatePhase2Response(payload []byte, state *ProxyAuthState) ([]byte, error) {
	kvs, trailer, err := parseAuthRespKVPList(payload)
	if err != nil {
		return nil, fmt.Errorf("parse upstream phase 2: %w", err)
	}
	// Regenerate SVR_RESPONSE so the client's placeholder-derived verification passes.
	newSvr, err := BuildSvrResponse(state.placeholderEncKey)
	if err != nil {
		return nil, fmt.Errorf("build placeholder SVR_RESPONSE: %w", err)
	}
	foundSvr := false
	for i := range kvs {
		if kvs[i].Key == "AUTH_SVR_RESPONSE" {
			kvs[i].Value = newSvr
			foundSvr = true
			break
		}
	}
	if !foundSvr {
		return nil, fmt.Errorf("upstream phase 2 missing AUTH_SVR_RESPONSE")
	}
	return rebuildAuthRespPayload(kvs, trailer), nil
}

// deriveProxyPasswordEncKey computes the key used for AUTH_PASSWORD encryption in
// phase 2, for verifier type 18453. Formula (from go-ora's generatePasswordEncKey):
//
//	keyBuffer = hex(clientSessKey || serverSessKey)
//	encKey    = generateSpeedyKey(pbkdf2CSKSaltRaw, keyBuffer, sderCount)[:32]
func deriveProxyPasswordEncKey(clientSessKey, serverSessKey []byte, pbkdf2CSKSaltHex string, sderCount int) ([]byte, error) {
	buffer := append([]byte(nil), clientSessKey...)
	buffer = append(buffer, serverSessKey...)
	keyBuffer := []byte(fmt.Sprintf("%X", buffer))
	cskSalt, err := hex.DecodeString(pbkdf2CSKSaltHex)
	if err != nil {
		return nil, fmt.Errorf("decode pbkdf2 salt: %w", err)
	}
	full := generateSpeedyKey(cskSalt, keyBuffer, sderCount)
	if len(full) < 32 {
		return nil, fmt.Errorf("speedy key too short: %d", len(full))
	}
	return full[:32], nil
}

// parsedKVP holds a decoded key/value/flag from a TTC auth response. We keep the key
// verbatim (including any trailing NULLs) so rebuilt packets match the wire format.
type parsedKVP struct {
	Key   string
	Value string
	Flag  int
}

// parseAuthRespKVPList decodes a TTC auth response payload (opcode 0x08) into an ordered
// KVP list plus the trailing summary bytes (opcode 0x04 onwards). Preserves the order
// and any non-standard fields so we can rebuild with minimal changes.
func parseAuthRespKVPList(payload []byte) (kvs []parsedKVP, trailer []byte, err error) {
	r := NewTTCReader(payload)
	op, err := r.GetByte()
	if err != nil {
		return nil, nil, err
	}
	if op != 0x08 {
		return nil, nil, fmt.Errorf("expected auth response opcode 0x08, got 0x%02X", op)
	}
	dictLen, err := r.GetInt(4, true, true)
	if err != nil {
		return nil, nil, fmt.Errorf("dict len: %w", err)
	}
	for i := 0; i < dictLen; i++ {
		keyLen, err := r.GetInt(4, true, true)
		if err != nil {
			return nil, nil, fmt.Errorf("kvp %d key len: %w", i, err)
		}
		var keyBytes []byte
		if keyLen > 0 {
			keyBytes, err = r.GetClr()
			if err != nil {
				return nil, nil, fmt.Errorf("kvp %d key: %w", i, err)
			}
			if len(keyBytes) > keyLen {
				keyBytes = keyBytes[:keyLen]
			}
		}
		valLen, err := r.GetInt(4, true, true)
		if err != nil {
			return nil, nil, fmt.Errorf("kvp %d val len: %w", i, err)
		}
		var valBytes []byte
		if valLen > 0 {
			valBytes, err = r.GetClr()
			if err != nil {
				return nil, nil, fmt.Errorf("kvp %d val: %w", i, err)
			}
			if len(valBytes) > valLen {
				valBytes = valBytes[:valLen]
			}
		}
		flag, err := r.GetInt(4, true, true)
		if err != nil {
			return nil, nil, fmt.Errorf("kvp %d flag: %w", i, err)
		}
		kvs = append(kvs, parsedKVP{
			Key:   string(bytes.TrimRight(keyBytes, "\x00")),
			Value: string(valBytes),
			Flag:  flag,
		})
	}
	// Trailer: everything remaining (usually the opcode 0x04 summary).
	trailer = make([]byte, r.Remaining())
	rem, _ := r.GetBytes(r.Remaining())
	copy(trailer, rem)
	return kvs, trailer, nil
}

// rebuildAuthRespPayload reconstructs a phase-1 or phase-2 auth response payload from
// the parsed KVP list plus the trailing summary bytes.
func rebuildAuthRespPayload(kvs []parsedKVP, trailer []byte) []byte {
	b := NewTTCBuilder()
	b.PutBytes(0x08)
	b.PutUint(uint64(len(kvs)), 4, true, true)
	for _, kv := range kvs {
		b.PutKeyValString(kv.Key, kv.Value, uint32(kv.Flag))
	}
	b.PutBytes(trailer...)
	return b.Bytes()
}

// rebuildPhase2Request replaces AUTH_SESSKEY and AUTH_PASSWORD values in a phase-2
// request payload while preserving the opcode/header prefix and all other KVPs.
//
// Phase-2 request layout:
//
//	u8 0x03, u8 0x73, u8 0, <header fields>, u8 hasUser, [user_len compressed], u32 mode
//	compressed, u8 1, u32 count compressed, u8 1, u8 1, [user bytes], <count KVPs>
//
// Rather than parse and rebuild byte-for-byte (risky — subtle header differences across
// clients), we scan for AUTH_SESSKEY and AUTH_PASSWORD keys in the payload and rewrite
// the associated CLR-encoded values in-place.
func rebuildPhase2Request(payload []byte, newESessKey, newEPassword string) ([]byte, error) {
	out := make([]byte, 0, len(payload)+128)
	out = append(out, payload...)

	out, err := replaceKVPValue(out, "AUTH_SESSKEY", newESessKey)
	if err != nil {
		return nil, fmt.Errorf("replace AUTH_SESSKEY: %w", err)
	}
	out, err = replaceKVPValue(out, "AUTH_PASSWORD", newEPassword)
	if err != nil {
		return nil, fmt.Errorf("replace AUTH_PASSWORD: %w", err)
	}
	return out, nil
}

// replaceKVPValue finds a PutKeyValString-encoded KVP for `key` within `payload` and
// replaces its value with `newValue`. Assumes the key appears exactly once.
//
// Encoded KVP layout (from go-ora's PutKeyVal):
//
//	key_len (compressed int)
//	key_len_again (1 byte, same value, before CLR bytes)   <-- this IS the CLR length
//	key bytes
//	val_len (compressed int)
//	val_len_again (1 byte, same as CLR length)
//	val bytes
//	flag (compressed int)
func replaceKVPValue(payload []byte, key, newValue string) ([]byte, error) {
	keyBytes := []byte(key)
	// Search for the key substring; confirm the preceding bytes look like a length prefix.
	idx := bytes.Index(payload, keyBytes)
	if idx < 0 {
		return nil, fmt.Errorf("key %q not found", key)
	}
	// Find the value start: skip over key, then parse (val_len compressed, val_len byte).
	pos := idx + len(keyBytes)
	if pos >= len(payload) {
		return nil, fmt.Errorf("truncated after key")
	}
	// val_len is compressed int.
	vSizeByte := payload[pos]
	pos++
	var vLen int
	if vSizeByte == 0 {
		vLen = 0
	} else if int(vSizeByte) <= 8 {
		for i := 0; i < int(vSizeByte); i++ {
			vLen = (vLen << 8) | int(payload[pos+i])
		}
		pos += int(vSizeByte)
	} else {
		return nil, fmt.Errorf("invalid val_len size byte %d", vSizeByte)
	}
	// If vLen > 0, there's a CLR length byte + vLen value bytes.
	if vLen > 0 {
		// CLR length byte
		if pos >= len(payload) || int(payload[pos]) != vLen {
			// Some encodings don't re-emit the length; handle gracefully by assuming 0 pad.
			// Still, expect the CLR-length prefix to match vLen.
			return nil, fmt.Errorf("CLR length byte mismatch for %q: got %d want %d", key, payload[pos], vLen)
		}
		pos++
		valBodyStart := pos
		valBodyEnd := valBodyStart + vLen
		// Build the new encoded value section: <vLen compressed-int><CLR(newVal)>.
		// TTCBuilder.PutClr emits the chunked 0xFE form when the value exceeds
		// 0xFC bytes; a single-byte length would wrap and corrupt AUTH_PASSWORD
		// for long (≥ 96-char) Oracle passwords.
		newVal := []byte(newValue)
		vb := NewTTCBuilder()
		vb.PutUint(uint64(len(newVal)), 4, true, true)
		vb.PutClr(newVal)
		newValSection := vb.Bytes()
		// Splice in the new value: keep bytes up to the end of the key, then the new
		// encoded value section, then everything after the old value's body.
		oldStart := idx + len(keyBytes)
		oldEnd := valBodyEnd
		out := make([]byte, 0, len(payload)+len(newValSection))
		out = append(out, payload[:oldStart]...)
		out = append(out, newValSection...)
		out = append(out, payload[oldEnd:]...)
		return out, nil
	}
	return payload, fmt.Errorf("unexpected empty value for %q", key)
}
