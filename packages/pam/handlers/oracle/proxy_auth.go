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

func (p *OracleProxy) handleConnectionProxied(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	defer func() {
		if err := p.config.SessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionID", p.config.SessionID).Msg("Failed to close session logger")
		}
	}()

	log.Info().Str("sessionID", p.config.SessionID).Str("target", p.config.TargetAddr).Msg("Oracle PAM session started (proxied auth)")

	// 1. Dial upstream (keep raw TCP ref — TCPS may need a second TLS handshake mid-flow).
	rawUpstream, tlsUpstream, err := dialUpstreamRaw(ctx, p.config)
	if err != nil {
		log.Error().Err(err).Str("sessionID", p.config.SessionID).Msg("Failed to dial Oracle upstream")
		_ = WriteRefuseToClient(clientConn, "(DESCRIPTION=(ERR=12564)(VSNNUM=0)(ERROR_STACK=(ERROR=(CODE=12564)(EMFI=4))))")
		return fmt.Errorf("upstream dial: %w", err)
	}
	var upstreamConn net.Conn
	if tlsUpstream != nil {
		upstreamConn = tlsUpstream
	} else {
		upstreamConn = rawUpstream
	}
	defer func() { upstreamConn.Close() }()

	// 2. Read client's CONNECT, rewrite SERVICE_NAME, forward to upstream.
	connectRaw, err := ReadFullPacket(clientConn, false)
	if err != nil {
		return fmt.Errorf("read client CONNECT: %w", err)
	}
	if PacketTypeOf(connectRaw) != PacketTypeConnect {
		return fmt.Errorf("expected CONNECT, got type=%d", connectRaw[4])
	}
	if p.config.InjectDatabase == "" {
		return fmt.Errorf("InjectDatabase (service name) is required but empty")
	}
	connectRaw = rewriteConnectServiceName(connectRaw, p.config.InjectDatabase)
	if _, err := upstreamConn.Write(connectRaw); err != nil {
		return fmt.Errorf("forward CONNECT: %w", err)
	}

	// If connect-data wasn't inline (JDBC thin / go-ora with long descriptions),
	// the client already sent it as a follow-up packet. Forward it now — some
	// Oracle listeners (e.g., OCI Autonomous DB) won't RESEND, they just wait.
	if len(connectRaw) >= 28 {
		cdLen := int(binary.BigEndian.Uint16(connectRaw[24:26]))
		cdOff := int(binary.BigEndian.Uint16(connectRaw[26:28]))
		if cdLen > 0 && cdOff+cdLen > len(connectRaw) {
			supplement, serr := ReadFullPacket(clientConn, false)
			if serr != nil {
				return fmt.Errorf("read connect-data supplement: %w", serr)
			}
			log.Info().Str("sessionID", p.config.SessionID).Int("supplementLen", len(supplement)).Msg("Proxy: forwarding connect-data supplement before handshake")
			if _, werr := upstreamConn.Write(supplement); werr != nil {
				return fmt.Errorf("forward connect-data supplement: %w", werr)
			}
		}
	}

	// 3. Read upstream responses until ACCEPT. Handle RESEND (TLS restart).
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

		// RESEND flag 0x08: tear down current TLS, do a fresh handshake on the raw socket.
		if p.config.EnableTLS && pktType == PacketTypeResend && origFlag&0x08 != 0 {
			tc, terr := upgradeToTLS(ctx, rawUpstream, p.config)
			if terr != nil {
				return fmt.Errorf("upstream TLS upgrade after RESEND(flag=0x08): %w", terr)
			}
			upstreamConn = tc
			log.Info().Str("sessionID", p.config.SessionID).Str("tlsVersion", tlsVersionString(tc.ConnectionState().Version)).Str("cipher", tls.CipherSuiteName(tc.ConnectionState().CipherSuite)).Msg("Proxy: upstream TLS re-handshook on RESEND(flag=0x08)")
		}

		// Mask byte 5 so thin clients don't try TLS upgrade on plain TCP.
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
			clientPkt, err := ReadFullPacket(clientConn, false)
			if err != nil {
				return fmt.Errorf("read client response after RESEND: %w", err)
			}
			log.Info().Str("sessionID", p.config.SessionID).Int("len", len(clientPkt)).Uint8("type", uint8(PacketTypeOf(clientPkt))).Msg("Proxy: forwarding client response after RESEND")
			if _, werr := upstreamConn.Write(clientPkt); werr != nil {
				return fmt.Errorf("forward client response after RESEND: %w", werr)
			}
			// Client may re-send CONNECT with non-inline connect-data — forward
			// the supplement too, same as we did before the handshake loop.
			if PacketTypeOf(clientPkt) == PacketTypeConnect && len(clientPkt) >= 28 {
				cdLen := int(binary.BigEndian.Uint16(clientPkt[24:26]))
				cdOff := int(binary.BigEndian.Uint16(clientPkt[26:28]))
				if cdLen > 0 && cdOff+cdLen > len(clientPkt) {
					supp, serr := ReadFullPacket(clientConn, false)
					if serr != nil {
						return fmt.Errorf("read connect-data supplement after RESEND: %w", serr)
					}
					log.Info().Str("sessionID", p.config.SessionID).Int("supplementLen", len(supp)).Msg("Proxy: forwarding connect-data supplement after RESEND")
					if _, werr := upstreamConn.Write(supp); werr != nil {
						return fmt.Errorf("forward connect-data supplement after RESEND: %w", werr)
					}
				}
			}
		}
	}

	var acceptVersion uint16
	if len(acceptRaw) >= 10 {
		acceptVersion = binary.BigEndian.Uint16(acceptRaw[8:10])
	}
	use32Bit := acceptVersion >= 315
	log.Info().Str("sessionID", p.config.SessionID).Uint16("acceptVersion", acceptVersion).Bool("use32Bit", use32Bit).Msg("Proxy: ACCEPT forwarded")



	p1Payload, err := proxyUntilAuthRequest(clientConn, upstreamConn, use32Bit, p.config.SessionID)
	if err != nil {
		return fmt.Errorf("pre-auth proxy: %w", err)
	}
	log.Info().Str("sessionID", p.config.SessionID).Int("p1Len", len(p1Payload)).Msg("Proxy: auth-request boundary reached")

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

	p2ReqClient, err := readDataPayload(clientConn, use32Bit)
	if err != nil {
		return fmt.Errorf("read client phase 2 request: %w", err)
	}
	p2ReqTranslated, err := translatePhase2Request(p2ReqClient, state, p.config.InjectPassword)
	if err != nil {
		_ = WriteErrorToClient(clientConn, ORA1017InvalidCredentials, "ORA-01017: invalid username/password; logon denied", use32Bit)
		return fmt.Errorf("translate phase 2 request: %w", err)
	}
	// Oracle cross-checks phase-2 username against phase-1.
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

	// AUTH_SVR_RESPONSE is keyed on session material (not password) — forward unchanged.
	p2RespRaw, err := ReadFullPacket(upstreamConn, use32Bit)
	if err != nil {
		return fmt.Errorf("read upstream phase 2 response: %w", err)
	}
	if _, err := clientConn.Write(p2RespRaw); err != nil {
		return fmt.Errorf("forward phase 2 response: %w", err)
	}
	log.Info().Str("sessionID", p.config.SessionID).Msg("Proxy: phase-2 response forwarded; client authenticated")

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

// Includes legacy RSA-CBC suites needed by Oracle 19c / AWS RDS.
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

// TLS 1.0–1.2 only: Oracle TCPS has no TLS-1.3 restart mechanism; RDS negotiates down to 1.0.
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

func proxyUntilAuthRequest(client, upstream net.Conn, use32Bit bool, sessionID string) ([]byte, error) {
	type result struct {
		payload []byte
		err     error
	}
	done := make(chan result, 2)
	stop := make(chan struct{})

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
			if pktType == PacketTypeData {
				payload, perr := extractDataPayload(pkt)
				if perr == nil && len(payload) >= 2 &&
					payload[0] == TTCMsgAuthRequest && payload[1] == AuthSubOpPhaseOne {
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
	// Unblock the other goroutine so it doesn't steal the phase-1 response.
	if uc, ok := upstream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = uc.SetReadDeadline(time.Now().Add(-1 * time.Second))
	}
	time.Sleep(50 * time.Millisecond)
	if uc, ok := upstream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = uc.SetReadDeadline(time.Time{})
	}
	if res.err != nil {
		return nil, res.err
	}
	return res.payload, nil
}

func extractDataPayload(pkt []byte) ([]byte, error) {
	const headerLen = 10
	if len(pkt) < headerLen {
		return nil, fmt.Errorf("packet too short: %d", len(pkt))
	}
	return pkt[headerLen:], nil
}

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
	if _, err := r.GetByte(); err != nil {
		return nil, err
	}

	hasUser, err := r.GetByte()
	if err != nil {
		return nil, err
	}
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

	middleStart := r.Pos()

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

	// go-ora prefixes user bytes with a CLR-length byte; JDBC thin omits it.
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

	newUserBytes := []byte(newUser)
	newUserLen := len(newUserBytes)

	out := make([]byte, 0, len(payload)+16)
	out = append(out, payload[:3]...)
	out = append(out, 0x01)
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

func rewriteConnectServiceName(pkt []byte, newName string) []byte {
	marker := []byte("SERVICE_NAME=")
	idx := bytes.Index(pkt, marker)
	if idx < 0 {
		return pkt
	}
	valStart := idx + len(marker)
	valEnd := bytes.IndexByte(pkt[valStart:], ')')
	if valEnd < 0 {
		return pkt
	}
	valEnd += valStart

	oldVal := pkt[valStart:valEnd]
	newVal := []byte(newName)
	if bytes.Equal(oldVal, newVal) {
		return pkt
	}

	out := make([]byte, 0, len(pkt)+len(newVal)-len(oldVal))
	out = append(out, pkt[:valStart]...)
	out = append(out, newVal...)
	out = append(out, pkt[valEnd:]...)

	binary.BigEndian.PutUint16(out[0:2], uint16(len(out)))
	if len(out) >= 26 {
		oldCDLen := binary.BigEndian.Uint16(pkt[24:26])
		binary.BigEndian.PutUint16(out[24:26], uint16(int(oldCDLen)+len(newVal)-len(oldVal)))
	}
	return out
}

func rewritePhase1User(payload []byte, newUser string) ([]byte, error) {
	return rewriteAuthRequestUser(payload, AuthSubOpPhaseOne, newUser)
}

func rewritePhase2User(payload []byte, newUser string) ([]byte, error) {
	return rewriteAuthRequestUser(payload, AuthSubOpPhaseTwo, newUser)
}

type ProxyAuthState struct {
	Salt            []byte
	Pbkdf2CSKSalt   string
	Pbkdf2VGenCount int
	Pbkdf2SDerCount int
	RealKey         []byte
	PlaceholderKey  []byte
	ServerSessKey   []byte
}

func translatePhase1Response(payload []byte, realPassword string) (*ProxyAuthState, []byte, error) {
	kvs, trailer, err := parseAuthRespKVPList(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("parse upstream phase 1: %w", err)
	}

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

	realKey, _, err := deriveServerKey(realPassword, salt, vGen)
	if err != nil {
		return nil, nil, fmt.Errorf("derive real key: %w", err)
	}
	placeholderKey, _, err := deriveServerKey(ProxyPasswordPlaceholder, salt, vGen)
	if err != nil {
		return nil, nil, fmt.Errorf("derive placeholder key: %w", err)
	}

	serverSessKey, err := decryptSessionKey(false, realKey, eSessKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt upstream server session key: %w", err)
	}
	newESessKey, err := encryptSessionKey(false, placeholderKey, serverSessKey)
	if err != nil {
		return nil, nil, fmt.Errorf("re-encrypt server session key: %w", err)
	}

	for i := range kvs {
		if kvs[i].Key == "AUTH_SESSKEY" {
			kvs[i].Value = newESessKey
			break
		}
	}

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

func translatePhase2Request(payload []byte, state *ProxyAuthState, realPassword string) ([]byte, error) {
	p2, err := ParseAuthPhaseTwo(payload)
	if err != nil {
		return nil, fmt.Errorf("parse client phase 2: %w", err)
	}

	// server session key
	// client session key
	// session1

	if p2.EClientSessKey == "" || p2.EPassword == "" {
		return nil, fmt.Errorf("client phase 2 missing AUTH_SESSKEY or AUTH_PASSWORD")
	}

	clientSessKey, err := decryptSessionKey(false, state.PlaceholderKey, p2.EClientSessKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt client session key: %w", err)
	}
	if len(clientSessKey) != len(state.ServerSessKey) {
		return nil, fmt.Errorf("client session key length mismatch: got %d want %d", len(clientSessKey), len(state.ServerSessKey))
	}
	newEClientSessKey, err := encryptSessionKey(false, state.RealKey, clientSessKey)
	if err != nil {
		return nil, fmt.Errorf("re-encrypt client session key: %w", err)
	}

	// encKey derives from session keys + CSK salt, not the password.
	encKey, err := deriveProxyPasswordEncKey(clientSessKey, state.ServerSessKey, state.Pbkdf2CSKSalt, state.Pbkdf2SDerCount)
	if err != nil {
		return nil, fmt.Errorf("derive enc key: %w", err)
	}
	// Verify the client used the placeholder password. Wrong password would also
	// fail cryptographically in phase 1 (ORA-17452), but this gives a clearer error.
	decoded, err := decryptSessionKey(true, encKey, p2.EPassword)
	if err != nil {
		return nil, fmt.Errorf("decrypt client password: %w", err)
	}
	if len(decoded) <= 16 || string(decoded[16:]) != ProxyPasswordPlaceholder {
		return nil, fmt.Errorf("password mismatch")
	}
	newEPassword, err := encryptPassword([]byte(realPassword), encKey, true)
	if err != nil {
		return nil, fmt.Errorf("encrypt real password: %w", err)
	}

	rebuilt, err := rebuildPhase2Request(payload, newEClientSessKey, newEPassword)
	if err != nil {
		return nil, fmt.Errorf("rebuild phase 2: %w", err)
	}
	return rebuilt, nil
}

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

type parsedKVP struct {
	Key   string
	Value string
	Flag  int
}

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
	trailer = make([]byte, r.Remaining())
	rem, _ := r.GetBytes(r.Remaining())
	copy(trailer, rem)
	return kvs, trailer, nil
}

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

func replaceKVPValue(payload []byte, key, newValue string) ([]byte, error) {
	keyBytes := []byte(key)
	idx := bytes.Index(payload, keyBytes)
	if idx < 0 {
		return nil, fmt.Errorf("key %q not found", key)
	}
	pos := idx + len(keyBytes)
	if pos >= len(payload) {
		return nil, fmt.Errorf("truncated after key")
	}
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
	if vLen > 0 {
		if pos >= len(payload) || int(payload[pos]) != vLen {
			return nil, fmt.Errorf("CLR length byte mismatch for %q: got %d want %d", key, payload[pos], vLen)
		}
		pos++
		valBodyStart := pos
		valBodyEnd := valBodyStart + vLen
		// PutClr handles chunked 0xFE form for values > 0xFC bytes.
		newVal := []byte(newValue)
		vb := NewTTCBuilder()
		vb.PutUint(uint64(len(newVal)), 4, true, true)
		vb.PutClr(newVal)
		newValSection := vb.Bytes()
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
