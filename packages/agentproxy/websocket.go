package agentproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	// wsIdleTimeout bounds a silent WebSocket. Without it a stalled or abandoned connection pins a goroutine
	// pair, an upstream TLS conn, and one of the proxy's maxConcurrentConns slots indefinitely. Real-time
	// APIs and their keepalive pings sit well inside this window.
	wsIdleTimeout = 10 * time.Minute

	// wsResponseTimeout bounds the upstream's reply to the upgrade request.
	wsResponseTimeout = 30 * time.Second

	// maxWSSubstitutionPayload caps the frame payload buffered for substitution; larger text frames stream
	// through untouched. Frame length is attacker-controlled, and auth payloads are tiny.
	maxWSSubstitutionPayload = 1 << 20
)

// WebSocket frame opcodes (RFC 6455 section 11.8).
const (
	wsOpText  = 0x1
	wsOpClose = 0x8
)

// websocketHandshakeHeaderNames are the upgrade headers that have to survive stripHopByHopHeaders. Without
// them the upstream never switches protocols, which is why the handshake fails outright when they are cut.
// Connection is deliberately absent: it is rebuilt rather than restored, see prepareUpstream.
var websocketHandshakeHeaderNames = []string{
	"Origin",
	"Sec-Websocket-Extensions",
	"Sec-Websocket-Key",
	"Sec-Websocket-Protocol",
	"Sec-Websocket-Version",
	"Upgrade",
}

func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, header := range r.Header.Values("Connection") {
		for _, token := range strings.Split(header, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// captureWebSocketHandshakeHeaders snapshots the upgrade headers so they can be restored after the
// hop-by-hop strip.
func captureWebSocketHandshakeHeaders(src http.Header) http.Header {
	captured := make(http.Header)
	for _, name := range websocketHandshakeHeaderNames {
		for _, value := range src.Values(name) {
			captured.Add(name, value)
		}
	}
	return captured
}

func restoreHeaders(dst, src http.Header) {
	for name, values := range src {
		dst.Del(name)
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

// serveWebSocket handles an upgrade request off the MITM tunnel (wss) or a plaintext forward request (ws).
// It runs the same resolve-match-inject path as forwardHTTP, then takes over the connection instead of
// relaying a response body: after 101 the proxy owns both sockets for the connection's lifetime.
func (ps *proxyServer) serveWebSocket(w http.ResponseWriter, r *http.Request, scheme, hostname, port, jwt string, scope agentScope) {
	reqPath := r.URL.EscapedPath()
	if len(reqPath) > maxLoggedPathLen {
		reqPath = reqPath[:maxLoggedPathLen] + "...[truncated]"
	}

	outcome, creds, err := ps.prepareUpstream(r, scheme, hostname, port, jwt, scope)
	if err != nil {
		decision, status := decisionError, http.StatusBadGateway
		if errors.Is(err, errHostBlocked) {
			decision, status = decisionBlocked, http.StatusForbidden
		}
		ps.emitActivity(r.Method, reqPath, hostname, port, decision, status, scope, outcome, err)
		http.Error(w, err.Error(), status)
		return
	}

	// Compression has to be settled before the handshake goes out. A permessage-deflate frame carries RSV1
	// and is never substituted, so leaving the offer in place would let the connection negotiate compression
	// and silently turn frame substitution into a no-op. Most clients offer it by default, so dropping the
	// offer is what makes the surface work at all; it only costs bandwidth, and only when subs are armed.
	wsSubs := websocketSubstitutions(creds)
	if len(wsSubs) > 0 && dropPerMessageDeflate(r.Header) {
		log.Debug().
			Str("host", hostname).
			Msg("dropped permessage-deflate from the websocket upgrade offer so frame substitution can read message text")
	}

	upstreamConn, upstreamReader, resp, err := ps.dialWebSocketUpstream(r.Context(), r)
	if err != nil {
		ps.emitActivity(r.Method, reqPath, hostname, port, decisionError, http.StatusBadGateway, scope, outcome, err)
		http.Error(w, "failed to reach upstream for websocket upgrade", http.StatusBadGateway)
		return
	}

	decision := decisionPassthrough
	if outcome.service != nil {
		decision = decisionBrokered
		ps.recordUsage(outcome.service.id)
	}

	// The upstream declined to upgrade: relay its response like any other, so the agent sees the real
	// rejection (401, 404, ...) rather than a proxy error.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer func() {
			_ = resp.Body.Close()
			_ = upstreamConn.Close()
		}()
		ps.emitActivity(r.Method, reqPath, hostname, port, decision, resp.StatusCode, scope, outcome, nil)

		stripHopByHopHeaders(resp.Header)
		dst := w.Header()
		for name, values := range resp.Header {
			for _, v := range values {
				dst.Add(name, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(flushingWriter{w}, resp.Body)
		return
	}

	// The upgrade record reports only what was actually applied to the handshake. Credentials armed for frame
	// substitution are not claimed here: no frame has been rewritten yet, and an agent may never send the
	// placeholder at all. The close record below reports what really happened.
	ps.emitActivity(r.Method, reqPath, hostname, port, decision, http.StatusSwitchingProtocols, scope, outcome, nil)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstreamConn.Close()
		http.Error(w, "connection hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		_ = upstreamConn.Close()
		return
	}

	// The inner tunnel server set ReadTimeout/WriteTimeout deadlines on this conn before the handler ran, and
	// Hijack leaves them in place. Clearing them is what keeps a long-lived WebSocket from dying at
	// tunnelReadTimeout; the pipe below applies its own idle deadline instead.
	_ = clientConn.SetDeadline(time.Time{})

	_ = clientConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := writeWebSocketSwitchingResponse(clientConn, resp); err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		return
	}
	_ = clientConn.SetWriteDeadline(time.Time{})

	substituted := pipeWebSocket(clientConn, clientBuf.Reader, upstreamConn, upstreamReader, wsSubs)

	// A connection that rewrote a credential is an audit event, so it is logged at the same level as a
	// brokered request rather than being filtered out with the passthrough noise.
	level := zerolog.DebugLevel
	if substituted > 0 {
		level = zerolog.InfoLevel
	}
	log.WithLevel(level).
		Str("event", activityEventName).
		Str("decision", decision).
		Str("agentId", outcome.agentID).
		Str("projectId", scope.projectID).
		Str("environment", scope.environment).
		Str("secretPath", scope.secretPath).
		Str("host", hostname).
		Str("path", reqPath).
		Int("framesSubstituted", substituted).
		Msg("websocket closed")
}

// dropPerMessageDeflate removes any compression extension from an upgrade offer, reporting whether it
// changed the header. Offers are comma separated and their parameters semicolon separated, so splitting on
// commas is safe.
func dropPerMessageDeflate(h http.Header) bool {
	values := h.Values("Sec-Websocket-Extensions")
	if len(values) == 0 {
		return false
	}

	var kept []string
	changed := false
	for _, value := range values {
		for _, offer := range strings.Split(value, ",") {
			offer = strings.TrimSpace(offer)
			if offer == "" {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(strings.SplitN(offer, ";", 2)[0]))
			if name == "permessage-deflate" || name == "x-webkit-deflate-frame" {
				changed = true
				continue
			}
			kept = append(kept, offer)
		}
	}
	if !changed {
		return false
	}

	h.Del("Sec-Websocket-Extensions")
	if len(kept) > 0 {
		h.Set("Sec-Websocket-Extensions", strings.Join(kept, ", "))
	}
	return true
}

// upstreamTLSConfig returns the TLS settings the plain HTTP path would use, so a WebSocket verifies its
// upstream identically. The WebSocket dial cannot go through http.Transport (it needs the raw conn), which is
// exactly why the config has to be read off the transport explicitly instead of being inherited.
func (ps *proxyServer) upstreamTLSConfig(serverName string) *tls.Config {
	cfg := &tls.Config{}
	if t, ok := ps.transport.(*http.Transport); ok && t.TLSClientConfig != nil {
		cfg = t.TLSClientConfig.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = serverName
	}
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	// WebSocket is HTTP/1.1 only; pin ALPN so the upstream cannot select h2.
	cfg.NextProtos = []string{"http/1.1"}
	return cfg
}

// dialWebSocketUpstream performs the upgrade handshake against the upstream on a connection the proxy owns,
// because a hijacked WebSocket cannot be driven through http.Transport's pooled round tripper.
func (ps *proxyServer) dialWebSocketUpstream(ctx context.Context, outReq *http.Request) (net.Conn, *bufio.Reader, *http.Response, error) {
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", outReq.URL.Host)
	if err != nil {
		return nil, nil, nil, err
	}

	// ws:// upstream: no TLS. pipeWebSocket and copyWithIdleTimeout only use net.Conn methods, so a
	// *net.TCPConn substitutes for a *tls.Conn.
	conn := net.Conn(rawConn)
	if outReq.URL.Scheme != "http" {
		tlsConn := tls.Client(rawConn, ps.upstreamTLSConfig(outReq.URL.Hostname()))
		_ = tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, nil, nil, err
		}
		_ = tlsConn.SetDeadline(time.Time{})
		conn = tlsConn
	}

	_ = conn.SetDeadline(time.Now().Add(wsResponseTimeout))
	if err := outReq.Write(conn); err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, outReq)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	_ = conn.SetDeadline(time.Time{})

	return conn, reader, resp, nil
}

// writeWebSocketSwitchingResponse writes the 101 by hand: the ResponseWriter is already hijacked, so
// Go's response machinery is no longer available to frame it.
func writeWebSocketSwitchingResponse(w io.Writer, resp *http.Response) error {
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	status := resp.Status
	if status == "" {
		status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	if _, err := fmt.Fprintf(w, "%s %s\r\n", proto, status); err != nil {
		return err
	}

	header := make(http.Header)
	for name, values := range resp.Header {
		if !isSafeWebSocketSwitchHeader(name) {
			continue
		}
		for _, v := range values {
			header.Add(name, v)
		}
	}
	header.Set("Connection", "Upgrade")
	header.Set("Upgrade", "websocket")

	for name, values := range header {
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		for _, v := range values {
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", canonical, v); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

// isSafeWebSocketSwitchHeader keeps the handshake headers the client needs to accept the upgrade and drops
// unknown Sec-* headers, so the upstream cannot smuggle extension state the proxy has not accounted for. It
// also drops body-framing headers: a 101 carries no body, and a stray Content-Length or Transfer-Encoding
// would desynchronize the client's frame parser.
func isSafeWebSocketSwitchHeader(name string) bool {
	canonical := http.CanonicalHeaderKey(name)
	switch canonical {
	case "Connection", "Upgrade", "Sec-Websocket-Accept", "Sec-Websocket-Extensions", "Sec-Websocket-Protocol":
		return true
	case "Content-Length", "Transfer-Encoding":
		return false
	}
	if strings.HasPrefix(canonical, "Sec-") {
		return false
	}
	// Every other hop-by-hop header is meaningless to the client and belongs to the upstream connection.
	for _, name := range hopByHopHeaders {
		if http.CanonicalHeaderKey(name) == canonical {
			return false
		}
	}
	return true
}

// pipeWebSocket relays frames both ways until either side closes, returning the number of client frames
// rewritten. Substitution runs on the client-to-upstream direction only: the proxy must never inject a real
// credential into a frame travelling back toward the agent.
func pipeWebSocket(clientConn net.Conn, clientReader *bufio.Reader, upstreamConn net.Conn, upstreamReader *bufio.Reader, wsSubs []wsSubstitution) int {
	done := make(chan struct{}, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = clientConn.Close()
			_ = upstreamConn.Close()
		})
	}

	substituted := 0
	go func() {
		defer func() {
			done <- struct{}{}
			closeBoth()
		}()
		src := io.MultiReader(clientReader, clientConn)
		if len(wsSubs) > 0 {
			substituted = copyWSFramesWithSubstitution(upstreamConn, src, clientConn, wsSubs)
		} else {
			copyWithIdleTimeout(upstreamConn, src, clientConn)
		}
	}()
	go func() {
		defer func() {
			done <- struct{}{}
			closeBoth()
		}()
		copyWithIdleTimeout(clientConn, io.MultiReader(upstreamReader, upstreamConn), upstreamConn)
	}()

	<-done
	<-done
	return substituted
}

// copyWithIdleTimeout streams src to dst, refreshing srcConn's read deadline each iteration so a silent
// connection trips the deadline instead of blocking forever. srcConn must be the net.Conn that src reads
// from: the deadline only covers real socket reads, not bytes already buffered.
func copyWithIdleTimeout(dst io.Writer, src io.Reader, srcConn net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		_ = srcConn.SetReadDeadline(time.Now().Add(wsIdleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// copyWSFramesWithSubstitution parses frames on the way to the upstream and substitutes placeholders in
// complete, uncompressed text frames. Binary, fragmented, compressed (RSV1) and oversized frames are
// forwarded byte-for-byte, so an unsupported shape degrades to passthrough rather than corrupting the stream.
func copyWSFramesWithSubstitution(dst io.Writer, src io.Reader, srcConn net.Conn, subs []wsSubstitution) int {
	r := bufio.NewReaderSize(src, 32*1024)
	substituted := 0

	for {
		_ = srcConn.SetReadDeadline(time.Now().Add(wsIdleTimeout))

		hdr := make([]byte, 2)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return substituted
		}

		fin := hdr[0]&0x80 != 0
		rsv1 := hdr[0]&0x40 != 0
		opcode := hdr[0] & 0x0F
		masked := hdr[1]&0x80 != 0
		payloadLen := uint64(hdr[1] & 0x7F)

		var extHdr []byte
		switch payloadLen {
		case 126:
			extHdr = make([]byte, 2)
			if _, err := io.ReadFull(r, extHdr); err != nil {
				return substituted
			}
			payloadLen = uint64(binary.BigEndian.Uint16(extHdr))
		case 127:
			extHdr = make([]byte, 8)
			if _, err := io.ReadFull(r, extHdr); err != nil {
				return substituted
			}
			payloadLen = binary.BigEndian.Uint64(extHdr)
			// RFC 6455 section 5.2: the MSB must be 0. Rejecting here prevents an int64 overflow in io.CopyN
			// that would desynchronize the frame parser.
			if payloadLen > math.MaxInt64 {
				return substituted
			}
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(r, maskKey[:]); err != nil {
				return substituted
			}
		}

		writeFrameHeader := func() bool {
			if _, err := dst.Write(hdr); err != nil {
				return false
			}
			if len(extHdr) > 0 {
				if _, err := dst.Write(extHdr); err != nil {
					return false
				}
			}
			if masked {
				if _, err := dst.Write(maskKey[:]); err != nil {
					return false
				}
			}
			return true
		}

		if opcode != wsOpText || !fin || rsv1 || payloadLen > maxWSSubstitutionPayload {
			if opcode == wsOpText && (!fin || rsv1 || payloadLen > maxWSSubstitutionPayload) {
				log.Warn().
					Bool("fragmented", !fin).
					Bool("compressed", rsv1).
					Uint64("payloadLen", payloadLen).
					Msg("websocket text frame not eligible for substitution; forwarding unchanged")
			}
			if !writeFrameHeader() {
				return substituted
			}
			if payloadLen > 0 {
				if _, err := io.CopyN(dst, r, int64(payloadLen)); err != nil {
					return substituted
				}
			}
			if opcode == wsOpClose {
				return substituted
			}
			continue
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return substituted
		}

		raw := make([]byte, len(payload))
		copy(raw, payload)

		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		text := string(payload)
		for _, sub := range subs {
			if replaced, ok := replaceWithinLimit(text, sub.placeholder, sub.value, maxWSSubstitutionPayload); ok {
				text = replaced
			}
		}

		// Nothing matched: forward the original bytes rather than re-encoding an identical frame.
		if text == string(payload) {
			if !writeFrameHeader() {
				return substituted
			}
			if _, err := dst.Write(raw); err != nil {
				return substituted
			}
			continue
		}

		if err := writeSubstitutedFrame(dst, hdr[0], []byte(text), masked); err != nil {
			return substituted
		}
		substituted++
	}
}

// writeSubstitutedFrame re-encodes a text frame whose payload changed length, preserving FIN/RSV/opcode and
// generating a fresh masking key (RFC 6455 section 5.3 requires client masks be unpredictable, so reusing
// the client's key would leak the plaintext relationship between the placeholder and the real credential).
func writeSubstitutedFrame(dst io.Writer, firstByte byte, payload []byte, masked bool) error {
	newLen := uint64(len(payload))

	var frame []byte
	switch {
	case newLen <= 125:
		second := byte(newLen)
		if masked {
			second |= 0x80
		}
		frame = append(frame, firstByte, second)
	case newLen <= 65535:
		second := byte(126)
		if masked {
			second |= 0x80
		}
		frame = append(frame, firstByte, second)
		frame = binary.BigEndian.AppendUint16(frame, uint16(newLen))
	default:
		second := byte(127)
		if masked {
			second |= 0x80
		}
		frame = append(frame, firstByte, second)
		frame = binary.BigEndian.AppendUint64(frame, newLen)
	}

	if masked {
		var newMask [4]byte
		if _, err := rand.Read(newMask[:]); err != nil {
			return err
		}
		maskedPayload := make([]byte, len(payload))
		for i := range payload {
			maskedPayload[i] = payload[i] ^ newMask[i%4]
		}
		frame = append(frame, newMask[:]...)
		frame = append(frame, maskedPayload...)
	} else {
		frame = append(frame, payload...)
	}

	_, err := dst.Write(frame)
	return err
}
