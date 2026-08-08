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
	// Without an idle bound a stalled or abandoned connection pins a goroutine pair, an upstream conn, and one
	// of the proxy's maxConcurrentConns slots indefinitely. Real-time keepalives sit well inside this window.
	wsIdleTimeout = 10 * time.Minute

	wsResponseTimeout = 30 * time.Second

	// The response timeout only starts once TCP is up, so without a dial bound an agent can aim a WebSocket at a
	// black-holed address and pin a connection slot for however long the OS takes to give up.
	wsDialTimeout = 10 * time.Second

	// Larger text frames stream through untouched: frame length is attacker-controlled and auth payloads are
	// tiny, so buffering by the declared length would be a memory-exhaustion lever.
	maxWSSubstitutionPayload = 1 << 20
)

// WebSocket frame opcodes (RFC 6455 section 11.8).
const (
	wsOpText  = 0x1
	wsOpClose = 0x8
)

// These have to survive stripHopByHopHeaders, or the upstream never switches protocols. Connection is
// deliberately absent: prepareUpstream rebuilds it rather than carrying the agent's value over.
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

// Serves both wss (off the MITM tunnel) and ws (a plaintext forward request). After 101 the proxy owns both
// sockets for the connection's lifetime rather than relaying through the ResponseWriter.
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

	// Settled before the handshake goes out. A permessage-deflate frame carries RSV1 and is never substituted,
	// and most clients offer compression by default, so leaving the offer in would silently turn substitution
	// into a no-op. Costs bandwidth, and only where the surface is actually used.
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

	// Relay a refusal like any other response, so the agent sees the real 401 or 404 rather than a proxy error.
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

	// Reports only what was applied to the handshake. Credentials armed for frame substitution are not claimed
	// here: no frame has been rewritten yet, and the agent may never send the placeholder at all.
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

	// Hijack leaves the server's ReadTimeout/WriteTimeout deadlines on the conn, which would kill a long-lived
	// WebSocket at tunnelReadTimeout. The pipe below applies its own idle deadline instead.
	_ = clientConn.SetDeadline(time.Time{})

	_ = clientConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := writeWebSocketSwitchingResponse(clientConn, resp); err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		return
	}
	_ = clientConn.SetWriteDeadline(time.Time{})

	// Resolved per message from the same place an HTTP request resolves it, so a rotated lease is picked up and a
	// revoked grant stops the substitution rather than replaying a value captured at the upgrade.
	matchPath := r.URL.Path
	resolveSubs := func() []wsSubstitution {
		services, err := ps.resolver.get(jwt, scope)
		if err != nil {
			return nil
		}
		svc := bestMatch(services, hostname, port, matchPath)
		if svc == nil {
			return nil
		}
		return websocketSubstitutions(ps.materializeCredentials(svc))
	}

	counts := pipeWebSocket(clientConn, clientBuf.Reader, upstreamConn, upstreamReader, resolveSubs, len(wsSubs) > 0)

	// A connection that rewrote a credential is an audit event, so it must not be filtered out with the
	// passthrough noise.
	level := zerolog.DebugLevel
	if counts.substituted > 0 || counts.redacted > 0 {
		level = zerolog.InfoLevel
	}
	ev := log.WithLevel(level).
		Str("event", activityEventName).
		Str("decision", decision).
		Str("agentId", outcome.agentID).
		Str("projectId", scope.projectID).
		Str("environment", scope.environment).
		Str("secretPath", scope.secretPath).
		Str("host", hostname).
		Str("path", reqPath).
		Int("framesSubstituted", counts.substituted).
		Int("framesRedacted", counts.redacted)
	// Named only once a frame was actually rewritten, so the record cannot claim a credential was applied to a
	// connection that never carried one.
	if counts.substituted > 0 {
		labels := make([]AppliedCredential, 0, len(wsSubs))
		for _, sub := range wsSubs {
			labels = append(labels, sub.label)
		}
		ev = ev.Interface("credentials", labels)
	}
	ev.Msg("websocket closed")
}

// Offers are comma separated and their parameters semicolon separated, so splitting on commas is safe.
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

// The WebSocket dial needs the raw conn, so it cannot inherit the transport's settings by going through it.
// Reading them off explicitly is what keeps upstream verification identical to the plain HTTP path.
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

// A hijacked WebSocket cannot be driven through http.Transport's pooled round tripper, so the handshake runs
// on a connection the proxy owns.
func (ps *proxyServer) dialWebSocketUpstream(ctx context.Context, outReq *http.Request) (net.Conn, *bufio.Reader, *http.Response, error) {
	dialer := &net.Dialer{Timeout: wsDialTimeout}
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

// The ResponseWriter is already hijacked, so Go's response machinery cannot frame this.
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

// Unknown Sec-* headers are dropped so the upstream cannot smuggle extension state the proxy has not
// accounted for. Body-framing headers are dropped too: a 101 carries no body, and a stray Content-Length or
// Transfer-Encoding would desynchronize the client's frame parser.
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

// wsIdle extends both read deadlines together. Per-direction deadlines would tear down a live connection: a
// subscribe-mostly stream can receive for hours while sending nothing, and its own deadline would expire and
// take the whole connection with it. Traffic either way counts as activity, so a timeout means both directions
// have gone quiet.
type wsIdle struct {
	mu    sync.Mutex
	conns [2]net.Conn
}

func (w *wsIdle) extend() {
	deadline := time.Now().Add(wsIdleTimeout)
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, c := range w.conns {
		_ = c.SetReadDeadline(deadline)
	}
}

type wsCounts struct {
	substituted int
	redacted    int
}

// resolveSubs is called per eligible message rather than once per connection, so a WebSocket picks up a rotated
// dynamic lease and a revoked grant the same way an HTTP request does. It returns nothing when the agent is no
// longer authorized, which leaves the placeholder in the message and fails closed at the service.
func pipeWebSocket(clientConn net.Conn, clientReader *bufio.Reader, upstreamConn net.Conn, upstreamReader *bufio.Reader, resolveSubs func() []wsSubstitution, armed bool) wsCounts {
	done := make(chan struct{}, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = clientConn.Close()
			_ = upstreamConn.Close()
		})
	}

	idle := &wsIdle{conns: [2]net.Conn{clientConn, upstreamConn}}
	idle.extend()

	var counts wsCounts
	go func() {
		defer func() {
			done <- struct{}{}
			closeBoth()
		}()
		src := io.MultiReader(clientReader, clientConn)
		if armed {
			counts.substituted = copyWSFrames(upstreamConn, src, idle, func() []wsReplacement {
				return forwardReplacements(resolveSubs())
			})
		} else {
			copyWithIdleTimeout(upstreamConn, src, idle)
		}
	}()
	go func() {
		defer func() {
			done <- struct{}{}
			closeBoth()
		}()
		src := io.MultiReader(upstreamReader, upstreamConn)
		// The agent picks where its placeholder goes, so it can plant one in a field the service echoes (a
		// correlation id, an error message) and read the real credential out of the reply. Swapping the value
		// back on the way in closes that, and also stops a service that quotes the credential in an error from
		// leaking it by accident.
		if armed {
			counts.redacted = copyWSFrames(clientConn, src, idle, func() []wsReplacement {
				return reverseReplacements(resolveSubs())
			})
		} else {
			copyWithIdleTimeout(clientConn, src, idle)
		}
	}()

	<-done
	<-done
	return counts
}

func copyWithIdleTimeout(dst io.Writer, src io.Reader, idle *wsIdle) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			idle.extend()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// Binary, fragmented, compressed (RSV1) and oversized frames are forwarded byte-for-byte, so a shape the
// parser cannot safely rewrite degrades to passthrough instead of corrupting the stream.
func copyWSFrames(dst io.Writer, src io.Reader, idle *wsIdle, replacements func() []wsReplacement) int {
	r := bufio.NewReaderSize(src, 32*1024)
	rewritten := 0

	for {
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return rewritten
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
				return rewritten
			}
			payloadLen = uint64(binary.BigEndian.Uint16(extHdr))
		case 127:
			extHdr = make([]byte, 8)
			if _, err := io.ReadFull(r, extHdr); err != nil {
				return rewritten
			}
			payloadLen = binary.BigEndian.Uint64(extHdr)
			// RFC 6455 section 5.2: the MSB must be 0. Rejecting here prevents an int64 overflow in io.CopyN
			// that would desynchronize the frame parser.
			if payloadLen > math.MaxInt64 {
				return rewritten
			}
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(r, maskKey[:]); err != nil {
				return rewritten
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
				return rewritten
			}
			if payloadLen > 0 {
				if _, err := io.CopyN(dst, r, int64(payloadLen)); err != nil {
					return rewritten
				}
			}
			idle.extend()
			if opcode == wsOpClose {
				return rewritten
			}
			continue
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return rewritten
		}
		idle.extend()

		raw := make([]byte, len(payload))
		copy(raw, payload)

		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		text := string(payload)
		for _, rep := range replacements() {
			if replaced, ok := replaceWithinLimit(text, rep.from, rep.to, maxWSSubstitutionPayload); ok {
				text = replaced
			}
		}

		// Nothing matched: forward the original bytes rather than re-encoding an identical frame.
		if text == string(payload) {
			if !writeFrameHeader() {
				return rewritten
			}
			if _, err := dst.Write(raw); err != nil {
				return rewritten
			}
			continue
		}

		if err := writeSubstitutedFrame(dst, hdr[0], []byte(text), masked); err != nil {
			return rewritten
		}
		rewritten++
	}
}

// RFC 6455 section 5.3 requires client masks be unpredictable, and reusing the client's key would leak the
// XOR relationship between the placeholder and the real credential, so a fresh key is generated here.
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
