package agentproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// wsFakeConn satisfies net.Conn for the frame copiers, which only ever call SetReadDeadline on it.
type wsFakeConn struct {
	io.Reader
	io.Writer
}

func (wsFakeConn) Close() error                     { return nil }
func (wsFakeConn) LocalAddr() net.Addr              { return nil }
func (wsFakeConn) RemoteAddr() net.Addr             { return nil }
func (wsFakeConn) SetDeadline(time.Time) error      { return nil }
func (wsFakeConn) SetReadDeadline(time.Time) error  { return nil }
func (wsFakeConn) SetWriteDeadline(time.Time) error { return nil }

func writeWSTextFrame(w io.Writer, text string, masked bool) error {
	payload := []byte(text)
	header := []byte{0x81, byte(len(payload))}
	if masked {
		header[1] |= 0x80
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	mask := []byte{1, 2, 3, 4}
	if masked {
		if _, err := w.Write(mask); err != nil {
			return err
		}
		for i := range payload {
			payload[i] ^= mask[i%len(mask)]
		}
	}
	_, err := w.Write(payload)
	return err
}

func readWSTextFrame(r io.Reader) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", err
	}
	if header[0]&0x0F != wsOpText {
		return "", fmt.Errorf("opcode = %d, want text", header[0]&0x0F)
	}

	masked := header[1]&0x80 != 0
	length := int(header[1] & 0x7F)
	switch length {
	case 126:
		extended := make([]byte, 2)
		if _, err := io.ReadFull(r, extended); err != nil {
			return "", err
		}
		length = int(binary.BigEndian.Uint16(extended))
	case 127:
		return "", fmt.Errorf("large frames are not supported by this test helper")
	}

	mask := []byte{0, 0, 0, 0}
	if masked {
		if _, err := io.ReadFull(r, mask); err != nil {
			return "", err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%len(mask)]
		}
	}
	return string(payload), nil
}

func maskedTextFrame(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := writeWSTextFrame(&buf, text, true); err != nil {
		t.Fatalf("writeWSTextFrame: %v", err)
	}
	return buf.Bytes()
}

// maskedCloseFrame is opcode 0x8, FIN set, masked, empty payload.
func maskedCloseFrame() []byte {
	return []byte{0x88, 0x80, 0x00, 0x00, 0x00, 0x00}
}

func maskedBinaryFrame(payload []byte, mask [4]byte) []byte {
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	hdr := []byte{0x82, byte(len(masked)) | 0x80}
	hdr = append(hdr, mask[:]...)
	return append(hdr, masked...)
}

// pingFrame is opcode 0x9, FIN set, unmasked.
func pingFrame(payload []byte) []byte {
	return append([]byte{0x89, byte(len(payload))}, payload...)
}

func wsSubs(placeholder, value string) []wsSubstitution {
	return []wsSubstitution{{placeholder: placeholder, value: value}}
}

func runFrameCopy(t *testing.T, frames []byte, subs []wsSubstitution) ([]byte, int) {
	t.Helper()
	var dst bytes.Buffer
	n := copyWSFramesWithSubstitution(&dst, bytes.NewReader(frames), wsFakeConn{}, subs)
	return dst.Bytes(), n
}

func TestWebSocketSubstitutesTextFrame(t *testing.T) {
	frames := append(
		maskedTextFrame(t, `{"op":2,"d":{"token":"__slack_token__","intents":513}}`),
		maskedCloseFrame()...,
	)

	out, n := runFrameCopy(t, frames, wsSubs("__slack_token__", "xoxb-real-token"))
	if n != 1 {
		t.Fatalf("substituted count = %d, want 1", n)
	}

	got, err := readWSTextFrame(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("readWSTextFrame: %v", err)
	}
	want := `{"op":2,"d":{"token":"xoxb-real-token","intents":513}}`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A rewritten client frame must carry a fresh mask, not the client's: reusing it would expose the XOR
// relationship between the placeholder the agent sent and the real credential.
func TestWebSocketSubstitutionRemasks(t *testing.T) {
	frames := append(maskedTextFrame(t, "__tk__"), maskedCloseFrame()...)

	out, _ := runFrameCopy(t, frames, wsSubs("__tk__", "abcdef"))
	if len(out) < 6 {
		t.Fatalf("output too short: %d bytes", len(out))
	}
	if out[1]&0x80 == 0 {
		t.Fatal("rewritten frame lost its mask bit")
	}
	if bytes.Equal(out[2:6], []byte{1, 2, 3, 4}) {
		t.Fatal("rewritten frame reused the client's masking key")
	}
	if got, err := readWSTextFrame(bytes.NewReader(out)); err != nil || got != "abcdef" {
		t.Fatalf("got %q (err %v), want %q", got, err, "abcdef")
	}
}

func TestWebSocketNoMatchPassesThrough(t *testing.T) {
	payload := `{"op":11,"d":null}`
	frames := append(maskedTextFrame(t, payload), maskedCloseFrame()...)

	out, n := runFrameCopy(t, frames, wsSubs("__slack_token__", "real"))
	if n != 0 {
		t.Fatalf("substituted count = %d, want 0", n)
	}
	got, err := readWSTextFrame(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("readWSTextFrame: %v", err)
	}
	if got != payload {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

func TestWebSocketBinaryFramePassesThrough(t *testing.T) {
	frames := append(
		maskedBinaryFrame([]byte{0x01, 0x02, 0x03, 0x04}, [4]byte{5, 6, 7, 8}),
		maskedCloseFrame()...,
	)

	out, n := runFrameCopy(t, frames, wsSubs("__token__", "real"))
	if n != 0 {
		t.Fatalf("substituted count = %d, want 0", n)
	}
	if out[0]&0x0F != 0x2 {
		t.Fatalf("opcode = 0x%x, want binary", out[0]&0x0F)
	}
}

func TestWebSocketPingPassesThrough(t *testing.T) {
	frames := append(pingFrame([]byte("hello")), maskedCloseFrame()...)

	out, _ := runFrameCopy(t, frames, wsSubs("__token__", "real"))
	if out[0]&0x0F != 0x9 {
		t.Fatalf("opcode = 0x%x, want ping", out[0]&0x0F)
	}
}

// A fragmented text frame cannot be substituted without reassembly, so it must pass through untouched rather
// than be rewritten in pieces.
func TestWebSocketFragmentedTextPassesThrough(t *testing.T) {
	// FIN clear, opcode text, masked, payload "__tk__" under mask {1,2,3,4}.
	payload := []byte("__tk__")
	for i := range payload {
		payload[i] ^= []byte{1, 2, 3, 4}[i%4]
	}
	frag := append([]byte{0x01, byte(len(payload)) | 0x80, 1, 2, 3, 4}, payload...)
	frames := append(frag, maskedCloseFrame()...)

	out, n := runFrameCopy(t, frames, wsSubs("__tk__", "real"))
	if n != 0 {
		t.Fatalf("substituted count = %d, want 0", n)
	}
	if out[0]&0x80 != 0 {
		t.Fatal("FIN bit was set on a forwarded fragment")
	}
}

func TestWebSocketCloseFrameExits(t *testing.T) {
	done := make(chan struct{})
	go func() {
		runFrameCopy(t, maskedCloseFrame(), wsSubs("__token__", "real"))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("frame copier did not exit after a close frame")
	}
}

// Substitution can push a payload across a length-encoding boundary, so the rewritten header has to switch
// from the 7-bit form to the 16-bit form.
func TestWebSocketLengthEncodingTransition(t *testing.T) {
	prefix := strings.Repeat("A", 115)
	frames := append(maskedTextFrame(t, prefix+"__tk__"), maskedCloseFrame()...)

	out, _ := runFrameCopy(t, frames, wsSubs("__tk__", strings.Repeat("X", 100)))
	if len(out) < 4 {
		t.Fatalf("output too short: %d bytes", len(out))
	}
	if got := out[1] & 0x7F; got != 126 {
		t.Fatalf("length byte = %d, want 126 (16-bit form)", got)
	}
	if got, want := int(binary.BigEndian.Uint16(out[2:4])), 215; got != want {
		t.Fatalf("encoded length = %d, want %d", got, want)
	}
	got, err := readWSTextFrame(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("readWSTextFrame: %v", err)
	}
	if got != prefix+strings.Repeat("X", 100) {
		t.Fatal("payload after substitution is not what was expected")
	}
}

func TestWebSocketOversizedFramePassesThrough(t *testing.T) {
	body := []byte(strings.Repeat("A", maxWSSubstitutionPayload+100) + "__token__")
	mask := [4]byte{1, 2, 3, 4}

	var frame bytes.Buffer
	frame.WriteByte(0x81)
	frame.WriteByte(127 | 0x80)
	lenBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBytes, uint64(len(body)))
	frame.Write(lenBytes)
	frame.Write(mask[:])
	for i := range body {
		body[i] ^= mask[i%4]
	}
	frame.Write(body)
	frame.Write(maskedCloseFrame())

	out, n := runFrameCopy(t, frame.Bytes(), wsSubs("__token__", "real"))
	if n != 0 {
		t.Fatalf("substituted count = %d, want 0", n)
	}
	if out[0]&0x0F != wsOpText {
		t.Fatalf("opcode = 0x%x, want text", out[0]&0x0F)
	}
	if got := out[1] & 0x7F; got != 127 {
		t.Fatalf("length byte = %d, want 127 (frame was re-encoded)", got)
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"upgrade", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}, true},
		{"mixed case", map[string]string{"Upgrade": "WebSocket", "Connection": "keep-alive, upgrade"}, true},
		{"no connection token", map[string]string{"Upgrade": "websocket", "Connection": "keep-alive"}, false},
		{"other protocol", map[string]string{"Upgrade": "h2c", "Connection": "Upgrade"}, false},
		{"plain request", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "https://example.com/ws", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := isWebSocketUpgrade(r); got != tc.want {
				t.Fatalf("isWebSocketUpgrade = %v, want %v", got, tc.want)
			}
		})
	}
}

// The upgrade headers are hop-by-hop, so the strip would kill the handshake unless they are restored.
func TestHandshakeHeadersSurviveHopByHopStrip(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "https://example.com/ws", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")

	captured := captureWebSocketHandshakeHeaders(r.Header)
	stripHopByHopHeaders(r.Header)
	if r.Header.Get("Upgrade") != "" {
		t.Fatal("expected the strip to remove Upgrade")
	}
	restoreHeaders(r.Header, captured)

	if got := r.Header.Get("Upgrade"); got != "websocket" {
		t.Fatalf("Upgrade = %q after restore, want websocket", got)
	}
	if got := r.Header.Get("Sec-WebSocket-Key"); got != "dGhlIHNhbXBsZSBub25jZQ==" {
		t.Fatalf("Sec-WebSocket-Key = %q after restore", got)
	}

	// Connection is not part of the restore set; prepareUpstream rebuilds it. See
	// TestUpgradeConnectionHeaderIsRebuilt for why it is not carried over from the agent.
	if got := r.Header.Get("Connection"); got != "" {
		t.Fatalf("Connection = %q after restore, want it left for prepareUpstream to rebuild", got)
	}
	r.Header.Set("Connection", "Upgrade")
	if !isWebSocketUpgrade(r) {
		t.Fatal("the rebuilt request is not recognised as an upgrade")
	}
}

// End to end over the plaintext forward path: the agent sends a placeholder in the handshake and in the
// first frame, and the upstream must see the real credential in both. This is what proves the handshake
// headers survive the hop-by-hop strip and that the hijacked conn outlives the server's read deadline.
func TestWebSocketEndToEndBrokersHandshakeAndFrame(t *testing.T) {
	type result struct {
		auth  string
		proto string
		frame string
	}
	results := make(chan result, 1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			http.Error(w, "expected a websocket upgrade", http.StatusBadRequest)
			return
		}
		got := result{auth: r.Header.Get("Authorization"), proto: r.Header.Get("Sec-Websocket-Protocol")}

		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"); err != nil {
			return
		}
		text, err := readWSTextFrame(buf)
		if err != nil {
			return
		}
		got.frame = text
		results <- got
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	jwt := "test.jwt.token"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	services := []*resolvedService{{
		id:           "svc-ws",
		name:         "realtime",
		hostPatterns: parseHostPatterns(u.Hostname()),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "real_secret"},
			{role: roleCredentialSub, placeholder: "__tk__", value: "xoxb-real", surfaces: []string{surfaceWebSocket}},
		},
	}}

	client := newTestProxy(t, UnmatchedAllow, jwt, scope, services)
	reader := bufio.NewReader(client)

	_, err = fmt.Fprintf(client,
		"GET http://%s/ws HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\nAuthorization: Bearer placeholder\r\n\r\n",
		u.Host, u.Host, proxyAuthHeader("proj", "prod", "/", jwt))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	if err := writeWSTextFrame(client, `{"token":"__tk__"}`, true); err != nil {
		t.Fatalf("writing client frame: %v", err)
	}

	select {
	case got := <-results:
		if got.auth != "Bearer real_secret" {
			t.Errorf("handshake Authorization = %q, want the injected credential", got.auth)
		}
		if got.proto != "chat" {
			t.Errorf("Sec-WebSocket-Protocol = %q, want chat", got.proto)
		}
		if want := `{"token":"xoxb-real"}`; got.frame != want {
			t.Errorf("frame = %q, want %q", got.frame, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the upgrade and frame")
	}
}

// An upstream that refuses to upgrade must have its real response relayed, so the agent sees the actual
// rejection rather than a proxy error.
func TestWebSocketUpgradeRefusalIsRelayed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "nope")
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	jwt := "test.jwt.token"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	client := newTestProxy(t, UnmatchedAllow, jwt, scope, nil)
	reader := bufio.NewReader(client)

	_, err = fmt.Fprintf(client,
		"GET http://%s/ws HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n\r\n",
		u.Host, u.Host, proxyAuthHeader("proj", "prod", "/", jwt))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 relayed from upstream", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "nope" {
		t.Fatalf("body = %q, want the upstream body", string(body))
	}
}

// The wss path: CONNECT, MITM TLS terminate, then an upgrade inside the tunnel. This is the shape a real
// agent uses, and it is the path where the inner tunnel server's ReadTimeout would otherwise kill the
// connection after 60s, so it covers the hijack deadline reset as well as TLS to the upstream.
func TestWebSocketOverConnectTunnel(t *testing.T) {
	frames := make(chan string, 1)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			http.Error(w, "expected an upgrade", http.StatusBadRequest)
			return
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"); err != nil {
			return
		}
		text, err := readWSTextFrame(buf)
		if err != nil {
			return
		}
		frames <- text
		// Reply so the test can assert the upstream-to-client direction, which is a separate copier and was
		// previously unasserted: a client that never receives frames is a broken WebSocket even if the
		// outbound substitution is perfect.
		_ = writeWSTextFrame(conn, "reply-from-upstream", false)
		// Hold the handler open so the reply is not raced by the deferred close.
		time.Sleep(2 * time.Second)
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	jwt := "test.jwt.token"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	services := []*resolvedService{{
		id:           "svc-wss",
		name:         "realtime",
		hostPatterns: parseHostPatterns(u.Hostname()),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{role: roleCredentialSub, placeholder: "__tk__", value: "xoxb-real", surfaces: []string{surfaceWebSocket}},
		},
	}}

	ca, interCert := newTestCA(t)
	cache := newAgentCache(func() string { return "" }, newLeaseStore(func() string { return "" }))
	cache.entries[cacheKey(jwt, scope)] = &agentEntry{jwt: jwt, scope: scope, services: services, lastSeen: time.Now()}

	// The proxy has to trust the test upstream's self-signed cert, which is exactly the transport TLS config
	// the WebSocket dial now reads instead of hardcoding system roots.
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedAllow},
		ca:        ca,
		resolver:  cache,
		transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: upstreamRoots}},
	}

	client, server := net.Pipe()
	l := newOneShotListener(server)
	srv := ps.newFrontServer()
	srv.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed || s == http.StateHijacked {
			_ = l.Close()
		}
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = client.Close() })

	_ = client.SetDeadline(time.Now().Add(15 * time.Second))

	if _, err := fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		u.Host, u.Host, proxyAuthHeader("proj", "prod", "/", jwt)); err != nil {
		t.Fatal(err)
	}
	established := "HTTP/1.1 200 Connection Established\r\n\r\n"
	buf := make([]byte, len(established))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}
	if string(buf) != established {
		t.Fatalf("CONNECT response = %q", buf)
	}

	mitmRoots := x509.NewCertPool()
	mitmRoots.AddCert(interCert)
	tlsClient := tls.Client(client, &tls.Config{ServerName: u.Hostname(), RootCAs: mitmRoots})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("MITM TLS handshake: %v", err)
	}

	// permessage-deflate is offered here deliberately: the proxy must drop it, or the upstream could negotiate
	// compression and the substitution below would silently never fire.
	if _, err := fmt.Fprintf(tlsClient,
		"GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n", u.Host); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatalf("reading upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if ext := resp.Header.Get("Sec-Websocket-Extensions"); strings.Contains(ext, "permessage-deflate") {
		t.Fatalf("compression was negotiated (%q); substitution would be silently skipped", ext)
	}

	if err := writeWSTextFrame(tlsClient, `{"token":"__tk__"}`, true); err != nil {
		t.Fatalf("writing frame: %v", err)
	}

	select {
	case got := <-frames:
		if want := `{"token":"xoxb-real"}`; got != want {
			t.Fatalf("upstream frame = %q, want %q", got, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upstream never received the substituted frame")
	}

	// The return direction: frames from the upstream must reach the client untouched.
	back, err := readWSTextFrame(tlsClient)
	if err != nil {
		t.Fatalf("reading the upstream's reply: %v", err)
	}
	if back != "reply-from-upstream" {
		t.Fatalf("reply = %q, want %q", back, "reply-from-upstream")
	}
}

// Every token in Connection is hop-by-hop to the upstream, so forwarding the agent's own value would let it
// name the injected credential and have the service strip it before seeing it.
func TestUpgradeConnectionHeaderIsRebuilt(t *testing.T) {
	jwt := "test.jwt.token"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	services := []*resolvedService{{
		name:         "realtime",
		hostPatterns: parseHostPatterns("example.com"),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "real_secret"},
		},
	}}

	cache := newAgentCache(func() string { return "" }, newLeaseStore(func() string { return "" }))
	cache.entries[cacheKey(jwt, scope)] = &agentEntry{jwt: jwt, scope: scope, services: services, lastSeen: time.Now()}
	ps := &proxyServer{opts: Options{UnmatchedHost: UnmatchedAllow}, resolver: cache, transport: &http.Transport{}}

	r, err := http.NewRequest(http.MethodGet, "http://example.com/ws", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Header.Set("Upgrade", "websocket")
	// A hostile value: naming Authorization would have the upstream drop the injected credential.
	r.Header.Set("Connection", "Upgrade, Authorization")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")

	if _, _, err := ps.prepareUpstream(r, "http", "example.com", "80", jwt, scope); err != nil {
		t.Fatalf("prepareUpstream: %v", err)
	}

	if got := r.Header.Get("Connection"); got != "Upgrade" {
		t.Fatalf("Connection = %q, want exactly %q", got, "Upgrade")
	}
	if got := r.Header.Get("Upgrade"); got != "websocket" {
		t.Fatalf("Upgrade = %q, want websocket", got)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer real_secret" {
		t.Fatalf("Authorization = %q, want the injected credential", got)
	}
	if got := r.Header.Get("Sec-WebSocket-Key"); got == "" {
		t.Fatal("Sec-WebSocket-Key was lost, the handshake would fail")
	}
}

// A compressed frame carries RSV1 and is never substituted, so the offer has to be dropped or the surface
// silently does nothing on any client that negotiates compression.
func TestDropPerMessageDeflate(t *testing.T) {
	cases := []struct {
		name    string
		offer   string
		want    string
		changed bool
	}{
		{"only deflate", "permessage-deflate", "", true},
		{"deflate with params", "permessage-deflate; client_max_window_bits=15", "", true},
		{"keeps other extensions", "permessage-deflate, x-custom-ext", "x-custom-ext", true},
		{"webkit variant", "x-webkit-deflate-frame", "", true},
		{"case insensitive", "PerMessage-Deflate", "", true},
		{"nothing to drop", "x-custom-ext", "x-custom-ext", false},
		{"no header", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := make(http.Header)
			if tc.offer != "" {
				h.Set("Sec-WebSocket-Extensions", tc.offer)
			}
			if got := dropPerMessageDeflate(h); got != tc.changed {
				t.Fatalf("dropPerMessageDeflate = %v, want %v", got, tc.changed)
			}
			if got := h.Get("Sec-WebSocket-Extensions"); got != tc.want {
				t.Fatalf("remaining extensions = %q, want %q", got, tc.want)
			}
		})
	}
}

// A 101 carries no body, so upstream framing headers must not reach the client: they would desynchronize its
// frame parser.
func TestSwitchingResponseDropsFramingHeaders(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Status:     "101 Switching Protocols",
		Proto:      "HTTP/1.1",
		Header: http.Header{
			"Sec-Websocket-Accept": []string{"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
			"Content-Length":       []string{"1234"},
			"Transfer-Encoding":    []string{"chunked"},
			"Keep-Alive":           []string{"timeout=5"},
			"Sec-Something-Else":   []string{"smuggled"},
			"Set-Cookie":           []string{"session=abc"},
		},
	}

	var buf bytes.Buffer
	if err := writeWebSocketSwitchingResponse(&buf, resp); err != nil {
		t.Fatalf("writeWebSocketSwitchingResponse: %v", err)
	}
	out := buf.String()

	for _, banned := range []string{"Content-Length", "Transfer-Encoding", "Keep-Alive", "Sec-Something-Else"} {
		if strings.Contains(out, banned) {
			t.Errorf("101 response leaked %s:\n%s", banned, out)
		}
	}
	for _, required := range []string{"101 Switching Protocols", "Sec-Websocket-Accept", "Upgrade: websocket", "Set-Cookie"} {
		if !strings.Contains(out, required) {
			t.Errorf("101 response is missing %s:\n%s", required, out)
		}
	}
}

func TestWebsocketSubstitutionsSelectsBySurface(t *testing.T) {
	creds := []resolvedCredential{
		{role: roleCredentialSub, placeholder: "__a__", value: "a", surfaces: []string{surfaceHeader, surfaceWebSocket}},
		{role: roleCredentialSub, placeholder: "__b__", value: "b", surfaces: []string{surfaceBody}},
		{role: roleCredentialSub, placeholder: "__c__", value: "c", surfaces: []string{surfaceWebSocket}},
		{role: roleHeaderRewrite, placeholder: "__d__", value: "d", surfaces: []string{surfaceWebSocket}},
		{role: roleCredentialSub, placeholder: "", value: "e", surfaces: []string{surfaceWebSocket}},
	}

	got := websocketSubstitutions(creds)
	if len(got) != 2 {
		t.Fatalf("got %d websocket substitutions, want 2", len(got))
	}
	if got[0].placeholder != "__a__" || got[1].placeholder != "__c__" {
		t.Fatalf("unexpected selection: %+v", got)
	}
	if got[0].label.Role != roleCredentialSub || len(got[0].label.Surfaces) != 1 || got[0].label.Surfaces[0] != surfaceWebSocket {
		t.Fatalf("unexpected activity label: %+v", got[0].label)
	}
}
