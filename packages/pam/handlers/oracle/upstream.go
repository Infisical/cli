package oracle

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
	"github.com/rs/zerolog/log"
)

// taplogConn wraps a net.Conn and accumulates bytes read from it during the auth
// phase. We later parse the accumulated bytes to extract the upstream's AUTH_* KVPs
// (AUTH_SESSION_ID, AUTH_SERIAL_NUM, NLS params, etc.) so we can mirror them when
// building our own server's phase-2 response. Without this, sqlcl authenticates but
// subsequent queries use session IDs the upstream doesn't recognise.
type taplogConn struct {
	net.Conn
	remaining  int
	readIdx    int
	accum      []byte // accumulated bytes up to 'remaining' limit
	mu         sync.Mutex
}

func (t *taplogConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if n > 0 && t.remaining > 0 {
		toCapture := n
		if toCapture > t.remaining {
			toCapture = t.remaining
		}
		t.readIdx++
		t.mu.Lock()
		t.accum = append(t.accum, b[:toCapture]...)
		t.mu.Unlock()
		log.Info().
			Int("readIdx", t.readIdx).
			Int("bytes", toCapture).
			Msg("Upstream Oracle read (captured)")
		t.remaining -= toCapture
	}
	return n, err
}

func (t *taplogConn) Captured() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]byte, len(t.accum))
	copy(out, t.accum)
	return out
}

// UpstreamCredentials holds everything the gateway needs to authenticate to the real
// Oracle target as the injected user.
type UpstreamCredentials struct {
	Host                  string
	Port                  int
	Service               string // Oracle service name (PAMCredentials.Database)
	Username              string
	Password              string
	SSLEnabled            bool
	SSLRejectUnauthorized bool
	SSLCertificate        string // PEM-encoded cert for pinning (optional)
}

// UpstreamConn wraps a captured authenticated net.Conn to the real Oracle target.
// Do NOT close the go-ora *sql.DB — that writes a logoff packet onto our captured conn
// and corrupts the relay. Close the net.Conn directly via Close().
type UpstreamConn struct {
	Conn  net.Conn
	sqlDB *sql.DB // Held only to prevent GC of the go-ora Connection during the session.

	// Phase2KVPs holds the AUTH_* key-value pairs we extracted from upstream Oracle's
	// phase-2 response during go-ora's authentication. Contains AUTH_SESSION_ID,
	// AUTH_SERIAL_NUM, AUTH_VERSION_STRING, NLS params, etc. We mirror these in our
	// server-facing phase-2 response so the client sees identical session metadata to
	// what upstream issued — otherwise subsequent RPCs reference IDs upstream rejects.
	Phase2KVPs map[string]string

	// UpstreamTCPNegoPayload and UpstreamDataTypeNegoPayload are the raw TTC payloads
	// (no TNS header) of upstream Oracle's responses during go-ora's auth. Forwarding
	// these to the client instead of constructing our own makes the client negotiate
	// with upstream's actual capability profile — ensuring session-state alignment
	// after auth (sequence numbers, framing flags, type table all agree).
	UpstreamTCPNegoPayload      []byte
	UpstreamDataTypeNegoPayload []byte
}

func (u *UpstreamConn) Close() error {
	if u == nil || u.Conn == nil {
		return nil
	}
	return u.Conn.Close()
}

// DialUpstream authenticates to the Oracle target using go-ora and returns the
// authenticated net.Conn for raw byte relay. The TLS wrap (when SSLEnabled) happens
// inside RegisterDial so session.conn is the *tls.Conn — and go-ora never calls its
// own TCPS negotiate() because we advertise Protocol=tcp in the DSN. See the plan's
// §5.2 "TLS-in-dial" note for why this is the key to capturing a usable conn.
func DialUpstream(ctx context.Context, creds UpstreamCredentials) (*UpstreamConn, error) {
	dsn := fmt.Sprintf("oracle://%s:%s@%s:%d/%s",
		url.QueryEscape(creds.Username),
		url.QueryEscape(creds.Password),
		creds.Host,
		creds.Port,
		creds.Service,
	)

	config, err := go_ora.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("go-ora ParseConfig: %w", err)
	}

	// Defensive: force "tcp" so UpdateSSL (configurations/session_info.go:48-66) leaves
	// SSL=false and go-ora's own negotiate() never wraps the conn in TLS.
	for i := range config.Servers {
		config.Servers[i].Protocol = "tcp"
	}
	config.Protocol = "tcp"

	var (
		captured net.Conn
		mu       sync.Mutex
	)

	config.RegisterDial(func(dctx context.Context, network, addr string) (net.Conn, error) {
		rawConn, derr := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(dctx, network, addr)
		if derr != nil {
			return nil, derr
		}

		if !creds.SSLEnabled {
			wrapped := &taplogConn{Conn: rawConn, remaining: 8192}
			mu.Lock()
			captured = wrapped
			mu.Unlock()
			return wrapped, nil
		}

		tlsCfg, terr := buildUpstreamTLSConfig(creds, addr)
		if terr != nil {
			rawConn.Close()
			return nil, terr
		}
		tlsConn := tls.Client(rawConn, tlsCfg)

		// Do the handshake explicitly so failure surfaces here, not inside go-ora's
		// session code on first write.
		if herr := tlsConn.HandshakeContext(dctx); herr != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TCPS handshake failed: %w", herr)
		}

		mu.Lock()
		captured = tlsConn
		mu.Unlock()
		return tlsConn, nil
	})

	go_ora.RegisterConnConfig(config)
	db, err := sql.Open("oracle", "")
	if err != nil {
		return nil, fmt.Errorf("sql.Open oracle: %w", err)
	}
	if perr := db.PingContext(ctx); perr != nil {
		return nil, fmt.Errorf("Oracle upstream auth failed: %w", perr)
	}

	mu.Lock()
	defer mu.Unlock()
	if captured == nil {
		_ = db.Close()
		return nil, fmt.Errorf("RegisterDial was never invoked (unexpected)")
	}

	// Pull the captured auth bytes (if we wrapped with taplogConn for plaintext) and
	// parse out the phase-2 AUTH_* KVPs and the TCPNego/DataTypeNego response payloads.
	var (
		phase2        map[string]string
		tcpNegoResp   []byte
		dataTypeResp  []byte
	)
	if tap, ok := captured.(*taplogConn); ok {
		raw := tap.Captured()
		phase2 = extractUpstreamPhase2KVPs(raw)
		tcpNegoResp = extractUpstreamDataPayload(raw, 0x01) // TCPNego response starts with 0x01
		dataTypeResp = extractUpstreamDataPayload(raw, 0x02) // DataTypeNego starts with 0x02
		log.Info().
			Int("kvpCount", len(phase2)).
			Str("sessionID", phase2["AUTH_SESSION_ID"]).
			Str("serialNum", phase2["AUTH_SERIAL_NUM"]).
			Int("tcpNegoLen", len(tcpNegoResp)).
			Int("dataTypeLen", len(dataTypeResp)).
			Msg("Upstream Oracle caps extracted")
	}

	return &UpstreamConn{
		Conn:                        captured,
		sqlDB:                       db,
		Phase2KVPs:                  phase2,
		UpstreamTCPNegoPayload:      tcpNegoResp,
		UpstreamDataTypeNegoPayload: dataTypeResp,
	}, nil
}

func buildUpstreamTLSConfig(creds UpstreamCredentials, addr string) (*tls.Config, error) {
	host, _, _ := net.SplitHostPort(addr)
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: !creds.SSLRejectUnauthorized,
	}
	if creds.SSLCertificate != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(creds.SSLCertificate)) {
			return nil, fmt.Errorf("invalid SSLCertificate PEM")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// extractUpstreamPhase2KVPs walks the captured upstream bytes (post-ACCEPT, so 32-bit
// length framing), identifies DATA packets whose first payload byte is 0x08 (TTC auth
// response), parses the key-value pairs inside, and returns the LARGEST/LAST such set
// — which is the phase-2 response (the phase-1 response is smaller and comes first).
//
// The phase-2 response carries AUTH_SESSION_ID, AUTH_SERIAL_NUM, all AUTH_NLS_* params,
// AUTH_VERSION_STRING, etc. These values are what a real Oracle server returned to
// go-ora; mirroring them downstream keeps our fake-server metadata consistent with the
// real upstream session the client's RPCs will actually run against.
func extractUpstreamPhase2KVPs(raw []byte) map[string]string {
	// Skip the initial CONNECT→ACCEPT handshake bytes, which use 16-bit framing and
	// have different header layout. The transition to 32-bit framing happens after
	// the ACCEPT response. We scan for the ACCEPT (packet type 0x02) and start
	// walking 32-bit frames from just past it.
	// In practice the captured stream starts with upstream's ACK (0x0B), ACCEPT (0x02),
	// then all 32-bit-framed DATA packets.
	pos := 0
	// Skip ACK (8 bytes 16-bit framed) if present.
	if len(raw) >= 8 && raw[4] == 0x0B {
		accL := int(raw[0])<<8 | int(raw[1])
		if accL >= 8 && accL <= 32 && pos+accL <= len(raw) {
			pos += accL
		}
	}
	// Skip ACCEPT (16-bit framed).
	if pos+5 <= len(raw) && raw[pos+4] == 0x02 {
		accL := int(raw[pos])<<8 | int(raw[pos+1])
		if accL >= 8 && pos+accL <= len(raw) {
			pos += accL
		}
	}

	// Now walk 32-bit DATA packets. Find the largest auth-response (opcode 0x08) —
	// that's the phase-2 response with all the session metadata we want to mirror.
	var best map[string]string
	var bestSize int
	for pos+10 <= len(raw) {
		pktLen := int(raw[pos])<<24 | int(raw[pos+1])<<16 | int(raw[pos+2])<<8 | int(raw[pos+3])
		if pktLen < 10 || pos+pktLen > len(raw) {
			break
		}
		pktType := raw[pos+4]
		if pktType != 0x06 { // not DATA — skip
			pos += pktLen
			continue
		}
		payload := raw[pos+10 : pos+pktLen]
		if len(payload) >= 1 && payload[0] == 0x08 {
			kvps := parseAuthResponseKVPs(payload)
			if kvps != nil && len(kvps) > bestSize {
				best = kvps
				bestSize = len(kvps)
			}
		}
		pos += pktLen
	}
	if best == nil {
		best = map[string]string{}
	}
	return best
}

// extractUpstreamDataPayload walks the captured upstream bytes and returns the body of
// the first 32-bit-framed DATA packet whose payload begins with the given opcode byte.
// Used to extract upstream's TCPNego (opcode 0x01) and DataTypeNego (opcode 0x02)
// responses so we can forward them verbatim to the client — aligning the client's
// negotiated caps with upstream's actual caps.
func extractUpstreamDataPayload(raw []byte, opcode byte) []byte {
	pos := 0
	if len(raw) >= 8 && raw[4] == 0x0B {
		accL := int(raw[0])<<8 | int(raw[1])
		if accL >= 8 && accL <= 32 && pos+accL <= len(raw) {
			pos += accL
		}
	}
	if pos+5 <= len(raw) && raw[pos+4] == 0x02 {
		accL := int(raw[pos])<<8 | int(raw[pos+1])
		if accL >= 8 && pos+accL <= len(raw) {
			pos += accL
		}
	}
	for pos+10 <= len(raw) {
		pktLen := int(raw[pos])<<24 | int(raw[pos+1])<<16 | int(raw[pos+2])<<8 | int(raw[pos+3])
		if pktLen < 10 || pos+pktLen > len(raw) {
			break
		}
		if raw[pos+4] != 0x06 { // DATA
			pos += pktLen
			continue
		}
		payload := raw[pos+10 : pos+pktLen]
		if len(payload) >= 1 && payload[0] == opcode {
			out := make([]byte, len(payload))
			copy(out, payload)
			return out
		}
		pos += pktLen
	}
	return nil
}

// parseAuthResponseKVPs decodes a TTC auth-response payload (opcode 0x08) into a map.
//
// Wire format from a real Oracle server (observed by decoding a captured AWS RDS
// phase-2 response). The server side of PutKeyVal differs subtly from what go-ora
// writes as the client: when a value is empty, Oracle does NOT write the single-zero
// placeholder byte that go-ora's own CLR encoding inserts. go-ora's default GetDlc
// consumes that placeholder, so parsing a real server response corrupts alignment
// after the first empty-value KVP (e.g., AUTH_CAPABILITY_TABLE). Our own KVP reader
// here handles the Oracle-server variant correctly.
//
// Per-KVP layout (Oracle server variant):
//   key_len     (compressed int)
//   if key_len > 0: CLR key bytes (1-byte length prefix + key_len bytes)
//   val_len     (compressed int)
//   if val_len > 0: CLR val bytes (1-byte length prefix + val_len bytes)
//   flag        (compressed int)
func parseAuthResponseKVPs(payload []byte) map[string]string {
	r := NewTTCReader(payload)
	op, err := r.GetByte()
	if err != nil || op != 0x08 {
		return nil
	}
	dictLen, err := r.GetInt(4, true, true)
	if err != nil || dictLen <= 0 || dictLen > 1000 {
		return nil
	}
	out := make(map[string]string, dictLen)
	for i := 0; i < dictLen; i++ {
		// key
		keyLen, err := r.GetInt(4, true, true)
		if err != nil {
			log.Debug().Int("iter", i).Err(err).Msg("Upstream KVP parse: key_len error")
			break
		}
		var keyBytes []byte
		if keyLen > 0 {
			keyBytes, err = r.GetClr()
			if err != nil {
				break
			}
			if len(keyBytes) > keyLen {
				keyBytes = keyBytes[:keyLen]
			}
		}
		// value
		valLen, err := r.GetInt(4, true, true)
		if err != nil {
			break
		}
		var valBytes []byte
		if valLen > 0 {
			valBytes, err = r.GetClr()
			if err != nil {
				break
			}
			if len(valBytes) > valLen {
				valBytes = valBytes[:valLen]
			}
		}
		// flag
		if _, err := r.GetInt(4, true, true); err != nil {
			break
		}

		if len(keyBytes) > 0 {
			key := string(bytes.TrimRight(keyBytes, "\x00"))
			out[key] = string(valBytes)
		}
	}
	return out
}
