package agentvault

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Socks5Options turns on a TLS-wrapped SOCKS5 listener beside the HTTP one, for clients such as E2B that
// tunnel a sandbox's traffic to a proxy from outside the sandbox, with the session token as the password.
type Socks5Options struct {
	Port int
	// The name the listener's certificate is minted for. Ignored when Cert is set.
	TLSName string
	// The operator's own certificate for the listener, in place of one minted from the proxy's CA.
	Cert                     *ListenerCert
	AllowPrivateDestinations bool
}

// RFC 1928 and RFC 1929.
const (
	socks5Version         = 0x05
	socks5AuthVersion     = 0x01
	socks5MethodUserPass  = 0x02
	socks5MethodNone      = 0xff
	socks5CmdConnect      = 0x01
	socks5AtypIPv4        = 0x01
	socks5AtypDomain      = 0x03
	socks5AtypIPv6        = 0x04
	socks5RepSucceeded    = 0x00
	socks5RepFailure      = 0x01
	socks5RepCmdUnsup     = 0x07
	socks5RepAtypUnsup    = 0x08
	socks5AuthStatusOK    = 0x00
	socks5AuthStatusRefus = 0x01
)

// A session token is "agv_" and 32 random bytes in unpadded base64url (backend
// agent-vault-session-fns.ts). Anything else is refused without asking Infisical.
const (
	sessionTokenPrefix = "agv_"
	sessionTokenLen    = len(sessionTokenPrefix) + 43
)

func plausibleSessionToken(s string) bool {
	if len(s) != sessionTokenLen || s[:len(sessionTokenPrefix)] != sessionTokenPrefix {
		return false
	}
	for i := len(sessionTokenPrefix); i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

var errSocks5Version = errors.New("not a SOCKS5 client")

// Reads are io.ReadFull straight off the connection, never through a bufio.Reader: whatever the client sends
// after the request belongs to the tunnel, and a buffer here would swallow it.
func readSocks5Greeting(r io.Reader) (offersUserPass bool, err error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return false, err
	}
	if head[0] != socks5Version {
		return false, errSocks5Version
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return false, err
	}
	for _, m := range methods {
		if m == socks5MethodUserPass {
			return true, nil
		}
	}
	return false, nil
}

// The username is read and dropped: the password alone is the session token, as on the HTTP door.
func readSocks5Auth(r io.Reader) (password string, err error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return "", err
	}
	if head[0] != socks5AuthVersion {
		return "", fmt.Errorf("unsupported auth version %d", head[0])
	}
	if _, err := io.CopyN(io.Discard, r, int64(head[1])); err != nil {
		return "", err
	}
	var plen [1]byte
	if _, err := io.ReadFull(r, plen[:]); err != nil {
		return "", err
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(r, pass); err != nil {
		return "", err
	}
	return string(pass), nil
}

type socks5Request struct {
	cmd  byte
	host string
	port uint16
}

// rep is the reply code to send when err is set, or 0 when the connection should just close. The reserved
// byte is not checked: other servers ignore it too, and refusing on it would only break odd clients.
func readSocks5Request(r io.Reader) (req socks5Request, rep byte, err error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return req, 0, err
	}
	if head[0] != socks5Version {
		return req, socks5RepFailure, errSocks5Version
	}
	req.cmd = head[1]

	switch head[3] {
	case socks5AtypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return req, 0, err
		}
		req.host = netip.AddrFrom4(b).String()
	case socks5AtypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return req, 0, err
		}
		req.host = netip.AddrFrom16(b).String()
	case socks5AtypDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return req, 0, err
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return req, 0, err
		}
		req.host = string(b)
	default:
		// The address length is unknown, so nothing after it can be read.
		return req, socks5RepAtypUnsup, fmt.Errorf("unsupported address type %d", head[3])
	}

	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return req, 0, err
	}
	req.port = binary.BigEndian.Uint16(port[:])

	// After the whole frame is read, so the refusal still reaches the client.
	if req.cmd != socks5CmdConnect {
		return req, socks5RepCmdUnsup, fmt.Errorf("unsupported command %d", req.cmd)
	}
	if req.host == "" || req.port == 0 {
		return req, socks5RepFailure, errors.New("the request names no host or port")
	}
	return req, 0, nil
}

func writeSocks5Reply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{socks5Version, rep, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

const (
	socks5StepTimeout       = 10 * time.Second
	socks5MaxAcceptBackoff  = time.Second
	socks5MismatchWarnEvery = time.Minute
)

type socks5Server struct {
	ps        *proxyServer
	tlsConfig *tls.Config
	// The client's own steps: TLS, greeting, login and request. Asking Infisical about the token runs on its
	// own timeout, so a slow Infisical does not cut off an agent that did nothing wrong.
	stepTimeout time.Duration

	// A count under a lock rather than a WaitGroup: a test waits for the connections so far and then opens
	// more, and a WaitGroup may not be added to again once a Wait has seen it reach zero.
	connsMu sync.Mutex
	connsN  int
	idle    *sync.Cond

	lastMismatchWarn atomic.Int64
}

func newSocks5Server(ps *proxyServer, tlsConfig *tls.Config) *socks5Server {
	s := &socks5Server{ps: ps, tlsConfig: tlsConfig, stepTimeout: socks5StepTimeout}
	s.idle = sync.NewCond(&s.connsMu)
	return s
}

// serve returns nil once the listener is closed. A temporary accept error, such as running out of file
// descriptors, is waited out the way net/http does rather than ending the listener.
func (s *socks5Server) serve(l net.Listener) error {
	var backoff time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var temporary interface{ Temporary() bool }
			if errors.As(err, &temporary) && temporary.Temporary() {
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else {
					backoff = min(backoff*2, socks5MaxAcceptBackoff)
				}
				log.Warn().Err(err).Dur("retryIn", backoff).Msg("agent-vault: SOCKS5 accept failed, retrying")
				time.Sleep(backoff)
				continue
			}
			return err
		}
		backoff = 0
		s.connsMu.Lock()
		s.connsN++
		s.connsMu.Unlock()
		go func() {
			defer func() {
				s.connsMu.Lock()
				s.connsN--
				if s.connsN == 0 {
					s.idle.Broadcast()
				}
				s.connsMu.Unlock()
			}()
			s.handle(conn)
		}()
	}
}

// wait blocks until no connection is being handled.
func (s *socks5Server) wait() {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	for s.connsN > 0 {
		s.idle.Wait()
	}
}

func (s *socks5Server) handle(raw net.Conn) {
	remote := raw.RemoteAddr().String()
	// net/http recovers a panicking handler for the HTTP door; this goroutine has nothing above it, so a panic
	// here would take both doors down.
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Str("door", "socks5").Str("remote", remote).
				Msg("agent-vault: SOCKS5 connection handler panicked")
		}
	}()
	defer raw.Close()

	_ = raw.SetDeadline(time.Now().Add(s.stepTimeout))
	// Peeked rather than left to the TLS handshake: a plain SOCKS5 greeting is shorter than a TLS record
	// header, so the handshake would only time out and never say why.
	buffered := newBufferedConn(raw)
	first, err := buffered.reader.Peek(1)
	if err != nil {
		return
	}
	if first[0] == socks5Version {
		s.warnMismatch(remote)
		return
	}
	conn := tls.Server(buffered, s.tlsConfig)
	if err := conn.Handshake(); err != nil {
		log.Debug().Err(err).Str("door", "socks5").Str("remote", remote).Msg("agent-vault: SOCKS5 TLS handshake failed")
		return
	}

	offersUserPass, err := readSocks5Greeting(conn)
	if err != nil {
		log.Debug().Err(err).Str("door", "socks5").Str("remote", remote).Msg("agent-vault: SOCKS5 greeting unreadable")
		return
	}
	if !offersUserPass {
		_, _ = conn.Write([]byte{socks5Version, socks5MethodNone})
		log.Debug().Str("door", "socks5").Str("remote", remote).Msg("agent-vault: refused, the client offered no username and password")
		return
	}
	if _, err := conn.Write([]byte{socks5Version, socks5MethodUserPass}); err != nil {
		return
	}

	sessionToken, err := readSocks5Auth(conn)
	if err != nil {
		log.Debug().Err(err).Str("door", "socks5").Str("remote", remote).Msg("agent-vault: SOCKS5 login unreadable")
		return
	}
	if !plausibleSessionToken(sessionToken) {
		_, _ = conn.Write([]byte{socks5AuthVersion, socks5AuthStatusRefus})
		log.Debug().Str("door", "socks5").Str("remote", remote).Msg("agent-vault: refused, the password is not a session token")
		return
	}

	_ = raw.SetDeadline(time.Time{})
	_, err = s.ps.cache.get(sessionToken)
	_ = raw.SetDeadline(time.Now().Add(s.stepTimeout))
	if err != nil {
		refusal := classifyGateRefusal(err)
		refusal.event.
			Str("door", "socks5").
			Str("remote", remote).
			Str("sessionKey", sessionKey(sessionToken)).
			Str("decision", refusal.decision).
			Msg(refusal.msg)
		_, _ = conn.Write([]byte{socks5AuthVersion, socks5AuthStatusRefus})
		return
	}
	if _, err := conn.Write([]byte{socks5AuthVersion, socks5AuthStatusOK}); err != nil {
		return
	}

	req, rep, err := readSocks5Request(conn)
	if err != nil {
		if rep != 0 {
			_ = writeSocks5Reply(conn, rep)
		}
		log.Debug().Err(err).Str("door", "socks5").Str("remote", remote).Msg("agent-vault: SOCKS5 request refused")
		return
	}
	hostname, port, err := checkedTarget(req.host, strconv.Itoa(int(req.port)))
	if err != nil {
		_ = writeSocks5Reply(conn, socks5RepFailure)
		log.Debug().Err(err).Str("door", "socks5").Str("remote", remote).Msg("agent-vault: SOCKS5 request refused")
		return
	}

	leaf, err := s.ps.ca.mintLeaf(hostname)
	if err != nil {
		_ = writeSocks5Reply(conn, socks5RepFailure)
		log.Error().Err(err).Str("door", "socks5").Str("host", hostname).Msg("agent-vault: failed to mint a certificate")
		return
	}
	if err := writeSocks5Reply(conn, socks5RepSucceeded); err != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{})

	s.ps.serveIntercepted(conn, tunnel{hostname: hostname, port: port, sessionToken: sessionToken, viaSocks5: true}, leaf)
}

// A first byte of 0x05 on the TLS port means the client was set up for plain SOCKS5, the likeliest setup
// mistake. Rate limited, since a misconfigured client repeats it on every connection.
func (s *socks5Server) warnMismatch(remote string) {
	now := time.Now().UnixNano()
	last := s.lastMismatchWarn.Load()
	if now-last < int64(socks5MismatchWarnEvery) || !s.lastMismatchWarn.CompareAndSwap(last, now) {
		return
	}
	log.Warn().Str("door", "socks5").Str("remote", remote).
		Msg("agent-vault: a client spoke plain SOCKS5 to the TLS port; turn on TLS in the client's proxy settings")
}

func socks5TLSConfig(ca *caManager, opts *Socks5Options) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.Cert != nil {
		cfg.Certificates = []tls.Certificate{opts.Cert.certificate}
		return cfg
	}
	// Per handshake rather than once, so the 24-hour leaf is replaced before it expires. The client's SNI is
	// ignored on purpose: an unauthenticated client must not choose what gets minted.
	name := opts.TLSName
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		leaf, err := ca.mintLeaf(name)
		if err != nil {
			return nil, err
		}
		return &leaf, nil
	}
	return cfg
}
