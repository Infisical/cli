package agentproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// How long a session's credentials may sit unused before being dropped. A gateway serving many short agent
// runs must not accumulate their credentials.
const brokerIdleTTL = 10 * time.Minute

type BrokerOptions struct {
	// The credential used to fetch resolved bundles: a gateway access token in the gateway, or the caller's
	// own token in local mode.
	Token func() string
	// How long a bundle may be served before re-fetching. Zero uses the default.
	BundleTTL time.Duration
	// Where hosts no service matches go when the bundle does not say. The bundle's own policy wins.
	UnmatchedHost string

	// ProxySecret, when set, must be presented in Proxy-Authorization by whoever connects. Local mode sets
	// it so a loopback listener is not an open credential-injection service for every process on the
	// machine; in the gateway the client is already authenticated by mTLS, so it stays empty.
	ProxySecret string

	// UseLocalCA signs MITM leaves from a root generated on this machine rather than one signed by the
	// organization's agent-proxy root. Local mode wants this: the developer already trusts their own
	// machine, and it keeps a local run from needing to mint an intermediate off an org-wide CA.
	UseLocalCA bool
	// Where a local root is persisted so it can be trusted once (macOS keychain) instead of per run. Empty
	// keeps it in memory for the life of the process.
	LocalCADir string
}

// Broker serves brokered requests for many sessions from one process. Everything it holds is either
// credential-free (the CA manager, the upstream transport) or keyed by session (the bundle cache), so one
// agent's traffic can never be served another's credentials: the session comes from the mTLS certificate a
// connection was established with, and is captured per connection rather than read from a request.
type Broker struct {
	shared  *proxyServer
	bundles *bundleResolver
	stop    chan struct{}
}

func NewBroker(opts BrokerOptions) (*Broker, error) {
	if opts.Token == nil {
		return nil, fmt.Errorf("a broker needs a token source")
	}

	unmatched := opts.UnmatchedHost
	if unmatched == "" {
		unmatched = UnmatchedAllow
	}

	// Remote brokering signs leaves from an intermediate Infisical issues off the organization's root, so an
	// agent on any host trusts one anchor. A local run signs from a root on this machine instead.
	var ca *caManager
	var err error
	switch {
	case opts.UseLocalCA && opts.LocalCADir != "":
		ca, err = newPersistentLocalCaManager(opts.LocalCADir)
	case opts.UseLocalCA:
		ca, err = newLocalCaManager()
	default:
		ca = newCaManager(opts.Token)
	}
	if err != nil {
		return nil, err
	}
	if err := ca.ensureSigningCert(); err != nil {
		return nil, fmt.Errorf("failed to initialize the broker CA: %w", err)
	}

	bundles := newBundleResolver(opts.Token, opts.BundleTTL)

	shared := &proxyServer{
		opts: Options{
			UnmatchedHost: unmatched,
			ProxyToken:    opts.Token,
			ProxySecret:   opts.ProxySecret,
		},
		ca:           ca,
		transport:    newUpstreamTransport(),
		usageTracker: newUsageTracker(),
		bundles:      bundles,
	}

	broker := &Broker{shared: shared, bundles: bundles, stop: make(chan struct{})}
	go broker.evictLoop()
	return broker, nil
}

// ServeConn serves one tunnel as a forward proxy for exactly one session. The session is passed in rather
// than parsed, which is the whole security property: nothing in the request can change which credentials
// apply.
func (b *Broker) ServeConn(conn net.Conn, session Session) {
	if session.expired() {
		conn.Close()
		return
	}

	// A shallow copy per connection: the shared pieces stay shared, and only the session differs.
	scoped := *b.shared
	scoped.session = &session
	if session.UnmatchedHost != "" {
		scoped.opts.UnmatchedHost = session.UnmatchedHost
	}
	scoped.opts.AllowedHosts = session.AllowedHosts

	server := &http.Server{
		Handler:           http.HandlerFunc(scoped.dispatch),
		ReadHeaderTimeout: frontReadHeaderTimeout,
	}

	// ServeConn must not return until the connection is genuinely finished, because in the gateway its caller
	// is an HTTP/2 handler and returning closes the stream this connection *is*. That rules out ending on
	// Serve's return: a CONNECT hijacks, Serve stops immediately, and the MITM handshake would then be cut
	// off mid-flight on a stream nobody is holding open any more. The conn's own Close is the real signal,
	// and both paths reach it: http.Server closes it on the keep-alive path, and the hijack handler closes it
	// when its tunnel ends.
	closed := make(chan struct{})
	tracked := &closeNotifyConn{Conn: conn, closed: closed}
	listener := newOneShotListener(tracked)

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()

	select {
	case <-closed:
	case err := <-serveErr:
		// Serve gave up before anything was hijacked (a listener error, or the request was malformed).
		log.Debug().Err(err).Msg("agent gateway tunnel closed")
	}
	_ = listener.Close()
}

// closeNotifyConn reports the one moment ServeConn cares about: this connection is done with, whoever closed
// it. Close is idempotent for the caller's sake, since both http.Server and the hijack path may reach it.
type closeNotifyConn struct {
	net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return err
}

// ForgetSession drops a session's cached credentials as soon as its transport goes away, rather than leaving
// them for the idle sweep.
func (b *Broker) ForgetSession(sessionID string) {
	b.bundles.forget(sessionID, false)
}

// RootPEM is the trust anchor the agent's HTTP clients must accept. Public material only; the private key
// never leaves this process.
func (b *Broker) RootPEM() []byte {
	return b.shared.ca.RootPEM()
}

func (b *Broker) Close() {
	close(b.stop)
	// Usage recorded since the last tick would otherwise be lost, and a local run is often shorter than one
	// flush interval.
	b.shared.usageTracker.flush(b.shared.opts.ProxyToken)
	b.bundles.close()
}

func (b *Broker) evictLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			b.bundles.evictIdle(brokerIdleTTL)
			b.shared.usageTracker.flush(b.shared.opts.ProxyToken)
		}
	}
}

// PipeConns joins two connections until either side hangs up, then closes both. Used by the CLI to relay an
// agent's plain forward-proxy connection over one tunnel stream.
func PipeConns(a net.Conn, b net.Conn) {
	done := make(chan struct{}, 2)

	copyOne := func(dst net.Conn, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// Half-closing tells the far end the request body is finished, which a streaming response needs; a
		// plain Close would tear down the reply direction too.
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		done <- struct{}{}
	}

	go copyOne(a, b)
	go copyOne(b, a)

	<-done
	a.Close()
	b.Close()
}
