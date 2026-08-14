package pam

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/pam"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/manifoldco/promptui"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog/log"
)

// LiveSession is everything needed to dial one active PAM session: where the relay is, the mTLS
// certificates for the relay and gateway hops, and when the session stops being usable.
type LiveSession struct {
	SessionId              string
	RelayHost              string
	RelayClientCert        string
	RelayClientKey         string
	RelayServerCertChain   string
	GatewayClientCert      string
	GatewayClientKey       string
	GatewayServerCertChain string
	Expiry                 time.Time
}

// SessionProvider supplies the live session a proxy dials through. Proxies launched by
// `pam access` hold a
// session for their whole lifetime and do not set one, falling back to the fields on
// BaseProxyServer. The agent runner supplies a provider that creates the session on the first
// connection, so an account nobody touches never opens one.
type SessionProvider interface {
	// Ensure returns the live session, creating one if there is not already a usable one.
	Ensure(ctx context.Context) (LiveSession, error)
	// Current returns the live session without creating one. Termination paths use this so
	// that shutting down an untouched proxy doesn't create a session just to end it.
	Current() (LiveSession, bool)
}

// BaseProxyServer contains common functionality for all local proxy types
type BaseProxyServer struct {
	httpClient             *resty.Client
	relayHost              string
	relayClientCert        string
	relayClientKey         string
	relayServerCertChain   string
	gatewayClientCert      string
	gatewayClientKey       string
	gatewayServerCertChain string
	sessionExpiry          time.Time
	sessionId              string
	resourceType           string
	ctx                    context.Context
	cancel                 context.CancelFunc
	activeConnections      sync.WaitGroup
	shutdownOnce           sync.Once
	shutdownCh             chan struct{}

	// Kept separate from shutdownOnce: sharing one Once meant whichever path fired first
	// silently disabled the other.
	shutdownSignalOnce sync.Once
	sessionLostOnce    sync.Once
	establishFailures  atomic.Int32

	// provider, when set, resolves the session lazily instead of using the fields above.
	provider SessionProvider
	// keepProcessAlive suppresses the os.Exit(0) at the end of graceful shutdown. The agent
	// runner sets it so one proxy shutting down cannot kill the agent it launched.
	keepProcessAlive bool
}

// staticSession builds a LiveSession from the fields set at construction time.
func (b *BaseProxyServer) staticSession() LiveSession {
	return LiveSession{
		SessionId:              b.sessionId,
		RelayHost:              b.relayHost,
		RelayClientCert:        b.relayClientCert,
		RelayClientKey:         b.relayClientKey,
		RelayServerCertChain:   b.relayServerCertChain,
		GatewayClientCert:      b.gatewayClientCert,
		GatewayClientKey:       b.gatewayClientKey,
		GatewayServerCertChain: b.gatewayServerCertChain,
		Expiry:                 b.sessionExpiry,
	}
}

// session returns the live session, creating one first if the proxy is lazy.
func (b *BaseProxyServer) session() (LiveSession, error) {
	if b.provider != nil {
		return b.provider.Ensure(b.ctx)
	}
	return b.staticSession(), nil
}

// currentSession returns the live session only if one already exists.
func (b *BaseProxyServer) currentSession() (LiveSession, bool) {
	if b.provider != nil {
		return b.provider.Current()
	}
	return b.staticSession(), b.sessionId != ""
}

// exitAfterShutdown reports whether graceful shutdown should end the process.
func (b *BaseProxyServer) exitAfterShutdown() bool {
	return !b.keepProcessAlive
}

// CreateRelayConnection establishes a TLS connection to the relay server
func (b *BaseProxyServer) CreateRelayConnection() (net.Conn, error) {
	session, err := b.session()
	if err != nil {
		return nil, err
	}
	return b.createRelayConnectionWith(session)
}

// createRelayConnectionWith dials the relay using an already-resolved session, so callers that must
// not create a session (such as termination) can pass what they already hold.
func (b *BaseProxyServer) createRelayConnectionWith(session LiveSession) (net.Conn, error) {
	var host string
	var port int = 8443

	if strings.Contains(session.RelayHost, ":") {
		var portStr string
		var err error
		host, portStr, err = net.SplitHostPort(session.RelayHost)
		if err != nil {
			return nil, fmt.Errorf("invalid relay host format: %w", err)
		}
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port in relay host: %w", err)
		}
	} else {
		host = session.RelayHost
	}

	// Load relay certificates
	cert, certErr := tls.X509KeyPair([]byte(session.RelayClientCert), []byte(session.RelayClientKey))
	if certErr != nil {
		return nil, fmt.Errorf("failed to load relay client certificate: %w", certErr)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(session.RelayServerCertChain)) {
		return nil, fmt.Errorf("failed to parse relay server certificate chain")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   host,
		MinVersion:   tls.VersionTLS12,
	}

	if util.IsDevelopmentMode() {
		tlsConfig.InsecureSkipVerify = true
		log.Debug().Msg("Development mode: skipping TLS certificate verification for relay connection")
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay: %w", err)
	}

	log.Debug().Msg("Relay TLS connection established")
	return conn, nil
}

// FetchGatewayCapabilities fetches the supported resource types from the gateway
func (b *BaseProxyServer) FetchGatewayCapabilities() (*pam.PAMCapabilitiesResponse, error) {
	relayConn, err := b.CreateRelayConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay: %w", err)
	}
	defer relayConn.Close()

	gatewayConn, err := b.CreateGatewayConnection(relayConn, ALPNInfisicalPAMCapabilities)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gateway: %w", err)
	}
	defer gatewayConn.Close()

	// Read length prefix (4 bytes)
	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(gatewayConn, lengthBytes); err != nil {
		return nil, fmt.Errorf("failed to read length prefix: %w", err)
	}

	length := uint32(lengthBytes[0])<<24 | uint32(lengthBytes[1])<<16 | uint32(lengthBytes[2])<<8 | uint32(lengthBytes[3])

	// Read JSON data
	data := make([]byte, length)
	if _, err := io.ReadFull(gatewayConn, data); err != nil {
		return nil, fmt.Errorf("failed to read capabilities response: %w", err)
	}

	var response pam.PAMCapabilitiesResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("failed to parse capabilities response: %w", err)
	}

	log.Debug().Strs("supportedTypes", response.SupportedResourceTypes).Msg("Received gateway capabilities")
	return &response, nil
}

// ValidateResourceTypeSupported checks if the resource type is supported by the gateway
func (b *BaseProxyServer) ValidateResourceTypeSupported() error {
	capabilities, err := b.FetchGatewayCapabilities()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to fetch gateway capabilities, assuming older gateway version")
		return nil
	}

	if len(capabilities.SupportedResourceTypes) == 0 {
		return nil
	}

	if slices.Contains(capabilities.SupportedResourceTypes, b.resourceType) {
		return nil
	}

	return fmt.Errorf(`The connected Infisical Gateway '%s' does not support '%s' PAM accounts.

Please contact your Gateway administrator and request that they:
1. Update the Gateway deployment to the latest version.
2. Restart the Gateway service.

After they have completed the upgrade, you can retry your access command.

The Gateway upgrade guide can be found at: https://infisical.com/docs/documentation/platform/gateways/gateway-deployment`, capabilities.GatewayName, b.resourceType)
}

// CreateGatewayConnection establishes a mTLS connection to the gateway over the relay
func (b *BaseProxyServer) CreateGatewayConnection(relayConn net.Conn, alpn ALPN) (net.Conn, error) {
	session, err := b.session()
	if err != nil {
		return nil, err
	}
	return b.createGatewayConnectionWith(relayConn, alpn, session)
}

// createGatewayConnectionWith performs the gateway mTLS handshake using an already-resolved session.
func (b *BaseProxyServer) createGatewayConnectionWith(relayConn net.Conn, alpn ALPN, session LiveSession) (net.Conn, error) {
	// Load gateway certificates
	cert, err := tls.X509KeyPair([]byte(session.GatewayClientCert), []byte(session.GatewayClientKey))
	if err != nil {
		return nil, fmt.Errorf("failed to load gateway client certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(session.GatewayServerCertChain)) {
		return nil, fmt.Errorf("failed to parse gateway server certificate chain")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{string(alpn)},
		ServerName:   "localhost",
	}

	gatewayConn := tls.Client(relayConn, tlsConfig)

	err = gatewayConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("failed to establish gateway mTLS: %w", err)
	}

	state := gatewayConn.ConnectionState()
	if !state.HandshakeComplete {
		return nil, fmt.Errorf("gateway TLS handshake not complete")
	}

	log.Debug().Msg("Gateway mTLS connection established")
	return gatewayConn, nil
}

// NotifySessionTermination sends a termination notification through the gateway.
// If no session was ever created (a lazy proxy nobody connected to), there is nothing to end.
func (b *BaseProxyServer) NotifySessionTermination() {
	session, ok := b.currentSession()
	if !ok {
		log.Debug().Msg("No live session to terminate")
		return
	}
	b.TerminateSession(session)
}

// TerminateSession ends one specific session, over the gateway if it can and through the API if
// not. Callers that hold a session the proxy is no longer tracking use this: a lazy proxy retires
// sessions it will not hand out again, and each of those still has to be ended.
func (b *BaseProxyServer) TerminateSession(session LiveSession) {
	if session.SessionId == "" {
		return
	}

	log.Debug().Msgf("Notifying session termination for session ID: %s", session.SessionId)

	// Try to notify via gateway connection first
	relayConn, err := b.createRelayConnectionWith(session)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to relay for termination notification")
		// Fallback to API call if relay connection fails
		b.fallbackToAPITerminationWith(session)
		return
	}
	defer relayConn.Close()

	gatewayConn, err := b.createGatewayConnectionWith(relayConn, ALPNInfisicalPAMCancellation, session)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to gateway for termination notification")
		// Fallback to API call if gateway connection fails
		b.fallbackToAPITerminationWith(session)
		return
	}
	defer gatewayConn.Close()
	log.Debug().Msg("Session termination notification sent successfully")
}

// FallbackToAPITermination terminates the session via API call
func (b *BaseProxyServer) FallbackToAPITermination() {
	session, ok := b.currentSession()
	if !ok {
		return
	}
	b.fallbackToAPITerminationWith(session)
}

func (b *BaseProxyServer) fallbackToAPITerminationWith(session LiveSession) {
	err := api.CallPAMSessionTermination(b.httpClient, session.SessionId)
	if err != nil {
		log.Error().Err(err).Msg("Failed to terminate session via API fallback")
	} else {
		log.Debug().Msg("Session terminated successfully via API fallback")
	}
}

// signalShutdown closes shutdownCh exactly once, whichever path gets there first.
func (b *BaseProxyServer) signalShutdown() {
	b.shutdownSignalOnce.Do(func() {
		close(b.shutdownCh)
	})
}

// HandleSessionLost stops the proxy when the whole session is gone rather than one connection.
// It only raises the signal: each accept loop calls its own gracefulShutdown, which is what
// notifies the platform. Cancelling the context here instead would race that branch and skip it.
func (b *BaseProxyServer) HandleSessionLost(reason string) {
	b.sessionLostOnce.Do(func() {
		fmt.Printf("\n%s Shutting down proxy...\n", reason)
		b.signalShutdown()
	})
}

// A single failed dial is a blip; a run of them means the resource is unreachable.
const establishFailureLimit = 3

func (b *BaseProxyServer) NoteEstablishFailure(reason string) {
	if b.establishFailures.Add(1) >= establishFailureLimit {
		b.HandleSessionLost(reason)
	}
}

func (b *BaseProxyServer) NoteEstablishSuccess() {
	b.establishFailures.Store(0)
}

// NewDisconnectChannels creates the error channels a proxied connection uses to report which side
// finished first.
func (b *BaseProxyServer) NewDisconnectChannels() (gatewayErrCh, clientErrCh chan error) {
	return make(chan error, 1), make(chan error, 1)
}

// WaitForConnectionClose blocks until either side of one proxied connection finishes, and ends
// only that connection. A gateway-side close is not a session-level event: the gateway closes a
// stream whenever the resource does, which is routine for pooled clients and for exchanges the
// server answers by closing, such as a Postgres CancelRequest.
func (b *BaseProxyServer) WaitForConnectionClose(gatewayErrCh, clientErrCh <-chan error, connCtx context.Context) {
	select {
	case <-gatewayErrCh:
	case <-clientErrCh:
	case <-connCtx.Done():
	}
}

// WaitForConnectionsWithTimeout waits for active connections to close with a timeout
func (b *BaseProxyServer) WaitForConnectionsWithTimeout(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		b.activeConnections.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Debug().Msg("All connections closed gracefully")
	case <-time.After(timeout):
		log.Warn().Msg("Timeout waiting for connections to close, forcing shutdown")
	}
}

func PromptForReason(required bool) (string, error) {
	label := "Reason for access"
	prompt := promptui.Prompt{
		Label: label,
		Validate: func(input string) error {
			if required && strings.TrimSpace(input) == "" {
				return fmt.Errorf("a reason is required")
			}
			return nil
		},
	}
	result, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(result), nil
}

const reasonRequiredErrorName = "PAM_REASON_REQUIRED"

// CallPAMAccessWithMFA attempts to access a PAM account and handles MFA if required.
// This is used by the legacy proxy implementations.
func CallPAMAccessWithMFA(
	httpClient *resty.Client,
	pamRequest api.PAMAccessRequest,
	interactive bool,
) (api.PAMAccessResponse, error) {
	pamResponse, err := api.CallPAMAccess(httpClient, pamRequest)
	if err != nil {
		if apiErr, ok := err.(*api.APIError); ok {
			if apiErr.Name == reasonRequiredErrorName {
				if !interactive || !isatty.IsTerminal(os.Stdin.Fd()) {
					return api.PAMAccessResponse{}, fmt.Errorf(
						"a reason is required to access this account — pass one with --reason")
				}
				log.Info().Msg("A reason is required to access this account.")
				reason, promptErr := PromptForReason(true)
				if promptErr != nil {
					return api.PAMAccessResponse{}, fmt.Errorf("reason prompt cancelled: %w", promptErr)
				}
				pamRequest.Reason = reason
				return CallPAMAccessWithMFA(httpClient, pamRequest, interactive)
			}

			if apiErr.Name == "SESSION_MFA_REQUIRED" {
				if details, ok := apiErr.Details.(map[string]interface{}); ok {
					mfaSessionId, _ := details["mfaSessionId"].(string)
					mfaMethod, _ := details["mfaMethod"].(string)

					if mfaSessionId != "" {
						err := util.HandleMFASession(httpClient, mfaSessionId, mfaMethod, config.INFISICAL_URL)
						if err != nil {
							return api.PAMAccessResponse{}, fmt.Errorf("MFA verification failed: %w", err)
						}

						log.Debug().Msg("Retrying PAM access with MFA session...")
						pamRequest.MfaSessionId = mfaSessionId
						pamResponse, err = api.CallPAMAccess(httpClient, pamRequest)
						if err != nil {
							return api.PAMAccessResponse{}, fmt.Errorf("failed to access PAM account after MFA: %w", err)
						}

						return pamResponse, nil
					}
				}
			}
		}
		return api.PAMAccessResponse{}, err
	}

	return pamResponse, nil
}
