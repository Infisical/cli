// Package gatewaydial dials an Infisical Gateway through a relay over the two nested mTLS hops the
// platform issues credentials for. It is deliberately free of any product-specific dependency: PAM and
// agent gateways both reach a gateway the same way, and only the ALPN protocol and the certificate
// extensions differ. Keeping the dial here is what lets agent-proxy code reach a gateway without
// importing PAM.
package gatewaydial

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
)

// The gateway selects its handler from the negotiated ALPN protocol, so this is how a caller says what
// kind of work it wants done rather than sending anything in band.
type ALPN string

const (
	ALPNInfisicalPAMProxy         ALPN = "infisical-pam-proxy"
	ALPNInfisicalPAMCancellation  ALPN = "infisical-pam-session-cancellation"
	ALPNInfisicalPAMCapabilities  ALPN = "infisical-pam-capabilities"
	ALPNInfisicalPAMRDPBrowser    ALPN = "infisical-pam-rdp-browser"
	ALPNInfisicalAgentGateway     ALPN = "infisical-agent-gateway"
	ALPNInfisicalAgentGatewayStop ALPN = "infisical-agent-gateway-cancellation"
)

// The default relay port when the host carries none.
const defaultRelayPort = 8443

// Credentials is everything needed to dial one gateway: where the relay is and the mTLS material for
// both hops. Every field is issued by the platform per session and is short-lived.
type Credentials struct {
	RelayHost              string
	RelayClientCert        string
	RelayClientKey         string
	RelayServerCertChain   string
	GatewayClientCert      string
	GatewayClientKey       string
	GatewayServerCertChain string
}

// DialRelay opens the outer TLS connection to the relay.
func DialRelay(creds Credentials) (net.Conn, error) {
	host := creds.RelayHost
	port := defaultRelayPort

	if strings.Contains(creds.RelayHost, ":") {
		splitHost, portStr, err := net.SplitHostPort(creds.RelayHost)
		if err != nil {
			return nil, fmt.Errorf("invalid relay host format: %w", err)
		}
		host = splitHost
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port in relay host: %w", err)
		}
	}

	cert, err := tls.X509KeyPair([]byte(creds.RelayClientCert), []byte(creds.RelayClientKey))
	if err != nil {
		return nil, fmt.Errorf("failed to load relay client certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(creds.RelayServerCertChain)) {
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

// DialGateway performs the inner gateway mTLS handshake nested inside an already-open relay connection.
// The server name is always "localhost" because the gateway's certificate is issued for its own loopback
// identity; the relay is what routed us to the right gateway.
func DialGateway(relayConn net.Conn, alpn ALPN, creds Credentials) (net.Conn, error) {
	cert, err := tls.X509KeyPair([]byte(creds.GatewayClientCert), []byte(creds.GatewayClientKey))
	if err != nil {
		return nil, fmt.Errorf("failed to load gateway client certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(creds.GatewayServerCertChain)) {
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
	if err := gatewayConn.Handshake(); err != nil {
		// A gateway whose CLI predates this ALPN rejects the handshake here rather than answering, so the
		// caller can translate this into an "upgrade the gateway" message instead of a raw TLS error.
		return nil, fmt.Errorf("failed to establish gateway mTLS: %w", err)
	}

	if !gatewayConn.ConnectionState().HandshakeComplete {
		return nil, fmt.Errorf("gateway TLS handshake not complete")
	}

	log.Debug().Msg("Gateway mTLS connection established")
	return gatewayConn, nil
}

// Dial opens both hops and returns the inner gateway connection. Closing it closes the relay hop too.
func Dial(alpn ALPN, creds Credentials) (net.Conn, error) {
	relayConn, err := DialRelay(creds)
	if err != nil {
		return nil, err
	}

	gatewayConn, err := DialGateway(relayConn, alpn, creds)
	if err != nil {
		relayConn.Close()
		return nil, err
	}

	return gatewayConn, nil
}
