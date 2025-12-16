package pam

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/pam"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

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
}

// CreateRelayConnection establishes a TLS connection to the relay server
func (b *BaseProxyServer) CreateRelayConnection() (net.Conn, error) {
	var host string
	var port int = 8443

	if strings.Contains(b.relayHost, ":") {
		var portStr string
		var err error
		host, portStr, err = net.SplitHostPort(b.relayHost)
		if err != nil {
			return nil, fmt.Errorf("invalid relay host format: %w", err)
		}
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port in relay host: %w", err)
		}
	} else {
		host = b.relayHost
	}

	// Load relay certificates
	cert, err := tls.X509KeyPair([]byte(b.relayClientCert), []byte(b.relayClientKey))
	if err != nil {
		return nil, fmt.Errorf("failed to load relay client certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(b.relayServerCertChain)) {
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
		return fmt.Errorf("failed to fetch gateway capabilities: %w", err)
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
	// Load gateway certificates
	cert, err := tls.X509KeyPair([]byte(b.gatewayClientCert), []byte(b.gatewayClientKey))
	if err != nil {
		return nil, fmt.Errorf("failed to load gateway client certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(b.gatewayServerCertChain)) {
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

// NotifySessionTermination sends a termination notification through the gateway
func (b *BaseProxyServer) NotifySessionTermination() {
	log.Debug().Msgf("Notifying session termination for session ID: %s", b.sessionId)

	// Try to notify via gateway connection first
	relayConn, err := b.CreateRelayConnection()
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to relay for termination notification")
		// Fallback to API call if relay connection fails
		b.FallbackToAPITermination()
		return
	}
	defer relayConn.Close()

	gatewayConn, err := b.CreateGatewayConnection(relayConn, ALPNInfisicalPAMCancellation)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to gateway for termination notification")
		// Fallback to API call if gateway connection fails
		b.FallbackToAPITermination()
		return
	}
	defer gatewayConn.Close()
	log.Debug().Msg("Session termination notification sent successfully")
}

// FallbackToAPITermination terminates the session via API call
func (b *BaseProxyServer) FallbackToAPITermination() {
	err := api.CallPAMSessionTermination(b.httpClient, b.sessionId)
	if err != nil {
		log.Error().Err(err).Msg("Failed to terminate session via API fallback")
	} else {
		log.Debug().Msg("Session terminated successfully via API fallback")
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
