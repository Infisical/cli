package gatewayv2

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// ForwardMode represents the type of forwarding
type ForwardMode string

const (
	ForwardModeHTTP ForwardMode = "HTTP"
	ForwardModeTCP  ForwardMode = "TCP"
	ForwardModePing ForwardMode = "PING"
)

type ActorType string

const (
	ActorTypePlatform ActorType = "platform"
	ActorTypeUser     ActorType = "user"
)

const GATEWAY_ROUTING_INFO_OID = "1.3.6.1.4.1.12345.100.1"
const GATEWAY_ACTOR_OID = "1.3.6.1.4.1.12345.100.2"

// ForwardConfig contains the configuration for forwarding
type ForwardConfig struct {
	Mode          ForwardMode
	CACertificate []byte // Decoded CA certificate for HTTPS verification
	VerifyTLS     bool   // Whether to verify TLS certificates
	TargetHost    string
	TargetPort    int
	ActorType     ActorType
}

// RoutingInfo represents the routing information embedded in client certificates
type RoutingInfo struct {
	TargetHost string `json:"targetHost"`
	TargetPort int    `json:"targetPort"`
}

type ActorDetails struct {
	Type string `json:"type"`
}

type GatewayConfig struct {
	Name           string
	ProxyName      string
	IdentityToken  string
	SSHPort        int
	ReconnectDelay time.Duration
}

type Gateway struct {
	GatewayID string

	httpClient *resty.Client
	config     *GatewayConfig
	sshClient  *ssh.Client

	// Certificate storage
	certificates *api.RegisterGatewayResponse

	// mTLS server components
	tlsConfig *tls.Config

	// Connection management
	mu          sync.RWMutex
	isConnected bool
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewGateway creates a new gateway instance
func NewGateway(config *GatewayConfig) (*Gateway, error) {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return nil, fmt.Errorf("unable to get client with custom headers [err=%v]", err)
	}

	httpClient.SetAuthToken(config.IdentityToken)

	ctx, cancel := context.WithCancel(context.Background())

	// Set default SSH port if not specified
	if config.SSHPort == 0 {
		config.SSHPort = 2222
	}

	return &Gateway{
		httpClient: httpClient,
		config:     config,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

func (g *Gateway) registerHeartBeat(ctx context.Context, errCh chan error) {
	sendHeartbeat := func() {
		if err := api.CallGatewayHeartBeatV2(g.httpClient); err != nil {
			log.Warn().Msgf("Heartbeat failed: %v", err)
			select {
			case errCh <- err:
			default:
				log.Warn().Msg("Error channel full, skipping heartbeat error report")
			}
		} else {
			log.Info().Msg("Gateway is reachable by Infisical")
		}
	}

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
			sendHeartbeat()
		}

		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sendHeartbeat()
			}
		}
	}()
}

func (g *Gateway) Start(ctx context.Context) error {
	log.Info().Msgf("Starting gateway")

	errCh := make(chan error, 1)
	g.registerHeartBeat(ctx, errCh)

	// Start certificate renewal goroutine
	go g.startCertificateRenewal(ctx)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-errCh:
				log.Warn().Msgf("Heartbeat error received: %v", err)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msgf("Gateway stopped by context cancellation")
			return nil
		default:
			if err := g.connectAndServe(); err != nil {
				log.Error().Msgf("Connection failed: %v, retrying in %v...", err, g.config.ReconnectDelay)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(g.config.ReconnectDelay):
					continue
				}
			}
			// If we get here, the connection was closed gracefully
			log.Info().Msgf("Connection closed, reconnecting in 10 seconds...")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Second):
				continue
			}
		}
	}
}

func (g *Gateway) SetToken(token string) {
	g.httpClient.SetAuthToken(token)
}

func (g *Gateway) Stop() {
	g.cancel()

	g.mu.Lock()
	if g.sshClient != nil {
		g.sshClient.Close()
		g.sshClient = nil
	}
	g.isConnected = false
	g.mu.Unlock()
}

func (g *Gateway) connectAndServe() error {
	if err := g.registerGateway(); err != nil {
		return fmt.Errorf("failed to register gateway: %v", err)
	}

	// Create SSH client config
	sshConfig, err := g.createSSHConfig()
	if err != nil {
		return fmt.Errorf("failed to create SSH config: %v", err)
	}

	// Connect to Proxy server
	log.Info().Msgf("Connecting to SSH server on %s:%d...", g.certificates.ProxyIP, g.config.SSHPort)
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", g.certificates.ProxyIP, g.config.SSHPort), sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %v", err)
	}
	log.Info().Msgf("SSH connection established for gateway")

	g.mu.Lock()
	g.sshClient = client
	g.isConnected = true
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		g.sshClient = nil
		g.isConnected = false
		g.mu.Unlock()
		client.Close()
	}()

	// Handle incoming channels from the server
	channels := client.HandleChannelOpen("direct-tcpip")
	if channels == nil {
		return fmt.Errorf("failed to handle channel open")
	}

	// Monitor for context cancellation and close SSH client
	go func() {
		<-g.ctx.Done()
		log.Info().Msg("Context cancelled, closing SSH connection...")
		client.Close()
	}()

	// Process incoming channels with context cancellation support
	for {
		select {
		case <-g.ctx.Done():
			log.Info().Msg("Context cancelled, stopping channel processing")
			return g.ctx.Err()
		case newChannel, ok := <-channels:
			if !ok {
				log.Info().Msg("SSH channels closed")
				return nil
			}
			go g.handleIncomingChannel(newChannel)
		}
	}
}

func (g *Gateway) registerGateway() error {
	body := api.RegisterGatewayRequest{
		ProxyName: g.config.ProxyName,
		Name:      g.config.Name,
	}

	certResp, err := api.CallRegisterGateway(g.httpClient, body)
	if err != nil {
		return fmt.Errorf("failed to register gateway: %v", err)
	}

	g.GatewayID = certResp.GatewayID
	g.certificates = &certResp
	log.Info().Msgf("Successfully registered gateway and received certificates")

	// Setup mTLS config
	if err := g.setupTLSConfig(); err != nil {
		return fmt.Errorf("failed to setup TLS config: %v", err)
	}

	return nil
}

func (g *Gateway) setupTLSConfig() error {
	serverCertBlock, _ := pem.Decode([]byte(g.certificates.PKI.ServerCertificate))
	if serverCertBlock == nil {
		return fmt.Errorf("failed to decode server certificate")
	}

	serverKeyBlock, _ := pem.Decode([]byte(g.certificates.PKI.ServerPrivateKey))
	if serverKeyBlock == nil {
		return fmt.Errorf("failed to decode server private key")
	}

	serverKey, err := x509.ParsePKCS8PrivateKey(serverKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse server private key: %v", err)
	}

	clientCAPool := x509.NewCertPool()
	var chainCerts [][]byte
	chainData := []byte(g.certificates.PKI.ClientCertificateChain)
	for {
		block, rest := pem.Decode(chainData)
		if block == nil {
			break
		}
		chainCerts = append(chainCerts, block.Bytes)
		chainData = rest
	}

	for i, certBytes := range chainCerts {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			log.Info().Msgf("Failed to parse client chain certificate %d: %v", i+1, err)
			continue
		}
		clientCAPool.AddCert(cert)
	}

	g.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCertBlock.Bytes},
				PrivateKey:  serverKey,
			},
		},
		ClientCAs:  clientCAPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}

	return nil
}

func (g *Gateway) createSSHConfig() (*ssh.ClientConfig, error) {
	privateKey, err := ssh.ParsePrivateKey([]byte(g.certificates.SSH.ClientPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %v", err)
	}

	// Parse certificate
	cert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(g.certificates.SSH.ClientCertificate))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	sshCert, ok := cert.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("parsed key is not an SSH certificate, got type: %T", cert)
	}

	// Create certificate signer
	certSigner, err := ssh.NewCertSigner(sshCert, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate signer: %v", err)
	}

	// Create SSH client config
	config := &ssh.ClientConfig{
		User: g.GatewayID,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(certSigner),
		},
		HostKeyCallback: g.createHostKeyCallback(),
		Timeout:         30 * time.Second,
		Config: ssh.Config{
			KeyExchanges: []string{
				"diffie-hellman-group14-sha256",
				"diffie-hellman-group16-sha512",
				"diffie-hellman-group18-sha512",
			},
			Ciphers: []string{
				"aes128-ctr",
				"aes192-ctr",
				"aes256-ctr",
			},
			MACs: []string{
				"hmac-sha2-256",
				"hmac-sha2-512",
			},
		},
	}

	return config, nil
}

func (g *Gateway) createHostKeyCallback() ssh.HostKeyCallback {
	caKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(g.certificates.SSH.ServerCAPublicKey))
	if err != nil {
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return fmt.Errorf("failed to parse CA public key: %v", err)
		}
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		cert, ok := key.(*ssh.Certificate)
		if !ok {
			return fmt.Errorf("host certificates required, raw host keys not allowed")
		}

		return g.validateHostCertificate(cert, hostname, caKey)
	}
}

func (g *Gateway) validateHostCertificate(cert *ssh.Certificate, hostname string, caKey ssh.PublicKey) error {
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
			return bytes.Equal(auth.Marshal(), caKey.Marshal())
		},
	}

	if err := checker.CheckCert(hostname, cert); err != nil {
		return fmt.Errorf("host certificate check failed: %v", err)
	}

	return nil
}

func (g *Gateway) handleIncomingChannel(newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Info().Msgf("Failed to accept channel: %v", err)
		return
	}
	defer channel.Close()

	go ssh.DiscardRequests(requests)

	// Create mTLS server configuration
	tlsConfig := g.tlsConfig
	if tlsConfig == nil {
		log.Info().Msgf("TLS config not initialized, cannot create mTLS server")
		return
	}

	// Create a virtual connection that pipes data between SSH channel and TLS
	virtualConn := &virtualConnection{
		channel: channel,
	}

	// Wrap the virtual connection with TLS
	tlsConn := tls.Server(virtualConn, tlsConfig)

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		log.Info().Msgf("TLS handshake failed: %v", err)
		return
	}

	// Create reader for the TLS connection
	reader := bufio.NewReader(tlsConn)

	// Get the forward mode here
	forwardConfig, err := g.parseForwardConfig(tlsConn, reader)
	if err != nil {
		log.Info().Msgf("Failed to parse forward command: %v", err)
		return
	}

	log.Info().Msgf("Forward config: %+v", forwardConfig)

	if forwardConfig.Mode == ForwardModeHTTP {
		handleHTTPProxy(g.ctx, tlsConn, reader, forwardConfig)
		return
	} else if forwardConfig.Mode == ForwardModeTCP {
		handleTCPProxy(g.ctx, tlsConn, forwardConfig)
		return
	} else if forwardConfig.Mode == ForwardModePing {
		handlePing(g.ctx, tlsConn, reader)
		return
	}
}

func (g *Gateway) parseForwardConfig(tlsConn *tls.Conn, reader *bufio.Reader) (*ForwardConfig, error) {
	config := &ForwardConfig{}

	if err := g.parseDetailsFromCertificate(tlsConn, config); err != nil {
		return nil, fmt.Errorf("failed to parse routing info from certificate: %v", err)
	}

	for {
		msg, err := reader.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read command: %v", err)
		}

		cmd := strings.ToUpper(strings.TrimSpace(string(strings.Split(string(msg), " ")[0])))
		args := strings.TrimSpace(strings.TrimPrefix(string(msg), strings.Split(string(msg), " ")[0]))

		switch cmd {
		case "FORWARD-TCP":
			config.Mode = ForwardModeTCP
			return config, nil

		case "FORWARD-HTTP":
			config.Mode = ForwardModeHTTP
			if args != "" {
				if err := g.parseForwardHTTPParams(args, config); err != nil {
					return nil, fmt.Errorf("failed to parse HTTP parameters: %v", err)
				}
			}

			return config, nil

		case "PING":
			config.Mode = ForwardModePing
			return config, nil

		default:
			return nil, fmt.Errorf("invalid forward command: %s", cmd)
		}
	}
}

func (g *Gateway) parseForwardHTTPParams(params string, config *ForwardConfig) error {
	parts := strings.Fields(params)

	for _, part := range parts {
		if strings.HasPrefix(part, "ca=") {
			caB64 := strings.TrimPrefix(part, "ca=")
			caCert, err := base64.StdEncoding.DecodeString(caB64)
			if err != nil {
				return fmt.Errorf("invalid base64 CA certificate: %v", err)
			}
			config.CACertificate = caCert
		} else if strings.HasPrefix(part, "verify=") {
			verifyStr := strings.TrimPrefix(part, "verify=")
			verify, err := strconv.ParseBool(verifyStr)
			if err != nil {
				return fmt.Errorf("invalid verify parameter: %s", verifyStr)
			}
			config.VerifyTLS = verify
		}
	}

	return nil
}

func (g *Gateway) parseDetailsFromCertificate(tlsConn *tls.Conn, config *ForwardConfig) error {
	// Get the peer certificates
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificates found")
	}

	clientCert := state.PeerCertificates[0]

	for _, ext := range clientCert.Extensions {
		// Extract target host and port from client certificate custom extension
		if ext.Id.String() == GATEWAY_ROUTING_INFO_OID {
			var routingInfo RoutingInfo
			if err := json.Unmarshal(ext.Value, &routingInfo); err != nil {
				return fmt.Errorf("failed to parse routing info JSON: %v", err)
			}

			config.TargetHost = routingInfo.TargetHost
			config.TargetPort = routingInfo.TargetPort
		}
		// Extract actor type from client certificate custom extension
		if ext.Id.String() == GATEWAY_ACTOR_OID {
			var actorDetails ActorDetails
			if err := json.Unmarshal(ext.Value, &actorDetails); err != nil {
				return fmt.Errorf("failed to parse actor details JSON: %v", err)
			}
			config.ActorType = ActorType(actorDetails.Type)
		}
	}

	return nil
}

// virtualConnection implements net.Conn to bridge SSH channel and TLS
type virtualConnection struct {
	channel ssh.Channel
}

func (vc *virtualConnection) Read(b []byte) (n int, err error) {
	return vc.channel.Read(b)
}

func (vc *virtualConnection) Write(b []byte) (n int, err error) {
	return vc.channel.Write(b)
}

func (vc *virtualConnection) Close() error {
	return vc.channel.Close()
}

func (vc *virtualConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (vc *virtualConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (vc *virtualConnection) SetDeadline(t time.Time) error {
	return nil
}

func (vc *virtualConnection) SetReadDeadline(t time.Time) error {
	return nil
}

func (vc *virtualConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

// startCertificateRenewal runs a background process to renew certificates every 10 days
func (g *Gateway) startCertificateRenewal(ctx context.Context) {
	log.Info().Msg("Starting gateway certificate renewal goroutine")
	ticker := time.NewTicker(10 * 24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Gateway certificate renewal goroutine stopping...")
			return
		case <-ticker.C:
			log.Info().Msg("Renewing gateway certificates...")
			if err := g.renewCertificates(); err != nil {
				log.Error().Msgf("Failed to renew gateway certificates: %v", err)
			} else {
				log.Info().Msg("Gateway certificates renewed successfully")
			}
		}
	}
}

// renewCertificates fetches new certificates and updates the gateway configurations
func (g *Gateway) renewCertificates() error {
	// Re-register gateway to get fresh certificates
	if err := g.registerGateway(); err != nil {
		return fmt.Errorf("failed to register gateway: %v", err)
	}

	return nil
}
