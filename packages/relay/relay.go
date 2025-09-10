package relay

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

type RelayConfig struct {
	// API Configuration
	Token     string
	RelayName string

	Type string

	// Server Ports
	SSHPort string
	TLSPort string

	// Network Configuration
	Host string
}

type Relay struct {
	httpClient *resty.Client
	config     *RelayConfig

	// Certificate storage
	certificates *api.RegisterRelayResponse

	// SSH server components
	sshConfig *ssh.ServerConfig
	sshCA     ssh.Signer

	// TLS server components
	tlsConfig *tls.Config
	tlsCACert []byte
	tlsCAKey  *rsa.PrivateKey

	// Tunnel storage (Gateway ID -> SSH connection)
	tunnels map[string]*ssh.ServerConn
	mu      sync.RWMutex

	// Server listeners
	sshListener net.Listener
	tlsListener net.Listener
}

func NewRelay(config *RelayConfig) (*Relay, error) {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return nil, fmt.Errorf("unable to get client with custom headers [err=%v]", err)
	}

	httpClient.SetAuthToken(config.Token)

	return &Relay{
		httpClient: httpClient,
		config:     config,
		tunnels:    make(map[string]*ssh.ServerConn),
	}, nil
}

func (r *Relay) SetToken(token string) {
	r.httpClient.SetAuthToken(token)
}

func (r *Relay) Start(ctx context.Context) error {
	if err := r.registerRelay(); err != nil {
		return fmt.Errorf("failed to register relay: %v", err)
	}

	// Setup SSH server
	if err := r.setupSSHServer(); err != nil {
		return fmt.Errorf("failed to setup SSH server: %v", err)
	}

	// Setup TLS server
	if err := r.setupTLSServer(); err != nil {
		return fmt.Errorf("failed to setup TLS server: %v", err)
	}

	// Start certificate renewal goroutine
	go r.startCertificateRenewal(ctx)

	// Start SSH server
	go r.startSSHServer()

	// Start TLS server
	go r.startTLSServer()

	log.Info().Msg("Relay server started successfully")

	// Wait for context cancellation
	<-ctx.Done()

	// Cleanup
	r.cleanup()
	return nil
}

func (r *Relay) registerRelay() error {
	body := api.RegisterRelayRequest{
		Host: r.config.Host,
		Name: r.config.RelayName,
	}

	if r.config.Type == "instance" {
		certResp, err := api.CallRegisterInstanceRelay(r.httpClient, body)
		if err != nil {
			return fmt.Errorf("failed to register instance relay: %v", err)
		}
		r.certificates = &certResp
	} else {
		certResp, err := api.CallRegisterRelay(r.httpClient, body)
		if err != nil {
			return fmt.Errorf("failed to register org relay: %v", err)
		}
		r.certificates = &certResp
	}

	log.Info().Msg("Successfully registered relay and received certificates from API")
	return nil
}

func (r *Relay) setupSSHServer() error {
	// Parse SSH CA public key
	sshCAPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.certificates.SSH.ClientCAPublicKey))
	if err != nil {
		return fmt.Errorf("failed to parse SSH CA public key: %v", err)
	}

	// Parse SSH server private key
	sshServerKey, err := ssh.ParsePrivateKey([]byte(r.certificates.SSH.ServerPrivateKey))
	if err != nil {
		return fmt.Errorf("failed to parse SSH server private key: %v", err)
	}

	// Parse SSH server certificate
	sshServerCert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.certificates.SSH.ServerCertificate))
	if err != nil {
		return fmt.Errorf("failed to parse SSH server certificate: %v", err)
	}

	// Create certificate signer
	certSigner, err := ssh.NewCertSigner(sshServerCert.(*ssh.Certificate), sshServerKey)
	if err != nil {
		return fmt.Errorf("failed to create SSH certificate signer: %v", err)
	}

	// Setup SSH server config
	r.sshConfig = &ssh.ServerConfig{
		MaxAuthTries: 3,
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Check if this is an SSH certificate
			cert, ok := key.(*ssh.Certificate)
			if !ok {
				log.Warn().Msgf("Gateway '%s' tried to authenticate with raw public key (rejected)", conn.User())
				return nil, fmt.Errorf("certificates required, raw public keys not allowed")
			}

			// Validate the certificate
			if err := r.validateSSHCertificate(cert, conn.User(), sshCAPubKey); err != nil {
				log.Error().Msgf("Gateway '%s' certificate validation failed: %v", conn.User(), err)
				return nil, err
			}

			gatewayId := ""
			if len(cert.ValidPrincipals) > 0 {
				gatewayId = cert.ValidPrincipals[0]
			}

			if gatewayId == "" {
				return nil, fmt.Errorf("gateway id is required")
			}

			// Validate that the user is authorized to connect to the current relay
			expectedKeyId := "client-" + r.config.RelayName
			if cert.KeyId != expectedKeyId {
				log.Error().Msgf("Gateway '%s' certificate Key ID '%s' does not match expected '%s'", conn.User(), cert.KeyId, expectedKeyId)
				return nil, fmt.Errorf("certificate Key ID does not match expected value")
			}

			return &ssh.Permissions{
				Extensions: map[string]string{
					"gateway-id": gatewayId,
				},
			}, nil
		},
	}

	r.sshConfig.AddHostKey(certSigner)
	return nil
}

func (r *Relay) setupTLSServer() error {
	// Parse TLS server certificate
	serverCertBlock, _ := pem.Decode([]byte(r.certificates.PKI.ServerCertificate))
	if serverCertBlock == nil {
		return fmt.Errorf("failed to decode server certificate")
	}

	// Note: serverCert is parsed for validation but not used in the TLS config
	// since we use the raw bytes directly
	_, err := x509.ParseCertificate(serverCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %v", err)
	}

	// Parse TLS server private key
	serverKeyBlock, _ := pem.Decode([]byte(r.certificates.PKI.ServerPrivateKey))
	if serverKeyBlock == nil {
		return fmt.Errorf("failed to decode server private key")
	}

	serverKey, err := x509.ParsePKCS8PrivateKey(serverKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse server private key: %v", err)
	}

	// Create certificate pool for client CAs
	clientCAPool := x509.NewCertPool()

	var chainCerts [][]byte
	chainData := []byte(r.certificates.PKI.ClientCertificateChain)
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
			log.Error().Msgf("Failed to parse client chain certificate %d: %v", i+1, err)
			continue
		}
		clientCAPool.AddCert(cert)
	}

	// Create TLS config
	r.tlsConfig = &tls.Config{
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

func (r *Relay) validateSSHCertificate(cert *ssh.Certificate, username string, caPubKey ssh.PublicKey) error {
	// Check certificate type
	if cert.CertType != ssh.UserCert {
		return fmt.Errorf("invalid certificate type: %d", cert.CertType)
	}

	// Check if certificate is signed by expected CA
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caPubKey.Marshal())
		},
	}

	// Validate the certificate
	if err := checker.CheckCert(username, cert); err != nil {
		return fmt.Errorf("certificate check failed: %v", err)
	}

	log.Debug().Msgf("SSH certificate valid for user '%s', principals: %v", username, cert.ValidPrincipals)
	return nil
}

func (r *Relay) startSSHServer() {
	listener, err := net.Listen("tcp", ":"+r.config.SSHPort)
	if err != nil {
		log.Fatal().Msgf("Failed to start SSH server: %v", err)
	}
	r.sshListener = listener

	log.Info().Msgf("SSH server listening on :%s for gateways", r.config.SSHPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Error().Msgf("Failed to accept SSH connection: %v", err)
			continue
		}
		go r.handleSSHAgent(conn)
	}
}

func (r *Relay) handleSSHAgent(conn net.Conn) {
	defer conn.Close()

	// SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, r.sshConfig)
	if err != nil {
		log.Error().Msgf("SSH handshake failed: %v", err)
		return
	}

	gatewayId := sshConn.Permissions.Extensions["gateway-id"]
	log.Info().Msgf("SSH handshake successful for gateway: %s", gatewayId)

	// Store the connection (ensure only one connection per gateway)
	r.mu.Lock()
	if _, exists := r.tunnels[gatewayId]; exists {
		r.mu.Unlock()
		log.Warn().Msgf("Gateway '%s' already has an active connection, rejecting new connection", gatewayId)
		sshConn.Close()
		return
	}

	r.tunnels[gatewayId] = sshConn
	r.mu.Unlock()

	// Clean up when agent disconnects
	defer func() {
		r.mu.Lock()
		delete(r.tunnels, gatewayId)
		r.mu.Unlock()
		log.Info().Msgf("Gateway %s disconnected", gatewayId)
	}()

	// Handle global requests (reject all for security)
	go func() {
		for req := range reqs {
			log.Debug().Msgf("Rejecting global request: %s from gateway %s", req.Type, gatewayId)
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()

	// Handle channel requests
	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			log.Debug().Msgf("Rejecting session channel from gateway %s", gatewayId)
			newChannel.Reject(ssh.Prohibited, "no shell access")
		case "x11":
			log.Debug().Msgf("Rejecting X11 forwarding from gateway %s", gatewayId)
			newChannel.Reject(ssh.Prohibited, "no X11 forwarding")
		case "auth-agent":
			log.Debug().Msgf("Rejecting auth-agent forwarding from gateway %s", gatewayId)
			newChannel.Reject(ssh.Prohibited, "no agent forwarding")
		case "forwarded-tcpip":
			log.Debug().Msgf("Rejecting forwarded-tcpip from gateway %s", gatewayId)
			newChannel.Reject(ssh.Prohibited, "no port forwarding")
		default:
			log.Warn().Msgf("Rejecting unknown channel type '%s' from gateway %s", newChannel.ChannelType(), gatewayId)
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func (r *Relay) startTLSServer() {
	listener, err := net.Listen("tcp", ":"+r.config.TLSPort)
	if err != nil {
		log.Fatal().Msgf("Failed to start TLS server: %v", err)
	}
	r.tlsListener = listener

	log.Info().Msgf("TLS server listening on :%s for clients", r.config.TLSPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Error().Msgf("Failed to accept TLS connection: %v", err)
			continue
		}
		go r.handleTLSClient(conn)
	}
}

func (r *Relay) handleTLSClient(conn net.Conn) {
	defer conn.Close()

	// Perform TLS handshake using current TLS config
	tlsConn := tls.Server(conn, r.tlsConfig)
	defer tlsConn.Close()

	// Set handshake timeout to avoid hanging on slow/malicious connections
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

	// Force TLS handshake
	err := tlsConn.Handshake()
	if err != nil {
		log.Debug().Msgf("TLS handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Clear deadline for actual data transfer
	tlsConn.SetDeadline(time.Time{})

	r.handleClient(tlsConn)
}

func (r *Relay) handleClient(tlsConn *tls.Conn) {
	var gatewayId string
	var orgDetails string
	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		log.Info().Msgf("Client connected with certificate: %s", cert.Subject.CommonName)
		gatewayId = cert.Subject.CommonName
		orgDetails = cert.Subject.Organization[0]
	} else {
		log.Warn().Msg("No peer certificates found")
		return
	}

	// Get the SSH connection for this gateway
	r.mu.RLock()
	conn, exists := r.tunnels[gatewayId]
	r.mu.RUnlock()

	if !exists {
		log.Warn().Msgf("Gateway '%s' not connected", gatewayId)
		tlsConn.Write([]byte("ERROR: Gateway not connected\n"))
		return
	}

	log.Info().Msgf("Routing connection from Organization %s to Gateway with ID: %s", orgDetails, gatewayId)

	channel, _, err := conn.OpenChannel("direct-tcpip", nil)
	if err != nil {
		log.Error().Msgf("Failed to connect to gateway: %v", err)
		tlsConn.Write([]byte("ERROR: Failed to connect to gateway\n"))
		return
	}
	defer channel.Close()

	// Bidirectional forwarding
	go func() {
		io.Copy(channel, tlsConn)
		channel.CloseWrite()
	}()

	io.Copy(tlsConn, channel)
	log.Info().Msgf("Client %s disconnected", tlsConn.RemoteAddr())
}

func (r *Relay) cleanup() {
	log.Info().Msg("Shutting down relay server...")

	if r.sshListener != nil {
		r.sshListener.Close()
	}
	if r.tlsListener != nil {
		r.tlsListener.Close()
	}

	log.Info().Msg("Relay server shutdown complete")
}

// startCertificateRenewal runs a background process to renew certificates every 6 hours
func (r *Relay) startCertificateRenewal(ctx context.Context) {
	ticker := time.NewTicker(6 * 60 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Certificate renewal goroutine stopping...")
			return
		case <-ticker.C:
			log.Info().Msg("Renewing certificates...")
			if err := r.renewCertificates(); err != nil {
				log.Error().Msgf("Failed to renew certificates: %v", err)
			} else {
				log.Info().Msg("Certificates renewed successfully")
			}
		}
	}
}

// renewCertificates fetches new certificates and updates the server configurations
func (r *Relay) renewCertificates() error {
	// Re-register relay to get fresh certificates
	if err := r.registerRelay(); err != nil {
		return fmt.Errorf("failed to register relay: %v", err)
	}

	// Update SSH server configuration
	if err := r.setupSSHServer(); err != nil {
		return fmt.Errorf("failed to setup SSH server: %v", err)
	}

	// Update TLS server configuration
	if err := r.setupTLSServer(); err != nil {
		return fmt.Errorf("failed to setup TLS server: %v", err)
	}

	return nil
}
