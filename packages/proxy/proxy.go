package proxy

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

type ProxyConfig struct {
	// API Configuration
	Token     string
	ProxyName string

	Type string

	// Server Ports
	SSHPort string
	TLSPort string

	// Network Configuration
	StaticIP string
}

type Proxy struct {
	httpClient *resty.Client
	config     *ProxyConfig

	// Certificate storage
	certificates *api.RegisterProxyResponse

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

func NewProxy(config *ProxyConfig) (*Proxy, error) {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return nil, fmt.Errorf("unable to get client with custom headers [err=%v]", err)
	}

	httpClient.SetAuthToken(config.Token)

	return &Proxy{
		httpClient: httpClient,
		config:     config,
		tunnels:    make(map[string]*ssh.ServerConn),
	}, nil
}

func (p *Proxy) SetToken(token string) {
	p.httpClient.SetAuthToken(token)
}

func (p *Proxy) Start(ctx context.Context) error {
	if err := p.registerProxy(); err != nil {
		return fmt.Errorf("failed to register proxy: %v", err)
	}

	// Setup SSH server
	if err := p.setupSSHServer(); err != nil {
		return fmt.Errorf("failed to setup SSH server: %v", err)
	}

	// Setup TLS server
	if err := p.setupTLSServer(); err != nil {
		return fmt.Errorf("failed to setup TLS server: %v", err)
	}

	// Start certificate renewal goroutine
	go p.startCertificateRenewal(ctx)

	// Start SSH server
	go p.startSSHServer()

	// Start TLS server
	go p.startTLSServer()

	log.Info().Msg("Proxy server started successfully")

	// Wait for context cancellation
	<-ctx.Done()

	// Cleanup
	p.cleanup()
	return nil
}

func (p *Proxy) registerProxy() error {
	body := api.RegisterProxyRequest{
		IP:   p.config.StaticIP,
		Name: p.config.ProxyName,
	}

	if p.config.Type == "instance" {
		certResp, err := api.CallRegisterInstanceProxy(p.httpClient, body)
		if err != nil {
			return fmt.Errorf("failed to register instance proxy: %v", err)
		}
		p.certificates = &certResp
	} else {
		certResp, err := api.CallRegisterProxy(p.httpClient, body)
		if err != nil {
			return fmt.Errorf("failed to register org proxy: %v", err)
		}
		p.certificates = &certResp
	}

	log.Info().Msg("Successfully registered proxy and received certificates from API")
	return nil
}

func (p *Proxy) setupSSHServer() error {
	// Parse SSH CA public key
	sshCAPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.certificates.SSH.ClientCAPublicKey))
	if err != nil {
		return fmt.Errorf("failed to parse SSH CA public key: %v", err)
	}

	// Parse SSH server private key
	sshServerKey, err := ssh.ParsePrivateKey([]byte(p.certificates.SSH.ServerPrivateKey))
	if err != nil {
		return fmt.Errorf("failed to parse SSH server private key: %v", err)
	}

	// Parse SSH server certificate
	sshServerCert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.certificates.SSH.ServerCertificate))
	if err != nil {
		return fmt.Errorf("failed to parse SSH server certificate: %v", err)
	}

	// Create certificate signer
	certSigner, err := ssh.NewCertSigner(sshServerCert.(*ssh.Certificate), sshServerKey)
	if err != nil {
		return fmt.Errorf("failed to create SSH certificate signer: %v", err)
	}

	// Setup SSH server config
	p.sshConfig = &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Check if this is an SSH certificate
			cert, ok := key.(*ssh.Certificate)
			if !ok {
				log.Warn().Msgf("Gateway '%s' tried to authenticate with raw public key (rejected)", conn.User())
				return nil, fmt.Errorf("certificates required, raw public keys not allowed")
			}

			// Validate the certificate
			if err := p.validateSSHCertificate(cert, conn.User(), sshCAPubKey); err != nil {
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

			// Validate that the user is authorized to connect to the current proxy
			expectedKeyId := "client-" + p.config.ProxyName
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

	p.sshConfig.AddHostKey(certSigner)
	return nil
}

func (p *Proxy) setupTLSServer() error {
	// Parse TLS server certificate
	serverCertBlock, _ := pem.Decode([]byte(p.certificates.PKI.ServerCertificate))
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
	serverKeyBlock, _ := pem.Decode([]byte(p.certificates.PKI.ServerPrivateKey))
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
	chainData := []byte(p.certificates.PKI.ClientCertificateChain)
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
	p.tlsConfig = &tls.Config{
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

func (p *Proxy) validateSSHCertificate(cert *ssh.Certificate, username string, caPubKey ssh.PublicKey) error {
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

func (p *Proxy) startSSHServer() {
	listener, err := net.Listen("tcp", ":"+p.config.SSHPort)
	if err != nil {
		log.Fatal().Msgf("Failed to start SSH server: %v", err)
	}
	p.sshListener = listener

	log.Info().Msgf("SSH server listening on :%s for gateways", p.config.SSHPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Error().Msgf("Failed to accept SSH connection: %v", err)
			continue
		}
		go p.handleSSHAgent(conn)
	}
}

func (p *Proxy) handleSSHAgent(conn net.Conn) {
	defer conn.Close()

	// SSH handshake
	sshConn, chans, _, err := ssh.NewServerConn(conn, p.sshConfig)
	if err != nil {
		log.Error().Msgf("SSH handshake failed: %v", err)
		return
	}

	gatewayId := sshConn.Permissions.Extensions["gateway-id"]
	log.Info().Msgf("SSH handshake successful for gateway: %s", gatewayId)

	// Store the connection
	p.mu.Lock()
	p.tunnels[gatewayId] = sshConn
	p.mu.Unlock()

	// Clean up when agent disconnects
	defer func() {
		p.mu.Lock()
		delete(p.tunnels, gatewayId)
		p.mu.Unlock()
		log.Info().Msgf("Gateway %s disconnected", gatewayId)
	}()

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			newChannel.Reject(ssh.Prohibited, "no shell access")
		case "x11":
			newChannel.Reject(ssh.Prohibited, "no X11 forwarding")
		case "auth-agent":
			newChannel.Reject(ssh.Prohibited, "no agent forwarding")
		}
	}
}

func (p *Proxy) startTLSServer() {
	listener, err := net.Listen("tcp", ":"+p.config.TLSPort)
	if err != nil {
		log.Fatal().Msgf("Failed to start TLS server: %v", err)
	}
	p.tlsListener = listener

	log.Info().Msgf("TLS server listening on :%s for clients", p.config.TLSPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Error().Msgf("Failed to accept TLS connection: %v", err)
			continue
		}
		go p.handleTLSClient(conn)
	}
}

func (p *Proxy) handleTLSClient(conn net.Conn) {
	defer conn.Close()

	// Perform TLS handshake using current TLS config
	tlsConn := tls.Server(conn, p.tlsConfig)
	defer tlsConn.Close()

	// Force TLS handshake
	err := tlsConn.Handshake()
	if err != nil {
		log.Error().Msgf("TLS handshake failed: %v", err)
		return
	}

	p.handleClient(tlsConn)
}

func (p *Proxy) handleClient(clientConn net.Conn) {
	defer clientConn.Close()

	var gatewayId string

	if tlsConn, ok := clientConn.(*tls.Conn); ok {
		log.Debug().Msg("TLS connection detected, forcing handshake...")
		err := tlsConn.Handshake()
		if err != nil {
			log.Error().Msgf("TLS handshake failed: %v", err)
			return
		}

		state := tlsConn.ConnectionState()

		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			log.Info().Msgf("Client connected with certificate: %s", cert.Subject.CommonName)
			gatewayId = cert.Subject.CommonName
		} else {
			log.Warn().Msg("No peer certificates found")
			return
		}
	} else {
		log.Error().Msgf("Not a TLS connection, connection type: %T", clientConn)
		return
	}

	// TODO: extract these from the certificate
	targetHost := "gateway"
	targetPort := uint32(22)

	// Get the SSH connection for this agent
	p.mu.RLock()
	conn, exists := p.tunnels[gatewayId]
	p.mu.RUnlock()

	if !exists {
		log.Warn().Msgf("Gateway '%s' not connected", gatewayId)
		clientConn.Write([]byte("ERROR: Gateway not connected\n"))
		return
	}

	log.Info().Msgf("Routing TCP connection to gateway: %s", gatewayId)

	// Open SSH channel to connect to agent's local service through the tunnel
	payload := struct {
		Host string
		Port uint32
		_    string
		_    uint32
	}{targetHost, targetPort, "", 0}

	channel, _, err := conn.OpenChannel("direct-tcpip", ssh.Marshal(&payload))
	if err != nil {
		log.Error().Msgf("Failed to connect to agent: %v", err)
		clientConn.Write([]byte("ERROR: Failed to connect to agent\n"))
		return
	}
	defer channel.Close()

	// Bidirectional forwarding
	go func() {
		io.Copy(channel, clientConn)
		channel.CloseWrite()
	}()

	io.Copy(clientConn, channel)
	log.Info().Msgf("Client %s disconnected", clientConn.RemoteAddr())
}

func (p *Proxy) cleanup() {
	log.Info().Msg("Shutting down proxy server...")

	if p.sshListener != nil {
		p.sshListener.Close()
	}
	if p.tlsListener != nil {
		p.tlsListener.Close()
	}

	log.Info().Msg("Proxy server shutdown complete")
}

// startCertificateRenewal runs a background process to renew certificates every 24 hours
func (p *Proxy) startCertificateRenewal(ctx context.Context) {
	log.Info().Msg("Starting certificate renewal goroutine")
	ticker := time.NewTicker(30 * time.Second) // TODO: update this to be every 10 days
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Certificate renewal goroutine stopping...")
			return
		case <-ticker.C:
			log.Info().Msg("Checking certificates for renewal...")
			if err := p.renewCertificates(); err != nil {
				log.Error().Msgf("Failed to renew certificates: %v", err)
			} else {
				log.Info().Msg("Certificates renewed successfully")
			}
		}
	}
}

// renewCertificates fetches new certificates and updates the server configurations
func (p *Proxy) renewCertificates() error {
	// Re-register proxy to get fresh certificates
	if err := p.registerProxy(); err != nil {
		return fmt.Errorf("failed to register proxy: %v", err)
	}

	// Update SSH server configuration
	if err := p.setupSSHServer(); err != nil {
		return fmt.Errorf("failed to setup SSH server: %v", err)
	}

	// Update TLS server configuration
	if err := p.setupTLSServer(); err != nil {
		return fmt.Errorf("failed to setup TLS server: %v", err)
	}

	return nil
}
