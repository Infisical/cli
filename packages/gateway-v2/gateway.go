package gatewayv2

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"golang.org/x/crypto/ssh"
)

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
	tlsCACert []byte
	tlsCAKey  *rsa.PrivateKey

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

// Change the Start method to accept a context
func (g *Gateway) Start(ctx context.Context) error {
	log.Printf("Starting gateway")
	for {
		select {
		case <-ctx.Done():
			log.Printf("Gateway stopped by context cancellation")
			return nil
		default:
			if err := g.connectAndServe(); err != nil {
				log.Printf("Connection failed: %v, retrying in %v...", err, g.config.ReconnectDelay)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(g.config.ReconnectDelay):
					continue
				}
			}
			// If we get here, the connection was closed gracefully
			log.Printf("Connection closed, reconnecting in 10 seconds...")
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
	log.Printf("Connecting to SSH server on %s:%d...", g.certificates.ProxyIP, g.config.SSHPort)
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", g.certificates.ProxyIP, g.config.SSHPort), sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %v", err)
	}

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

	log.Printf("SSH connection established for gateway")

	// Handle incoming channels from the server
	channels := client.HandleChannelOpen("direct-tcpip")
	if channels == nil {
		return fmt.Errorf("failed to handle channel open")
	}

	// Process incoming channels
	for newChannel := range channels {
		go g.handleIncomingChannel(newChannel)
	}

	return nil // Connection closed
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
	log.Printf("Successfully registered gateway and received certificates")
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

	// Create certificate signer
	certSigner, err := ssh.NewCertSigner(cert.(*ssh.Certificate), privateKey)
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
	// Parse CA public key once when creating the callback
	caKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(g.certificates.SSH.ServerCAPublicKey))
	if err != nil {
		// Return a callback that always fails since we can't parse the CA key
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

	log.Printf("Host certificate validated successfully for %s", hostname)
	return nil
}

func (g *Gateway) handleIncomingChannel(newChannel ssh.NewChannel) {
	var req struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}

	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		log.Printf("Failed to parse channel request: %v", err)
		newChannel.Reject(ssh.Prohibited, "invalid request")
		return
	}

	log.Printf("Incoming connection request to %s:%d from %s:%d",
		req.Host, req.Port, req.OriginHost, req.OriginPort)

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Failed to accept channel: %v", err)
		return
	}
	defer channel.Close()

	go ssh.DiscardRequests(requests)

	// Determine the target address
	target := fmt.Sprintf("%s:%d", req.Host, req.Port)
	log.Printf("Creating TCP tunnel to: %s", target)

	// Create mTLS server configuration
	tlsConfig, err := g.createMTLSConfig()
	if err != nil {
		log.Printf("Failed to create mTLS config: %v", err)
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
		log.Printf("TLS handshake failed: %v", err)
		return
	}

	log.Printf("mTLS connection established with client: %s", tlsConn.ConnectionState().ServerName)

	// Connect to local service
	localConn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("Failed to connect to local service %s: %v", target, err)
		return
	}
	defer localConn.Close()

	log.Printf("TCP tunnel established to %s", target)

	// Create bidirectional tunnel with TLS
	// Forward data from TLS connection to local service
	go func() {
		io.Copy(localConn, tlsConn)
		localConn.Close()
		log.Printf("TLS -> local service tunnel closed")
	}()

	// Forward data from local service to TLS connection
	io.Copy(tlsConn, localConn)
	log.Printf("Local service -> TLS tunnel closed")
}

func (g *Gateway) createMTLSConfig() (*tls.Config, error) {
	// Parse server certificate
	serverCertBlock, _ := pem.Decode([]byte(g.certificates.PKI.ServerCertificate))
	if serverCertBlock == nil {
		return nil, fmt.Errorf("failed to decode server certificate")
	}

	// Parse server private key
	serverKeyBlock, _ := pem.Decode([]byte(g.certificates.PKI.ServerPrivateKey))
	if serverKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode server private key")
	}

	serverKey, err := x509.ParsePKCS8PrivateKey(serverKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server private key: %v", err)
	}

	// Create certificate pool for client CAs
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
			log.Printf("Failed to parse client chain certificate %d: %v", i+1, err)
			continue
		}
		clientCAPool.AddCert(cert)
		log.Printf("Added client CA certificate %d to pool: %s", i+1, cert.Subject.CommonName)
	}

	// Create TLS config
	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCertBlock.Bytes},
				PrivateKey:  serverKey,
			},
		},
		ClientCAs:  clientCAPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}, nil
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
