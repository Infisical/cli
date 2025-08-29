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
	"log"
	"net"

	"strconv"
	"strings"
	"sync"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
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
	// Register proxy and get certificates from API
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

	// Start SSH server
	go p.startSSHServer()

	// Start TLS server
	go p.startTLSServer()

	log.Printf("Proxy server started successfully")

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

	log.Printf("Successfully registered proxy and received certificates from API")
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
				log.Printf("Gateway '%s' tried to authenticate with raw public key (rejected)", conn.User())
				return nil, fmt.Errorf("certificates required, raw public keys not allowed")
			}

			// Validate the certificate
			if err := p.validateSSHCertificate(cert, conn.User(), sshCAPubKey); err != nil {
				log.Printf("Gateway '%s' certificate validation failed: %v", conn.User(), err)
				return nil, err
			}

			gatewayId := ""
			if len(cert.ValidPrincipals) > 0 {
				gatewayId = cert.ValidPrincipals[0]
			}

			if gatewayId == "" {
				return nil, fmt.Errorf("gateway id is required")
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

	// Parse all certificates from the chain (intermediate + root CAs)
	var chainCerts [][]byte
	chainData := []byte(p.certificates.PKI.ServerCertificateChain)
	for {
		block, rest := pem.Decode(chainData)
		if block == nil {
			break
		}
		chainCerts = append(chainCerts, block.Bytes)
		chainData = rest
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

	// Parse client CA certificate
	clientCABlock, _ := pem.Decode([]byte(p.certificates.PKI.ClientCA))
	if clientCABlock == nil {
		return fmt.Errorf("failed to decode client CA certificate")
	}

	clientCA, err := x509.ParseCertificate(clientCABlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse client CA certificate: %v", err)
	}

	// Create certificate pool for client CAs
	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(clientCA)

	// Create certificate chain: server cert + chain certs (intermediate + root)
	certChain := [][]byte{serverCertBlock.Bytes}
	certChain = append(certChain, chainCerts...)

	// Create TLS config
	p.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: certChain,
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

	// Check if certificate is signed by our CA
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caPubKey.Marshal())
		},
	}

	// Validate the certificate
	if err := checker.CheckCert(username, cert); err != nil {
		return fmt.Errorf("certificate check failed: %v", err)
	}

	log.Printf("SSH certificate valid for user '%s', principals: %v", username, cert.ValidPrincipals)
	return nil
}

func (p *Proxy) startSSHServer() {
	listener, err := net.Listen("tcp", ":"+p.config.SSHPort)
	if err != nil {
		log.Fatalf("Failed to start SSH server: %v", err)
	}
	p.sshListener = listener

	log.Printf("SSH server listening on :%s for gateways", p.config.SSHPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept SSH connection: %v", err)
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
		log.Printf("SSH handshake failed: %v", err)
		return
	}

	gatewayId := sshConn.Permissions.Extensions["gateway-id"]
	log.Printf("SSH handshake successful for gateway: %s", gatewayId)

	// Store the connection
	p.mu.Lock()
	p.tunnels[gatewayId] = sshConn
	p.mu.Unlock()

	// Clean up when agent disconnects
	defer func() {
		p.mu.Lock()
		delete(p.tunnels, gatewayId)
		p.mu.Unlock()
		log.Printf("Gateway %s disconnected", gatewayId)
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
	listener, err := tls.Listen("tcp", ":"+p.config.TLSPort, p.tlsConfig)
	if err != nil {
		log.Fatalf("Failed to start TLS server: %v", err)
	}
	p.tlsListener = listener

	log.Printf("TLS server listening on :%s for clients", p.config.TLSPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept TLS connection: %v", err)
			continue
		}
		go p.handleClient(conn)
	}
}

func (p *Proxy) handleClient(clientConn net.Conn) {
	defer clientConn.Close()

	// Log client certificate info if this is a TLS connection
	if tlsConn, ok := clientConn.(*tls.Conn); ok {
		if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
			cert := tlsConn.ConnectionState().PeerCertificates[0]
			log.Printf("Client connected with certificate: %s", cert.Subject.CommonName)
		}
	}

	// Read the first few bytes to determine which agent to connect to
	// Format: "agent1:host:port\n" or "agent1:host:port" followed by data
	buffer := make([]byte, 1024)
	n, err := clientConn.Read(buffer)
	if err != nil {
		log.Printf("Failed to read from client: %v", err)
		return
	}

	// Find the first newline to separate agent info from data
	data := buffer[:n]
	log.Printf("Received %d bytes from client: %q", n, string(data))
	newlineIndex := bytes.IndexByte(data, '\n')

	var gatewayId, targetHost string
	var targetPort uint32
	var remainingData []byte

	if newlineIndex != -1 {
		// Agent info is everything before the newline
		agentInfo := string(data[:newlineIndex])
		remainingData = data[newlineIndex+1:]

		// Parse agent info in format "agent:host:port"
		parts := strings.Split(agentInfo, ":")
		if len(parts) != 3 {
			log.Printf("Invalid client data format, expected 'agent:host:port', got: %s", agentInfo)
			clientConn.Write([]byte("ERROR: Invalid format. Expected 'agent:host:port'\n"))
			return
		}

		gatewayId = parts[0]
		targetHost = parts[1]
		portStr := parts[2]

		// Parse port number
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			log.Printf("Invalid port number: %s", portStr)
			clientConn.Write([]byte("ERROR: Invalid port number\n"))
			return
		}
		targetPort = uint32(port)

		log.Printf("Extracted gateway: %s, target: %s:%d", gatewayId, targetHost, targetPort)
	} else {
		log.Printf("Invalid client data format - no newline found")
		clientConn.Write([]byte("ERROR: Please use format 'gatewayId:host:port'\n"))
		return
	}

	// Get the SSH connection for this agent
	p.mu.RLock()
	conn, exists := p.tunnels[gatewayId]
	p.mu.RUnlock()

	if !exists {
		log.Printf("Gateway '%s' not connected", gatewayId)
		clientConn.Write([]byte("ERROR: Gateway not connected\n"))
		return
	}

	log.Printf("Routing TCP connection to gateway: %s", gatewayId)

	// Open SSH channel to connect to agent's local service through the tunnel
	payload := struct {
		Host string
		Port uint32
		_    string
		_    uint32
	}{targetHost, targetPort, "", 0}

	channel, _, err := conn.OpenChannel("direct-tcpip", ssh.Marshal(&payload))
	if err != nil {
		log.Printf("Failed to connect to agent: %v", err)
		clientConn.Write([]byte("ERROR: Failed to connect to agent\n"))
		return
	}
	defer channel.Close()

	// If we have remaining data from the initial read, write it to the channel
	if len(remainingData) > 0 {
		channel.Write(remainingData)
	}

	// Bidirectional forwarding
	go func() {
		io.Copy(channel, clientConn)
		channel.CloseWrite()
	}()

	io.Copy(clientConn, channel)
	log.Printf("Client %s disconnected", clientConn.RemoteAddr())
}

func (p *Proxy) cleanup() {
	log.Printf("Shutting down proxy server...")

	if p.sshListener != nil {
		p.sshListener.Close()
	}
	if p.tlsListener != nil {
		p.tlsListener.Close()
	}

	log.Printf("Proxy server shutdown complete")
}
