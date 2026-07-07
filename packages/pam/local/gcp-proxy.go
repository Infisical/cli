package pam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

type GCPProxyServer struct {
	BaseProxyServer
	server           net.Listener
	port             int
	gcloudConfigured bool
	tokenFilePath    string
	caFilePath       string
	caCertPEM        []byte
	caKeyPEM         []byte
}

func (p *GCPProxyServer) generateCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial: %w", err)
	}

	caExpiry := time.Until(p.sessionExpiry) + 5*time.Minute
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Infisical PAM GCP Proxy CA"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(caExpiry),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	p.caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal CA key: %w", err)
	}
	p.caKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return nil
}

func (p *GCPProxyServer) Start(port int) error {
	var err error
	if port == 0 {
		p.server, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		p.server, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	}

	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	addr := p.server.Addr().(*net.TCPAddr)
	p.port = addr.Port

	return nil
}

func (p *GCPProxyServer) SetupGcloudProxy() error {
	tokenFile, err := os.CreateTemp("", "infisical-gcp-token-*")
	if err != nil {
		return fmt.Errorf("failed to create token file: %w", err)
	}
	if _, err := tokenFile.WriteString("PROXY_MANAGED"); err != nil {
		tokenFile.Close()
		os.Remove(tokenFile.Name())
		return fmt.Errorf("failed to write token file: %w", err)
	}
	tokenFile.Close()
	p.tokenFilePath = tokenFile.Name()

	caFile, err := os.CreateTemp("", "infisical-gcp-ca-*")
	if err != nil {
		return fmt.Errorf("failed to create CA file: %w", err)
	}
	if _, err := caFile.Write(p.caCertPEM); err != nil {
		caFile.Close()
		os.Remove(caFile.Name())
		return fmt.Errorf("failed to write CA file: %w", err)
	}
	caFile.Close()
	p.caFilePath = caFile.Name()

	commands := [][]string{
		{"config", "set", "proxy/type", "http"},
		{"config", "set", "proxy/address", "localhost"},
		{"config", "set", "proxy/port", fmt.Sprintf("%d", p.port)},
		{"config", "set", "auth/access_token_file", p.tokenFilePath},
		{"config", "set", "core/custom_ca_certs_file", p.caFilePath},
	}
	for _, args := range commands {
		if err := exec.Command("gcloud", args...).Run(); err != nil {
			p.RevertGcloudProxy()
			return fmt.Errorf("failed to run gcloud %v: %w", args, err)
		}
	}
	p.gcloudConfigured = true
	log.Info().Int("port", p.port).Msg("Configured gcloud proxy settings")
	return nil
}

func (p *GCPProxyServer) RevertGcloudProxy() {
	if !p.gcloudConfigured {
		return
	}
	properties := []string{"proxy/type", "proxy/address", "proxy/port", "auth/access_token_file", "core/custom_ca_certs_file"}
	for _, prop := range properties {
		cmd := exec.Command("gcloud", "config", "unset", prop)
		if err := cmd.Run(); err != nil {
			log.Warn().Err(err).Str("property", prop).Msg("Failed to unset gcloud proxy property")
		}
	}
	if p.tokenFilePath != "" {
		os.Remove(p.tokenFilePath)
	}
	if p.caFilePath != "" {
		os.Remove(p.caFilePath)
	}
	p.gcloudConfigured = false
	log.Info().Msg("Reverted gcloud proxy settings")
}

func (p *GCPProxyServer) gracefulShutdown() {
	p.shutdownOnce.Do(func() {
		log.Info().Msg("Starting graceful shutdown of GCP proxy...")

		p.RevertGcloudProxy()
		p.NotifySessionTermination()

		close(p.shutdownCh)

		if p.server != nil {
			p.server.Close()
		}

		p.cancel()

		p.WaitForConnectionsWithTimeout(10 * time.Second)

		log.Info().Msg("GCP proxy shutdown complete")
		os.Exit(0)
	})
}

func (p *GCPProxyServer) Run() {
	defer p.server.Close()

	for {
		select {
		case <-p.ctx.Done():
			log.Info().Msg("Context cancelled, stopping proxy server")
			return
		case <-p.shutdownCh:
			log.Info().Msg("Shutdown signal received, stopping proxy server")
			return
		default:
			if time.Now().After(p.sessionExpiry) {
				log.Warn().Msg("GCP session expired, shutting down proxy")
				p.gracefulShutdown()
				return
			}

			if tcpListener, ok := p.server.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
			}

			conn, err := p.server.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				select {
				case <-p.ctx.Done():
					return
				case <-p.shutdownCh:
					return
				default:
					log.Error().Err(err).Msg("Failed to accept connection")
					continue
				}
			}

			p.activeConnections.Add(1)
			go p.handleConnection(conn)
		}
	}
}

func writeLengthPrefixed(conn net.Conn, data []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func (p *GCPProxyServer) handleConnection(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		p.activeConnections.Done()
	}()

	log.Info().Msgf("New connection from %s", clientConn.RemoteAddr())

	select {
	case <-p.ctx.Done():
		log.Info().Msg("Context cancelled, closing connection immediately")
		return
	default:
	}

	relayConn, err := p.CreateRelayConnection()
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to relay")
		return
	}
	defer relayConn.Close()

	gatewayConn, err := p.CreateGatewayConnection(relayConn, ALPNInfisicalPAMProxy)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to gateway")
		return
	}
	defer gatewayConn.Close()

	if err := writeLengthPrefixed(gatewayConn, p.caCertPEM); err != nil {
		log.Error().Err(err).Msg("Failed to send CA cert to gateway")
		return
	}
	if err := writeLengthPrefixed(gatewayConn, p.caKeyPEM); err != nil {
		log.Error().Err(err).Msg("Failed to send CA key to gateway")
		return
	}

	log.Info().Msg("Established connection to GCP Service Account resource")

	connCtx, connCancel := context.WithCancel(p.ctx)
	defer connCancel()

	done := make(chan struct{}, 2)

	go func() {
		defer connCancel()
		_, err := io.Copy(clientConn, gatewayConn)
		if err != nil {
			select {
			case <-connCtx.Done():
			default:
				log.Debug().Err(err).Msg("Gateway to client copy ended")
			}
		}
		done <- struct{}{}
	}()

	go func() {
		defer connCancel()
		_, err := io.Copy(gatewayConn, clientConn)
		if err != nil {
			select {
			case <-connCtx.Done():
			default:
				log.Debug().Err(err).Msg("Client to gateway copy ended")
			}
		}
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-connCtx.Done():
		log.Info().Msg("Connection cancelled by context")
	}

	log.Info().Msgf("Connection closed for client: %s", clientConn.RemoteAddr().String())
}

func startGCPProxy(httpClient *resty.Client, response *api.PAMAccessResponse, path, durationStr string, port int) {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &GCPProxyServer{
		BaseProxyServer: BaseProxyServer{
			httpClient:             httpClient,
			relayHost:              response.RelayHost,
			relayClientCert:        response.RelayClientCertificate,
			relayClientKey:         response.RelayClientPrivateKey,
			relayServerCertChain:   response.RelayServerCertificateChain,
			gatewayClientCert:      response.GatewayClientCertificate,
			gatewayClientKey:       response.GatewayClientPrivateKey,
			gatewayServerCertChain: response.GatewayServerCertificateChain,
			sessionExpiry:          time.Now().Add(duration),
			sessionId:              response.SessionId,
			resourceType:           response.AccountType,
			ctx:                    ctx,
			cancel:                 cancel,
			shutdownCh:             make(chan struct{}),
		},
	}

	if err := proxy.ValidateResourceTypeSupported(); err != nil {
		util.HandleError(err, "Gateway version outdated")
		return
	}

	if err := proxy.generateCA(); err != nil {
		util.HandleError(err, "Failed to generate CA for proxy")
		return
	}

	err = proxy.Start(port)
	if err != nil {
		util.HandleError(err, "Failed to start proxy server")
		return
	}

	if err := proxy.SetupGcloudProxy(); err != nil {
		log.Warn().Err(err).Msg("Failed to configure gcloud proxy settings automatically. You can set them manually.")
	}
	defer proxy.RevertGcloudProxy()

	folder, account := parsePath(path)
	serviceAccountEmail := response.Metadata["serviceAccountEmail"]

	log.Info().Msgf("GCP Service Account proxy server listening on port %d", proxy.port)
	printGCPSessionInfo(folder, account, duration, serviceAccountEmail, proxy.port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal %v, initiating graceful shutdown...", sig)
		go func() {
			<-sigChan
			log.Warn().Msg("Forced exit")
			os.Exit(1)
		}()
		proxy.gracefulShutdown()
	}()

	proxy.Run()
}

func printGCPSessionInfo(folder, account string, duration time.Duration, serviceAccountEmail string, port int) {
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("              GCP Service Account Proxy Session Started!                          \n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
	if folder != "" {
		fmt.Printf("  Folder:           %s\n", folder)
	}
	fmt.Printf("  Account:          %s\n", account)
	fmt.Printf("  Service Account:  %s\n", serviceAccountEmail)
	fmt.Printf("  Duration:         %s\n", duration.String())
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                           How to Connect                             \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	fmt.Printf("  Your gcloud CLI has been configured to use this proxy.\n")
	fmt.Printf("  You can now use gcloud commands as usual:\n")
	fmt.Printf("\n")
	fmt.Printf("  Examples:\n")
	util.PrintfStderr("    $ gcloud compute instances list\n")
	util.PrintfStderr("    $ gcloud storage ls\n")
	fmt.Printf("\n")
	fmt.Printf("  Press Ctrl+C to stop the proxy.\n")
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
}
