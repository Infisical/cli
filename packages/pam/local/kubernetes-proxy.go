package pam

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"k8s.io/client-go/tools/clientcmd"
	k8sapi "k8s.io/client-go/tools/clientcmd/api"
)

type KubernetesProxyServer struct {
	BaseProxyServer // Embed common functionality
	server          net.Listener
	port            int
}

func StartKubernetesLocalProxy(accessToken string, accountPath string, durationStr string, port int) {
	log.Info().Str("accountPath", accountPath).Str("duration", durationStr).Msg("Starting kubernetes proxy")

	httpClient := resty.New()
	httpClient.SetAuthToken(accessToken)
	httpClient.SetHeader("User-Agent", "infisical-cli")

	pamRequest := api.PAMAccessRequest{
		Duration:    durationStr,
		AccountPath: accountPath,
		// TODO: pass in the desired resource type, and reject the req in backend if this is not the expected type
	}

	pamResponse, err := api.CallPAMAccess(httpClient, pamRequest)
	if err != nil {
		util.HandleError(err, "Failed to access PAM account")
		return
	}

	if pamResponse.ResourceType != "kubernetes" {
		util.HandleError(err, "Invalid PAM response type, expected kubernetes but got %s", pamResponse.ResourceType)
		return
	}

	log.Info().Msgf("Kubernetes session created with ID: %s", pamResponse.SessionId)

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &KubernetesProxyServer{
		BaseProxyServer: BaseProxyServer{
			httpClient:             httpClient,
			relayHost:              pamResponse.RelayHost,
			relayClientCert:        pamResponse.RelayClientCertificate,
			relayClientKey:         pamResponse.RelayClientPrivateKey,
			relayServerCertChain:   pamResponse.RelayServerCertificateChain,
			gatewayClientCert:      pamResponse.GatewayClientCertificate,
			gatewayClientKey:       pamResponse.GatewayClientPrivateKey,
			gatewayServerCertChain: pamResponse.GatewayServerCertificateChain,
			sessionExpiry:          time.Now().Add(duration),
			sessionId:              pamResponse.SessionId,
			ctx:                    ctx,
			cancel:                 cancel,
			shutdownCh:             make(chan struct{}),
		},
	}

	err = proxy.Start(port)
	if err != nil {
		util.HandleError(err, "Failed to start proxy server")
		return
	}

	if port == 0 {
		fmt.Printf("Kubernetes proxy started for account %s with duration %s on port %d (auto-assigned)\n", accountID, duration.String(), proxy.port)
	} else {
		fmt.Printf("Kubernetes proxy started for account %s with duration %s on port %d\n", accountID, duration.String(), proxy.port)
	}

	accountName, ok := pamResponse.Metadata["accountName"]
	if !ok {
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'accountName'"), "Failed to start proxy server")
		return
	}
	accountPath, ok := pamResponse.Metadata["accountPath"]
	if !ok {
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'accountPath'"), "Failed to start proxy server")
		return
	}

	// TODO: we should let the user decide whether if they want to update kubeconfig or not
	configLoader := clientcmd.NewDefaultClientConfigLoadingRules()
	config, err := configLoader.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load kubernetes config")
		return
	}
	clusterName := fmt.Sprintf("infisical-k8s-pam%s%s", accountPath, accountName)
	config.Clusters[clusterName] = &k8sapi.Cluster{
		Server: fmt.Sprintf("http://localhost:%d", proxy.port),
	}
	config.AuthInfos[clusterName] = &k8sapi.AuthInfo{}
	config.Contexts[clusterName] = &k8sapi.Context{
		Cluster:  clusterName,
		AuthInfo: clusterName,
	}
	config.CurrentContext = clusterName
	kubeconfig := configLoader.GetDefaultFilename()
	if err = clientcmd.WriteToFile(*config, kubeconfig); err != nil {
		log.Fatal().Err(err).Str("kubeconfig", kubeconfig).Msg("Failed to write kubernetes config")
		return
	}
	log.Info().Str("kubeconfig", kubeconfig).Msg("Updated kubeconfig file")

	log.Info().Msgf("Kubernetes proxy server listening on port %d", proxy.port)
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("                  Kubernetes Proxy Session Started!                   \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("Accessing account %s at folder path %s\n", accountName, accountPath)
	fmt.Printf("\n")
	// TODO: write kubectl config

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal %v, initiating graceful shutdown...", sig)
		proxy.gracefulShutdown()
	}()

	proxy.Run()
}

func (p *KubernetesProxyServer) Start(port int) error {
	var err error
	if port == 0 {
		p.server, err = net.Listen("tcp", ":0")
	} else {
		p.server, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	}

	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	addr := p.server.Addr().(*net.TCPAddr)
	p.port = addr.Port

	return nil
}

func (p *KubernetesProxyServer) gracefulShutdown() {
	p.shutdownOnce.Do(func() {
		log.Info().Msg("Starting graceful shutdown of kubernetes proxy...")

		// Send session termination notification before cancelling context
		p.NotifySessionTermination()

		// Signal the accept loop to stop
		close(p.shutdownCh)

		// Close the server to stop accepting new connections
		if p.server != nil {
			p.server.Close()
		}

		// Cancel context to signal all goroutines to stop
		p.cancel()

		// Wait for connections to close
		p.WaitForConnectionsWithTimeout(10 * time.Second)

		log.Info().Msg("Kubernetes proxy shutdown complete")
		os.Exit(0)
	})
}

func (p *KubernetesProxyServer) Run() {
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
			// Check if session has expired
			if time.Now().After(p.sessionExpiry) {
				log.Warn().Msg("Kubernetes session expired, shutting down proxy")
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

			// Track active connection
			p.activeConnections.Add(1)
			go p.handleConnection(conn)
		}
	}
}

func (p *KubernetesProxyServer) handleConnection(clientConn net.Conn) {
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

	log.Info().Msg("Established connection to kubernetes resource")

	connCtx, connCancel := context.WithCancel(p.ctx)
	defer connCancel()

	errCh := make(chan error, 2)

	// Bidirectional data forwarding with context cancellation
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
		errCh <- err
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
		errCh <- err
	}()

	select {
	case <-errCh:
	case <-connCtx.Done():
		log.Info().Msg("Connection cancelled by context")
	}

	log.Info().Msgf("Connection closed for client: %s", clientConn.RemoteAddr().String())
}
