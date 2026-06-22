package pam

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"k8s.io/client-go/tools/clientcmd"
	k8sapi "k8s.io/client-go/tools/clientcmd/api"
)

type KubernetesProxyServer struct {
	BaseProxyServer           // Embed common functionality
	server                    net.Listener
	port                      int
	kubeConfigPath            string
	kubeConfigClusterName     string
	kubeConfigOriginalContext string
}


func (p *KubernetesProxyServer) SetupKubeconfig(clusterName string) error {
	configLoader := clientcmd.NewDefaultClientConfigLoadingRules()
	config, err := configLoader.Load()
	if err != nil {
		return fmt.Errorf("failed to load kubernetes config: %w", err)
	}

	config.Clusters[clusterName] = &k8sapi.Cluster{
		Server: fmt.Sprintf("http://localhost:%d", p.port),
	}
	config.AuthInfos[clusterName] = &k8sapi.AuthInfo{}
	config.Contexts[clusterName] = &k8sapi.Context{
		Cluster:  clusterName,
		AuthInfo: clusterName,
	}
	p.kubeConfigOriginalContext = config.CurrentContext
	config.CurrentContext = clusterName
	kubeconfig := configLoader.GetDefaultFilename()
	if err = clientcmd.WriteToFile(*config, kubeconfig); err != nil {
		return fmt.Errorf("failed to write kubernetes config: %w", err)
	}
	log.Info().Str("kubeconfig", kubeconfig).Msg("Updated kubeconfig file")
	p.kubeConfigClusterName = clusterName
	p.kubeConfigPath = kubeconfig
	return nil
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

		if p.kubeConfigPath != "" && p.kubeConfigClusterName != "" {
			log.Info().
				Str("kubeconfig", p.kubeConfigPath).
				Str("clusterName", p.kubeConfigClusterName).
				Msg("Reverting changes made to the kubeconfig file")
			configLoader := clientcmd.NewDefaultClientConfigLoadingRules()
			config, err := configLoader.Load()
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to load kubernetes config")
				return
			}

			delete(config.Contexts, p.kubeConfigClusterName)
			delete(config.AuthInfos, p.kubeConfigClusterName)
			delete(config.Clusters, p.kubeConfigClusterName)
			if p.kubeConfigOriginalContext != "" {
				config.CurrentContext = p.kubeConfigOriginalContext
			}
			kubeconfig := configLoader.GetDefaultFilename()
			if err = clientcmd.WriteToFile(*config, kubeconfig); err != nil {
				log.Fatal().Err(err).Str("kubeconfig", kubeconfig).Msg("Failed to write kubernetes config")
				return
			}
		}

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

	// For Kubernetes, each kubectl command opens a separate connection.
	// Unlike persistent protocols (SSH, databases), the gateway closing after
	// handling a request is normal — not a session-level disconnect.
	// So we just wait for either side to finish and return, without triggering
	// HandleGatewayDisconnect which would shut down the entire proxy.
	done := make(chan struct{}, 2)

	// Gateway → Client
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

	// Client → Gateway
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

	// Wait for either side to finish — this is a per-connection close, not a session close
	select {
	case <-done:
	case <-connCtx.Done():
		log.Info().Msg("Connection cancelled by context")
	}

	log.Info().Msgf("Connection closed for client: %s", clientConn.RemoteAddr().String())
}
