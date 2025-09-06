package connector

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

func buildHttpInternalServerError(message string) string {
	return fmt.Sprintf("HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"message\": \"connector: %s\"}", message)
}

func handleHTTPProxy(ctx context.Context, conn *tls.Conn, reader *bufio.Reader, forwardConfig *ForwardConfig) error {
	targetURL := fmt.Sprintf("%s:%d", forwardConfig.TargetHost, forwardConfig.TargetPort)
	caCert := forwardConfig.CACertificate
	verifyTLS := forwardConfig.VerifyTLS

	transport := &http.Transport{
		DisableKeepAlives: false,
		MaxIdleConns:      10,
		IdleConnTimeout:   30 * time.Second,
	}

	if strings.HasPrefix(targetURL, "https://") {
		tlsConfig := &tls.Config{}

		if len(caCert) > 0 {
			caCertPool := x509.NewCertPool()
			if caCertPool.AppendCertsFromPEM(caCert) {
				tlsConfig.RootCAs = caCertPool
				log.Info().Msg("Using provided CA certificate from connector client")
			} else {
				log.Error().Msg("Failed to parse provided CA certificate")
			}
		}

		tlsConfig.InsecureSkipVerify = !verifyTLS
		log.Info().Msgf("TLS verification set to: %v", verifyTLS)

		transport.TLSClientConfig = tlsConfig
	}

	// Loop to handle multiple HTTP requests on the same connection
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Context cancelled, closing HTTP proxy connection")
			return ctx.Err()
		default:
		}

		log.Info().Msg("Attempting to read HTTP request...")

		// Create a channel to receive the request or error
		reqCh := make(chan *http.Request, 1)
		errCh := make(chan error, 1)

		// Read request in a goroutine so we can cancel it
		go func() {
			req, err := http.ReadRequest(reader)
			if err != nil {
				errCh <- err
			} else {
				reqCh <- req
			}
		}()

		var req *http.Request
		select {
		case <-ctx.Done():
			log.Info().Msg("Context cancelled while reading HTTP request")
			return ctx.Err()
		case err := <-errCh:
			if errors.Is(err, io.EOF) {
				log.Info().Msg("Client closed HTTP connection")
				return nil
			}
			log.Error().Msgf("Failed to read HTTP request: %v", err)
			return fmt.Errorf("failed to read HTTP request: %v", err)
		case req = <-reqCh:
			// Successfully received request
		}

		log.Info().Msgf("Received HTTP request: %s", req.URL.Path)

		actionHeader := HttpProxyAction(req.Header.Get(INFISICAL_HTTP_PROXY_ACTION_HEADER))

		// Only platform actor can perform privileged actions
		if actionHeader != "" && forwardConfig.ActorType == ActorTypePlatform {
			if actionHeader == HttpProxyActionInjectConnectorK8sServiceAccountToken {
				token, err := os.ReadFile(KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH)
				if err != nil {
					conn.Write([]byte(buildHttpInternalServerError("failed to read k8s sa auth token")))
					continue // Continue to next request instead of returning
				}
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(token)))
				log.Info().Msgf("Injected connector k8s SA auth token in request to %s", targetURL)
			} else if actionHeader == HttpProxyActionUseConnectorK8sServiceAccount {
				// will work without a target URL set
				// set the ca cert to the pod's k8s service account ca cert:
				caCert, err := os.ReadFile(KUBERNETES_SERVICE_ACCOUNT_CA_CERT_PATH)
				if err != nil {
					conn.Write([]byte(buildHttpInternalServerError("failed to read k8s sa ca cert")))
					continue
				}

				caCertPool := x509.NewCertPool()
				if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
					conn.Write([]byte(buildHttpInternalServerError("failed to parse k8s sa ca cert")))
					continue
				}

				transport.TLSClientConfig = &tls.Config{
					RootCAs: caCertPool,
				}

				// set authorization header to the pod's k8s service account token:
				token, err := os.ReadFile(KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH)
				if err != nil {
					conn.Write([]byte(buildHttpInternalServerError("failed to read k8s sa auth token")))
					continue
				}
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(token)))

				// update the target URL to point to the kubernetes API server:
				kubernetesServiceHost := os.Getenv(KUBERNETES_SERVICE_HOST_ENV_NAME)
				kubernetesServicePort := os.Getenv(KUBERNETES_SERVICE_PORT_HTTPS_ENV_NAME)

				fullBaseUrl := fmt.Sprintf("https://%s:%s", kubernetesServiceHost, kubernetesServicePort)
				targetURL = fullBaseUrl

				log.Info().Msgf("Redirected request to Kubernetes API server: %s", targetURL)
			}

			req.Header.Del(INFISICAL_HTTP_PROXY_ACTION_HEADER)
		}

		// Build full target URL
		var targetFullURL string
		if strings.HasPrefix(targetURL, "http://") || strings.HasPrefix(targetURL, "https://") {
			baseURL := strings.TrimSuffix(targetURL, "/")
			targetFullURL = baseURL + req.URL.Path
			if req.URL.RawQuery != "" {
				targetFullURL += "?" + req.URL.RawQuery
			}
		} else {
			baseURL := strings.TrimSuffix("http://"+targetURL, "/")
			targetFullURL = baseURL + req.URL.Path
			if req.URL.RawQuery != "" {
				targetFullURL += "?" + req.URL.RawQuery
			}
		}

		// create the request to the target
		proxyReq, err := http.NewRequest(req.Method, targetFullURL, req.Body)
		if err != nil {
			log.Error().Msgf("Failed to create proxy request: %v", err)
			conn.Write([]byte(buildHttpInternalServerError("failed to create proxy request")))
			continue // Continue to next request
		}
		proxyReq.Header = req.Header.Clone()

		log.Info().Msgf("Proxying %s %s to %s", req.Method, req.URL.Path, targetFullURL)

		client := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}

		resp, err := client.Do(proxyReq)
		if err != nil {
			log.Error().Msgf("Failed to reach target: %v", err)
			conn.Write([]byte(buildHttpInternalServerError(fmt.Sprintf("failed to reach target due to networking error: %s", err.Error()))))
			continue // Continue to next request
		}

		// Write the entire response (status line, headers, body) to the connection
		resp.Header.Del("Connection")

		log.Info().Msgf("Writing response to connection: %s", resp.Status)

		if err := resp.Write(conn); err != nil {
			log.Error().Err(err).Msg("Failed to write response to connection")
			resp.Body.Close()
			return fmt.Errorf("failed to write response to connection: %w", err)
		}

		resp.Body.Close()

		// Check if client wants to close connection
		if req.Header.Get("Connection") == "close" {
			log.Info().Msg("Client requested connection close")
			return nil
		}
	}
}

func handleTCPProxy(ctx context.Context, conn *tls.Conn, forwardConfig *ForwardConfig) error {
	target := fmt.Sprintf("%s:%d", forwardConfig.TargetHost, forwardConfig.TargetPort)
	localConn, err := net.Dial("tcp", target)
	if err != nil {
		log.Error().Msgf("Failed to connect to local service %s: %v", target, err)
		return fmt.Errorf("failed to connect to local service %s: %v", target, err)
	}
	defer localConn.Close()

	// Create a context for this connection that gets cancelled when the parent context is cancelled
	// or when either connection closes
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Error channel to collect errors from both copy goroutines
	errCh := make(chan error, 2)

	// Forward data from TLS connection to local service
	go func() {
		defer cancel()
		_, err := io.Copy(localConn, conn)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				log.Debug().Msgf("TLS to local copy ended normally: %v", err)
			} else {
				log.Error().Msgf("TLS to local copy failed: %v", err)
			}
		}
		errCh <- err
	}()

	// Forward data from local service to TLS connection
	go func() {
		defer cancel()
		_, err := io.Copy(conn, localConn)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				log.Debug().Msgf("Local to TLS copy ended normally: %v", err)
			} else {
				log.Error().Msgf("Local to TLS copy failed: %v", err)
			}
		}
		errCh <- err
	}()

	// Wait for either context cancellation or one of the copy operations to complete
	select {
	case <-connCtx.Done():
		log.Info().Msg("TCP proxy connection cancelled")
		return connCtx.Err()
	case err := <-errCh:
		// One of the copy operations completed (or failed)
		// The defer cancel() will stop the other goroutine
		return err
	}
}

func handlePing(ctx context.Context, conn *tls.Conn, reader *bufio.Reader) error {
	conn.Write([]byte("PONG\n"))
	return nil
}
