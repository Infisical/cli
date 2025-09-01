package gatewayv2

import (
	"bufio"
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
	return fmt.Sprintf("HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"message\": \"gateway: %s\"}", message)
}

func handleHTTPProxy(conn *tls.Conn, reader *bufio.Reader, forwardConfig *ForwardConfig) error {
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
				log.Info().Msg("Using provided CA certificate from gateway client")
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
		log.Info().Msg("Attempting to read HTTP request...")
		req, err := http.ReadRequest(reader)

		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Info().Msg("Client closed HTTP connection")
				return nil
			}

			log.Error().Msgf("Failed to read HTTP request: %v", err)
			return fmt.Errorf("failed to read HTTP request: %v", err)
		}
		log.Info().Msgf("Received HTTP request: %s", req.URL.Path)

		actionHeader := HttpProxyAction(req.Header.Get(INFISICAL_HTTP_PROXY_ACTION_HEADER))

		// Only platform actor can perform privileged actions
		if actionHeader != "" && forwardConfig.ActorType == ActorTypePlatform {
			if actionHeader == HttpProxyActionInjectGatewayK8sServiceAccountToken {
				token, err := os.ReadFile(KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH)
				if err != nil {
					conn.Write([]byte(buildHttpInternalServerError("failed to read k8s sa auth token")))
					continue // Continue to next request instead of returning
				}
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(token)))
				log.Info().Msgf("Injected gateway k8s SA auth token in request to %s", targetURL)
			} else if actionHeader == HttpProxyActionUseGatewayK8sServiceAccount { // will work without a target URL set
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

func handleTCPProxy(conn *tls.Conn, forwardConfig *ForwardConfig) error {
	target := fmt.Sprintf("%s:%d", forwardConfig.TargetHost, forwardConfig.TargetPort)
	localConn, err := net.Dial("tcp", target)
	if err != nil {
		log.Error().Msgf("Failed to connect to local service %s: %v", target, err)
		return fmt.Errorf("failed to connect to local service %s: %v", target, err)
	}
	defer localConn.Close()

	// Create bidirectional tunnel with TLS
	// Forward data from TLS connection to local service
	go func() {
		io.Copy(localConn, conn)
		localConn.Close()
	}()

	// Forward data from local service to TLS connection
	io.Copy(conn, localConn)

	return nil
}
