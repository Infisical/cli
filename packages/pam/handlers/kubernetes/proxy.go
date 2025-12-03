package kubernetes

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

type KubernetesProxyConfig struct {
	TargetApiServer           string
	AuthMethod                string
	InjectServiceAccountToken string
	SessionID                 string
	SessionLogger             session.SessionLogger
}

type KubernetesProxy struct {
	config      KubernetesProxyConfig
	mutex       sync.Mutex
	sessionData []byte // Store session data for logging
	inputBuffer []byte // Buffer for input data to batch keystrokes
}

func NewKubernetesProxy(config KubernetesProxyConfig) *KubernetesProxy {
	return &KubernetesProxy{config: config}
}

func buildHttpInternalServerError(message string) string {
	return fmt.Sprintf("HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"message\": \"gateway: %s\"}", message)
}

func (p *KubernetesProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	reader := bufio.NewReader(clientConn)
	selfServerClient := &http.Client{
		Timeout: 10 * time.Second,
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

		// If there's any authorization header, let's delete it
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.config.InjectServiceAccountToken))

		newUrl, err := url.Parse(fmt.Sprintf("%s/%s", strings.Trim(p.config.TargetApiServer, "/"), req.URL.Path))
		if err != nil {
			_, writeErr := clientConn.Write([]byte(buildHttpInternalServerError("Invalid target api server URL")))
			if err != nil {
				return writeErr
			}
			continue
		}
		req.URL = newUrl

		resp, err := selfServerClient.Do(req)
		if err != nil {
			return err
		}

		// Write the entire response (status line, headers, body) to the connection
		resp.Header.Del("Connection")

		log.Info().Msgf("Writing response to connection: %s", resp.Status)

		if err := resp.Write(clientConn); err != nil {
			log.Error().Err(err).Msg("Failed to write response to connection")
			resp.Body.Close()
			return fmt.Errorf("failed to write response to connection: %w", err)
		}

		err = resp.Body.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
