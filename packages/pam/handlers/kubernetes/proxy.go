package kubernetes

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type KubernetesProxyConfig struct {
	TargetApiServer           string
	AuthMethod                string
	InjectServiceAccountToken string
	TLSConfig                 *tls.Config
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

	sessionID := p.config.SessionID
	defer func() {
		if err := p.config.SessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to close session logger")
		}
	}()

	log.Info().
		Str("sessionID", sessionID).
		Str("targetApiServer", p.config.TargetApiServer).
		Msg("New Kubernetes connection for PAM session")

	reader := bufio.NewReader(clientConn)

	transport := &http.Transport{
		DisableKeepAlives: false,
		MaxIdleConns:      10,
		IdleConnTimeout:   30 * time.Second,
		TLSClientConfig:   p.config.TLSConfig,
	}
	selfServerClient := &http.Client{
		Transport: transport,
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
			log.Error().Err(err).Msg("Failed to read HTTP request")
			return fmt.Errorf("failed to read HTTP request: %v", err)
		case req = <-reqCh:
			// Successfully received request
		}

		requestId := uuid.New()
		log.Info().
			Str("url", req.URL.String()).
			Str("reqId", requestId.String()).
			Msg("Received HTTP request")

		// TODO: what if this is a DOS attack? maybe limit the totally req body size?
		reqBody, err := io.ReadAll(req.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read request body")
			_, err = clientConn.Write([]byte(buildHttpInternalServerError("failed to read request body")))
			if err != nil {
				return err
			}
			return err
		}
		err = p.config.SessionLogger.LogHttpEvent(session.HttpEvent{
			Timestamp: time.Now(),
			RequestId: requestId.String(),
			EventType: session.HttpEventRequest,
			URL:       req.URL.String(),
			Method:    req.Method,
			// TODO: filter out sensitive headers?
			Headers: req.Header,
			Body:    reqBody,
		})
		if err != nil {
			log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to log HTTP request event")
		}

		// create the request to the target
		newUrl := fmt.Sprintf("%s%s", p.config.TargetApiServer, req.URL.RequestURI())
		proxyReq, err := http.NewRequest(req.Method, newUrl, bytes.NewReader(reqBody))
		if err != nil {
			log.Error().Err(err).Msg("Failed to create proxy request")
			_, err = clientConn.Write([]byte(buildHttpInternalServerError("failed to create proxy request")))
			if err != nil {
				return err
			}
			continue // Continue to next request
		}
		proxyReq.Header = req.Header.Clone()
		proxyReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.config.InjectServiceAccountToken))

		resp, err := selfServerClient.Do(proxyReq)
		if err != nil {
			return err
		}

		// Write the entire response (status line, headers, body) to the connection
		resp.Header.Del("Connection")
		log.Info().Str("status", resp.Status).Msgf("Writing response to connection")

		// Tee the body to a local buffer so that we can eventually log it
		var bodyCopy bytes.Buffer
		resp.Body = struct {
			io.ReadCloser
		}{
			ReadCloser: io.NopCloser(io.TeeReader(resp.Body, &bodyCopy)),
		}

		if err := resp.Write(clientConn); err != nil {
			log.Error().Err(err).Msg("Failed to write response to connection")
			err := resp.Body.Close()
			if err != nil {
				return err
			}
			return fmt.Errorf("failed to write response to connection: %w", err)
		}

		err = resp.Body.Close()
		if err != nil {
			return err
		}

		err = p.config.SessionLogger.LogHttpEvent(session.HttpEvent{
			Timestamp: time.Now(),
			RequestId: requestId.String(),
			EventType: session.HttpEventResponse,
			Status:    resp.Status,
			// TODO: remove sensitive stuff
			Headers: resp.Header,
			// TODO: well... this might be really really big for the case of `kubectl cp` or `kubectl logs`
			// 		 instead of writing the data into a big chunk mem blob,
			//		 we should break it down into smaller fixed size chunks and flush as resp event with seq numbers
			//		 (like a respBodyPart event type?)
			Body: bodyCopy.Bytes(),
		})
		if err != nil {
			return err
		}
	}

	return nil
}
