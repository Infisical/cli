package webapp

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
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type WebAppProxyConfig struct {
	TargetAddr    string
	Protocol      string // "http" or "https"
	TLSConfig     *tls.Config
	SessionID     string
	SessionLogger session.SessionLogger
}

type WebAppProxy struct {
	config WebAppProxyConfig
}

func NewWebAppProxy(config WebAppProxyConfig) *WebAppProxy {
	return &WebAppProxy{config: config}
}

func (p *WebAppProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	sessionID := p.config.SessionID
	l := log.With().Str("sessionID", sessionID).Logger()
	defer func() {
		if err := p.config.SessionLogger.Close(); err != nil {
			l.Error().Err(err).Msg("Failed to close session logger")
		}
	}()

	l.Info().
		Str("targetAddr", p.config.TargetAddr).
		Str("protocol", p.config.Protocol).
		Msg("New WebApp connection for PAM session")

	reader := bufio.NewReader(clientConn)

	// Loop to handle multiple HTTP requests on the same keep-alive connection
	for {
		select {
		case <-ctx.Done():
			l.Info().Msg("Context cancelled, closing WebApp proxy connection")
			return ctx.Err()
		default:
		}

		// Read request in a goroutine so we can cancel it
		reqCh := make(chan *http.Request, 1)
		errCh := make(chan error, 1)

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
			l.Info().Msg("Context cancelled while reading HTTP request")
			return ctx.Err()
		case err := <-errCh:
			if errors.Is(err, io.EOF) {
				l.Info().Msg("Client closed connection")
				return nil
			}
			l.Error().Err(err).Msg("Failed to read HTTP request")
			return fmt.Errorf("failed to read HTTP request: %w", err)
		case req = <-reqCh:
			// Successfully received request
		}

		requestId := uuid.New().String()
		l.Info().
			Str("url", req.URL.String()).
			Str("method", req.Method).
			Str("reqId", requestId).
			Msg("Received HTTP request from tunnel")

		// Read request body
		reqBody, err := io.ReadAll(req.Body)
		if err != nil {
			l.Error().Err(err).Msg("Failed to read request body")
			writeErrorResponse(clientConn, "failed to read request body")
			continue
		}
		req.Body.Close()

		// Log the request
		if logErr := p.config.SessionLogger.LogHttpEvent(session.HttpEvent{
			Timestamp: time.Now(),
			RequestId: requestId,
			EventType: session.HttpEventRequest,
			URL:       req.URL.String(),
			Method:    req.Method,
			Headers:   req.Header,
			Body:      reqBody,
		}); logErr != nil {
			l.Error().Err(logErr).Msg("Failed to log HTTP request event")
		}

		// Connect to target and forward request
		targetURL := fmt.Sprintf("%s://%s%s", p.config.Protocol, p.config.TargetAddr, req.URL.RequestURI())

		proxyReq, err := http.NewRequest(req.Method, targetURL, bytes.NewReader(reqBody))
		if err != nil {
			l.Error().Err(err).Msg("Failed to create proxy request")
			writeErrorResponse(clientConn, "failed to create proxy request")
			continue
		}
		proxyReq.Header = req.Header.Clone()

		transport := &http.Transport{
			DisableKeepAlives: false,
			MaxIdleConns:      10,
			IdleConnTimeout:   30 * time.Second,
			TLSClientConfig:   p.config.TLSConfig,
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			// Don't follow redirects — let the client handle them
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := client.Do(proxyReq)
		if err != nil {
			l.Error().Err(err).Msg("Failed to forward request to target")
			writeErrorResponse(clientConn, fmt.Sprintf("failed to reach target: %s", err.Error()))
			continue
		}

		// Tee the body for logging
		var bodyCopy bytes.Buffer
		resp.Body = struct {
			io.ReadCloser
		}{
			ReadCloser: io.NopCloser(io.TeeReader(resp.Body, &bodyCopy)),
		}

		// Write response back to tunnel client
		resp.Header.Del("Connection")
		if err := resp.Write(clientConn); err != nil {
			if errors.Is(err, io.EOF) {
				l.Info().Msg("Client closed connection during response write")
			} else {
				l.Error().Err(err).Msg("Failed to write response to connection")
			}
			resp.Body.Close()
			return fmt.Errorf("failed to write response: %w", err)
		}
		resp.Body.Close()

		// Log the response
		if logErr := p.config.SessionLogger.LogHttpEvent(session.HttpEvent{
			Timestamp: time.Now(),
			RequestId: requestId,
			EventType: session.HttpEventResponse,
			Status:    resp.Status,
			Headers:   resp.Header,
			Body:      bodyCopy.Bytes(),
		}); logErr != nil {
			l.Error().Err(logErr).Msg("Failed to log HTTP response event")
		}

		l.Info().
			Str("reqId", requestId).
			Str("status", resp.Status).
			Msg("Forwarded response back to tunnel")
	}
}

func writeErrorResponse(conn net.Conn, message string) {
	errResp := fmt.Sprintf(
		"HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n\r\n{\"message\": \"gateway: %s\"}",
		message,
	)
	conn.Write([]byte(errResp))
}
