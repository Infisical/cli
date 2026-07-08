package webapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

type WebAppProxyConfig struct {
	TargetURL     string
	SessionID     string
	SessionLogger session.SessionLogger
}

type WebAppProxy struct {
	config WebAppProxyConfig
}

func NewWebAppProxy(config WebAppProxyConfig) *WebAppProxy {
	return &WebAppProxy{config: config}
}

// cdpEnvelope is what gets JSON-marshaled into SessionEvent.Data for ChannelType=webapp.
type cdpEnvelope struct {
	Direction string          `json:"direction"` // "browser_to_client" | "client_to_browser"
	Message   json.RawMessage `json:"message"`
}

func (p *WebAppProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	sessionID := p.config.SessionID
	defer func() {
		if err := p.config.SessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to close session logger")
		}
	}()

	allowedHost, err := targetHostPort(p.config.TargetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	egressProxy, err := newEgressAllowlistProxy(allowedHost)
	if err != nil {
		return fmt.Errorf("failed to start egress allowlist proxy: %w", err)
	}
	defer egressProxy.Close()

	log.Info().Str("sessionId", sessionID).Str("allowedHost", allowedHost).Msg("Started WebApp egress allowlist proxy")

	chrome, err := launchChrome(ctx, sessionID, egressProxy.Addr())
	if err != nil {
		return fmt.Errorf("failed to launch chrome: %w", err)
	}
	defer chrome.Close()

	pageWsURL, err := waitForCDPPageWebSocketURL(ctx, chrome.debugPort)
	if err != nil {
		return fmt.Errorf("failed to discover CDP page target: %w", err)
	}

	cdpConn, _, err := websocket.DefaultDialer.DialContext(ctx, pageWsURL, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to chrome devtools: %w", err)
	}
	defer cdpConn.Close()

	log.Info().Str("sessionId", sessionID).Str("cdpUrl", pageWsURL).Msg("Connected to Chrome DevTools Protocol")

	if err := sendInitialNavigate(cdpConn, p.config.TargetURL); err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to send initial navigation")
	}

	sessionStart := time.Now()
	var cleanupOnce sync.Once
	done := make(chan struct{})
	closeAll := func() {
		cleanupOnce.Do(func() {
			_ = clientConn.Close()
			_ = cdpConn.Close()
			close(done)
		})
	}

	// browser -> client
	go func() {
		defer closeAll()
		for {
			_, message, readErr := cdpConn.ReadMessage()
			if readErr != nil {
				if !isExpectedCloseErr(readErr) {
					log.Debug().Err(readErr).Str("sessionId", sessionID).Msg("webapp session: cdp read closed")
				}
				return
			}

			logCDPEvent(p.config.SessionLogger, sessionID, sessionStart, "browser_to_client", message)

			if writeErr := writeFrame(clientConn, message); writeErr != nil {
				log.Debug().Err(writeErr).Str("sessionId", sessionID).Msg("webapp session: tunnel write failed")
				return
			}
		}
	}()

	// client -> browser
	go func() {
		defer closeAll()
		for {
			payload, readErr := readFrame(clientConn)
			if readErr != nil {
				log.Debug().Err(readErr).Str("sessionId", sessionID).Msg("webapp session: tunnel read closed")
				return
			}

			logCDPEvent(p.config.SessionLogger, sessionID, sessionStart, "client_to_browser", payload)

			if writeErr := cdpConn.WriteMessage(websocket.TextMessage, payload); writeErr != nil {
				log.Debug().Err(writeErr).Str("sessionId", sessionID).Msg("webapp session: cdp write failed")
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		closeAll()
	case <-done:
	}

	return nil
}

func logCDPEvent(logger session.SessionLogger, sessionID string, sessionStart time.Time, direction string, message []byte) {
	data, err := json.Marshal(cdpEnvelope{Direction: direction, Message: message})
	if err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("failed to encode webapp session event")
		return
	}
	event := session.SessionEvent{
		Timestamp:   time.Now(),
		EventType:   session.SessionEventWebApp,
		ChannelType: session.SessionChannelWebApp,
		Data:        data,
		ElapsedTime: time.Since(sessionStart).Seconds(),
	}
	if err := logger.LogSessionEvent(event); err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("failed to log webapp session event")
	}
}

func sendInitialNavigate(cdpConn *websocket.Conn, targetURL string) error {
	navigateCmd := map[string]any{
		"id":     1,
		"method": "Page.navigate",
		"params": map[string]string{"url": targetURL},
	}
	return cdpConn.WriteJSON(navigateCmd)
}

func isExpectedCloseErr(err error) bool {
	return websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway)
}

// targetHostPort normalizes the account's target URL into the host:port form
// Chromium's CONNECT/HTTP requests will use, so the egress allowlist can
// compare against it directly.
func targetHostPort(targetURL string) (string, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	if parsed.Port() != "" {
		return parsed.Host, nil
	}
	if parsed.Scheme == "https" {
		return net.JoinHostPort(parsed.Hostname(), "443"), nil
	}
	return net.JoinHostPort(parsed.Hostname(), "80"), nil
}
