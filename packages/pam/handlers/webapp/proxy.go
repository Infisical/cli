package webapp

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

//go:embed playwright-agent.js
var playwrightAgentJS []byte

// WebAppProxyConfig holds the connection details for a WebApp PAM session.
type WebAppProxyConfig struct {
	URL                   string
	SSLRejectUnauthorized bool
	SSLCertificate        string
	SessionID             string
	SessionLogger         session.SessionLogger
}

// WebAppProxy drives a Playwright headless browser for a WebApp PAM session.
type WebAppProxy struct {
	config WebAppProxyConfig
}

// NewWebAppProxy creates a new WebAppProxy.
func NewWebAppProxy(config WebAppProxyConfig) *WebAppProxy {
	return &WebAppProxy{config: config}
}

// HandleConnection is the entry point called from HandlePAMProxy.
//
// It writes the embedded playwright-agent.js to a temp file, spawns
// `node playwright-agent.js`, then simply pipes:
//
//	relay conn → subprocess stdin  (input events from backend → browser)
//	subprocess stdout → relay conn (JPEG frames/page-info from browser → backend)
//
// The framing and protocol parsing happen entirely in the Node.js agent and
// in the backend TypeScript handler — the Go layer is a transparent pipe.
func (p *WebAppProxy) HandleConnection(ctx context.Context, conn *tls.Conn) error {
	defer conn.Close()

	// Verify that node is available before attempting to start a session.
	if _, err := exec.LookPath("node"); err != nil {
		return fmt.Errorf("node binary not found — install Node.js to use WebApp PAM sessions: %w", err)
	}

	// Pass configuration via environment variables (avoids exposing secrets in
	// the process argument list, which is visible in `ps` output).
	env := os.Environ()

	// Ensure globally-installed npm packages (e.g. playwright) are resolvable.
	// `npm root -g` returns the global node_modules path; we append it to
	// NODE_PATH so `require("playwright")` works without a local install.
	if nodePath, err := exec.Command("npm", "root", "-g").Output(); err == nil {
		existing := os.Getenv("NODE_PATH")
		newPath := strings.TrimSpace(string(nodePath))
		if existing != "" {
			newPath = existing + string(os.PathListSeparator) + newPath
		}
		env = append(env, "NODE_PATH="+newPath)
	}

	env = append(env, "WEBAPP_URL="+p.config.URL)
	if !p.config.SSLRejectUnauthorized {
		env = append(env, "WEBAPP_SSL_REJECT_UNAUTHORIZED=false")
	}
	if p.config.SSLCertificate != "" {
		env = append(env, "WEBAPP_SSL_CERTIFICATE="+p.config.SSLCertificate)
	}

	cmd := exec.CommandContext(ctx, "node", "-e", string(playwrightAgentJS))
	cmd.Env = env
	cmd.Stderr = os.Stderr // forward agent logs/errors to gateway stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("getting stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("getting stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting playwright agent: %w", err)
	}

	log.Info().
		Str("sessionId", p.config.SessionID).
		Str("url", p.config.URL).
		Int("pid", cmd.Process.Pid).
		Msg("WebApp PAM session started")

	errCh := make(chan error, 3)

	// relay conn → subprocess stdin: input events (backend → agent)
	go func() {
		_, copyErr := io.Copy(stdin, conn)
		stdin.Close()
		errCh <- fmt.Errorf("conn→stdin closed: %w", copyErr)
	}()

	// subprocess stdout → relay conn: frames + page-info (agent → backend)
	// or HTTP events (agent → Go session logger only)
	go func() {
		for {
			msgType, payload, readErr := ReadMessage(stdout)
			if readErr != nil {
				errCh <- fmt.Errorf("stdout message stream closed: %w", readErr)
				return
			}

			switch msgType {
			case MsgTypeFrame, MsgTypePageInfo:
				if writeErr := WriteMessage(conn, msgType, payload); writeErr != nil {
					errCh <- fmt.Errorf("forwarding agent message 0x%02x: %w", msgType, writeErr)
					return
				}
			case MsgTypeHttpEvent:
				var event session.HttpEvent
				if err := json.Unmarshal(payload, &event); err != nil {
					log.Error().Err(err).Str("sessionId", p.config.SessionID).Msg("Failed to decode WebApp HTTP event")
					continue
				}
				if err := p.config.SessionLogger.LogHttpEvent(event); err != nil {
					log.Error().Err(err).Str("sessionId", p.config.SessionID).Msg("Failed to log WebApp HTTP event")
				}
			default:
				log.Debug().
					Str("sessionId", p.config.SessionID).
					Uint8("msgType", msgType).
					Msg("Ignoring unknown WebApp agent message type")
			}
		}
	}()

	// wait for the agent process to exit
	go func() {
		if waitErr := cmd.Wait(); waitErr != nil {
			errCh <- fmt.Errorf("playwright agent exited: %w", waitErr)
		} else {
			errCh <- fmt.Errorf("playwright agent exited normally")
		}
	}()

	select {
	case err := <-errCh:
		log.Info().Err(err).Str("sessionId", p.config.SessionID).Msg("WebApp session ended")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
