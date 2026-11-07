package gatewayv2

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/handlers/webapp"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

type webAppProbeContextKey struct{}

func (g *Gateway) probeWebApp(ctx context.Context, host string, port int) error {
	if g.webRegistry == nil || !webapp.Ready() {
		return errors.New("browser runtime unavailable")
	}
	return webapp.ProbeFromNetwork(ctx, g.webRegistry.Options, g.GatewayID, host, port)
}

func (g *Gateway) startWebRuntime(ctx context.Context) {
	options := g.config.BrowserOptions
	if options.EgressNetwork == "" {
		options.EgressNetwork = "bridge"
	}
	if options.Memory == "" {
		options.Memory = "1g"
	}
	if options.CPUs == "" {
		options.CPUs = "1.0"
	}
	if options.MaxSessions == 0 {
		options.MaxSessions = 4
	}
	if options.SpoolMaxBytes == 0 {
		options.SpoolMaxBytes = 2 << 30
	}
	if err := webapp.CheckRuntime(ctx, &options, g.GatewayID); err != nil {
		log.Info().Err(err).Msg("PAM browser runtime unavailable")
	}
	r := webapp.NewRegistry(g.GatewayID, options, g.httpClient, g.pamCredentialsManager)
	r.Register = func(id string, cancel func()) func() {
		g.RegisterPAMSession(id, cancel, nil)
		return func() { g.DeregisterPAMSession(id, nil) }
	}
	g.webRegistry = r
	_, allocationDirErr := os.Stat(filepath.Join(session.GetSessionRecordingDir(), "webapp"))
	if options.Image != "" || allocationDirErr == nil {
		if err := r.Reap(ctx); err != nil {
			log.Warn().Err(err).Msg("Browser worker reaper could not confirm cleanup")
		}
		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					_ = r.Reap(ctx)
				}
			}
		}()
	}
	if err := session.ResumeWebRecordings(g.pamCredentialsManager, g.httpClient); err != nil {
		log.Warn().Err(err).Msg("Browser recording recovery requires attention")
	}
	go func() { <-ctx.Done(); r.Stop() }()
}

func (g *Gateway) handlePAMWebBrowser(conn *tls.Conn, reader *bufio.Reader, config *ForwardConfig) error {
	errorFrame := func(code string) {
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_ = webapp.WriteFrame(conn, webapp.ControlFrame(map[string]string{"t": "error", "code": code, "message": code}))
	}
	if config.PAMConfig.ResourceType != session.ResourceTypeWebApp || config.PAMConfig.WebApp == nil {
		errorFrame("protocol")
		return errors.New("browser certificate binding required")
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	// Relay channels have inert deadlines, so close the stream independently of ReadFrame.
	timer := time.AfterFunc(10*time.Second, func() { conn.Close() })
	b, err := webapp.ReadFrame(reader, webapp.FromPlatform, false)
	timer.Stop()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		errorFrame("protocol")
		return err
	}
	var attach webapp.Attach
	if b[0] != webapp.Control || json.Unmarshal(b[1:], &attach) != nil {
		errorFrame("protocol")
		return errors.New("attach required")
	}
	if err := attach.Validate(config.PAMConfig.SessionId, *config.PAMConfig.WebApp); err != nil {
		errorFrame("protocol")
		return err
	}
	if !webapp.Ready() || g.webRegistry == nil {
		errorFrame("internal")
		return errors.New("browser runtime unavailable")
	}
	credentials, err := g.pamCredentialsManager.GetPAMSessionCredentials(attach.SessionID, config.PAMConfig.ExpiryTime)
	if err != nil {
		errorFrame("internal")
		return err
	}
	supervisor, err := g.webRegistry.GetOrCreate(attach.SessionID, attach.AllocationGen, credentials)
	if err != nil {
		code := "internal"
		if err.Error() == "capacity" {
			code = "capacity"
		}
		if err.Error() == "allocation-lost" {
			code = "allocation-lost"
		}
		errorFrame(code)
		return err
	}
	return supervisor.Attach(conn, reader, attach)
}
