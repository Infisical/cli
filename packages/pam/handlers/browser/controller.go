package browser

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
)

const (
	AuthMethodNone   = "none"
	AuthMethodBasic  = "basic"
	AuthMethodBearer = "bearer"
	AuthMethodHeader = "header"
)

// Safe to show the viewer.
var ErrOpenFailed = errors.New("could not open the web app")

func StartSession(ctx context.Context, engine BrowserEngine, config BrowserProxyConfig, width, height int) (Session, string, error) {
	appURL, err := url.Parse(config.TargetURL)
	if err != nil || (appURL.Scheme != "http" && appURL.Scheme != "https") || appURL.Hostname() == "" {
		return nil, "", fmt.Errorf("invalid web app URL %q", config.TargetURL)
	}
	startURL, err := resolveStartPath(appURL, config.StartPath)
	if err != nil {
		return nil, "", err
	}
	headers, err := credentialHeaders(config)
	if err != nil {
		return nil, "", err
	}
	if config.TLSCaCertificate != "" {
		log.Warn().Str("sessionID", config.SessionID).Msg("Web app CA certificates are not applied yet; the browser trusts only its built-in roots")
	}

	session, err := engine.Start(ctx, StartOptions{
		SessionID:         config.SessionID,
		Width:             width,
		Height:            height,
		AllowedHost:       appURL.Hostname(),
		CredentialOrigin:  Origin(config.TargetURL),
		CredentialHeaders: headers,
		IgnoreTLSErrors:   !config.TLSRejectUnauthorized,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to start browser: %w", err)
	}
	if err := session.Navigate(ctx, startURL); err != nil {
		session.Stop(EndError)
		return nil, "", fmt.Errorf("%w at %s: %v", ErrOpenFailed, startURL, err)
	}
	return session, startURL, nil
}

// data: and blob: URLs never leave the browser.
func RequestAllowed(rawURL, host string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "data", "blob":
		return true
	case "http", "https", "ws", "wss":
		return strings.EqualFold(u.Hostname(), host)
	}
	return false
}

func Origin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		switch scheme {
		case "http", "ws":
			port = "80"
		case "https", "wss":
			port = "443"
		}
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

func resolveStartPath(appURL *url.URL, startPath string) (string, error) {
	if startPath == "" {
		return appURL.String(), nil
	}
	ref, err := url.Parse(startPath)
	if err != nil || ref.Scheme != "" || ref.Host != "" || !strings.HasPrefix(ref.Path, "/") {
		return "", fmt.Errorf("invalid start path %q", startPath)
	}
	return appURL.ResolveReference(ref).String(), nil
}

func credentialHeaders(config BrowserProxyConfig) (map[string]string, error) {
	var headers map[string]string
	switch config.AuthMethod {
	case "", AuthMethodNone:
		return nil, nil
	case AuthMethodBasic:
		encoded := base64.StdEncoding.EncodeToString([]byte(config.Username + ":" + config.Password))
		headers = map[string]string{"Authorization": "Basic " + encoded}
	case AuthMethodBearer:
		headers = map[string]string{"Authorization": "Bearer " + config.Token}
	case AuthMethodHeader:
		if !validHeaderName(config.HeaderName) {
			return nil, fmt.Errorf("invalid credential header name %q", config.HeaderName)
		}
		headers = map[string]string{config.HeaderName: config.HeaderValue}
	default:
		return nil, fmt.Errorf("unsupported web app auth method %q", config.AuthMethod)
	}
	for _, value := range headers {
		if strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("credential header value contains a line break")
		}
	}
	return headers, nil
}

// Same rule as the platform.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !(r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}
