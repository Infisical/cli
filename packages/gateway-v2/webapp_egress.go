package gatewayv2

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// startEgressProxy runs a per-session forward proxy on loopback that only permits
// traffic to the one authorized target host:port. Every other destination is
// refused (HTTP 403) and logged. This is the egress wall (Wall #2): it contains
// the gateway's headless browser to the single resource the user was granted,
// blocking SSRF, lateral movement, and exfiltration to other internal hosts.
//
// It returns the proxy's listen address; the caller points Chromium at it with
// --proxy-server (plus --proxy-bypass-list=<-loopback> so even loopback destinations
// are filtered). The proxy stops when ctx is cancelled.
func startEgressProxy(ctx context.Context, sessionID, allowHost string, allowPort int) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("egress proxy listen: %w", err)
	}
	allowed := net.JoinHostPort(allowHost, strconv.Itoa(allowPort))

	// allow reports whether a "host:port" (or bare host) destination is the target.
	allow := func(dest string) bool {
		host, port, splitErr := net.SplitHostPort(dest)
		if splitErr != nil {
			host, port = dest, "80" // plain HTTP with no explicit port
		}
		return host == allowHost && port == strconv.Itoa(allowPort)
	}

	deny := func(w http.ResponseWriter, dest string) {
		log.Warn().
			Str("sessionId", sessionID).
			Str("allowed", allowed).
			Str("blocked", dest).
			Msg("web-app: egress blocked")
		http.Error(w, "egress destination not allowed", http.StatusForbidden)
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HTTPS: the browser sends CONNECT host:port; tunnel raw bytes if allowed.
		if r.Method == http.MethodConnect {
			if !allow(r.Host) {
				deny(w, r.Host)
				return
			}
			tunnelConnect(w, r)
			return
		}
		// Plain HTTP: the browser sends an absolute-form request to the proxy.
		dest := r.URL.Host
		if dest == "" {
			dest = r.Host
		}
		if !allow(dest) {
			deny(w, dest)
			return
		}
		r.RequestURI = ""
		resp, ferr := transport.RoundTrip(r)
		if ferr != nil {
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()
	go func() {
		if serveErr := server.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Error().Err(serveErr).Str("sessionId", sessionID).Msg("web-app: egress proxy stopped unexpectedly")
		}
	}()

	log.Info().
		Str("sessionId", sessionID).
		Str("addr", ln.Addr().String()).
		Str("allowed", allowed).
		Msg("web-app: egress wall active")
	return ln.Addr().String(), nil
}

// tunnelConnect pipes bytes both ways for an allowed HTTPS CONNECT.
func tunnelConnect(w http.ResponseWriter, r *http.Request) {
	upstream, derr := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if derr != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		_ = upstream.Close()
		return
	}
	client, _, herr := hj.Hijack()
	if herr != nil {
		_ = upstream.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() {
		_, _ = io.Copy(upstream, client)
		_ = upstream.Close()
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
	}()
}
