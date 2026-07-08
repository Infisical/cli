package webapp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// egressAllowlistProxy is a minimal HTTP/CONNECT forward proxy that only
// permits requests to a single allowed host:port. Chromium is launched with
// --proxy-server pointed at this proxy's address (see chrome.go).
type egressAllowlistProxy struct {
	listener    net.Listener
	allowedHost string // host:port, e.g. "internal-app.local:8080"
	server      *http.Server
}

func newEgressAllowlistProxy(allowedHost string) (*egressAllowlistProxy, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind egress proxy listener: %w", err)
	}

	p := &egressAllowlistProxy{listener: listener, allowedHost: allowedHost}
	p.server = &http.Server{Handler: http.HandlerFunc(p.handle)}
	go func() {
		_ = p.server.Serve(listener)
	}()
	return p, nil
}

func (p *egressAllowlistProxy) Addr() string {
	return p.listener.Addr().String()
}

func (p *egressAllowlistProxy) Close() {
	_ = p.server.Close()
}

func (p *egressAllowlistProxy) isAllowed(hostPort string) bool {
	return strings.EqualFold(hostPort, p.allowedHost)
}

func (p *egressAllowlistProxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handlePlainHTTP(w, r)
}

// handleConnect services HTTPS traffic by splicing raw bytes between the
// client and destination sockets once the destination is confirmed allowed.
func (p *egressAllowlistProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	if !p.isAllowed(r.Host) {
		http.Error(w, "destination not allowed", http.StatusForbidden)
		return
	}

	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(destConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, destConn)
		done <- struct{}{}
	}()
	<-done
}

// handlePlainHTTP services non-TLS HTTP requests made through the proxy.
func (p *egressAllowlistProxy) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.isAllowed(r.Host) {
		http.Error(w, "destination not allowed", http.StatusForbidden)
		return
	}

	outReq := r.Clone(context.Background())
	outReq.RequestURI = ""

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
