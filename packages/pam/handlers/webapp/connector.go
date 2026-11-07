package webapp

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"golang.org/x/net/idna"
)

var mandatoryDeny = []string{"127.0.0.0/8", "::1/128", "0.0.0.0/8", "::/128", "169.254.0.0/16", "fe80::/10", "224.0.0.0/4", "ff00::/8", "100.100.100.200/32", "192.0.0.0/24", "fd00:ec2::254/128", "2001:db8::/32"}

type ConnectorPolicy struct {
	C                   string                  `json:"c"`
	AllowedDestinations []api.PAMWebDestination `json:"allowedDestinations"`
	DenyCIDRs           []string                `json:"denyCidrs"`
	HostAddresses       []string                `json:"hostAddresses"`
}

type destinationPolicy struct {
	entries []api.PAMWebDestination
	deny    []netip.Prefix
	hosts   map[netip.Addr]bool
	mu      sync.RWMutex
	lookup  func(context.Context, string) ([]net.IPAddr, error)
}

func normalizeHost(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		if ip, err := netip.ParseAddr(host[1 : len(host)-1]); err == nil && ip.Zone() == "" {
			return ip.Unmap().String(), nil
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", errors.New("zone forbidden")
		}
		return ip.Unmap().String(), nil
	}
	h, err := idna.Lookup.ToASCII(host)
	if err != nil || h == "" || len(h) > 253 || strings.ContainsAny(h, "/:@[]\\\x00 \t\r\n") {
		return "", errors.New("invalid host")
	}
	for label := range strings.SplitSeq(h, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("invalid hostname")
		}
	}
	return h, nil
}

func newDestinationPolicy(p ConnectorPolicy) (*destinationPolicy, error) {
	d := &destinationPolicy{hosts: map[netip.Addr]bool{}, lookup: net.DefaultResolver.LookupIPAddr}
	if len(p.AllowedDestinations) == 0 || len(p.AllowedDestinations) > 50 || len(p.DenyCIDRs) > 20 {
		return nil, errors.New("invalid destination count")
	}
	for _, entry := range p.AllowedDestinations {
		host, wildcard := strings.CutPrefix(entry.Host, "*.")
		h, err := normalizeHost(host)
		if err != nil || entry.Port < 1 || entry.Port > 65535 || (entry.Scheme != "http" && entry.Scheme != "https") {
			return nil, errors.New("invalid destination")
		}
		if wildcard {
			if _, err := netip.ParseAddr(h); err == nil {
				return nil, errors.New("wildcard IP")
			}
			h = "*." + h
		}
		entry.Host = h
		d.entries = append(d.entries, entry)
	}
	for _, cidr := range append(append([]string{}, mandatoryDeny...), p.DenyCIDRs...) {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid denied range: %w", err)
		}
		d.deny = append(d.deny, prefix)
	}
	d.refresh(p.HostAddresses)
	return d, nil
}

func hostMatches(pattern, host string) bool {
	if suffix, wildcard := strings.CutPrefix(pattern, "*."); wildcard {
		prefix, ok := strings.CutSuffix(host, "."+suffix)
		return ok && prefix != "" && !strings.Contains(prefix, ".")
	}
	return pattern == host
}

func (p *destinationPolicy) match(host string, port int, scheme string) bool {
	for _, e := range p.entries {
		if e.Port == port && e.Scheme == scheme && hostMatches(e.Host, host) {
			return true
		}
	}
	return false
}

func (p *destinationPolicy) denied(ip netip.Addr) bool {
	ip = ip.Unmap()
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.hosts[ip] {
		return true
	}
	for _, prefix := range p.deny {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *destinationPolicy) refresh(addresses []string) {
	hosts := map[netip.Addr]bool{}
	for _, s := range addresses {
		if ip, err := netip.ParseAddr(s); err == nil {
			hosts[ip.Unmap()] = true
		}
	}
	p.mu.Lock()
	p.hosts = hosts
	p.mu.Unlock()
}

func (p *destinationPolicy) resolve(ctx context.Context, host string, port int, scheme string) ([]netip.Addr, error) {
	h, err := normalizeHost(host)
	if err != nil || !p.match(h, port, scheme) {
		return nil, errors.New("destination not permitted")
	}
	resolved, err := p.lookup(ctx, h)
	if err != nil {
		return nil, err
	}
	if len(resolved) == 0 {
		return nil, errors.New("DNS lookup failed")
	}
	ips := make([]netip.Addr, 0, len(resolved))
	for _, addr := range resolved {
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok || p.denied(ip) {
			return nil, errors.New("address forbidden")
		}
		ip = ip.Unmap()
		if ip.IsPrivate() {
			exact := false
			for _, e := range p.entries {
				if e.Host == h && e.Port == port && e.Scheme == scheme {
					exact = true
					break
				}
			}
			if !exact {
				return nil, errors.New("private address requires exact destination")
			}
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func discoverHostAddresses(ctx context.Context, supplied []string) []string {
	addresses := append([]string{}, supplied...)
	if interfaces, err := net.InterfaceAddrs(); err == nil {
		for _, a := range interfaces {
			if prefix, err := netip.ParsePrefix(a.String()); err == nil {
				addresses = append(addresses, prefix.Addr().Unmap().String())
			}
		}
	}
	for _, name := range []string{"host.docker.internal", "gateway.docker.internal"} {
		if ips, err := net.DefaultResolver.LookupIPAddr(ctx, name); err == nil {
			for _, ip := range ips {
				addresses = append(addresses, ip.IP.String())
			}
		}
	}
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 && f[1] == "00000000" {
				if bytes, err := hex.DecodeString(f[2]); err == nil && len(bytes) == 4 {
					v := binary.LittleEndian.Uint32(bytes)
					addresses = append(addresses, net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String())
				}
			}
		}
	}
	if b, err := os.ReadFile("/proc/net/ipv6_route"); err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 5 && f[0] == strings.Repeat("0", 32) && f[1] == "00" {
				if raw, err := hex.DecodeString(f[4]); err == nil && len(raw) == 16 {
					addresses = append(addresses, net.IP(raw).String())
				}
			}
		}
	}
	return addresses
}

type connector struct {
	policy      *destinationPolicy
	mux         *Mux
	mu          sync.Mutex
	connections map[net.Conn]bool
	closed      bool
	denials     atomic.Uint64
}

func (c *connector) track(conn net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		conn.Close()
		return false
	}
	c.connections[conn] = true
	return true
}

func (c *connector) forget(conn net.Conn) {
	conn.Close()
	c.mu.Lock()
	delete(c.connections, conn)
	c.mu.Unlock()
}
func (c *connector) cut() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for conn := range c.connections {
		conn.Close()
	}
}

func (c *connector) dial(ctx context.Context, host string, port int, scheme string) (net.Conn, error) {
	ips, err := c.policy.resolve(ctx, host, port, scheme)
	if err != nil {
		return nil, err
	}
	var last error
	for range ips {
		// Re-resolve each retry; no address obtained outside policy is ever dialed.
		pinned, err := c.policy.resolve(ctx, host, port, scheme)
		if err != nil {
			return nil, err
		}
		for _, ip := range pinned {
			conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
			if err == nil {
				if !c.track(conn) {
					return nil, errors.New("connector stopped")
				}
				return conn, nil
			}
			last = err
		}
	}
	return nil, last
}

func (c *connector) deny(w http.ResponseWriter, host string, port int, reason string) {
	c.denials.Add(1)
	_ = c.mux.Control(map[string]any{"c": "deny", "host": truncate(host, 253), "port": port, "reason": truncate(reason, 500)})
	http.Error(w, "Forbidden", http.StatusForbidden)
}

func (c *connector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var host, scheme string
	var port int
	if r.Method == http.MethodConnect {
		h, p, err := net.SplitHostPort(r.Host)
		if err != nil {
			c.deny(w, "", 0, "explicit port required")
			return
		}
		host = h
		port, _ = strconv.Atoi(p)
		scheme = "https"
	} else {
		if !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.User != nil {
			c.deny(w, "", 0, "absolute HTTP URI required")
			return
		}
		host = r.URL.Hostname()
		port = 80
		scheme = "http"
		if p := r.URL.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	upstream, err := c.dial(ctx, host, port, scheme)
	cancel()
	if err != nil {
		c.deny(w, host, port, err.Error())
		return
	}
	defer c.forget(upstream)
	if r.Method == http.MethodConnect {
		downstream, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		if !c.track(downstream) {
			return
		}
		defer c.forget(downstream)
		if writeFull(downstream, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")) != nil {
			return
		}
		copyTunnel(downstream, upstream, buffered.Reader)
		return
	}
	r.RequestURI = ""
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")
	_ = upstream.SetDeadline(time.Now().Add(30 * time.Second))
	if err := r.Write(upstream); err != nil {
		http.Error(w, "Upstream failed", 502)
		return
	}
	reader := bufio.NewReader(upstream)
	response, err := http.ReadResponse(reader, r)
	if err != nil {
		http.Error(w, "Upstream failed", 502)
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusSwitchingProtocols {
		downstream, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		if !c.track(downstream) {
			return
		}
		defer c.forget(downstream)
		_ = upstream.SetDeadline(time.Time{})
		_, _ = fmt.Fprintf(downstream, "HTTP/1.1 101 Switching Protocols\r\n")
		_ = response.Header.Write(downstream)
		_ = writeFull(downstream, []byte("\r\n"))
		go func() { _, _ = io.Copy(upstream, buffered.Reader); upstream.Close() }()
		_, _ = io.Copy(downstream, reader)
		return
	}
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func copyTunnel(downstream, upstream net.Conn, reader io.Reader) {
	done := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, reader); upstream.Close(); close(done) }()
	_, copyErr := io.Copy(downstream, upstream)
	if copyErr != nil {
		fmt.Fprintf(os.Stderr, "PAM relay copy: %v\n", copyErr)
	}
	downstream.Close()
	upstream.Close()
	<-done
}

func RunConnector(ctx context.Context, mux *Mux, socket string, hard, until time.Time) error {
	ch, b, err := mux.Read()
	if err != nil {
		return err
	}
	var policy ConnectorPolicy
	if ch != MuxControl || json.Unmarshal(b, &policy) != nil || policy.C != "policy" {
		return errors.New("policy must be the first message")
	}
	p, err := newDestinationPolicy(policy)
	if err != nil {
		return err
	}
	refresh := func() {
		refreshCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		p.refresh(discoverHostAddresses(refreshCtx, policy.HostAddresses))
	}
	refresh()
	l, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer os.Remove(socket)
	if err := os.Chmod(socket, 0660); err != nil {
		l.Close()
		return err
	}
	c := &connector{policy: p, mux: mux, connections: map[net.Conn]bool{}}
	server := &http.Server{Handler: c, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10, ConnState: func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			c.track(conn)
		}
		if state == http.StateClosed {
			c.forget(conn)
		}
	}}
	clock := newLeaseClock(hard, until, 5*time.Second)
	defer clock.Stop()
	cutDone := make(chan struct{})
	defer close(cutDone)
	go func() {
		select {
		case <-clock.done:
			c.cut()
			_ = server.Close()
			_ = l.Close()
		case <-cutDone:
		}
	}()
	defer func() { c.cut(); server.Close(); l.Close() }()
	go server.Serve(l)
	if err := mux.Control(map[string]string{"c": "ready"}); err != nil {
		return err
	}
	controls := make(chan []byte, 8)
	go func() {
		defer close(controls)
		for {
			ch, b, err := mux.Read()
			if err != nil || ch != MuxControl {
				return
			}
			var lease struct {
				C       string `json:"c"`
				Seconds *int   `json:"leaseSeconds"`
			}
			if json.Unmarshal(b, &lease) != nil {
				c.cut()
				return
			}
			if lease.C == "lease" {
				if lease.Seconds == nil || *lease.Seconds < 0 || *lease.Seconds > 45 {
					c.cut()
					return
				}
				clock.Renew(time.Now().Add(time.Duration(*lease.Seconds) * time.Second))
				continue
			}
			if lease.C == "shutdown" {
				c.cut()
				_ = server.Close()
				_ = l.Close()
			}
			select {
			case controls <- b:
			case <-ctx.Done():
				return
			case <-clock.done:
				return
			default:
				c.cut()
				return
			}
		}
	}()
	stats := time.NewTicker(5 * time.Second)
	defer stats.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-clock.done:
			_ = mux.Control(map[string]string{"c": "exit", "reason": "lease-expired"})
			return nil
		case b, ok := <-controls:
			if !ok {
				return nil
			}
			var msg struct {
				C         string   `json:"c"`
				Addresses []string `json:"addresses"`
			}
			if json.Unmarshal(b, &msg) != nil {
				return errors.New("malformed control")
			}
			switch msg.C {
			case "hosts":
				policy.HostAddresses = msg.Addresses
				refresh()
			case "shutdown":
				c.cut()
				_ = server.Close()
				_ = l.Close()
				return mux.Control(map[string]string{"c": "stopped"})
			default:
				return errors.New("unexpected connector control")
			}
		case <-stats.C:
			refresh()
			c.mu.Lock()
			open := len(c.connections)
			c.mu.Unlock()
			_ = mux.Control(map[string]any{"c": "stats", "open": open, "denied": c.denials.Load()})
		}
	}
}
