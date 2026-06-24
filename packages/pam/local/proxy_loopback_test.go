package pam

import (
	"net"
	"testing"
)

// TestLocalProxiesBindLoopback guards that the local PAM proxies bind to a
// loopback address rather than all interfaces. Start() only creates the
// listener (the accept loop lives in Run), so it can be exercised in isolation
// without a gateway or an active session.
func TestLocalProxiesBindLoopback(t *testing.T) {
	cases := []struct {
		name  string
		start func() (net.Listener, error)
	}{
		{"database", func() (net.Listener, error) { p := &DatabaseProxyServer{}; err := p.Start(0); return p.server, err }},
		{"redis", func() (net.Listener, error) { p := &RedisProxyServer{}; err := p.Start(0); return p.server, err }},
		{"kubernetes", func() (net.Listener, error) { p := &KubernetesProxyServer{}; err := p.Start(0); return p.server, err }},
		{"rdp", func() (net.Listener, error) { p := &RDPProxyServer{}; err := p.Start(0); return p.server, err }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := tc.start()
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			defer func() { _ = ln.Close() }()

			addr, ok := ln.Addr().(*net.TCPAddr)
			if !ok {
				t.Fatalf("unexpected listener address type %T", ln.Addr())
			}
			if !addr.IP.IsLoopback() {
				t.Fatalf("%s proxy bound to %s; must bind a loopback address, not all interfaces", tc.name, addr.IP)
			}
		})
	}
}
