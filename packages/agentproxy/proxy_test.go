package agentproxy

import "testing"

func TestParseConnectTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		hostname string
		port     string
		wantErr  bool
	}{
		{name: "host with port", target: "api.stripe.com:443", hostname: "api.stripe.com", port: "443"},
		{name: "host without port defaults to 443", target: "api.stripe.com", hostname: "api.stripe.com", port: "443"},
		{name: "host with custom port", target: "internal.corp.com:3000", hostname: "internal.corp.com", port: "3000"},
		{name: "bracketed IPv6 with port", target: "[::1]:8443", hostname: "::1", port: "8443"},
		{name: "bracketed IPv6 without port defaults to 443", target: "[::1]", hostname: "::1", port: "443"},
		{name: "IPv4 with port", target: "127.0.0.1:443", hostname: "127.0.0.1", port: "443"},
		{name: "IPv4 without port defaults to 443", target: "127.0.0.1", hostname: "127.0.0.1", port: "443"},
		{name: "unbracketed IPv6 is rejected", target: "::1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostname, port, err := parseConnectTarget(tt.target)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q:%q", tt.target, hostname, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.target, err)
			}
			if hostname != tt.hostname || port != tt.port {
				t.Fatalf("parseConnectTarget(%q) = %q, %q; want %q, %q", tt.target, hostname, port, tt.hostname, tt.port)
			}
		})
	}
}
