package gcp

import "testing"

func TestIsGCPHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"googleapis.com", true},
		{"storage.googleapis.com", true},
		{"compute.googleapis.com", true},
		{"oauth2.googleapis.com:443", true},
		{"storage.googleapis.com:443", true},

		{"evil.com", false},
		{"evil.com#.googleapis.com", false},
		{"evil.com?.googleapis.com", false},
		{"evil.com/.googleapis.com", false},
		{"evil.com\\.googleapis.com", false},
		{"user@googleapis.com", false},
		{"user:pass@googleapis.com", false},
		{"notgoogleapis.com", false},
		{"evil-googleapis.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := isGCPHost(tt.host); got != tt.want {
				t.Errorf("isGCPHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}
