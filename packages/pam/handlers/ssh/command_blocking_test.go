package ssh

import (
	"regexp"
	"testing"
)

func TestMatchBlockedCommand(t *testing.T) {
	proxy := &SSHProxy{
		config: SSHProxyConfig{
			BlockedCommandPatterns: []*regexp.Regexp{
				regexp.MustCompile(`rm\s+-rf`),
				regexp.MustCompile(`shutdown`),
				regexp.MustCompile(`reboot`),
			},
		},
	}

	tests := []struct {
		name    string
		command string
		blocked bool
	}{
		{"blocks rm -rf", "rm -rf /", true},
		{"blocks rm  -rf with extra space", "rm  -rf /home", true},
		{"blocks sudo rm -rf", "sudo rm -rf /", true},
		{"blocks shutdown", "shutdown -h now", true},
		{"blocks reboot", "reboot", true},
		{"allows ls", "ls -la", false},
		{"allows rm without -rf", "rm file.txt", false},
		{"allows empty command", "", false},
		{"allows whitespace only", "   ", false},
		{"allows normal commands", "cat /etc/hosts", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := proxy.matchBlockedCommand(tt.command)
			if result != tt.blocked {
				t.Errorf("matchBlockedCommand(%q) = %v, want %v", tt.command, result, tt.blocked)
			}
		})
	}
}

func TestMatchBlockedCommandNoPatterns(t *testing.T) {
	proxy := &SSHProxy{
		config: SSHProxyConfig{},
	}

	if proxy.matchBlockedCommand("rm -rf /") {
		t.Error("with no patterns, should never block")
	}
}
