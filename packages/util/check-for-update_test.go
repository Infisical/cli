package util

import (
	"testing"
)

func TestGetUpdateInstructions(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		execPath string
		expected string
	}{
		// darwin
		{
			name:     "darwin brew",
			goos:     "darwin",
			execPath: "/opt/homebrew/bin/infisical",
			expected: "brew update && brew upgrade infisical",
		},
		{
			name:     "darwin npm",
			goos:     "darwin",
			execPath: "/opt/homebrew/lib/node_modules/@infisical/cli/bin/infisical",
			expected: "npm update -g @infisical/cli",
		},

		// windows
		{
			name:     "windows scoop",
			goos:     "windows",
			execPath: `C:\Users\user\scoop\apps\infisical\current\infisical.exe`,
			expected: "scoop update infisical",
		},
		{
			name:     "windows npm",
			goos:     "windows",
			execPath: `C:\Users\user\AppData\Roaming\npm\node_modules\@infisical\cli\bin\infisical.exe`,
			expected: "npm update -g @infisical/cli",
		},
		{
			name:     "windows winget",
			goos:     "windows",
			execPath: `C:\Users\user\AppData\Local\Microsoft\WinGet\Links\infisical.exe`,
			expected: "winget upgrade Infisical.Infisical",
		},
		{
			name:     "windows unknown defaults to scoop",
			goos:     "windows",
			execPath: `C:\infisical\infisical.exe`,
			expected: "scoop update infisical",
		},

		// linux
		{
			name:     "linux apt",
			goos:     "linux",
			execPath: "/usr/bin/infisical",
			expected: "", // apt detection is runtime — tested in integration
		},
		{
			name:     "linux npm",
			goos:     "linux",
			execPath: "/home/user/.npm-global/lib/node_modules/@infisical/cli/bin/infisical",
			expected: "npm update -g @infisical/cli",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getUpdateInstructions(tt.goos, tt.execPath)
			if tt.expected == "" {
				return // skip runtime-dependent cases
			}
			if !contains(result, tt.expected) {
				t.Errorf("expected %q to contain %q", result, tt.expected)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
