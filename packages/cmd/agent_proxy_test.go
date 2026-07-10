package cmd

import "testing"

func TestMergeNoProxy(t *testing.T) {
	tests := []struct {
		name     string
		operator []string
		want     string
	}{
		{
			name:     "defaults only when no operator entries",
			operator: nil,
			want:     "localhost,127.0.0.1",
		},
		{
			name:     "operator entries are appended after the loopback defaults",
			operator: []string{"app.infisical.com,internal.corp.com"},
			want:     "localhost,127.0.0.1,app.infisical.com,internal.corp.com",
		},
		{
			name:     "duplicates and blanks are removed, loopback is never dropped",
			operator: []string{"localhost, ,app.infisical.com", "app.infisical.com,10.0.0.5"},
			want:     "localhost,127.0.0.1,app.infisical.com,10.0.0.5",
		},
		{
			name:     "empty operator strings are ignored",
			operator: []string{"", ""},
			want:     "localhost,127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeNoProxy(tt.operator...); got != tt.want {
				t.Fatalf("mergeNoProxy(%v) = %q; want %q", tt.operator, got, tt.want)
			}
		})
	}
}
