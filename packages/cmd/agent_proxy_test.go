package cmd

import (
	"reflect"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
)

func TestReadableBrokeredSecrets(t *testing.T) {
	brokered := map[string]struct{}{"STRIPE_API_KEY": {}, "GITHUB_TOKEN": {}}
	real := func(keys ...string) []models.SingleEnvironmentVariable {
		out := make([]models.SingleEnvironmentVariable, len(keys))
		for i, k := range keys {
			out[i] = models.SingleEnvironmentVariable{Key: k}
		}
		return out
	}

	tests := []struct {
		name string
		real []models.SingleEnvironmentVariable
		want []string
	}{
		{name: "no overlap", real: real("DATABASE_URL", "OTHER"), want: nil},
		{name: "agent has no readable secrets", real: nil, want: nil},
		{name: "single overlap", real: real("DATABASE_URL", "STRIPE_API_KEY"), want: []string{"STRIPE_API_KEY"}},
		{name: "multiple overlap sorted", real: real("GITHUB_TOKEN", "DATABASE_URL", "STRIPE_API_KEY"), want: []string{"GITHUB_TOKEN", "STRIPE_API_KEY"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := readableBrokeredSecrets(brokered, tt.real); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

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
