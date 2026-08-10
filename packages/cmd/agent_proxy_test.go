package cmd

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

// Every command offering --auth-method has to declare all of the flags the strategies read, including
// the ones only some methods use. GetCmdFlagOrEnv looks a flag up before it looks at the environment
// and errors on a name the command never declared, so a missing registration breaks that method even
// for someone who only ever set its environment variable, and does it at authentication time rather
// than at startup.
func TestMachineIdentityAuthFlagsAreRegistered(t *testing.T) {
	commands := map[string]*cobra.Command{
		"agent-proxy start":   agentProxyStartCmd,
		"agent-proxy connect": agentProxyConnectCmd,
		"pam agentic-access":  pamAgenticAccessCmd,
	}

	for name, cmd := range commands {
		t.Run(name, func(t *testing.T) {
			for _, flag := range util.MachineIdentityAuthFlags {
				if cmd.Flags().Lookup(flag) == nil {
					t.Errorf("%s does not register --%s", name, flag)
				}
			}
		})
	}
}

// Which credentials win when more than one is present, asserted on the branch resolveAgentProxyLogin
// picks rather than on a login it cannot perform in a test. Only the non-erroring paths are covered:
// the rest of packages/cmd exits the process on a bad input, and this follows that.
func TestResolveAgentProxyLoginPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		env        map[string]string
		wantLogin  bool
		wantSource string
	}{
		{
			name:      "nothing configured leaves the caller on its token fallback",
			wantLogin: false,
		},
		{
			name: "client credentials on their own mean universal-auth",
			env: map[string]string{
				util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME:     "id",
				util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME: "secret",
			},
			wantLogin:  true,
			wantSource: "universal-auth-env",
		},
		{
			name:       "an explicit auth method is used",
			env:        map[string]string{util.INFISICAL_AUTH_METHOD_NAME: "aws-iam"},
			wantLogin:  true,
			wantSource: "aws-iam-env",
		},
		{
			name: "an explicit auth method beats client credentials",
			env: map[string]string{
				util.INFISICAL_AUTH_METHOD_NAME:                  "aws-iam",
				util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME:     "id",
				util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME: "secret",
			},
			wantLogin:  true,
			wantSource: "aws-iam-env",
		},
		{
			// "user" is how some callers spell the human login, and there is no such thing here, so it
			// has to fall through rather than be treated as a method name.
			name:      "the user pseudo-method is not a machine identity",
			env:       map[string]string{util.INFISICAL_AUTH_METHOD_NAME: "user"},
			wantLogin: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, key := range append([]string{}, util.MachineIdentityAuthEnvVars...) {
				t.Setenv(key, "")
			}
			for key, value := range tt.env {
				t.Setenv(key, value)
			}

			login, source := resolveAgentProxyLogin(agentProxyConnectCmd)

			if (login != nil) != tt.wantLogin {
				t.Fatalf("login != nil = %v, want %v", login != nil, tt.wantLogin)
			}
			if source != tt.wantSource {
				t.Errorf("source = %q, want %q", source, tt.wantSource)
			}
		})
	}
}

// The scrub list is derived from the auth env vars rather than written out, so that adding a machine
// identity auth method cannot quietly widen what the agent inherits. This checks the derivation held.
func TestCredentialEnvKeysCoverEveryAuthEnvVar(t *testing.T) {
	scrubbed := make(map[string]bool, len(credentialEnvKeys))
	for _, key := range credentialEnvKeys {
		scrubbed[key] = true
	}

	for _, envVar := range util.MachineIdentityAuthEnvVars {
		if !scrubbed[envVar] {
			t.Errorf("%s reaches the agent; add it to credentialEnvKeys", envVar)
		}
	}
}

// buildAgentEnv is what stands between the parent's credentials and the agent, so the guarantee is
// worth asserting on the built environment and not just on the list feeding it.
func TestBuildAgentEnvScrubsMachineIdentityCredentials(t *testing.T) {
	for _, envVar := range append([]string{util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME}, util.MachineIdentityAuthEnvVars...) {
		t.Setenv(envVar, "leaked-"+envVar)
	}

	env := buildAgentEnv("http://proxy:17322", "/tmp/ca.pem", "agent-jwt", "", nil, nil)

	for _, entry := range env {
		key, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(value, "leaked-") {
			t.Errorf("%s reached the agent's environment", key)
		}
	}
}

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
