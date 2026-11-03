package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/util"
)

func secretsManagerDefaultsOutput(t *testing.T, setup func()) string {
	t.Helper()
	for _, name := range []string{util.INFISICAL_TOKEN_NAME, util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, util.INFISICAL_GATEWAY_TOKEN_NAME_LEGACY,
		util.INFISICAL_PROJECT_ID_NAME, util.INFISICAL_ENVIRONMENT_NAME, util.INFISICAL_SECRET_PATH_NAME} {
		t.Setenv(name, "")
	}
	t.Chdir(t.TempDir())
	if setup != nil {
		setup()
	}
	var out bytes.Buffer
	oldStdout := util.GetStdoutWriter
	util.GetStdoutWriter = func() io.Writer { return &out }
	t.Cleanup(func() { util.GetStdoutWriter = oldStdout })
	printSecretsManagerDefaults()
	return out.String()
}

func linkDirectory(t *testing.T, yaml string) {
	t.Helper()
	if err := os.WriteFile(util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProfileCurrentShowsWhatCommandsHereUse(t *testing.T) {
	cases := map[string]struct {
		setup func()
		want  []string
		never []string
	}{
		"a linked directory with no environment falls back to dev": {
			setup: func() { linkDirectory(t, "secrets-management:\n  project-id: "+testProjectID+"\n") },
			want: []string{"Project: " + testProjectID + "\n", "Project via: .infisical.yaml\n",
				"Environment: dev\n", "Environment via: default\n", "Secret path: /\n", "Secret path via: default\n", "Project config: "},
			never: []string{"Token override"},
		},
		"environment variables win over the config file": {
			setup: func() {
				linkDirectory(t, "secrets-management:\n  project-id: fromfile\n  environment: staging\n  secret-path: /app\n")
				t.Setenv(util.INFISICAL_PROJECT_ID_NAME, "fromenv")
				t.Setenv(util.INFISICAL_ENVIRONMENT_NAME, "prod")
			},
			want: []string{"Project: fromenv\n", "Project via: INFISICAL_PROJECT_ID environment variable\n",
				"Environment: prod\n", "Environment via: INFISICAL_ENVIRONMENT environment variable\n",
				"Secret path: /app\n", "Secret path via: .infisical.yaml\n"},
		},
		"no project": {
			want:  []string{"Project: none. Run [infisical init]"},
			never: []string{"Project via", "Project config"},
		},
		"a service token reads its own project": {
			setup: func() {
				linkDirectory(t, "secrets-management:\n  project-id: "+testProjectID+"\n")
				t.Setenv(util.INFISICAL_TOKEN_NAME, "st.id.secret.key")
			},
			want: []string{"Token override: INFISICAL_TOKEN environment variable.", "Project: the service token's own project\n",
				"Project via: service token in INFISICAL_TOKEN environment variable, which takes the place of " + testProjectID + " from .infisical.yaml\n"},
			never: []string{"st.id.secret.key"},
		},
		"a machine identity token keeps the configured project": {
			setup: func() {
				linkDirectory(t, "secrets-management:\n  project-id: "+testProjectID+"\n")
				t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, "identity-access-token")
			},
			want:  []string{"Token override: INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN environment variable.", "Project: " + testProjectID + "\n"},
			never: []string{"identity-access-token"},
		},
		"an unreadable config file": {
			setup: func() { linkDirectory(t, "secrets-management: [\n") },
			want:  []string{"Project: unknown. The project config can't be read"},
			never: []string{"Project via", "yaml:"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			out := secretsManagerDefaultsOutput(t, c.setup)
			for _, want := range c.want {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q in:\n%s", want, out)
				}
			}
			for _, never := range c.never {
				if strings.Contains(out, never) {
					t.Errorf("unexpected %q in:\n%s", never, out)
				}
			}
		})
	}
}

// An unreadable config must stop the command, not run it as if the directory weren't linked.
func TestUnreadableProjectConfigStillStopsCommands(t *testing.T) {
	fake := &fakeEnvironmentsAPI{}
	fake.serve(t)
	setup := func() { linkDirectory(t, "secrets-management: [\n") }
	stderr, _, exited := runUnderSecretsManagerAfter(t, setup, buildEnvironmentsCmd, "environments", "get", "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeProjectConfigInvalid {
		t.Errorf("exited=%v stderr=%s", exited, stderr)
	}
}
