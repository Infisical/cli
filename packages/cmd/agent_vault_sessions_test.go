package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func TestMintAgentVaultSessionSendsTheProject(t *testing.T) {
	var sent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent-vault/sessions" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &sent)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session":{"id":"s1","token":"agv_x","projectId":"` + projectFromFlag + `","label":null,"expiresAt":null,"createdAt":"2026-11-04T00:00:00Z","accessBundle":{"id":"b1","name":"coding-agent"}}}`))
	}))
	t.Cleanup(srv.Close)
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = old })

	minted, err := mintAgentVaultSession(resty.New(), agentVaultProject{ID: projectFromFlag}, []string{"coding-agent"}, "8h", "")
	if err != nil {
		t.Fatal(err)
	}
	if sent["projectId"] != projectFromFlag || sent["accessBundle"] != "coding-agent" || sent["ttl"] != "8h" {
		t.Fatalf("body %v", sent)
	}
	if _, ok := sent["label"]; ok {
		t.Fatalf("an empty label should stay out of the body: %v", sent)
	}
	if minted.Token != "agv_x" || minted.ProjectID != projectFromFlag || minted.AccessBundle == nil || minted.AccessBundle.Name != "coding-agent" {
		t.Fatalf("minted %+v", minted)
	}
}

func TestAgentVaultSessionOutputFormats(t *testing.T) {
	label, expires := "nightly deploy", "2026-11-05T00:00:00Z"
	out := agentVaultSessionOutputFrom(api.AgentVaultSession{
		ID: "s1", Token: "agv_x", ProjectID: projectFromFlag, Label: &label, ExpiresAt: &expires,
		AccessBundle: &api.AgentVaultSessionAccessBundle{ID: "b1", Name: "coding-agent"},
	}, agentVaultProject{ID: projectFromFlag}, "coding-agent")
	want := map[string]any{
		"id": "s1", "token": "agv_x", "projectId": projectFromFlag, "accessBundle": "coding-agent",
		"label": label, "expiresAt": expires,
	}

	for _, format := range []string{util.OUTPUT_FORMAT_JSON, util.OUTPUT_FORMAT_YAML} {
		formatted, err := util.FormatOutput(format, out, nil)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if format == util.OUTPUT_FORMAT_JSON {
			err = json.Unmarshal([]byte(formatted), &got)
		} else {
			err = yaml.Unmarshal([]byte(formatted), &got)
		}
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: keys %v, want %v", format, got, want)
		}
		for key, value := range want {
			if got[key] != value {
				t.Errorf("%s: %s = %v, want %v", format, key, got[key], value)
			}
		}
	}
}

func TestAgentVaultSessionOutputWithNoExpiryOrLabelPrintsNull(t *testing.T) {
	formatted, err := util.FormatOutput(util.OUTPUT_FORMAT_JSON, agentVaultSessionOutputFrom(api.AgentVaultSession{ID: "s1", Token: "agv_x"}, agentVaultProject{ID: projectFromFlag}, "coding-agent"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{`"expiresAt":null`, `"label":null`, `"projectId":"` + projectFromFlag + `"`, `"accessBundle":"coding-agent"`} {
		if !strings.Contains(formatted, part) {
			t.Errorf("want %s in %s", part, formatted)
		}
	}
}

func TestValidateAgentVaultRevokeTarget(t *testing.T) {
	id := "0b6f3a1e-1111-4111-8111-111111111111"
	cases := []struct {
		name      string
		args      []string
		envToken  string
		wantToken string
		wantErr   string
	}{
		{"by id", []string{id}, "", "", ""},
		{"by id ignores the variable", []string{id}, "agv_env", "", ""},
		{"by token", []string{"--session-token", " agv_x "}, "", "agv_x", ""},
		{"the flag beats the variable", []string{"--session-token", "agv_x"}, "agv_env", "agv_x", ""},
		{"by the variable", nil, "agv_env", "agv_env", ""},
		{"both", []string{id, "--session-token", "agv_x"}, "", "", "not both"},
		{"neither", nil, "", "", "name the session to revoke"},
		{"empty token", []string{"--session-token", "  "}, "agv_env", "", "--session-token was given but is empty"},
		{"a token as the argument", []string{"agv_secretvalue"}, "", "", "looks like a session token, not a session ID"},
		{"not an id", []string{"secret-ish-value"}, "", "", "the argument is not a session ID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(agentVaultSessionTokenEnv, tc.envToken)
			cmd := &cobra.Command{Use: "revoke", Run: func(*cobra.Command, []string) {}}
			cmd.Flags().String("session-token", "", "")
			if err := cmd.Flags().Parse(tc.args); err != nil {
				t.Fatal(err)
			}

			token, err := validateAgentVaultRevokeTarget(cmd, cmd.Flags().Args())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if token != tc.wantToken {
					t.Fatalf("token %q, want %q", token, tc.wantToken)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err %v, want %q", err, tc.wantErr)
			}
			for _, arg := range cmd.Flags().Args() {
				if strings.Contains(err.Error(), arg) {
					t.Fatalf("the error echoes the argument %q: %v", arg, err)
				}
			}
		})
	}
}

func fakeAgentVaultRevokeServer(t *testing.T, auth, path *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*auth, *path = r.Header.Get("Authorization"), r.Method+" "+r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session":{"id":"s1","revokedAt":"2026-11-04T00:00:00Z"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func useAgentVaultDomainExplicitlySet(t *testing.T, set bool) {
	t.Helper()
	old := config.INFISICAL_DOMAIN_EXPLICITLY_SET
	config.INFISICAL_DOMAIN_EXPLICITLY_SET = set
	t.Cleanup(func() { config.INFISICAL_DOMAIN_EXPLICITLY_SET = old })
}

func TestRevokeAgentVaultSessionByTokenSendsOnlyTheToken(t *testing.T) {
	var auth, path string
	srv := fakeAgentVaultRevokeServer(t, &auth, &path)
	useInfisicalURL(t, srv.URL+"/api")
	useAgentVaultDomainExplicitlySet(t, true)

	id, err := revokeAgentVaultSessionByToken(context.Background(), resty.New(), "agv_x")
	if err != nil {
		t.Fatal(err)
	}
	if id != "s1" || auth != "Bearer agv_x" || path != "POST /api/v1/agent-vault/session/revoke" {
		t.Fatalf("id %q, auth %q, path %q", id, auth, path)
	}
}

func TestRevokeAgentVaultSessionByTokenIgnoresTheDomainInARepoFile(t *testing.T) {
	var auth, path string
	srv := fakeAgentVaultRevokeServer(t, &auth, &path)
	home := isolateSkillsHome(t)
	if err := os.MkdirAll(filepath.Join(home, util.CONFIG_FOLDER_NAME), 0o700); err != nil {
		t.Fatal(err)
	}
	profile := `{"LoggedInUserDomain":"` + srv.URL + `"}`
	if err := os.WriteFile(filepath.Join(home, util.CONFIG_FOLDER_NAME, util.CONFIG_FILE_NAME), []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME), []byte("version: 1\ngeneral:\n  domain: https://evil.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	useInfisicalURL(t, "https://evil.example/api")
	useAgentVaultDomainExplicitlySet(t, false)
	warnings := captureWarnings(t)

	if _, err := revokeAgentVaultSessionByToken(context.Background(), resty.New(), "agv_x"); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer agv_x" || config.INFISICAL_URL != srv.URL+"/api" {
		t.Fatalf("the token went to %s (auth %q)", config.INFISICAL_URL, auth)
	}
	if warnings.Len() != 0 {
		t.Fatalf("an Agent Vault command does not read the file, so has nothing to warn about: %q", warnings.String())
	}
}

func TestRevokeAgentVaultSessionStopsAtItsDeadline(t *testing.T) {
	var auth, path string
	srv := fakeAgentVaultRevokeServer(t, &auth, &path)
	useInfisicalURL(t, srv.URL+"/api")
	useAgentVaultDomainExplicitlySet(t, true)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	if _, err := revokeAgentVaultSessionByToken(ctx, resty.New(), "agv_x"); err == nil {
		t.Fatal("a revoke past its deadline should fail")
	}
	if err := api.CallRevokeAgentVaultSession(ctx, resty.New(), "s1"); err == nil {
		t.Fatal("a revoke by ID past its deadline should fail")
	}
	if auth != "" {
		t.Fatal("nothing should be sent past the deadline")
	}
	if messages := agentVaultRevokeErrorMessages(ctx, errors.New("timeout"), true); len(messages) != 1 || !strings.Contains(messages[0], "did not answer within 30s") {
		t.Fatalf("messages %v", messages)
	}
}

func TestAgentVaultRevokeErrorMessages(t *testing.T) {
	unauthorized := &api.APIError{StatusCode: http.StatusUnauthorized}
	if messages := agentVaultRevokeErrorMessages(context.Background(), unauthorized, true); !strings.Contains(messages[0], "does not recognize this session token") {
		t.Fatalf("by token: %v", messages)
	}
	if messages := agentVaultRevokeErrorMessages(context.Background(), unauthorized, false); messages[0] != "Unable to revoke the session" {
		t.Fatalf("by ID: %v", messages)
	}
}

func TestRefuseAgentVaultMintOnlyFlagsRefusesAProjectWithASessionToken(t *testing.T) {
	newCmd := func(args ...string) *cobra.Command {
		cmd := &cobra.Command{Use: "run", Run: func(*cobra.Command, []string) {}}
		cmd.Flags().String("ttl", "never", "")
		cmd.Flags().Bool("keep-session", false, "")
		cmd.Flags().String("project-id", "", "")
		if err := cmd.Flags().Parse(args); err != nil {
			t.Fatal(err)
		}
		return cmd
	}

	err := refuseAgentVaultMintOnlyFlags(newCmd("--project-id", projectFromFlag), "agv_x", agentVaultSourceEnv)
	if err == nil || !strings.Contains(err.Error(), "--project-id") || !strings.Contains(err.Error(), agentVaultSessionTokenEnv) {
		t.Fatalf("err %v", err)
	}
	if err := refuseAgentVaultMintOnlyFlags(newCmd("--project-id", projectFromFlag), "", agentVaultSourceNone); err != nil {
		t.Fatalf("minting takes --project-id: %v", err)
	}
	// A project in the environment is ambient, so a run on a dashboard session just ignores it.
	t.Setenv(agentVaultProjectIDEnv, projectFromAgvEnv)
	if err := refuseAgentVaultMintOnlyFlags(newCmd(), "agv_x", agentVaultSourceFlag); err != nil {
		t.Fatalf("err %v", err)
	}
}
