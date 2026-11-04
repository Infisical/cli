package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		_, _ = w.Write([]byte(`{"session":{"id":"s1","token":"agv_x","projectId":"` + projectFromFlag + `","label":null,"expiresAt":null,"createdAt":"2026-11-04T00:00:00Z","accessBundles":[{"id":"b1","name":"coding-agent"}]}}`))
	}))
	t.Cleanup(srv.Close)
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = old })

	minted, err := mintAgentVaultSession(resty.New(), agentVaultProject{ID: projectFromFlag}, []string{"coding-agent"}, "8h", "")
	if err != nil {
		t.Fatal(err)
	}
	if sent["projectId"] != projectFromFlag || sent["ttl"] != "8h" {
		t.Fatalf("body %v", sent)
	}
	if _, ok := sent["label"]; ok {
		t.Fatalf("an empty label should stay out of the body: %v", sent)
	}
	if minted.Token != "agv_x" || minted.ProjectID != projectFromFlag || len(minted.AccessBundles) != 1 || minted.AccessBundles[0].Name != "coding-agent" {
		t.Fatalf("minted %+v", minted)
	}
}

func TestAgentVaultSessionOutputFormats(t *testing.T) {
	label, expires := "nightly deploy", "2026-11-05T00:00:00Z"
	out := agentVaultSessionOutputFrom(api.AgentVaultSession{
		ID: "s1", Token: "agv_x", ProjectID: projectFromFlag, Label: &label, ExpiresAt: &expires,
		AccessBundles: []api.AgentVaultSessionAccessBundle{{ID: "b1", Name: "coding-agent"}},
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
		name       string
		args       []string
		tokenGiven bool
		token      string
		wantErr    string
	}{
		{"by id", []string{id}, false, "", ""},
		{"by token", nil, true, "agv_x", ""},
		{"both", []string{id}, true, "agv_x", "not both"},
		{"neither", nil, false, "", "name the session"},
		{"empty token", nil, true, "  ", "--session-token was given but is empty"},
		{"not an id", []string{"agv_x"}, false, "", "is not a session ID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAgentVaultRevokeTarget(tc.args, tc.tokenGiven, tc.token)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestRevokeAgentVaultSessionByTokenSendsOnlyTheToken(t *testing.T) {
	var auth, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, path = r.Header.Get("Authorization"), r.Method+" "+r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session":{"id":"s1","revokedAt":"2026-11-04T00:00:00Z"}}`))
	}))
	t.Cleanup(srv.Close)
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = old })

	id, err := revokeAgentVaultSessionByToken(resty.New(), "agv_x")
	if err != nil {
		t.Fatal(err)
	}
	if id != "s1" || auth != "Bearer agv_x" || path != "POST /api/v1/agent-vault/session/revoke" {
		t.Fatalf("id %q, auth %q, path %q", id, auth, path)
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
