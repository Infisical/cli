package agentproxy

import (
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestLevelFor(t *testing.T) {
	cases := map[string]zerolog.Level{
		decisionBrokered:    zerolog.InfoLevel,
		decisionPassthrough: zerolog.DebugLevel,
		decisionBlocked:     zerolog.WarnLevel,
		decisionError:       zerolog.ErrorLevel,
		decisionCanceled:    zerolog.DebugLevel,
	}
	for decision, want := range cases {
		if got := levelFor(decision); got != want {
			t.Fatalf("levelFor(%q) = %v, want %v", decision, got, want)
		}
	}
}

func TestApplyCredentialsReportsHeaderRewrite(t *testing.T) {
	req := newReq(t, "")
	svc := &resolvedService{credentials: []resolvedCredential{
		{secretKey: "ACME_API_KEY", role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "sk_real"},
	}}
	applied, err := applyCredentials(req, svc.credentials)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 {
		t.Fatalf("want 1 applied credential, got %d", len(applied))
	}
	got := applied[0]
	if got.Key != "ACME_API_KEY" || got.Role != roleHeaderRewrite || got.Header != "Authorization" {
		t.Fatalf("unexpected applied credential: %+v", got)
	}
}

func TestApplyCredentialsReportsDynamicSecret(t *testing.T) {
	req := newReq(t, "")
	svc := &resolvedService{credentials: []resolvedCredential{
		{
			role:         roleHeaderRewrite,
			headerName:   "Authorization",
			headerPrefix: "Bearer",
			value:        "minted-lease-value",
			dynamic:      &dynamicCredentialRef{secretName: "my-postgres-creds", field: "DB_PASSWORD"},
		},
	}}
	applied, err := applyCredentials(req, svc.credentials)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 {
		t.Fatalf("want 1 applied credential, got %d", len(applied))
	}
	got := applied[0]
	if got.Key != "" || got.DynamicSecretName != "my-postgres-creds" || got.DynamicSecretField != "DB_PASSWORD" {
		t.Fatalf("dynamic credential not recorded correctly: %+v", got)
	}
}

func TestApplyCredentialsReportsBasicAuthPair(t *testing.T) {
	req := newReq(t, "")
	svc := &resolvedService{credentials: []resolvedCredential{
		{secretKey: "JIRA_USER", role: roleHeaderRewrite, headerPurpose: purposeUsername, value: "user"},
		{secretKey: "JIRA_PASS", role: roleHeaderRewrite, headerPurpose: purposePassword, value: "pass"},
	}}
	applied, err := applyCredentials(req, svc.credentials)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 2 {
		t.Fatalf("want 2 applied credentials, got %d: %+v", len(applied), applied)
	}
	for _, c := range applied {
		if c.Header != "Authorization" || c.Role != roleHeaderRewrite {
			t.Fatalf("basic-auth entry should target Authorization: %+v", c)
		}
	}
	if applied[0].Purpose != purposeUsername || applied[1].Purpose != purposePassword {
		t.Fatalf("purposes not reported: %+v", applied)
	}
}

func TestApplyCredentialsReportsOnlyMatchedSurfaces(t *testing.T) {
	req := httptest.NewRequest("GET", "https://api.example.com/orders?id=placeholder_x", nil)
	svc := &resolvedService{credentials: []resolvedCredential{
		{secretKey: "ACME_ACCOUNT", role: roleCredentialSub, placeholder: "placeholder_x", value: "real", surfaces: []string{surfacePath, surfaceQuery}},
	}}
	applied, err := applyCredentials(req, svc.credentials)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 {
		t.Fatalf("want 1 applied credential, got %d", len(applied))
	}
	if len(applied[0].Surfaces) != 1 || applied[0].Surfaces[0] != surfaceQuery {
		t.Fatalf("want only [query], got %v", applied[0].Surfaces)
	}
}

func TestApplyCredentialsOmitsSubstitutionThatMatchedNothing(t *testing.T) {
	req := httptest.NewRequest("GET", "https://api.example.com/orders", nil)
	svc := &resolvedService{credentials: []resolvedCredential{
		{secretKey: "ACME_ACCOUNT", role: roleCredentialSub, placeholder: "placeholder_x", value: "real", surfaces: []string{surfacePath, surfaceQuery}},
	}}
	applied, err := applyCredentials(req, svc.credentials)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 0 {
		t.Fatalf("want 0 applied credentials, got %+v", applied)
	}
}
