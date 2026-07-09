package agentproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newReq(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/charges?token=placeholder_x", strings.NewReader(body))
	return req
}

func TestBearerHeaderRewrite(t *testing.T) {
	req := newReq(t, "")
	svc := &resolvedService{credentials: []resolvedCredential{
		{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "sk_live_real"},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk_live_real" {
		t.Fatalf("unexpected Authorization header: %q", got)
	}
}

func TestApiKeyHeaderNoPrefix(t *testing.T) {
	req := newReq(t, "")
	svc := &resolvedService{credentials: []resolvedCredential{
		{role: roleHeaderRewrite, headerName: "x-api-key", value: "abc123"},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("x-api-key"); got != "abc123" {
		t.Fatalf("unexpected x-api-key header: %q", got)
	}
}

func TestBasicAuthFromTwoCredentials(t *testing.T) {
	req := newReq(t, "")
	svc := &resolvedService{credentials: []resolvedCredential{
		{role: roleHeaderRewrite, headerPurpose: purposeUsername, value: "user"},
		{role: roleHeaderRewrite, headerPurpose: purposePassword, value: "pass"},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	// base64("user:pass") == "dXNlcjpwYXNz"
	if got := req.Header.Get("Authorization"); got != "Basic dXNlcjpwYXNz" {
		t.Fatalf("unexpected basic auth header: %q", got)
	}
}

func TestSubstitutionInQuery(t *testing.T) {
	req := newReq(t, "")
	svc := &resolvedService{credentials: []resolvedCredential{
		{role: roleCredentialSub, placeholder: "placeholder_x", value: "real_secret", surfaces: []string{surfaceQuery}},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(req.URL.RawQuery, "real_secret") || strings.Contains(req.URL.RawQuery, "placeholder_x") {
		t.Fatalf("query not substituted: %q", req.URL.RawQuery)
	}
}

func TestSubstitutionInPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://api.telegram.org/", nil)
	req.URL.Path = "/botplaceholder_tg/sendMessage"
	svc := &resolvedService{credentials: []resolvedCredential{
		{role: roleCredentialSub, placeholder: "placeholder_tg", value: "12345:realtoken", surfaces: []string{surfacePath}},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(req.URL.Path, "12345:realtoken") {
		t.Fatalf("path not substituted: %q", req.URL.Path)
	}
}

func TestSubstitutionInBody(t *testing.T) {
	req := newReq(t, `{"token":"placeholder_x"}`)
	svc := &resolvedService{credentials: []resolvedCredential{
		{role: roleCredentialSub, placeholder: "placeholder_x", value: "real_secret", surfaces: []string{surfaceBody}},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "real_secret") || strings.Contains(string(body), "placeholder_x") {
		t.Fatalf("body not substituted: %q", string(body))
	}
}

func TestProxyAuthParsing(t *testing.T) {
	// base64("proj-123:prod/myapp:jwt.abc.def")
	header := "Basic cHJvai0xMjM6cHJvZC9teWFwcDpqd3QuYWJjLmRlZg=="
	scope, jwt, ok := parseProxyAuth(header)
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if scope.projectID != "proj-123" || scope.environment != "prod" || scope.secretPath != "/myapp" {
		t.Fatalf("unexpected scope: %+v", scope)
	}
	if jwt != "jwt.abc.def" {
		t.Fatalf("unexpected jwt: %q", jwt)
	}
}
