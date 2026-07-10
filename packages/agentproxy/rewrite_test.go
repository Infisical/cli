package agentproxy

import (
	"fmt"
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

func TestHeaderRewritePrefixVariations(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		value  string
		want   string
	}{
		{"with prefix has exactly one space", "Bearer", "sk_live_real", "Bearer sk_live_real"},
		{"empty prefix has no leading space", "", "abc123", "abc123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newReq(t, "")
			svc := &resolvedService{credentials: []resolvedCredential{
				{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: tc.prefix, value: tc.value},
			}}
			if err := applyCredentials(req, svc); err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get("Authorization"); got != tc.want {
				t.Fatalf("want %q, got %q", tc.want, got)
			}
		})
	}
}

func TestSubstitutionInHeader(t *testing.T) {
	req := newReq(t, "")
	req.Header.Set("X-Custom", "prefix-PLACEHOLDER-suffix")
	svc := &resolvedService{credentials: []resolvedCredential{
		{role: roleCredentialSub, placeholder: "PLACEHOLDER", value: "REALSECRET", surfaces: []string{surfaceHeader}},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Custom"); got != "prefix-REALSECRET-suffix" {
		t.Fatalf("header not substituted: %q", got)
	}
}

func TestSubstitutionAcrossAllSurfacesInOneCredential(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/PLACEHOLDER/x?q=PLACEHOLDER", strings.NewReader(`{"k":"PLACEHOLDER"}`))
	req.Header.Set("X-Token", "pre-PLACEHOLDER-post")
	svc := &resolvedService{credentials: []resolvedCredential{
		{
			role:        roleCredentialSub,
			placeholder: "PLACEHOLDER",
			value:       "REALSECRET",
			surfaces:    []string{surfacePath, surfaceQuery, surfaceBody, surfaceHeader},
		},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(req.URL.Path, "PLACEHOLDER") || !strings.Contains(req.URL.Path, "REALSECRET") {
		t.Fatalf("path not substituted: %q", req.URL.Path)
	}
	if strings.Contains(req.URL.RawQuery, "PLACEHOLDER") || !strings.Contains(req.URL.RawQuery, "REALSECRET") {
		t.Fatalf("query not substituted: %q", req.URL.RawQuery)
	}
	if got := req.Header.Get("X-Token"); got != "pre-REALSECRET-post" {
		t.Fatalf("header not substituted: %q", got)
	}
	body, _ := io.ReadAll(req.Body)
	if strings.Contains(string(body), "PLACEHOLDER") || !strings.Contains(string(body), "REALSECRET") {
		t.Fatalf("body not substituted: %q", string(body))
	}
}

func TestHeaderRewriteAndSubstitutionCombined(t *testing.T) {
	req := newReq(t, "")
	svc := &resolvedService{credentials: []resolvedCredential{
		{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "sk_live_real"},
		{role: roleCredentialSub, placeholder: "placeholder_x", value: "real_secret", surfaces: []string{surfaceQuery}},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk_live_real" {
		t.Fatalf("unexpected Authorization header: %q", got)
	}
	if strings.Contains(req.URL.RawQuery, "placeholder_x") || !strings.Contains(req.URL.RawQuery, "real_secret") {
		t.Fatalf("query not substituted: %q", req.URL.RawQuery)
	}
}

func TestMultipleSubstitutionsDistinctPlaceholders(t *testing.T) {
	req := newReq(t, `{"a":"PH_ONE","b":"PH_TWO"}`)
	svc := &resolvedService{credentials: []resolvedCredential{
		{role: roleCredentialSub, placeholder: "PH_ONE", value: "real_one", surfaces: []string{surfaceBody}},
		{role: roleCredentialSub, placeholder: "PH_TWO", value: "real_two", surfaces: []string{surfaceBody}},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "real_one") || !strings.Contains(string(body), "real_two") ||
		strings.Contains(string(body), "PH_ONE") || strings.Contains(string(body), "PH_TWO") {
		t.Fatalf("both placeholders should be substituted: %q", string(body))
	}
}

func TestBodySubstitutionUpdatesContentLength(t *testing.T) {
	req := newReq(t, `{"token":"placeholder_x"}`)
	svc := &resolvedService{credentials: []resolvedCredential{
		{role: roleCredentialSub, placeholder: "placeholder_x", value: "a_substantially_longer_real_secret", surfaces: []string{surfaceBody}},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	if req.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength %d does not match body length %d", req.ContentLength, len(body))
	}
	if got := req.Header.Get("Content-Length"); got != fmt.Sprintf("%d", len(body)) {
		t.Fatalf("Content-Length header %q does not match body length %d", got, len(body))
	}
}

func TestBodySubstitutionSkippedWhenContentEncoded(t *testing.T) {
	req := newReq(t, `{"token":"placeholder_x"}`)
	req.Header.Set("Content-Encoding", "gzip")
	svc := &resolvedService{credentials: []resolvedCredential{
		{role: roleCredentialSub, placeholder: "placeholder_x", value: "real_secret", surfaces: []string{surfaceBody}},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "placeholder_x") {
		t.Fatalf("encoded body must not be rewritten: %q", string(body))
	}
}

func TestBodyOversizedForwardedUnchanged(t *testing.T) {
	original := "placeholder_x" + strings.Repeat("a", maxBodyRewriteSize)
	req := newReq(t, original)
	svc := &resolvedService{credentials: []resolvedCredential{
		{role: roleCredentialSub, placeholder: "placeholder_x", value: "real_secret", surfaces: []string{surfaceBody}},
	}}
	if err := applyCredentials(req, svc); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	if len(body) != len(original) {
		t.Fatalf("oversized body must be forwarded whole, not truncated: got %d want %d", len(body), len(original))
	}
	if !strings.Contains(string(body), "placeholder_x") {
		t.Fatalf("oversized body must be forwarded unchanged (placeholder intact)")
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
