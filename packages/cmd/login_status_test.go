package cmd

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
	jwt "github.com/golang-jwt/jwt/v5"
)

func TestFormatExpiry(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name       string
		expiresAt  time.Time
		wantPrefix string
		wantExact  string
	}{
		{
			name:      "already expired",
			expiresAt: now.Add(-1 * time.Minute),
			wantExact: "expired",
		},
		{
			name:      "exactly at now is expired",
			expiresAt: now,
			wantExact: "expired",
		},
		{
			name:       "minutes only",
			expiresAt:  now.Add(15*time.Minute + 30*time.Second),
			wantPrefix: "15m",
		},
		{
			name:       "hours and minutes",
			expiresAt:  now.Add(5*time.Hour + 30*time.Minute),
			wantPrefix: "5h ",
		},
		{
			name:       "days and hours",
			expiresAt:  now.Add(50*time.Hour + 30*time.Second),
			wantPrefix: "2d ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatExpiry(tc.expiresAt)
			if tc.wantExact != "" {
				if got != tc.wantExact {
					t.Errorf("formatExpiry(%v) = %q, want %q", tc.expiresAt, got, tc.wantExact)
				}
				return
			}
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("formatExpiry(%v) = %q, want prefix %q", tc.expiresAt, got, tc.wantPrefix)
			}
		})
	}
}

func TestParseLoginJWTClaims(t *testing.T) {
	t.Run("happy path with org and sub-org", func(t *testing.T) {
		exp := time.Now().Add(time.Hour).Unix()
		token := makeUnsignedJWT(t, map[string]any{
			"organizationId":    "org-1",
			"subOrganizationId": "sub-1",
			"exp":               exp,
		})

		claims, err := parseLoginJWTClaims(token)
		if err != nil {
			t.Fatalf("parseLoginJWTClaims: unexpected error: %v", err)
		}
		if claims.OrganizationID != "org-1" {
			t.Errorf("OrganizationID = %q, want %q", claims.OrganizationID, "org-1")
		}
		if claims.SubOrganizationID != "sub-1" {
			t.Errorf("SubOrganizationID = %q, want %q", claims.SubOrganizationID, "sub-1")
		}
		if claims.ExpiresAt == nil || claims.ExpiresAt.Unix() != exp {
			t.Errorf("ExpiresAt = %v, want unix %d", claims.ExpiresAt, exp)
		}
	})

	t.Run("machine identity claims parse", func(t *testing.T) {
		exp := time.Now().Add(time.Hour).Unix()
		token := makeUnsignedJWT(t, map[string]any{
			"identityId":   "id-123",
			"identityName": "my-ci-bot",
			"authMethod":   "universal-auth",
			"orgId":        "org-1",
			"exp":          exp,
		})

		claims, err := parseLoginJWTClaims(token)
		if err != nil {
			t.Fatalf("parseLoginJWTClaims: unexpected error: %v", err)
		}
		if claims.IdentityID != "id-123" {
			t.Errorf("IdentityID = %q, want %q", claims.IdentityID, "id-123")
		}
		if claims.IdentityName != "my-ci-bot" {
			t.Errorf("IdentityName = %q, want %q", claims.IdentityName, "my-ci-bot")
		}
		if claims.AuthMethod != "universal-auth" {
			t.Errorf("AuthMethod = %q, want %q", claims.AuthMethod, "universal-auth")
		}
		if claims.OrgID != "org-1" {
			t.Errorf("OrgID = %q, want %q", claims.OrgID, "org-1")
		}
	})

	t.Run("token without organization claims still parses", func(t *testing.T) {
		token := makeUnsignedJWT(t, map[string]any{
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		claims, err := parseLoginJWTClaims(token)
		if err != nil {
			t.Fatalf("parseLoginJWTClaims: unexpected error: %v", err)
		}
		if claims.OrganizationID != "" {
			t.Errorf("OrganizationID = %q, want empty", claims.OrganizationID)
		}
		if claims.SubOrganizationID != "" {
			t.Errorf("SubOrganizationID = %q, want empty", claims.SubOrganizationID)
		}
	})

	t.Run("malformed token returns error", func(t *testing.T) {
		if _, err := parseLoginJWTClaims("not-a-jwt"); err == nil {
			t.Errorf("parseLoginJWTClaims(%q) = nil error, want error", "not-a-jwt")
		}
	})

	t.Run("non-base64 payload returns error", func(t *testing.T) {
		if _, err := parseLoginJWTClaims("aaa.!!!.ccc"); err == nil {
			t.Errorf("parseLoginJWTClaims with bad payload = nil error, want error")
		}
	})
}

func TestDetectMachineIdentityEnvToken(t *testing.T) {
	t.Run("no env vars set", func(t *testing.T) {
		t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, "")
		t.Setenv(util.INFISICAL_TOKEN_NAME, "")

		if _, _, ok := detectMachineIdentityEnvToken(); ok {
			t.Errorf("detectMachineIdentityEnvToken() = ok, want !ok when no env vars set")
		}
	})

	t.Run("universal-auth access token takes precedence", func(t *testing.T) {
		t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, "ua-token")
		t.Setenv(util.INFISICAL_TOKEN_NAME, "should-be-ignored")

		token, source, ok := detectMachineIdentityEnvToken()
		if !ok {
			t.Fatalf("detectMachineIdentityEnvToken() = !ok, want ok")
		}
		if token != "ua-token" {
			t.Errorf("token = %q, want %q", token, "ua-token")
		}
		if !strings.Contains(source, util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME) {
			t.Errorf("source = %q, want it to contain %q", source, util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME)
		}
	})

	t.Run("falls back to INFISICAL_TOKEN", func(t *testing.T) {
		t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, "")
		t.Setenv(util.INFISICAL_TOKEN_NAME, "st.abc.def")

		token, source, ok := detectMachineIdentityEnvToken()
		if !ok {
			t.Fatalf("detectMachineIdentityEnvToken() = !ok, want ok")
		}
		if token != "st.abc.def" {
			t.Errorf("token = %q, want %q", token, "st.abc.def")
		}
		if !strings.Contains(source, util.INFISICAL_TOKEN_NAME) {
			t.Errorf("source = %q, want it to contain %q", source, util.INFISICAL_TOKEN_NAME)
		}
	})

	t.Run("whitespace-only env value is ignored", func(t *testing.T) {
		t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, "   ")
		t.Setenv(util.INFISICAL_TOKEN_NAME, "")

		if _, _, ok := detectMachineIdentityEnvToken(); ok {
			t.Errorf("detectMachineIdentityEnvToken() = ok for whitespace-only value, want !ok")
		}
	})
}

func TestContextStatus(t *testing.T) {
	cases := []struct {
		name string
		ctx  loginStatusContext
		want string
	}{
		{
			name: "user not expired, no verification",
			ctx:  loginStatusContext{kind: principalKindUser},
			want: statusAuthenticated,
		},
		{
			name: "locally expired user trumps backend",
			ctx: loginStatusContext{
				kind:         principalKindUser,
				loggedInUser: util.LoggedInUserDetails{LoginExpired: true},
				verification: verificationResult{state: verifyStateVerified},
			},
			want: statusExpired,
		},
		{
			name: "machine identity locally expired",
			ctx: loginStatusContext{
				kind: principalKindMachineIdentity,
				claims: loginTokenClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
					},
				},
			},
			want: statusExpired,
		},
		{
			name: "backend rejected downgrades to rejected",
			ctx: loginStatusContext{
				kind:         principalKindUser,
				verification: verificationResult{state: verifyStateRejected},
			},
			want: statusRejected,
		},
		{
			name: "unknown verification stays authenticated",
			ctx: loginStatusContext{
				kind:         principalKindUser,
				verification: verificationResult{state: verifyStateUnknown},
			},
			want: statusAuthenticated,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := contextStatus(tc.ctx); got != tc.want {
				t.Errorf("contextStatus = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVerifySession_NoToken(t *testing.T) {
	got := verifySession(loginStatusContext{kind: principalKindUser})
	if got.state != verifyStateSkipped {
		t.Errorf("verifySession no-token = %q, want %q", got.state, verifyStateSkipped)
	}
}

func TestVerifySession_LocallyExpiredSkipsCall(t *testing.T) {
	var hit int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hit, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	ctx := loginStatusContext{
		kind:         principalKindUser,
		rawToken:     "tok",
		domain:       server.URL,
		loggedInUser: util.LoggedInUserDetails{LoginExpired: true},
	}
	got := verifySession(ctx)
	if got.state != verifyStateSkipped {
		t.Errorf("verifySession locally-expired = %q, want %q", got.state, verifyStateSkipped)
	}
	if atomic.LoadInt32(&hit) != 0 {
		t.Errorf("verifySession hit server %d times for locally-expired ctx, want 0", hit)
	}
}

func TestPerformVerification(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		path       string
		method     string
		want       string
	}{
		{name: "user 200 verified", statusCode: http.StatusOK, path: "/api/v1/auth/checkAuth", method: http.MethodPost, want: verifyStateVerified},
		{name: "user 401 rejected", statusCode: http.StatusUnauthorized, path: "/api/v1/auth/checkAuth", method: http.MethodPost, want: verifyStateRejected},
		{name: "user 403 rejected", statusCode: http.StatusForbidden, path: "/api/v1/auth/checkAuth", method: http.MethodPost, want: verifyStateRejected},
		{name: "user 500 unknown", statusCode: http.StatusInternalServerError, path: "/api/v1/auth/checkAuth", method: http.MethodPost, want: verifyStateUnknown},
		{name: "machine identity 200 verified", statusCode: http.StatusOK, path: "/api/v1/identities/details", method: http.MethodGet, want: verifyStateVerified},
		{name: "machine identity 401 rejected", statusCode: http.StatusUnauthorized, path: "/api/v1/identities/details", method: http.MethodGet, want: verifyStateRejected},
		{name: "machine identity 403 rejected", statusCode: http.StatusForbidden, path: "/api/v1/identities/details", method: http.MethodGet, want: verifyStateRejected},
		{name: "service token 200 verified", statusCode: http.StatusOK, path: "/api/v2/service-token", method: http.MethodGet, want: verifyStateVerified},
		{name: "service token 401 rejected", statusCode: http.StatusUnauthorized, path: "/api/v2/service-token", method: http.MethodGet, want: verifyStateRejected},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotMethod, gotAuth string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotMethod = r.Method
				gotAuth = r.Header.Get("Authorization")
				w.WriteHeader(tc.statusCode)
			}))
			t.Cleanup(server.Close)

			got := performVerification("tok-abc", server.URL, tc.path, tc.method)
			if got.state != tc.want {
				t.Errorf("performVerification state = %q, want %q (detail=%q)", got.state, tc.want, got.reason)
			}
			if gotPath != tc.path {
				t.Errorf("server saw path %q, want %q", gotPath, tc.path)
			}
			if gotMethod != tc.method {
				t.Errorf("server saw method %q, want %q", gotMethod, tc.method)
			}
			if gotAuth != "Bearer tok-abc" {
				t.Errorf("server saw Authorization %q, want %q", gotAuth, "Bearer tok-abc")
			}
		})
	}
}

func TestPerformVerification_NetworkError(t *testing.T) {
	// Close the server immediately so dialing fails.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close()

	got := performVerification("tok", server.URL, "/api/v1/auth/checkAuth", http.MethodPost)
	if got.state != verifyStateUnknown {
		t.Errorf("performVerification network-error state = %q, want %q", got.state, verifyStateUnknown)
	}
}

func makeUnsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	headerJSON, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(payloadJSON) + "."
}
