package agentvault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
)

func subOn(placeholder, value string, surfaces ...string) substitution {
	set := map[string]bool{}
	for _, surface := range surfaces {
		set[surface] = true
	}
	return substitution{placeholder: placeholder, surfaces: set, value: []byte(value)}
}

func TestInjectCustomHeaders(t *testing.T) {
	t.Run("writes name, prefix and value", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/x", nil)
		injectCustomHeaders(req, []customHeader{
			{name: "X-Org-Id", prefix: "", value: []byte("acme")},
			{name: "X-Api-Ver", prefix: "v", value: []byte("2")},
		})
		if got := req.Header.Get("X-Org-Id"); got != "acme" {
			t.Fatalf("X-Org-Id = %q", got)
		}
		if got := req.Header.Get("X-Api-Ver"); got != "v 2" {
			t.Fatalf("X-Api-Ver = %q", got)
		}
	})

	t.Run("overwrites whatever the agent sent", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/x", nil)
		req.Header.Set("X-Org-Id", "spoofed")
		injectCustomHeaders(req, []customHeader{{name: "X-Org-Id", value: []byte("acme")}})
		if got := req.Header.Get("X-Org-Id"); got != "acme" {
			t.Fatalf("X-Org-Id = %q", got)
		}
	})

	t.Run("a Connection header cannot delete an injected custom header", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/x", nil)
		req.Header.Set("Connection", "X-Org-Id")
		stripHopByHopHeaders(req.Header)
		injectCustomHeaders(req, []customHeader{{name: "X-Org-Id", value: []byte("acme")}})
		if got := req.Header.Get("X-Org-Id"); got != "acme" {
			t.Fatalf("X-Org-Id = %q", got)
		}
	})
}

type unreadableBody struct{ t *testing.T }

func (b *unreadableBody) Read([]byte) (int, error) {
	b.t.Fatal("body was read even though the declared length is over the limit")
	return 0, nil
}

func (b *unreadableBody) Close() error { return nil }

func TestAnOversizedDeclaredBodyIsNeverRead(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://api.github.com/x", nil)
	req.Body = &unreadableBody{t: t}
	req.ContentLength = maxBodyRewriteSize + 1

	if applyBodySubstitutions(req, "github", []substitution{subOn("__PAT__", "real", surfaceBody)}) {
		t.Fatal("reported a substitution on a body it should not have touched")
	}
}

type halfBody struct {
	data  []byte
	n     int
	limit int
}

func (b *halfBody) Read(p []byte) (int, error) {
	if b.n >= b.limit {
		return 0, errors.New("unexpected EOF")
	}
	c := copy(p, b.data[b.n:b.limit])
	b.n += c
	return c, nil
}

func (b *halfBody) Close() error { return nil }

func TestABrokenUploadIsNotForwardedTruncated(t *testing.T) {
	full := strings.Repeat("A", 500) + "__PAT__" + strings.Repeat("B", 500)
	req, _ := http.NewRequest("POST", "https://api.github.com/x", nil)
	req.Body = &halfBody{data: []byte(full), limit: 300}
	req.ContentLength = int64(len(full))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(full)))

	applyBodySubstitutions(req, "github", []substitution{subOn("__PAT__", "real", surfaceBody)})

	if req.ContentLength != int64(len(full)) {
		t.Fatalf("ContentLength = %d, want the declared %d so the transport refuses", req.ContentLength, len(full))
	}
	if got := req.Header.Get("Content-Length"); got != fmt.Sprintf("%d", len(full)) {
		t.Fatalf("Content-Length header = %q, want the declared length", got)
	}
	sent, _ := io.ReadAll(req.Body)
	if len(sent) >= len(full) {
		t.Fatalf("body = %d bytes, expected only the part that was read", len(sent))
	}
}

func TestApplySubstitutions(t *testing.T) {
	t.Run("path", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/repos/__TOKEN__/x", nil)
		surfaces := applySubstitutions(req, "github", []substitution{subOn("__TOKEN__", "real", surfacePath)})
		if req.URL.Path != "/repos/real/x" {
			t.Fatalf("path = %q", req.URL.Path)
		}
		if len(surfaces) != 1 || surfaces[0] != surfacePath {
			t.Fatalf("surfaces = %v", surfaces)
		}
	})

	t.Run("path, placeholder Go re-encodes", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://gitlab.com/api/v4/projects/{{PROJECT}}/pipelines", nil)
		surfaces := applySubstitutions(req, "gitlab", []substitution{subOn("{{PROJECT}}", "group/project", surfacePath)})
		if len(surfaces) != 1 || surfaces[0] != surfacePath {
			t.Fatalf("surfaces = %v", surfaces)
		}
		if got := req.URL.RequestURI(); got != "/api/v4/projects/group%2Fproject/pipelines" {
			t.Fatalf("wire path = %q", got)
		}
	})

	t.Run("query", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/x?key=__TOKEN__", nil)
		applySubstitutions(req, "github", []substitution{subOn("__TOKEN__", "real", surfaceQuery)})
		if req.URL.RawQuery != "key=real" {
			t.Fatalf("query = %q", req.URL.RawQuery)
		}
	})

	t.Run("header", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/x", nil)
		req.Header.Set("X-Key", "Bearer __TOKEN__")
		applySubstitutions(req, "github", []substitution{subOn("__TOKEN__", "real", surfaceHeader)})
		if got := req.Header.Get("X-Key"); got != "Bearer real" {
			t.Fatalf("X-Key = %q", got)
		}
	})

	t.Run("body, with Content-Length corrected", func(t *testing.T) {
		body := `{"token":"__TOKEN__"}`
		req, _ := http.NewRequest("POST", "https://api.github.com/x", strings.NewReader(body))
		applySubstitutions(req, "github", []substitution{subOn("__TOKEN__", "realvalue", surfaceBody)})
		got, _ := io.ReadAll(req.Body)
		want := `{"token":"realvalue"}`
		if string(got) != want {
			t.Fatalf("body = %q", got)
		}
		if req.ContentLength != int64(len(want)) {
			t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(want))
		}
	})

	t.Run("a surface the substitution does not name is left alone", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/repos/__TOKEN__", nil)
		req.Header.Set("X-Key", "__TOKEN__")
		applySubstitutions(req, "github", []substitution{subOn("__TOKEN__", "real", surfaceHeader)})
		if req.URL.Path != "/repos/__TOKEN__" {
			t.Fatalf("path should be untouched, got %q", req.URL.Path)
		}
		if got := req.Header.Get("X-Key"); got != "real" {
			t.Fatalf("X-Key = %q", got)
		}
	})

	t.Run("an encoded body is forwarded untouched", func(t *testing.T) {
		body := `{"token":"__TOKEN__"}`
		req, _ := http.NewRequest("POST", "https://api.github.com/x", strings.NewReader(body))
		req.Header.Set("Content-Encoding", "gzip")
		surfaces := applySubstitutions(req, "github", []substitution{subOn("__TOKEN__", "real", surfaceBody)})
		got, _ := io.ReadAll(req.Body)
		if string(got) != body {
			t.Fatalf("body should be untouched, got %q", got)
		}
		if len(surfaces) != 0 {
			t.Fatalf("nothing should be reported as changed, got %v", surfaces)
		}
	})

	t.Run("a body over the limit is forwarded untouched and still readable", func(t *testing.T) {
		body := strings.Repeat("a", maxBodyRewriteSize+10) + "__TOKEN__"
		req, _ := http.NewRequest("POST", "https://api.github.com/x", strings.NewReader(body))
		applySubstitutions(req, "github", []substitution{subOn("__TOKEN__", "real", surfaceBody)})
		got, _ := io.ReadAll(req.Body)
		if !bytes.Equal(got, []byte(body)) {
			t.Fatalf("an oversize body must be forwarded byte for byte (got %d bytes, want %d)", len(got), len(body))
		}
	})

	t.Run("a body with no placeholder in it is untouched", func(t *testing.T) {
		body := `{"a":"b"}`
		req, _ := http.NewRequest("POST", "https://api.github.com/x", strings.NewReader(body))
		surfaces := applySubstitutions(req, "github", []substitution{subOn("__TOKEN__", "real", surfaceBody)})
		got, _ := io.ReadAll(req.Body)
		if string(got) != body {
			t.Fatalf("body = %q", got)
		}
		if len(surfaces) != 0 {
			t.Fatalf("surfaces = %v", surfaces)
		}
	})

	t.Run("several substitutions apply to one request", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/repos/__A__", nil)
		req.Header.Set("X-Key", "__B__")
		applySubstitutions(req, "github", []substitution{
			subOn("__A__", "one", surfacePath),
			subOn("__B__", "two", surfaceHeader),
		})
		if req.URL.Path != "/repos/one" {
			t.Fatalf("path = %q", req.URL.Path)
		}
		if got := req.Header.Get("X-Key"); got != "two" {
			t.Fatalf("X-Key = %q", got)
		}
	})
}

// A placeholder that starts with another one is only swapped correctly when the longer runs first, and the
// server is free to send them in either order.
func TestAPlaceholderPrefixingAnotherStillSendsItsOwnSecret(t *testing.T) {
	short := api.AgentVaultSubstitution{Placeholder: "__TOKEN__", Surfaces: []string{"header"}, Value: "SECRET_A"}
	long := api.AgentVaultSubstitution{Placeholder: "__TOKEN__V2", Surfaces: []string{"header"}, Value: "SECRET_B"}

	for _, wire := range [][]api.AgentVaultSubstitution{{short, long}, {long, short}} {
		req := requestTo(t, "GET", "/")
		req.Header.Set("X-A", "__TOKEN__")
		req.Header.Set("X-B", "__TOKEN__V2")
		applySubstitutions(req, "svc", toSubstitutions(wire))

		if got := req.Header.Get("X-A"); got != "SECRET_A" {
			t.Errorf("server order %q: X-A = %q, want SECRET_A", wire[0].Placeholder, got)
		}
		if got := req.Header.Get("X-B"); got != "SECRET_B" {
			t.Errorf("server order %q: X-B = %q, want SECRET_B", wire[0].Placeholder, got)
		}
	}
}

// A client building the query from parameters percent-encodes the placeholder first, so both forms have to
// be matched. Underscore-style placeholders are never encoded and stand as the control.
func TestAQuerySubstitutionMatchesTheEncodedPlaceholderToo(t *testing.T) {
	cases := []struct {
		placeholder string
		wire        string
	}{
		{"__PAT__", "__PAT__"},
		{"{{PAT}}", "{{PAT}}"},
		{"{{PAT}}", "%7B%7BPAT%7D%7D"},
	}

	for _, c := range cases {
		req := requestTo(t, "GET", "/v1?key="+c.wire)
		applySubstitutions(req, "svc", []substitution{subOn(c.placeholder, "SECRET", surfaceQuery)})
		if got := req.URL.RawQuery; got != "key=SECRET" {
			t.Errorf("placeholder %q sent as %q: query = %q, want key=SECRET", c.placeholder, c.wire, got)
		}
	}
}

func TestAPathSubstitutionLeavesTheRestOfThePathAlone(t *testing.T) {
	for _, tc := range []struct{ name, target, wantURI string }{
		{
			"an encoded slash survives",
			"https://gitlab.com/api/v4/projects/group%2Fproject/repository/__PAT__",
			"/api/v4/projects/group%2Fproject/repository/real",
		},
		{
			"an encoded plus survives",
			"https://api.github.com/repos/a%2Bb/__PAT__",
			"/repos/a%2Bb/real",
		},
		{
			"an encoded space survives",
			"https://api.github.com/repos/a%20b/__PAT__",
			"/repos/a%20b/real",
		},
		{
			"non-ASCII survives",
			"https://api.github.com/repos/caf%C3%A9/__PAT__",
			"/repos/caf%C3%A9/real",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tc.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			applySubstitutions(req, "gitlab", []substitution{subOn("__PAT__", "real", surfacePath)})
			if got := req.URL.RequestURI(); got != tc.wantURI {
				t.Fatalf("wire path = %q, want %q", got, tc.wantURI)
			}
		})
	}

	t.Run("a secret containing a slash cannot add a segment", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/repos/__PAT__", nil)
		applySubstitutions(req, "github", []substitution{subOn("__PAT__", "a/b", surfacePath)})
		if got := req.URL.RequestURI(); got != "/repos/a%2Fb" {
			t.Fatalf("wire path = %q, want the slash escaped", got)
		}
	})
}

func TestAQuerySubstitutionEscapesTheValue(t *testing.T) {
	for _, tc := range []struct{ name, secret, wantKey string }{
		{"a base64 key with a plus", "aB+cD/eF==", "aB+cD/eF=="},
		{"a value with a space", "has space", "has space"},
		{"a value with an ampersand", "a&page=99", "a&page=99"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://api.example.com/x?key=__PAT__&page=2", nil)
			applySubstitutions(req, "svc", []substitution{subOn("__PAT__", tc.secret, surfaceQuery)})

			parsed, err := url.ParseQuery(req.URL.RawQuery)
			if err != nil {
				t.Fatalf("the query no longer parses: %v", err)
			}
			if got := parsed.Get("key"); got != tc.wantKey {
				t.Fatalf("upstream reads key=%q, want %q", got, tc.wantKey)
			}
			if got := parsed.Get("page"); got != "2" {
				t.Fatalf("the substitution disturbed another parameter: page=%q", got)
			}
		})
	}
}
