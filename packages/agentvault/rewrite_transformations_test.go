package agentvault

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func subOn(placeholder, value string, surfaces ...string) substitution {
	set := map[string]bool{}
	for _, surface := range surfaces {
		set[surface] = true
	}
	return substitution{placeholder: placeholder, surfaces: set, value: []byte(value)}
}

func TestInjectHeaders(t *testing.T) {
	t.Run("writes name, prefix and value", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/x", nil)
		injectHeaders(req, []customHeader{
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
		injectHeaders(req, []customHeader{{name: "X-Org-Id", value: []byte("acme")}})
		if got := req.Header.Get("X-Org-Id"); got != "acme" {
			t.Fatalf("X-Org-Id = %q", got)
		}
	})

	// Same trap injectCredential documents: a Connection list naming the header would delete it.
	t.Run("a Connection header cannot delete an injected custom header", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/x", nil)
		req.Header.Set("Connection", "X-Org-Id")
		stripHopByHopHeaders(req.Header)
		injectHeaders(req, []customHeader{{name: "X-Org-Id", value: []byte("acme")}})
		if got := req.Header.Get("X-Org-Id"); got != "acme" {
			t.Fatalf("X-Org-Id = %q", got)
		}
	})
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

	// The placeholder goes upstream unchanged here, which is why the proxy logs it rather than staying quiet.
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
