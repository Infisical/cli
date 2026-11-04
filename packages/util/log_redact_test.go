package util

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
)

// A token pasted into a flag that ends up in the request (--path in the query string) is URL-encoded
// there, which hides it from a plain redaction of the URL.
func TestPrettyAPIErrorRedactsCredentialsInTheRequest(t *testing.T) {
	token := "ghp" + "_" + strings.Repeat("aB3", 12)
	var buf bytes.Buffer
	old := GetStderrWriter
	GetStderrWriter = func() io.Writer { return &buf }
	t.Cleanup(func() { GetStderrWriter = old })

	printPrettyAPIError(api.APIError{Method: "GET", StatusCode: 500,
		URL:          "http://localhost:8080/api/v2/folders?environment=dev&path=%2F" + token + "&projectId=p",
		ErrorMessage: "Folder with path '/" + token + "' not found"})

	if out := buf.String(); strings.Contains(out, token) || strings.Contains(out, strings.TrimPrefix(token, "ghp_")) || !strings.Contains(out, "<redacted>") {
		t.Errorf("the box repeats the token:\n%s", out)
	}
}

func TestDisplayRequestURL(t *testing.T) {
	token := "ghp" + "_" + strings.Repeat("aB3", 12)
	cases := map[string]string{
		// Shown as sent, so the error box (and the CLI's snapshot tests) read as before.
		"http://x/api/v4/secrets?environment=dev&secretPath=%2F":   "http://x/api/v4/secrets?environment=dev&secretPath=%2F",
		"http://x/api/v2/folders?path=%2Fa%0Ab%1B%5B31m":           "http://x/api/v2/folders?path=%2Fa%0Ab%1B%5B31m",
		"http://x/api/v2/folders?path=%2F" + token:                 "http://x/api/v2/folders?path=/<redacted>",
		"http://x/api/v2/folders?path=%2F" + token + "%0A%1B%5B2J": "http://x/api/v2/folders?path=/<redacted>[2J",
	}
	for raw, want := range cases {
		if got := displayRequestURL(raw); got != want {
			t.Errorf("displayRequestURL(%q) = %q, want %q", raw, got, want)
		}
	}
}
