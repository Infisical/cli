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
