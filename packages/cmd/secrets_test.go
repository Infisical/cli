package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcessSecretsSetArgs(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(filePath, []byte("file-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := processSecretsSetArgs([]string{
		"FROM_FILE=@" + filePath,
		"ESCAPED=\\@literal",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"FROM_FILE=file-value\n",
		"ESCAPED=@literal",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d processed arguments, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("processed argument %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestProcessSecretsSetArgsMissingFile(t *testing.T) {
	_, err := processSecretsSetArgs([]string{"SECRET=@" + filepath.Join(t.TempDir(), "missing")})
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
