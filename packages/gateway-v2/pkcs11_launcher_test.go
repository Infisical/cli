//go:build !pkcs11

package gatewayv2

import (
	"path/filepath"
	"testing"
)

func TestPkcs11BinDirUsesHomeWhenSet(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if got, want := pkcs11BinDir(), filepath.Join(home, ".infisical", "bin"); got != want {
		t.Fatalf("pkcs11BinDir() = %q, want %q", got, want)
	}
}

func TestPkcs11BinDirFallsBackWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if got := pkcs11BinDir(); got != pkcs11SystemBinDir {
		t.Fatalf("pkcs11BinDir() = %q, want %q", got, pkcs11SystemBinDir)
	}
}
