//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
)

func TestCertOutputFilesForceKeepsTheCertificateGroupOnly(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	for _, path := range []string{certPath, keyPath} {
		if err := os.WriteFile(path, []byte("old"), 0640); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	// A new file in dir gets this group too, so the group the test hands over must differ from it.
	newFileGroup := int(info.Sys().(*syscall.Stat_t).Gid)
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	group := -1
	for _, g := range groups {
		if g != newFileGroup {
			group = g
			break
		}
	}
	if group == -1 {
		t.Skip("needs a supplementary group to hand the files to")
	}
	for _, path := range []string{certPath, keyPath} {
		if err := os.Chown(path, -1, group); err != nil {
			t.Skipf("can't change the fixture's group: %v", err)
		}
	}

	if _, err := (certOutputFiles{Cert: certPath, Key: keyPath, Force: true}).write(api.CertificateData{Certificate: "NEW", PrivateKey: "KEY"}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]int{certPath: group, keyPath: newFileGroup} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if gid := int(info.Sys().(*syscall.Stat_t).Gid); gid != want {
			t.Errorf("%s group = %d, want %d", filepath.Base(path), gid, want)
		}
	}
}
