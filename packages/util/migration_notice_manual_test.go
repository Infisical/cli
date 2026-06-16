package util

import (
	"os"
	"testing"
)

// Manual visual check of the Cloudsmith migration notice.
// Run inside a Linux container with a package manager present:
//   go test ./packages/util/ -run TestMigrationNoticeManual -v
func TestMigrationNoticeManual(t *testing.T) {
	// Use an isolated HOME so the throttle cache starts empty and the notice prints.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	DisplayPackageRepoMigrationNoticeWithWriter(false, os.Stdout)
}
