//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPullAgentVaultSkillFolderFollowsTheUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	folder := filepath.Join(t.TempDir(), "code-review")
	if _, err := pullAgentVaultSkill(newFakeSkillsReadAPI(t, codeReviewSkillAPI()), testSkillsProject, "code-review", folder, 0, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(folder)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("folder mode %o, want 700", got)
	}
}
