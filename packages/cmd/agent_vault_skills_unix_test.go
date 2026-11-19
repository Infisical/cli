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

func TestPullAgentVaultSkillForceKeepsAPrivateFolderPrivate(t *testing.T) {
	folder := filepath.Join(t.TempDir(), "code-review")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := pullAgentVaultSkill(newFakeSkillsReadAPI(t, codeReviewSkillAPI()), testSkillsProject, "code-review", folder, 0, true); err != nil {
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

func TestPullAgentVaultSkillForceReplacesAnEmptyReadOnlyFolder(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write to read-only folders")
	}
	folder := filepath.Join(t.TempDir(), "code-review")
	if err := os.Mkdir(folder, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(folder, 0o755) })
	if _, err := pullAgentVaultSkill(newFakeSkillsReadAPI(t, codeReviewSkillAPI()), testSkillsProject, "code-review", folder, 0, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(folder, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(folder)
	if err != nil || info.Mode().Perm() != 0o555 {
		t.Fatalf("folder %v %v, want mode 555", info, err)
	}
}
