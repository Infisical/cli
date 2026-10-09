package util

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func shortenWorkspaceConfigLockTimeout(t *testing.T) {
	t.Helper()
	original := workspaceConfigLockTimeout
	workspaceConfigLockTimeout = 100 * time.Millisecond
	t.Cleanup(func() { workspaceConfigLockTimeout = original })
}

func TestConcurrentFirstReadsAllSeeTheMigratedConfig(t *testing.T) {
	useTempHome(t)
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
	writeTestFile(t, jsonPath, legacyWorkspaceJSON)

	// every reader starts on the legacy JSON. Without the lock, the ones that lose the race find the JSON already
	// removed and fail instead of reading the YAML the winner wrote
	const readers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			cfg, err := GetWorkSpaceFromFilePath(dir)
			if err != nil {
				t.Errorf("concurrent read failed: %v", err)
				return
			}
			assertFullWorkspaceConfig(t, cfg, "proj-123")
		}()
	}
	close(start)
	wg.Wait()

	if fileExists(jsonPath) {
		t.Errorf("legacy %s should have been removed", jsonPath)
	}
	if !fileExists(filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)) {
		t.Error("yaml should have been created")
	}
}

func TestMigrationWaitingOnTheLockKeepsAConcurrentInit(t *testing.T) {
	useTempHome(t)
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
	yamlPath := filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
	writeTestFile(t, jsonPath, legacyWorkspaceJSON)

	// stand in for `infisical init`, which holds the lock while it writes
	unlock, err := LockWorkspaceConfigDir(dir)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}

	type readResult struct {
		workspaceId string
		err         error
	}
	done := make(chan readResult, 1)
	go func() {
		cfg, err := GetWorkSpaceFromFilePath(dir)
		done <- readResult{cfg.WorkspaceId, err}
	}()

	// give the read time to miss the YAML and block on the lock
	time.Sleep(100 * time.Millisecond)
	select {
	case r := <-done:
		unlock()
		t.Fatalf("read returned while the lock was held: %+v", r)
	default:
	}

	writeTestFile(t, yamlPath, "secrets-management:\n  project-id: proj-new\n")
	if err := os.Remove(jsonPath); err != nil {
		t.Fatalf("remove json: %v", err)
	}
	unlock()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("unexpected error: %v", r.err)
		}
		if r.workspaceId != "proj-new" {
			t.Errorf("WorkspaceId = %q, want proj-new", r.workspaceId)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read did not finish after the lock was released")
	}

	onDisk, err := readWorkspaceConfigYaml(yamlPath)
	if err != nil {
		t.Fatalf("reading yaml: %v", err)
	}
	if onDisk.WorkspaceId != "proj-new" {
		t.Errorf("yaml on disk has WorkspaceId = %q, want proj-new; the migration overwrote init", onDisk.WorkspaceId)
	}
}

func TestGetWorkSpaceFromFilePathReadsJsonWithoutMigratingWhenUnlockable(t *testing.T) {
	t.Run("lockfile cannot be created", func(t *testing.T) {
		// a home that is a regular file makes creating the locks directory fail
		home := filepath.Join(t.TempDir(), "home")
		writeTestFile(t, home, "")
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		dir := t.TempDir()
		jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, legacyWorkspaceJSON)

		cfg, err := GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")
		if !fileExists(jsonPath) {
			t.Errorf("legacy %s should not be removed without the lock", jsonPath)
		}
		if fileExists(filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)) {
			t.Error("yaml should not be written without the lock")
		}
	})

	t.Run("lock is held past the timeout", func(t *testing.T) {
		useTempHome(t)
		shortenWorkspaceConfigLockTimeout(t)

		dir := t.TempDir()
		jsonPath := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		writeTestFile(t, jsonPath, legacyWorkspaceJSON)

		unlock, err := LockWorkspaceConfigDir(dir)
		if err != nil {
			t.Fatalf("lock: %v", err)
		}
		defer unlock()

		cfg, err := GetWorkSpaceFromFilePath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFullWorkspaceConfig(t, cfg, "proj-123")
		if !fileExists(jsonPath) {
			t.Errorf("legacy %s should not be removed without the lock", jsonPath)
		}
		if fileExists(filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)) {
			t.Error("yaml should not be written without the lock")
		}
	})
}

func TestLockWorkspaceConfigDir(t *testing.T) {
	t.Run("released lock can be taken again", func(t *testing.T) {
		useTempHome(t)
		shortenWorkspaceConfigLockTimeout(t)
		dir := t.TempDir()

		unlock, err := LockWorkspaceConfigDir(dir)
		if err != nil {
			t.Fatalf("lock: %v", err)
		}
		unlock()

		unlock, err = LockWorkspaceConfigDir(dir)
		if err != nil {
			t.Fatalf("relock after release: %v", err)
		}
		unlock()
	})

	t.Run("different directories do not contend", func(t *testing.T) {
		useTempHome(t)
		shortenWorkspaceConfigLockTimeout(t)

		unlock, err := LockWorkspaceConfigDir(t.TempDir())
		if err != nil {
			t.Fatalf("lock: %v", err)
		}
		defer unlock()

		otherUnlock, err := LockWorkspaceConfigDir(t.TempDir())
		if err != nil {
			t.Fatalf("lock on another directory: %v", err)
		}
		otherUnlock()
	})

	t.Run("symlinked path shares the lock", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("creating symlinks needs extra privileges on windows")
		}
		useTempHome(t)
		shortenWorkspaceConfigLockTimeout(t)

		dir := t.TempDir()
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		unlock, err := LockWorkspaceConfigDir(dir)
		if err != nil {
			t.Fatalf("lock: %v", err)
		}
		defer unlock()

		if linkUnlock, err := LockWorkspaceConfigDir(link); err == nil {
			linkUnlock()
			t.Fatal("expected the symlinked path to wait on the same lock")
		}
	})
}
