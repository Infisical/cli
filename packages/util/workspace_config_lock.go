package util

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// workspaceConfigLockTimeout bounds how long a command waits for another one that is migrating or initializing the
// same directory. The lock is only held for a few file operations, so running into it means the holder is stuck.
var workspaceConfigLockTimeout = 5 * time.Second

// LockWorkspaceConfigDir takes the lock shared by everything that writes the workspace config in dir: the
// .infisical.json to .infisical.yaml migration and `infisical init`. Holding it keeps one command from removing the
// JSON another is about to migrate, or from replacing a freshly written YAML with stale settings. The lockfile lives
// under ~/.infisical/locks, keyed by the directory's resolved path, so it never ends up in the user's repository.
// Uses gofrs/flock so it also works on Windows. The returned func releases the lock.
func LockWorkspaceConfigDir(dir string) (func(), error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	// resolve symlinks so every path to the same directory shares one lockfile
	if resolvedDir, err := filepath.EvalSymlinks(absDir); err == nil {
		absDir = resolvedDir
	}

	homeDir, err := GetHomeDir()
	if err != nil {
		return nil, err
	}
	lockDir := filepath.Join(homeDir, CONFIG_FOLDER_NAME, "locks")
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return nil, fmt.Errorf("unable to create %s [err=%w]", lockDir, err)
	}

	dirHash := sha256.Sum256([]byte(absDir))
	fileLock := flock.New(filepath.Join(lockDir, "workspace-config-"+hex.EncodeToString(dirHash[:8])+".lock"))

	ctx, cancel := context.WithTimeout(context.Background(), workspaceConfigLockTimeout)
	defer cancel()
	if _, err := fileLock.TryLockContext(ctx, 50*time.Millisecond); err != nil {
		return nil, fmt.Errorf("unable to lock the workspace config in %s [err=%w]", absDir, err)
	}
	return func() { _ = fileLock.Unlock() }, nil
}
