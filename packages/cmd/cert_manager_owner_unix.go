//go:build !windows

package cmd

import (
	"os"
	"syscall"
)

// keepOwner gives f the owner and group of the file it replaces. It changes the open file rather than
// its path, so a path swapped for a symlink can't redirect the change to another file.
func keepOwner(f *os.File, existing os.FileInfo) error {
	want, ok := existing.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	// Skipping an unchanged owner spares filesystems that refuse chown even to the same ids.
	if staged, err := f.Stat(); err == nil {
		if got, ok := staged.Sys().(*syscall.Stat_t); ok && got.Uid == want.Uid && got.Gid == want.Gid {
			return nil
		}
	}
	return f.Chown(int(want.Uid), int(want.Gid))
}
