package util

import (
	"errors"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes to a temp file beside path and renames it into place, so a reader never sees a
// truncated or half-written file and a crash leaves either the old contents or the new.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// StageFile writes data to a new temp file beside path and returns its name. The caller renames it into
// place, or removes it. The file stays 0600 until prepare, which may be nil, has run on it, such as to
// change its owner, and only then takes mode perm, so no other user can open it for writing first.
func StageFile(path string, data []byte, perm os.FileMode, prepare func(*os.File) error) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return "", err
	}
	err = func() error {
		if _, err := tmp.Write(data); err != nil {
			return err
		}
		if prepare != nil {
			if err := prepare(tmp); err != nil {
				return err
			}
		}
		return tmp.Chmod(perm)
	}()
	if err := errors.Join(err, tmp.Close()); err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}
