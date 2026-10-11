//go:build !unix

package quarantine

import (
	"errors"
	"io"
	"os"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
)

// neutralizePerms removes read/write/execute access on non-POSIX platforms.
func neutralizePerms(path string) error {
	return os.Chmod(path, 0000)
}

// moveFile relocates src into the vault directory via a safe fsync'd copy
// followed by an inode-verified source unlink. Non-POSIX platforms lack a
// portable cross-device rename, so the copy path is always used.
func moveFile(srcPath string, dev, ino uint64, destPath, vaultDir string) error {
	src, err := fsutil.OpenSafe(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	tmp, err := os.CreateTemp(vaultDir, ".tmp-move-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	if _, err := io.Copy(tmp, src.File); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	match, err := fsutil.VerifyPathInodeMatch(srcPath, dev, ino)
	if err != nil {
		return err
	}
	if !match {
		_ = os.Remove(destPath)
		return errors.New("source inode changed during move")
	}
	return os.Remove(srcPath)
}
