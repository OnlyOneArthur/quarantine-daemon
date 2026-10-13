//go:build unix

package quarantine

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
)

// neutralizePerms strips all POSIX permission bits (chmod 0000) from path,
// neutralizing read/write/execute for owner, group, and others. Symlinks and
// non-regular files are rejected before chmod, which would otherwise follow a
// symlink to an unrelated target.
func neutralizePerms(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", fsutil.ErrNotRegularFile, path)
	}
	return os.Chmod(path, 0000)
}

// moveFile relocates src into the vault directory. On the same filesystem this is
// an atomic rename. Across a mount boundary (e.g. /tmp tmpfs -> ~/.local/share)
// rename returns EXDEV, so we fall back to a safe copy-then-unlink: write to a
// temp file in the vault dir, fsync it, atomically rename into place, then unlink
// the source only after verifying its inode still matches (anti-TOCTOU).
// The source inode is also verified before rename so a swapped path (including a
// symlink) is rejected instead of moved.
func moveFile(srcPath string, dev, ino uint64, destPath, vaultDir string) error {
	match, err := fsutil.VerifyPathInodeMatch(srcPath, dev, ino)
	if err != nil {
		return err
	}
	if !match {
		return errors.New("source inode changed before move")
	}

	err = os.Rename(srcPath, destPath)
	if err == nil || !errors.Is(err, unix.EXDEV) {
		return err
	}
	return crossDeviceCopy(srcPath, dev, ino, destPath, vaultDir)
}

// crossDeviceCopy performs the EXDEV fallback move.
func crossDeviceCopy(srcPath string, dev, ino uint64, destPath, vaultDir string) error {
	src, err := fsutil.OpenSafe(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	if src.Dev != dev || src.Ino != ino {
		return errors.New("source inode changed before cross-device copy")
	}

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
	if err := os.Chmod(tmpPath, 0600); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	match, err := fsutil.VerifyPathInodeMatch(srcPath, dev, ino)
	if err != nil {
		_ = os.Remove(destPath)
		return err
	}
	if !match {
		_ = os.Remove(destPath)
		return errors.New("source inode changed during cross-device move")
	}

	if err := os.Remove(srcPath); err != nil {
		_ = os.Remove(destPath)
		return err
	}
	return nil
}
