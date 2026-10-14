//go:build unix

package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// OpenSafe opens a file for reading without following symbolic links (O_NOFOLLOW)
// and ensures it is a regular file.
func OpenSafe(path string) (*SafeFile, error) {
	cleanPath := filepath.Clean(path)

	// O_NONBLOCK prevents hanging indefinitely if path is a FIFO / named pipe.
	fd, err := unix.Open(cleanPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: %s", ErrSymlinkNotAllowed, cleanPath)
		}
		return nil, fmt.Errorf("open safe %s: %w", cleanPath, err)
	}

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("fstat %s: %w", cleanPath, err)
	}

	if (st.Mode & unix.S_IFMT) != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: %s (mode: %o)", ErrNotRegularFile, cleanPath, st.Mode)
	}

	if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err == nil {
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK)
	}

	f := os.NewFile(uintptr(fd), cleanPath)
	// The numeric conversions below are required for portability: unix.Stat_t
	// field widths differ per platform (e.g. Dev is int32 on darwin, uint64 on
	// linux), so they cannot be dropped even where the host type already
	// matches the target type.
	//nolint:unconvert
	return &SafeFile{
		File:   f,
		Path:   cleanPath,
		Dev:    uint64(st.Dev),
		Ino:    uint64(st.Ino),
		Size:   int64(st.Size),
		Blocks: int64(st.Blocks),
		Mode:   os.FileMode(st.Mode & 07777),
		UID:    int(st.Uid),
		GID:    int(st.Gid),
	}, nil
}

// VerifyPathInodeMatch verifies that the path (using Lstat, without following symlinks)
// currently refers to the expected device and inode.
func VerifyPathInodeMatch(path string, expectedDev, expectedIno uint64) (bool, error) {
	cleanPath := filepath.Clean(path)

	var st unix.Stat_t
	if err := unix.Lstat(cleanPath, &st); err != nil {
		return false, fmt.Errorf("lstat %s: %w", cleanPath, err)
	}

	//nolint:unconvert // unix.Stat_t field widths are platform-dependent.
	return uint64(st.Dev) == expectedDev && uint64(st.Ino) == expectedIno, nil
}

// OpenSafeCreate creates a new file exclusively without following symlinks.
func OpenSafeCreate(path string, perm os.FileMode) (*os.File, error) {
	cleanPath := filepath.Clean(path)
	flags := unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Open(cleanPath, flags, uint32(perm))
	if err != nil {
		return nil, fmt.Errorf("safe create %s: %w", cleanPath, err)
	}
	return os.NewFile(uintptr(fd), cleanPath), nil
}

// LockFile applies a non-blocking exclusive file lock (flock).
func LockFile(f *os.File) (func() error, error) {
	if f == nil {
		return nil, errors.New("nil file")
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("flock lock: %w", err)
	}

	unlock := func() error {
		return unix.Flock(int(f.Fd()), unix.LOCK_UN)
	}
	return unlock, nil
}
