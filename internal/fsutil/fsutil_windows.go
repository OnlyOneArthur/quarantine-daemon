//go:build windows

package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// OpenSafe opens a file safely on Windows checking against reparse points (symlinks/junctions).
func OpenSafe(path string) (*SafeFile, error) {
	cleanPath := filepath.Clean(path)
	pathPtr, err := windows.UTF16PtrFromString(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("utf16 ptr %s: %w", cleanPath, err)
	}

	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open safe windows %s: %w", cleanPath, err)
	}

	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("get file info %s: %w", cleanPath, err)
	}

	if fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %s is directory", ErrNotRegularFile, cleanPath)
	}

	if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %s is reparse point/symlink", ErrSymlinkNotAllowed, cleanPath)
	}

	f := os.NewFile(uintptr(h), cleanPath)
	fileInfo, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat %s: %w", cleanPath, err)
	}

	size := (int64(fi.FileSizeHigh) << 32) | int64(fi.FileSizeLow)
	ino := (uint64(fi.FileIndexHigh) << 32) | uint64(fi.FileIndexLow)
	dev := uint64(fi.VolumeSerialNumber)

	return &SafeFile{
		File:   f,
		Path:   cleanPath,
		Dev:    dev,
		Ino:    ino,
		Size:   size,
		Blocks: (size + 511) / 512,
		Mode:   fileInfo.Mode(),
		UID:    0,
		GID:    0,
	}, nil
}

func VerifyPathInodeMatch(path string, expectedDev, expectedIno uint64) (bool, error) {
	sf, err := OpenSafe(path)
	if err != nil {
		return false, err
	}
	defer sf.Close()
	return sf.Dev == expectedDev && sf.Ino == expectedIno, nil
}

func OpenSafeCreate(path string, perm os.FileMode) (*os.File, error) {
	cleanPath := filepath.Clean(path)
	return os.OpenFile(cleanPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
}

func LockFile(f *os.File) (func() error, error) {
	if f == nil {
		return nil, errors.New("nil file")
	}

	var overlapped windows.Overlapped
	h := windows.Handle(f.Fd())
	err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
	if err != nil {
		return nil, fmt.Errorf("lock file ex: %w", err)
	}

	unlock := func() error {
		return windows.UnlockFileEx(h, 0, 1, 0, &overlapped)
	}
	return unlock, nil
}
