package fsutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenSafeRegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.bin")
	content := []byte("hello safe file")

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	sf, err := OpenSafe(filePath)
	if err != nil {
		t.Fatalf("OpenSafe failed: %v", err)
	}
	defer sf.Close()

	if sf.Size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), sf.Size)
	}
	if sf.Ino == 0 {
		t.Errorf("expected non-zero inode")
	}

	pathMatch, err := VerifyPathInodeMatch(filePath, sf.Dev, sf.Ino)
	if err != nil || !pathMatch {
		t.Errorf("expected path inode match: %v, err: %v", pathMatch, err)
	}
}

func TestOpenSafeSymlinkRejected(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "target.bin")
	symlinkPath := filepath.Join(tmpDir, "link.bin")

	if err := os.WriteFile(targetPath, []byte("target"), 0644); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	_, err := OpenSafe(symlinkPath)
	if err == nil {
		t.Fatalf("expected OpenSafe to fail on symlink, got nil error")
	}
	if !errors.Is(err, ErrSymlinkNotAllowed) {
		t.Errorf("expected ErrSymlinkNotAllowed, got: %v", err)
	}
}

func TestOpenSafeDirectoryRejected(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := OpenSafe(tmpDir)
	if err == nil {
		t.Fatalf("expected OpenSafe to fail on directory, got nil error")
	}
	if !errors.Is(err, ErrNotRegularFile) {
		t.Errorf("expected ErrNotRegularFile, got: %v", err)
	}
}

func TestReadBounded(t *testing.T) {
	data := []byte("0123456789abcdef")

	buf, err := ReadBounded(bytes.NewReader(data), 16)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !bytes.Equal(buf, data) {
		t.Errorf("expected equal bytes")
	}

	bufExceeded, err := ReadBounded(bytes.NewReader(data), 10)
	if !errors.Is(err, ErrExceedsMaxScanSize) {
		t.Errorf("expected ErrExceedsMaxScanSize, got: %v", err)
	}
	if len(bufExceeded) != 10 {
		t.Errorf("expected 10 bytes returned, got %d", len(bufExceeded))
	}
}

func TestLockFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "lock_test.bin")
	if err := os.WriteFile(filePath, []byte("data"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	sf, err := OpenSafe(filePath)
	if err != nil {
		t.Fatalf("OpenSafe: %v", err)
	}
	defer sf.Close()

	unlock, err := LockFile(sf.File)
	if err != nil {
		t.Fatalf("LockFile: %v", err)
	}
	if err := unlock(); err != nil {
		t.Errorf("unlock: %v", err)
	}
}
