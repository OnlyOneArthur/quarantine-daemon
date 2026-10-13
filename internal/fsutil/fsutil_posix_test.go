//go:build unix

package fsutil

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenSafeFIFONonBlocking(t *testing.T) {
	tmpDir := t.TempDir()
	fifoPath := filepath.Join(tmpDir, "test.fifo")

	if err := unix.Mkfifo(fifoPath, 0600); err != nil {
		t.Fatalf("mkfifo failed: %v", err)
	}

	_, err := OpenSafe(fifoPath)
	if err == nil {
		t.Fatalf("expected OpenSafe on FIFO to return error, got nil")
	}
	if !errors.Is(err, ErrNotRegularFile) {
		t.Fatalf("expected ErrNotRegularFile, got: %v", err)
	}
}
