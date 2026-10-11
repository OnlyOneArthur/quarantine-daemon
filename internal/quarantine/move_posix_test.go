//go:build unix

package quarantine

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestNeutralizePermsRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	writeFile(t, target, []byte("unrelated"), 0644)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := neutralizePerms(link); err == nil {
		t.Fatal("neutralizePerms on symlink: want error, got nil")
	}
	if mode := fileMode(t, target); mode != 0644 {
		t.Errorf("symlink target mode = %04o, want 0644 (untouched)", mode)
	}
}

func TestMoveFileRejectsSwappedSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	writeFile(t, src, []byte("payload"), 0644)
	var st syscall.Stat_t
	if err := syscall.Stat(src, &st); err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Expect a different inode than the one on disk, simulating a swap after hashing.
	dest := filepath.Join(dir, "dest")
	if err := moveFile(src, uint64(st.Dev), uint64(st.Ino)+1, dest, dir); err == nil {
		t.Fatal("moveFile with mismatched inode: want error, got nil")
	}
	if _, err := os.Lstat(src); err != nil {
		t.Errorf("source must remain after rejected move: %v", err)
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Errorf("destination must not exist after rejected move, lstat err: %v", err)
	}
}
