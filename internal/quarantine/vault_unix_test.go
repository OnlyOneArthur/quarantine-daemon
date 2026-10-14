//go:build unix

package quarantine

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestQuarantineCrossDeviceEXDEV exercises the EXDEV fallback: source on one
// filesystem (tmpfs) and vault on another (ext4). Skips when no second mount
// with a distinct device id is available.
func TestQuarantineCrossDeviceEXDEV(t *testing.T) {
	srcDir := t.TempDir() // typically tmpfs under /tmp

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}
	vaultRoot, err := os.MkdirTemp(home, ".quarantine-test-*")
	if err != nil {
		t.Skipf("cannot create vault under home: %v", err)
	}
	defer os.RemoveAll(vaultRoot)

	srcDev := deviceID(t, srcDir)
	vaultDev := deviceID(t, vaultRoot)
	if srcDev == vaultDev {
		t.Skipf("src and vault share device %d; EXDEV not exercisable here", srcDev)
	}

	v, err := New(vaultRoot)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer v.Close()

	content := []byte("cross-device payload spanning mount boundary")
	srcPath := filepath.Join(srcDir, "payload.bin")
	writeFile(t, srcPath, content, 0755)

	meta, err := v.QuarantineFile(srcPath, 92, nil, nil, nil)
	if err != nil {
		t.Fatalf("QuarantineFile cross-device: %v", err)
	}

	if _, err := os.Lstat(srcPath); !os.IsNotExist(err) {
		t.Errorf("expected source unlinked after cross-device move, err: %v", err)
	}
	artifact := v.artifactPath(meta.ID)
	if mode := fileMode(t, artifact); mode != 0000 {
		t.Errorf("expected artifact perms 0000, got %04o", mode)
	}

	// Restore back across the boundary.
	if err := v.Restore(meta.ID, ""); err != nil {
		t.Fatalf("Restore cross-device: %v", err)
	}
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Errorf("restored content mismatch")
	}
	if mode := fileMode(t, srcPath); mode != 0755 {
		t.Errorf("restored mode = %04o, want 0755", mode)
	}
}

func TestRestoreRejectsUntrustedParent(t *testing.T) {
	v, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	srcPath := filepath.Join(t.TempDir(), "payload.bin")
	writeFile(t, srcPath, []byte("payload"), 0644)
	meta, err := v.QuarantineFile(srcPath, 93, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// World-writable, non-sticky parent: another user could swap the stage file.
	unsafeDir := t.TempDir()
	if err := os.Chmod(unsafeDir, 0777); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(unsafeDir, "restored.bin")
	if err := v.Restore(meta.ID, dest); err == nil {
		t.Fatal("expected restore into world-writable parent to fail")
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Errorf("unexpected destination created: %v", err)
	}
	if _, err := v.Inspect(meta.ID); err != nil {
		t.Errorf("item lost after refusal: %v", err)
	}
}

func TestRestoreMissingParentFails(t *testing.T) {
	v, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	srcPath := filepath.Join(t.TempDir(), "payload.bin")
	writeFile(t, srcPath, []byte("payload"), 0644)
	meta, err := v.QuarantineFile(srcPath, 93, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(t.TempDir(), "absent", "restored.bin")
	if err := v.Restore(meta.ID, dest); err == nil {
		t.Fatal("expected restore into missing parent to fail")
	}
	if _, err := v.Inspect(meta.ID); err != nil {
		t.Errorf("item lost after refusal: %v", err)
	}
}

func deviceID(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no POSIX stat_t available")
	}
	return uint64(st.Dev)
}
