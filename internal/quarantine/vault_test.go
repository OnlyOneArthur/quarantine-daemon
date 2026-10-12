package quarantine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
)

func writeFile(t *testing.T, path string, content []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, perm); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

func TestQuarantineFileNeutralizesArtifact(t *testing.T) {
	vaultDir := t.TempDir()
	srcDir := t.TempDir()
	v, err := New(vaultDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer v.Close()

	content := []byte("malicious binary payload")
	srcPath := filepath.Join(srcDir, "evil.bin")
	writeFile(t, srcPath, content, 0755)

	meta, err := v.QuarantineFile(srcPath, 90, []string{"reverse_shell"}, []string{"remote_execution"}, []string{"go_runtime"})
	if err != nil {
		t.Fatalf("QuarantineFile: %v", err)
	}

	// Source is gone from staging.
	if _, err := os.Lstat(srcPath); !os.IsNotExist(err) {
		t.Errorf("expected source to be removed, lstat err: %v", err)
	}

	// Artifact lives in vault under its sha256 with permissions 0000.
	if mode := fileMode(t, v.artifactPath(meta.ID)); mode != 0000 {
		t.Errorf("expected artifact perms 0000, got %04o", mode)
	}
	sum := sha256.Sum256(content)
	if want := hex.EncodeToString(sum[:]); meta.SHA256 != want {
		t.Errorf("expected sha256 %s, got %s", want, meta.SHA256)
	}
	if filepath.Base(v.artifactPath(meta.ID)) != meta.SHA256 {
		t.Errorf("artifact path %s not named by sha256", v.artifactPath(meta.ID))
	}

	data, err := os.ReadFile(v.artifactPath(meta.ID))
	if err != nil {
		// 0000 perms block read as non-root; that is the desired state.
		t.Logf("artifact unreadable at 0000 (expected for non-root): %v", err)
	} else if !bytes.Equal(data, content) {
		t.Errorf("artifact content mismatch: %q", data)
	}

	// Metadata sidecar persisted with all fields.
	got, err := v.Inspect(meta.ID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.OriginalPath != srcPath {
		t.Errorf("OriginalPath = %s, want %s", got.OriginalPath, srcPath)
	}
	if got.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", got.Size, len(content))
	}
	if got.Score != 90 || got.IsPKGBUILD {
		t.Errorf("Score=%d IsPKGBUILD=%v", got.Score, got.IsPKGBUILD)
	}
	if len(got.Triggers) != 1 || got.Triggers[0] != "reverse_shell" {
		t.Errorf("Triggers = %v", got.Triggers)
	}
	if got.OriginalMode != 0755 {
		t.Errorf("OriginalMode = %04o, want 0755", got.OriginalMode)
	}

	// List surfaces exactly one item.
	items, err := v.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 1 || items[0].ID != meta.ID {
		t.Errorf("List = %d items, want 1 (%s)", len(items), meta.ID)
	}
}

func TestQuarantineRespectsVaultSizeCap(t *testing.T) {
	v, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	v.SetLimits(1, 0)
	srcDir := t.TempDir()
	first := filepath.Join(srcDir, "first.bin")
	second := filepath.Join(srcDir, "second.bin")
	writeFile(t, first, bytes.Repeat([]byte("a"), 600*1024), 0644)
	writeFile(t, second, bytes.Repeat([]byte("b"), 600*1024), 0644)
	if _, err := v.QuarantineFile(first, 90, nil, nil, nil); err != nil {
		t.Fatalf("first quarantine: %v", err)
	}
	if _, err := v.QuarantineFile(second, 90, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "vault size cap exceeded") {
		t.Fatalf("second quarantine error = %v, want size cap error", err)
	}
	if got, err := os.ReadFile(second); err != nil || len(got) != 600*1024 {
		t.Fatalf("rejected source was modified: len=%d, error=%v", len(got), err)
	}
	items, err := v.List()
	if err != nil || len(items) != 1 {
		t.Fatalf("vault after rejection = %d items, error=%v; want 1", len(items), err)
	}
}

func TestSweepPurgesExpiredItems(t *testing.T) {
	v, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	v.SetLimits(0, 14)
	srcDir := t.TempDir()
	oldPath := filepath.Join(srcDir, "old.bin")
	newPath := filepath.Join(srcDir, "new.bin")
	writeFile(t, oldPath, []byte("old"), 0644)
	writeFile(t, newPath, []byte("new"), 0644)
	oldItem, err := v.QuarantineFile(oldPath, 90, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	newItem, err := v.QuarantineFile(newPath, 90, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldItem.QuarantinedAt = time.Now().UTC().AddDate(0, 0, -15)
	if err := v.writeMeta(oldItem); err != nil {
		t.Fatal(err)
	}
	if err := v.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if _, err := v.Inspect(oldItem.ID); err != ErrItemNotFound {
		t.Errorf("expired metadata still present: %v", err)
	}
	if _, err := os.Stat(v.artifactPath(oldItem.ID)); !os.IsNotExist(err) {
		t.Errorf("expired artifact still present: %v", err)
	}
	if _, err := v.Inspect(newItem.ID); err != nil {
		t.Errorf("unexpired item removed: %v", err)
	}
}

func TestQuarantinePKGBUILDWritesBlockingStub(t *testing.T) {
	vaultDir := t.TempDir()
	srcDir := t.TempDir()
	v, err := New(vaultDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer v.Close()

	orig := []byte("pkgname=evil\npkgver=1.0\npkgrel=1\n")
	srcPath := filepath.Join(srcDir, "PKGBUILD")
	writeFile(t, srcPath, orig, 0644)

	meta, err := v.QuarantineFile(srcPath, 88, []string{"eval"}, []string{"remote_execution"}, nil)
	if err != nil {
		t.Fatalf("QuarantineFile: %v", err)
	}
	if !meta.IsPKGBUILD {
		t.Fatalf("expected IsPKGBUILD=true")
	}

	// Artifact neutralized to 0000.
	if mode := fileMode(t, v.artifactPath(meta.ID)); mode != 0000 {
		t.Errorf("expected artifact perms 0000, got %04o", mode)
	}

	// Stub replaces the original path and blocks execution.
	stub, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read stub: %v", err)
	}
	stubStr := string(stub)
	if !strings.Contains(stubStr, "ERROR: PKGBUILD blocked due to high-confidence security threat (Score >= 85)") {
		t.Errorf("stub missing block message:\n%s", stubStr)
	}
	if !strings.Contains(stubStr, "exit 1") {
		t.Errorf("stub missing exit 1:\n%s", stubStr)
	}
	if mode := fileMode(t, srcPath); mode != 0755 {
		t.Errorf("expected stub perms 0755, got %04o", mode)
	}

	// Original content is preserved only in the vault.
	if bytes.Equal(stub, orig) {
		t.Errorf("stub equals original PKGBUILD content")
	}
}

func TestRestoreToOriginalPath(t *testing.T) {
	vaultDir := t.TempDir()
	srcDir := t.TempDir()
	v, err := New(vaultDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer v.Close()

	content := []byte("restore me")
	srcPath := filepath.Join(srcDir, "payload.bin")
	writeFile(t, srcPath, content, 0640)

	meta, err := v.QuarantineFile(srcPath, 95, nil, nil, nil)
	if err != nil {
		t.Fatalf("QuarantineFile: %v", err)
	}

	if err := v.Restore(meta.ID, ""); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Errorf("restored content = %q, want %q", data, content)
	}
	if mode := fileMode(t, srcPath); mode != 0640 {
		t.Errorf("restored mode = %04o, want 0640", mode)
	}

	// Vault entries removed.
	if _, err := os.Lstat(v.artifactPath(meta.ID)); !os.IsNotExist(err) {
		t.Errorf("expected artifact removed, lstat err: %v", err)
	}
	if _, err := os.Lstat(v.metaPath(meta.ID)); !os.IsNotExist(err) {
		t.Errorf("expected meta removed, lstat err: %v", err)
	}
	if _, err := v.Inspect(meta.ID); err != ErrItemNotFound {
		t.Errorf("Inspect after restore = %v, want ErrItemNotFound", err)
	}
}

func TestQuarantinePreservesArtifactWhenMetadataWriteFails(t *testing.T) {
	vaultDir := t.TempDir()
	srcDir := t.TempDir()
	v, err := New(vaultDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer v.Close()

	content := []byte("preserve me")
	srcPath := filepath.Join(srcDir, "payload.bin")
	writeFile(t, srcPath, content, 0644)

	sum := sha256.Sum256(content)
	id := hex.EncodeToString(sum[:])
	// Make the sidecar rename fail after the source has moved into the vault.
	if err := os.Mkdir(v.metaPath(id), 0700); err != nil {
		t.Fatal(err)
	}
	_, err = v.QuarantineFile(srcPath, 90, nil, nil, nil)
	if err == nil {
		t.Fatal("expected metadata write failure")
	}
	artifact := v.artifactPath(id)
	if _, statErr := os.Stat(artifact); statErr != nil {
		t.Fatalf("artifact was lost after failed quarantine: %v", statErr)
	}
	if err := os.Chmod(artifact, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(artifact)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("preserved artifact = %q, err %v", got, err)
	}
}

func TestRestoreToSymlinkFails(t *testing.T) {
	vaultDir := t.TempDir()
	srcDir := t.TempDir()
	v, err := New(vaultDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer v.Close()

	srcPath := filepath.Join(srcDir, "data.bin")
	writeFile(t, srcPath, []byte("payload"), 0644)

	meta, err := v.QuarantineFile(srcPath, 91, nil, nil, nil)
	if err != nil {
		t.Fatalf("QuarantineFile: %v", err)
	}

	// Plant a symlink at the destination to catch symlink-follow attacks.
	victimPath := filepath.Join(srcDir, "victim.txt")
	writeFile(t, victimPath, []byte("victim"), 0644)
	if err := os.Symlink(victimPath, srcPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := v.Restore(meta.ID, ""); err == nil {
		t.Fatalf("expected restore to fail against symlink destination")
	}

	// Victim untouched, artifact back to 0000, item still quarantined.
	victim, _ := os.ReadFile(victimPath)
	if !bytes.Equal(victim, []byte("victim")) {
		t.Errorf("victim modified: %q", victim)
	}
	if mode := fileMode(t, v.artifactPath(meta.ID)); mode != 0000 {
		t.Errorf("expected artifact re-neutralized to 0000, got %04o", mode)
	}
	if _, err := v.Inspect(meta.ID); err != nil {
		t.Errorf("expected item still present after failed restore: %v", err)
	}
}

func TestRestoreCustomDestination(t *testing.T) {
	vaultDir := t.TempDir()
	srcDir := t.TempDir()
	v, err := New(vaultDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer v.Close()

	srcPath := filepath.Join(srcDir, "orig.bin")
	writeFile(t, srcPath, []byte("custom"), 0600)

	meta, err := v.QuarantineFile(srcPath, 89, nil, nil, nil)
	if err != nil {
		t.Fatalf("QuarantineFile: %v", err)
	}

	customDest := filepath.Join(t.TempDir(), "restored.bin")
	if err := v.Restore(meta.ID, customDest); err != nil {
		t.Fatalf("Restore custom: %v", err)
	}
	data, err := os.ReadFile(customDest)
	if err != nil || !bytes.Equal(data, []byte("custom")) {
		t.Errorf("custom restore content = %q, err %v", data, err)
	}
	if mode := fileMode(t, customDest); mode != 0600 {
		t.Errorf("custom restore mode = %04o, want 0600", mode)
	}
}

func TestConcurrentQuarantineSerializedByLock(t *testing.T) {
	vaultDir := t.TempDir()
	srcDir := t.TempDir()
	v, err := New(vaultDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer v.Close()

	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			src := filepath.Join(srcDir, "f"+string(rune('a'+i)))
			writeFile(t, src, []byte{byte(i)}, 0644)
			if _, err := v.QuarantineFile(src, 87, nil, nil, nil); err != nil {
				t.Errorf("QuarantineFile %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	items, err := v.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != n {
		t.Errorf("List = %d items, want %d", len(items), n)
	}
}

func TestInspectUnknownID(t *testing.T) {
	v, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer v.Close()

	if _, err := v.Inspect("does-not-exist"); err != ErrItemNotFound {
		t.Errorf("Inspect = %v, want ErrItemNotFound", err)
	}
}

// TestVaultLockHeldDuringOperation asserts the flock is actually taken by
// withLock: a second independent fd on vault.lock cannot lock concurrently.
func TestVaultLockHeldDuringOperation(t *testing.T) {
	v, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer v.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = v.withLock(func() error {
			second, err := os.OpenFile(v.lockFile.Name(), os.O_RDWR, 0600)
			if err != nil {
				t.Errorf("open lock file: %v", err)
				return nil
			}
			defer second.Close()
			if unlock, err := fsutil.LockFile(second); err == nil {
				_ = unlock()
				t.Error("expected second lock attempt to fail while held")
			}
			return nil
		})
	}()
	<-done

	// Lock released after withLock returns.
	second, err := os.OpenFile(v.lockFile.Name(), os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("open lock file: %v", err)
	}
	defer second.Close()
	unlock, err := fsutil.LockFile(second)
	if err != nil {
		t.Fatalf("expected lock available after release: %v", err)
	}
	_ = unlock()
}
