package watcher

import (
	"os"

	"github.com/fsnotify/fsnotify"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecursiveWatcherSubdirRegistration(t *testing.T) {
	tempDir := t.TempDir()

	w, err := New(Config{
		Roots:         []string{tempDir},
		DebounceDelay: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}
	defer w.Close()

	// Create a subdirectory inside tempDir
	subDir := filepath.Join(tempDir, "pkg-build-aur")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	// Give watcher a moment to receive Create event on directory and register it
	time.Sleep(100 * time.Millisecond)

	// Verify subdirectory is in watched dirs
	watched := w.WatchedDirectories()
	found := false
	for _, d := range watched {
		if d == subDir {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected subDir %s to be in watched dirs: %v", subDir, watched)
	}

	// Create a file inside the newly watched subDir
	testFile := filepath.Join(subDir, "payload.bin")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	select {
	case ev := <-w.Events():
		if ev.Path != testFile {
			t.Fatalf("expected event for %s, got %s", testFile, ev.Path)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for file event in newly created subdirectory")
	}
}

func TestDebounceHandling(t *testing.T) {
	tempDir := t.TempDir()

	w, err := New(Config{
		Roots:         []string{tempDir},
		DebounceDelay: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}
	defer w.Close()

	testFile := filepath.Join(tempDir, "write_stream.bin")

	// Perform multiple rapid writes
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(testFile, []byte("chunk"), 0644); err != nil {
			t.Fatalf("failed to write: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Wait for debounced event
	eventCount := 0
	deadline := time.After(500 * time.Millisecond)

loop:
	for {
		select {
		case ev := <-w.Events():
			if ev.Path == testFile {
				eventCount++
			}
		case <-deadline:
			break loop
		}
	}

	// Debouncing should coalesce rapid writes into 1 (or at most 2 depending on Create vs Modify) event
	if eventCount == 0 {
		t.Fatalf("expected at least 1 debounced event, got 0")
	}
	if eventCount > 2 {
		t.Fatalf("expected debouncing to coalesce 5 writes, but received %d events", eventCount)
	}
}

func TestIgnoredExtensions(t *testing.T) {
	tempDir := t.TempDir()

	w, err := New(Config{
		Roots:            []string{tempDir},
		IgnoreExtensions: []string{".crdownload", ".part", ".tmp"},
		DebounceDelay:    50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}
	defer w.Close()

	// Write ignored files
	ignored1 := filepath.Join(tempDir, "download.crdownload")
	ignored2 := filepath.Join(tempDir, "partial.part")
	ignored3 := filepath.Join(tempDir, "temp.tmp")

	_ = os.WriteFile(ignored1, []byte("tmp1"), 0644)
	_ = os.WriteFile(ignored2, []byte("tmp2"), 0644)
	_ = os.WriteFile(ignored3, []byte("tmp3"), 0644)

	// Write one valid file
	validFile := filepath.Join(tempDir, "valid.bin")
	_ = os.WriteFile(validFile, []byte("valid"), 0644)

	receivedValid := false
	timeout := time.After(300 * time.Millisecond)

loop:
	for {
		select {
		case ev := <-w.Events():
			if ev.Path == ignored1 || ev.Path == ignored2 || ev.Path == ignored3 {
				t.Fatalf("received event for ignored file: %s", ev.Path)
			}
			if ev.Path == validFile {
				receivedValid = true
			}
		case <-timeout:
			break loop
		}
	}

	if !receivedValid {
		t.Fatalf("expected to receive event for valid file")
	}
}

func TestRemovedFileCancelsPendingDebounce(t *testing.T) {
	for _, op := range []fsnotify.Op{fsnotify.Remove, fsnotify.Rename} {
		t.Run(op.String(), func(t *testing.T) {
			w, err := New(Config{Roots: []string{t.TempDir()}, DebounceDelay: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			path := filepath.Join(t.TempDir(), "moved.bin")
			w.dispatchFileEvent(path)
			w.handleFsEvent(fsnotify.Event{Name: path, Op: op})
			w.mu.Lock()
			_, pending := w.timers[path]
			w.mu.Unlock()
			if pending {
				t.Fatalf("debounce timer left for %s after %s", path, op)
			}
			select {
			case ev := <-w.Events():
				t.Fatalf("stale event for moved-away path: %+v", ev)
			default:
			}
		})
	}
}

func TestImmediateFileKindsMatchPipeline(t *testing.T) {
	w := &Watcher{}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"x.pkgbuild", false},
		{"PKGBUILD", true},
		{"x.install", true},
	} {
		if got := w.isImmediate(tc.path); got != tc.want {
			t.Errorf("isImmediate(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestImmediatePKGBUILD(t *testing.T) {
	tempDir := t.TempDir()

	w, err := New(Config{
		Roots:         []string{tempDir},
		DebounceDelay: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}
	defer w.Close()

	pkgbuild := filepath.Join(tempDir, "PKGBUILD")
	start := time.Now()
	if err := os.WriteFile(pkgbuild, []byte("pkgname=foo\n"), 0644); err != nil {
		t.Fatalf("failed to write PKGBUILD: %v", err)
	}

	select {
	case ev := <-w.Events():
		elapsed := time.Since(start)
		if ev.Path != pkgbuild {
			t.Fatalf("expected PKGBUILD event, got %s", ev.Path)
		}
		if !ev.Immediate {
			t.Fatalf("expected Immediate flag to be true for PKGBUILD")
		}
		if elapsed >= 200*time.Millisecond {
			t.Fatalf("expected immediate dispatch (< 200ms debounce), took %v", elapsed)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for PKGBUILD event")
	}
}

func TestReconcileWalk(t *testing.T) {
	tempDir := t.TempDir()

	// Create subdirectories and files prior to walk
	nestedDir := filepath.Join(tempDir, "a", "b")
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}
	fileA := filepath.Join(tempDir, "a", "fileA.bin")
	fileB := filepath.Join(nestedDir, "fileB.bin")
	_ = os.WriteFile(fileA, []byte("A"), 0644)
	_ = os.WriteFile(fileB, []byte("B"), 0644)

	w, err := New(Config{
		Roots:         []string{tempDir},
		DebounceDelay: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}
	defer w.Close()

	// Trigger reconciliation walk
	if err := w.ReconcileWalk(); err != nil {
		t.Fatalf("reconcile walk failed: %v", err)
	}

	foundA := false
	foundB := false
	timeout := time.After(500 * time.Millisecond)

loop:
	for {
		select {
		case ev := <-w.Events():
			if ev.Path == fileA {
				foundA = true
			}
			if ev.Path == fileB {
				foundB = true
			}
			if foundA && foundB {
				break loop
			}
		case <-timeout:
			break loop
		}
	}

	if !foundA || !foundB {
		t.Fatalf("reconcile walk missed files: foundA=%v, foundB=%v", foundA, foundB)
	}
}

func TestQueueOverflowReconciliation(t *testing.T) {
	tempDir := t.TempDir()

	w, err := New(Config{
		Roots:         []string{tempDir},
		DebounceDelay: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}
	defer w.Close()

	// Create a file in tempDir without giving time to watch or simulating missed event
	fileX := filepath.Join(tempDir, "missed_during_overflow.bin")
	if err := os.WriteFile(fileX, []byte("overflow content"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Trigger queue overflow recovery
	w.triggerReconcile()

	found := false
	timeout := time.After(1 * time.Second)
loop:
	for {
		select {
		case ev := <-w.Events():
			if ev.Path == fileX {
				found = true
				break loop
			}
		case <-timeout:
			break loop
		}
	}

	if !found {
		t.Fatalf("queue overflow reconciliation failed to discover %s", fileX)
	}
}

func TestAddRoot(t *testing.T) {
	tempDir := t.TempDir()

	w, err := New(Config{
		Roots:         []string{tempDir},
		DebounceDelay: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}
	defer w.Close()

	// 1. AddRoot on non-existent path must fail loudly
	missingPath := filepath.Join(tempDir, "does_not_exist_dir", "missing")
	err = w.AddRoot(missingPath)
	if err == nil {
		t.Fatalf("expected error adding non-existent path %s, got nil", missingPath)
	}
	wantPrefix := "watch path does not exist:"
	if !strings.Contains(err.Error(), wantPrefix) {
		t.Fatalf("expected error containing %q, got: %v", wantPrefix, err)
	}

	// 2. AddRoot on existing individual file works and appears in WatchedDirs()
	filePath := filepath.Join(tempDir, "standalone.txt")
	if err := os.WriteFile(filePath, []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	if err := w.AddRoot(filePath); err != nil {
		t.Fatalf("expected AddRoot on individual file to succeed, got: %v", err)
	}

	watchedDirs := w.WatchedDirectories()
	found := false
	for _, d := range watchedDirs {
		if d == filePath {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected file %s to appear in WatchedDirectories: %v", filePath, watchedDirs)
	}
}

func TestDirectoryMoveDispatchesNestedFiles(t *testing.T) {
	watchRoot := t.TempDir()
	outsideDir := t.TempDir()

	nestedSubdir := filepath.Join(outsideDir, "staged_dir")
	if err := os.MkdirAll(nestedSubdir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	nestedFile := filepath.Join(nestedSubdir, "payload.bin")
	if err := os.WriteFile(nestedFile, []byte("data"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	w, err := New(Config{
		Roots:         []string{watchRoot},
		DebounceDelay: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New watcher: %v", err)
	}
	defer w.Close()

	// Move staged_dir into watchRoot
	destDir := filepath.Join(watchRoot, "moved_dir")
	if err := os.Rename(nestedSubdir, destDir); err != nil {
		t.Fatalf("rename dir: %v", err)
	}

	expectedFile := filepath.Join(destDir, "payload.bin")
	select {
	case ev := <-w.Events():
		if ev.Path != expectedFile {
			t.Fatalf("expected event for %s, got %s", expectedFile, ev.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for event on moved directory nested file")
	}
}
