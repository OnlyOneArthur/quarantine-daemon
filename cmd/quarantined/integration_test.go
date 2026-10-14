// Package main exercises the quarantined daemon end to end over a real Unix
// socket and vault.
package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/watcher"
)

// waitFor repeatedly invokes check until it returns true or the timeout expires.
func waitFor(t *testing.T, check func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return check()
}

// shortSocketDir creates a temporary directory in os.TempDir to stay within
// the 108-character sockaddr_un limit.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "qint")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// TestEndToEndPipelineIntegration verifies the complete daemon lifecycle:
// directory monitoring, threat detection, safe isolation into the vault,
// chmod 0000 neutralization, .meta.json sidecar generation, PKGBUILD stubbing,
// symlink non-traversal, and all IPC client RPC operations.
func TestEndToEndPipelineIntegration(t *testing.T) {
	root := t.TempDir()
	vaultDir := filepath.Join(root, "vault")
	watchDir := filepath.Join(root, "watch1")
	if err := os.MkdirAll(watchDir, 0700); err != nil {
		t.Fatalf("mkdir watchDir: %v", err)
	}

	sockDir := shortSocketDir(t)
	sockPath := filepath.Join(sockDir, "daemon.sock")

	cfg := config.DefaultConfig()
	cfg.Quarantine.VaultDir = vaultDir
	cfg.Paths.Watch = []string{watchDir}
	cfg.Service.SocketPath = sockPath
	cfg.Service.PollIntervalMs = 50

	v, err := quarantine.New(cfg.Quarantine.VaultDir)
	if err != nil {
		t.Fatalf("quarantine.New: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	w, err := watcher.New(watcher.Config{
		Roots:         cfg.Paths.Watch,
		DebounceDelay: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("watcher.New: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	p := newPipeline(cfg, v, discardLogger())
	ctrl := newDaemonController(p, w, cfg, Version)

	srv := ipc.NewServer(cfg.Service.SocketPath, v, ctrl)
	srv.SetWatchManager(ctrl)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvErrCh := make(chan error, 1)
	go func() {
		srvErrCh <- srv.Start(ctx)
	}()
	t.Cleanup(func() {
		_ = srv.Stop()
	})

	// Background worker processing events from the watcher pipeline.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-w.Events():
				if !ok {
					return
				}
				if _, err := p.handlePath(ev.Path); err != nil {
					// Logged internally by the pipeline; the file is simply retried on
					// the next event.
					_ = err
				}
			case _, ok := <-w.Errors():
				if !ok {
					return
				}
			}
		}
	}()

	dialDeadline := time.Now().Add(3 * time.Second)
	for {
		c, dialErr := net.DialTimeout("unix", sockPath, 50*time.Millisecond)
		if dialErr == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(dialDeadline) {
			t.Fatalf("timed out waiting for IPC socket %s: %v", sockPath, dialErr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	client, err := ipc.NewClient(sockPath)
	if err != nil {
		t.Fatalf("ipc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	rpcCtx, rpcCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rpcCancel()

	if err := client.Ping(rpcCtx); err != nil {
		t.Fatalf("client.Ping failed: %v", err)
	}

	cleanContent := []byte("harmless text data from benign author\n")
	cleanPath := filepath.Join(watchDir, "clean_doc.txt")
	if err := os.WriteFile(cleanPath, cleanContent, 0644); err != nil {
		t.Fatalf("write clean file: %v", err)
	}

	ok := waitFor(t, func() bool {
		st, err := client.GetStatus(rpcCtx)
		return err == nil && st.ScannedCount >= 1
	})
	if !ok {
		t.Fatalf("timed out waiting for clean file to be scanned (scannedCount=%d)", p.scanned.Load())
	}

	cleanGot, err := os.ReadFile(cleanPath)
	if err != nil {
		t.Fatalf("read clean file: %v", err)
	}
	if !bytes.Equal(cleanGot, cleanContent) {
		t.Fatalf("clean file content modified: %q", string(cleanGot))
	}

	st, err := client.GetStatus(rpcCtx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if st.QuarantineCount != 0 {
		t.Fatalf("expected 0 quarantined items, got %d", st.QuarantineCount)
	}

	pkgbuildPath := filepath.Join(watchDir, "PKGBUILD")
	if err := os.WriteFile(pkgbuildPath, []byte(maliciousPKGBUILD), 0644); err != nil {
		t.Fatalf("write malicious PKGBUILD: %v", err)
	}

	ok = waitFor(t, func() bool {
		st, err := client.GetStatus(rpcCtx)
		return err == nil && st.QuarantineCount >= 1
	})
	if !ok {
		t.Fatalf("timed out waiting for malicious PKGBUILD to be quarantined (quarantined=%d)", p.quarantined.Load())
	}

	stubContent, err := os.ReadFile(pkgbuildPath)
	if err != nil {
		t.Fatalf("read stub: %v", err)
	}
	if !strings.Contains(string(stubContent), "Quarantined by quarantined daemon") {
		t.Fatalf("expected decoy stub at watched path, got: %s", string(stubContent))
	}

	fixturePath := filepath.Join("..", "..", "testdata", "binary", "elf_malicious_combined")
	maliciousBinBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	binTarget := filepath.Join(watchDir, "malicious_elf")
	if err := os.WriteFile(binTarget, maliciousBinBytes, 0755); err != nil {
		t.Fatalf("write malicious binary: %v", err)
	}

	ok = waitFor(t, func() bool {
		st, err := client.GetStatus(rpcCtx)
		return err == nil && st.QuarantineCount >= 2
	})
	if !ok {
		t.Fatalf("timed out waiting for malicious binary to be quarantined (quarantined=%d)", p.quarantined.Load())
	}

	if _, err := os.Stat(binTarget); !os.IsNotExist(err) {
		t.Fatalf("expected original binary to be removed from watch dir, err=%v", err)
	}

	vaultItems, err := client.ListVault(rpcCtx)
	if err != nil {
		t.Fatalf("client.ListVault: %v", err)
	}
	if len(vaultItems) != 2 {
		t.Fatalf("expected 2 vault items, got %d", len(vaultItems))
	}

	var pkgMeta, binMeta *quarantine.ItemMetadata
	for _, item := range vaultItems {
		if item.IsPKGBUILD {
			pkgMeta = item
		} else {
			binMeta = item
		}
	}
	if pkgMeta == nil || binMeta == nil {
		t.Fatalf("expected both PKGBUILD and binary items in vault, got: %+v", vaultItems)
	}

	binArtifactPath := filepath.Join(vaultDir, binMeta.ID)
	binArtifactInfo, err := os.Stat(binArtifactPath)
	if err != nil {
		t.Fatalf("stat vault artifact %s: %v", binArtifactPath, err)
	}
	if binArtifactInfo.Mode().Perm() != 0000 {
		t.Fatalf("expected neutralized 0000 permissions on vault artifact, got: %o", binArtifactInfo.Mode().Perm())
	}

	binSidecarPath := filepath.Join(vaultDir, binMeta.ID+".meta.json")
	if _, err := os.Stat(binSidecarPath); err != nil {
		t.Fatalf("expected sidecar meta file %s: %v", binSidecarPath, err)
	}
	if binMeta.Score < 85 {
		t.Fatalf("expected binary score >= 85, got %d", binMeta.Score)
	}
	if len(binMeta.Triggers) == 0 {
		t.Fatal("expected triggers recorded in binary metadata")
	}

	inspected, err := client.InspectItem(rpcCtx, binMeta.ID)
	if err != nil {
		t.Fatalf("client.InspectItem: %v", err)
	}
	if inspected.SHA256 != binMeta.SHA256 || inspected.Score != binMeta.Score {
		t.Fatalf("inspected metadata mismatch: got %+v, want %+v", inspected, binMeta)
	}

	_, err = client.InspectItem(rpcCtx, "nonexistent-hash")
	var rpcErr *ipc.RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != "ITEM_NOT_FOUND" {
		t.Fatalf("expected ITEM_NOT_FOUND error for nonexistent ID, got %v", err)
	}

	dummyTarget := filepath.Join(root, "target.txt")
	_ = os.WriteFile(dummyTarget, []byte("target"), 0644)
	symlinkDest := filepath.Join(root, "symlink_dest")
	if err := os.Symlink(dummyTarget, symlinkDest); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if err := client.RestoreItem(rpcCtx, binMeta.ID, symlinkDest); err == nil {
		t.Fatal("expected RestoreItem to reject symlink destination, but it succeeded")
	}

	restoreDest := filepath.Join(root, "restored_binary")
	if err := client.RestoreItem(rpcCtx, binMeta.ID, restoreDest); err != nil {
		t.Fatalf("client.RestoreItem: %v", err)
	}

	restoredBytes, err := os.ReadFile(restoreDest)
	if err != nil {
		t.Fatalf("read restored binary: %v", err)
	}
	if !bytes.Equal(restoredBytes, maliciousBinBytes) {
		t.Fatal("restored content does not match original malicious binary")
	}
	restoredInfo, err := os.Stat(restoreDest)
	if err != nil {
		t.Fatalf("stat restored binary: %v", err)
	}
	if restoredInfo.Mode().Perm() != 0755 {
		t.Fatalf("expected restored permissions 0755, got: %o", restoredInfo.Mode().Perm())
	}

	if _, err := os.Stat(binArtifactPath); !os.IsNotExist(err) {
		t.Fatalf("expected vault artifact %s to be unlinked after restore", binArtifactPath)
	}
	if _, err := os.Stat(binSidecarPath); !os.IsNotExist(err) {
		t.Fatalf("expected sidecar %s to be unlinked after restore", binSidecarPath)
	}

	pkgArtifactPath := filepath.Join(vaultDir, pkgMeta.ID)
	pkgSidecarPath := filepath.Join(vaultDir, pkgMeta.ID+".meta.json")

	if err := client.PurgeItem(rpcCtx, pkgMeta.ID); err != nil {
		t.Fatalf("client.PurgeItem: %v", err)
	}
	if _, err := os.Stat(pkgArtifactPath); !os.IsNotExist(err) {
		t.Fatalf("expected purged artifact %s to be removed", pkgArtifactPath)
	}
	if _, err := os.Stat(pkgSidecarPath); !os.IsNotExist(err) {
		t.Fatalf("expected purged sidecar %s to be removed", pkgSidecarPath)
	}

	remaining, err := client.ListVault(rpcCtx)
	if err != nil {
		t.Fatalf("ListVault after purge: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected empty vault after purge, got %d items", len(remaining))
	}

	watchDir2 := filepath.Join(root, "watch2")
	if err := os.MkdirAll(watchDir2, 0700); err != nil {
		t.Fatalf("mkdir watchDir2: %v", err)
	}
	if err := client.AddWatchPath(rpcCtx, watchDir2); err != nil {
		t.Fatalf("client.AddWatchPath: %v", err)
	}

	st, err = client.GetStatus(rpcCtx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	foundWatch2 := false
	for _, wp := range st.WatchPaths {
		if wp == watchDir2 {
			foundWatch2 = true
			break
		}
	}
	if !foundWatch2 {
		t.Fatalf("expected watchDir2 in Status.WatchPaths, got: %v", st.WatchPaths)
	}

	target2 := filepath.Join(watchDir2, "injected_rootkit")
	if err := os.WriteFile(target2, maliciousBinBytes, 0755); err != nil {
		t.Fatalf("write payload to watchDir2: %v", err)
	}

	ok = waitFor(t, func() bool {
		items, err := client.ListVault(rpcCtx)
		return err == nil && len(items) == 1
	})
	if !ok {
		t.Fatalf("timed out waiting for file in dynamically added watch directory to be quarantined")
	}

	if _, err := os.Stat(target2); !os.IsNotExist(err) {
		t.Fatalf("expected file in watchDir2 to be quarantined and removed")
	}

	outsideSecret := filepath.Join(root, "outside_secret.txt")
	secretData := []byte("confidential root configuration")
	if err := os.WriteFile(outsideSecret, secretData, 0600); err != nil {
		t.Fatalf("write outside secret: %v", err)
	}

	symlinkAttack := filepath.Join(watchDir, "symlink_to_secret")
	if err := os.Symlink(outsideSecret, symlinkAttack); err != nil {
		t.Fatalf("create symlink to secret: %v", err)
	}

	_, symlinkErr := p.handlePath(symlinkAttack)
	if symlinkErr == nil {
		t.Fatal("expected pipeline.handlePath to reject symlink, but it succeeded")
	}
	if !strings.Contains(symlinkErr.Error(), fsutil.ErrSymlinkNotAllowed.Error()) {
		t.Fatalf("expected ErrSymlinkNotAllowed in error message, got: %v", symlinkErr)
	}

	secretGot, err := os.ReadFile(outsideSecret)
	if err != nil {
		t.Fatalf("read outside secret: %v", err)
	}
	if !bytes.Equal(secretGot, secretData) {
		t.Fatal("outside secret was modified or corrupted by symlink handling")
	}
}
