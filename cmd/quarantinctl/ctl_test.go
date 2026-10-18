package main

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
)

type mockProvider struct{}

func (m *mockProvider) Status() ipc.StatusResponse {
	return ipc.StatusResponse{
		Uptime:          123.4,
		Version:         Version,
		ScannedCount:    42,
		QuarantineCount: 1,
		WatchPaths:      []string{"/tmp/watch"},
		ThresholdScore:  85,
		AlertScore:      50,
	}
}

func (m *mockProvider) AddWatchPath(path string) error {
	return nil
}

func setupTestServer(t *testing.T) (string, func()) {
	t.Helper()
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "test.sock")

	v, err := quarantine.New(t.TempDir())
	if err != nil {
		t.Fatalf("quarantine.New: %v", err)
	}

	prov := &mockProvider{}
	srv := ipc.NewServer(sockPath, v, prov)
	srv.SetWatchManager(prov)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for socket to become ready
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, dialErr := net.Dial("unix", sockPath)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server socket did not appear in time: %v", dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cleanup := func() {
		cancel()
		_ = srv.Stop()
		_ = v.Close()
	}
	return sockPath, cleanup
}

func TestQuarantinctlStatus(t *testing.T) {
	sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	client, err := ipc.NewClient(sockPath)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := handleStatus(ctx, client, false); err != nil {
		t.Fatalf("handleStatus text: %v", err)
	}
	if err := handleStatus(ctx, client, true); err != nil {
		t.Fatalf("handleStatus json: %v", err)
	}
}

func TestQuarantinctlListEmpty(t *testing.T) {
	sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	client, err := ipc.NewClient(sockPath)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := handleList(ctx, client, false); err != nil {
		t.Fatalf("handleList text: %v", err)
	}
	if err := handleList(ctx, client, true); err != nil {
		t.Fatalf("handleList json: %v", err)
	}
}

func TestQuarantinctlWatchAdd(t *testing.T) {
	sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	client, err := ipc.NewClient(sockPath)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := handleWatchAdd(ctx, client, t.TempDir()); err != nil {
		t.Fatalf("handleWatchAdd: %v", err)
	}
}

func TestResolveSocket(t *testing.T) {
	sock := resolveSocket("/custom/sock.sock", "")
	if sock != "/custom/sock.sock" {
		t.Errorf("got %s, want /custom/sock.sock", sock)
	}

	sockDefault := resolveSocket("", "")
	if sockDefault == "" {
		t.Error("expected non-empty default socket path")
	}
}
