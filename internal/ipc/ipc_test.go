package ipc_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
)

// shortSocketPath returns a socket path short enough for the 108-byte sun_path limit.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ipc")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func newVault(t *testing.T) *quarantine.Vault {
	t.Helper()
	v, err := quarantine.New(t.TempDir())
	if err != nil {
		t.Fatalf("quarantine.New: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

// startServer boots a server on a fresh socket and returns its path plus a stop func.
func startServer(t *testing.T, v *quarantine.Vault, provider ipc.StatusProvider) (string, *ipc.Server) {
	t.Helper()
	sock := shortSocketPath(t)
	srv := ipc.NewServer(sock, v, provider)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	// Wait for the socket to become dialable.
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("unix", sock, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("server Start returned error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("server did not shut down")
		}
	})
	return sock, srv
}

// quarantineOne places a file into the vault and returns its metadata.
func quarantineOne(t *testing.T, v *quarantine.Vault, name string, score int) *quarantine.ItemMetadata {
	t.Helper()
	src := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(src, []byte("malicious payload"), 0755); err != nil {
		t.Fatalf("write src: %v", err)
	}
	meta, err := v.QuarantineFile(src, score, []string{"test.trigger"}, []string{"test"}, nil)
	if err != nil {
		t.Fatalf("QuarantineFile: %v", err)
	}
	return meta
}

func TestRPCPing(t *testing.T) {
	v := newVault(t)
	sock, _ := startServer(t, v, ipc.StaticStatusProvider{})

	client, err := ipc.NewClient(sock)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestRPCGetStatus(t *testing.T) {
	v := newVault(t)
	provider := ipc.StaticStatusProvider{StatusData: ipc.StatusResponse{
		Uptime:          12.5,
		Version:         "test-1.0",
		ScannedCount:    7,
		QuarantineCount: 3,
		WatchPaths:      []string{"/tmp", "/home/user/Downloads"},
	}}
	sock, _ := startServer(t, v, provider)

	client, err := ipc.NewClient(sock)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	st, err := client.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if st.Version != "test-1.0" || st.ScannedCount != 7 || st.QuarantineCount != 3 {
		t.Fatalf("unexpected status: %+v", st)
	}
	if len(st.WatchPaths) != 2 {
		t.Fatalf("unexpected watch paths: %+v", st.WatchPaths)
	}
}

func TestRPCEndToEnd(t *testing.T) {
	v := newVault(t)
	meta := quarantineOne(t, v, "evil.bin", 95)
	sock, _ := startServer(t, v, ipc.StaticStatusProvider{})

	client, err := ipc.NewClient(sock)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// ListVault
	items, err := client.ListVault(ctx)
	if err != nil {
		t.Fatalf("ListVault: %v", err)
	}
	if len(items) != 1 || items[0].ID != meta.ID {
		t.Fatalf("ListVault mismatch: %+v", items)
	}

	// InspectItem
	got, err := client.InspectItem(ctx, meta.ID)
	if err != nil {
		t.Fatalf("InspectItem: %v", err)
	}
	if got.ID != meta.ID || got.Score != 95 {
		t.Fatalf("InspectItem mismatch: %+v", got)
	}

	// RestoreItem to a custom destination.
	dest := filepath.Join(t.TempDir(), "restored.bin")
	if err := client.RestoreItem(ctx, meta.ID, dest); err != nil {
		t.Fatalf("RestoreItem: %v", err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("restored file missing: %v", err)
	}
	if items, _ := client.ListVault(ctx); len(items) != 0 {
		t.Fatalf("vault should be empty after restore: %+v", items)
	}

	// PurgeItem
	meta2 := quarantineOne(t, v, "evil2.bin", 99)
	if err := client.PurgeItem(ctx, meta2.ID); err != nil {
		t.Fatalf("PurgeItem: %v", err)
	}
	if items, _ := client.ListVault(ctx); len(items) != 0 {
		t.Fatalf("vault should be empty after purge: %+v", items)
	}
}

func TestRPCInspectUnknownItem(t *testing.T) {
	v := newVault(t)
	sock, _ := startServer(t, v, ipc.StaticStatusProvider{})

	client, err := ipc.NewClient(sock)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.InspectItem(ctx, "does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown id")
	}
	if !ipc.IsNotFound(err) {
		t.Fatalf("expected ITEM_NOT_FOUND, got %v", err)
	}
}

func TestRPCUnknownMethod(t *testing.T) {
	v := newVault(t)
	sock, _ := startServer(t, v, ipc.StaticStatusProvider{})

	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := ipc.Request{ID: "1", Method: "BogusMethod"}
	data, _ := json.Marshal(req)
	if _, err := conn.Write(append(data, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp ipc.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != "METHOD_NOT_FOUND" {
		t.Fatalf("expected METHOD_NOT_FOUND, got %+v", resp)
	}
}

func TestRPCInvalidJSON(t *testing.T) {
	v := newVault(t)
	sock, _ := startServer(t, v, ipc.StaticStatusProvider{})

	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("this is not json\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp ipc.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != "INVALID_REQUEST" {
		t.Fatalf("expected INVALID_REQUEST, got %+v", resp)
	}
}

func TestStaleSocketRecovery(t *testing.T) {
	v := newVault(t)
	sock := shortSocketPath(t)

	// Create a socket file and close the listener without unlinking: a stale socket.
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Keep the socket file on close so we simulate a genuinely stale socket.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("expected stale socket to remain: %v", err)
	}

	// Starting the server must detect and remove the stale socket, then listen.
	srv := ipc.NewServer(sock, v, ipc.StaticStatusProvider{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		c, derr := net.DialTimeout("unix", sock, 50*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not recover stale socket: %v", derr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down")
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket file should be removed on stop, got err=%v", err)
	}
}

func TestAlreadyRunningRejected(t *testing.T) {
	v := newVault(t)
	sock, _ := startServer(t, v, ipc.StaticStatusProvider{})

	second := ipc.NewServer(sock, v, ipc.StaticStatusProvider{})
	err := second.Start(context.Background())
	if !errors.Is(err, ipc.ErrServerAlreadyRunning) {
		t.Fatalf("expected ErrServerAlreadyRunning, got %v", err)
	}
}

func TestSocketPermissions(t *testing.T) {
	v := newVault(t)
	sock, _ := startServer(t, v, ipc.StaticStatusProvider{})

	info, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected socket perms 0600, got %o", perm)
	}
}

func TestStopRemovesSocket(t *testing.T) {
	v := newVault(t)
	sock := shortSocketPath(t)
	srv := ipc.NewServer(sock, v, ipc.StaticStatusProvider{})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		c, derr := net.DialTimeout("unix", sock, 50*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", derr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-errCh
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket file should be gone, got err=%v", err)
	}
}

func TestClientReconnectAfterServerRestart(t *testing.T) {
	v := newVault(t)
	provider := ipc.StaticStatusProvider{StatusData: ipc.StatusResponse{Version: "v1"}}
	sock := shortSocketPath(t)

	srv := ipc.NewServer(sock, v, provider)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()
	waitDialable(t, sock)

	client, err := ipc.NewClient(sock)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	callCtx, callCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer callCancel()
	if _, err := client.GetStatus(callCtx); err != nil {
		t.Fatalf("initial GetStatus: %v", err)
	}

	// Stop the first server and wait for its teardown.
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop srv: %v", err)
	}
	cancel()
	<-errCh

	provider2 := ipc.StaticStatusProvider{StatusData: ipc.StatusResponse{Version: "v2"}}
	srv2 := ipc.NewServer(sock, v, provider2)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	errCh2 := make(chan error, 1)
	go func() { errCh2 <- srv2.Start(ctx2) }()
	waitDialable(t, sock)

	callCtx2, callCancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer callCancel2()
	st, err := client.GetStatus(callCtx2)
	if err != nil {
		t.Fatalf("GetStatus after restart: %v", err)
	}
	if st.Version != "v2" {
		t.Fatalf("expected reconnected to v2, got %q", st.Version)
	}
}

func waitDialable(t *testing.T, sock string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("unix", sock, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket never became dialable: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
