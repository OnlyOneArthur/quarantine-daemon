package ipc_test

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
)

func TestStartAfterStopReturnsErrClosed(t *testing.T) {
	v := newVault(t)
	sock := shortSocketPath(t)
	srv := ipc.NewServer(sock, v, ipc.StaticStatusProvider{})
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	err := srv.Start(context.Background())
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Start after Stop: want net.ErrClosed, got %v", err)
	}
	if _, statErr := os.Lstat(sock); !os.IsNotExist(statErr) {
		t.Errorf("socket must not remain after closed Start, lstat err: %v", statErr)
	}
}

func TestOversizedRequestReturnsInvalidRequest(t *testing.T) {
	v := newVault(t)
	sock, _ := startServer(t, v, ipc.StaticStatusProvider{})

	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Exceed the server's 10MB scanner limit without a newline so Scan fails.
	go func() {
		chunk := []byte(strings.Repeat("a", 1<<20))
		for i := 0; i < 11; i++ {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	}()

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(string(line), `"code":"INVALID_REQUEST"`) {
		t.Fatalf("response = %s, want INVALID_REQUEST", line)
	}
}

// fakeDropServer accepts connections and drops the first `drops` of them after
// reading one request line without replying; later connections get an OK reply.
type fakeDropServer struct {
	ln       net.Listener
	drops    int
	mu       sync.Mutex
	requests int
}

func startFakeDropServer(t *testing.T, drops int) *fakeDropServer {
	t.Helper()
	ln, err := net.Listen("unix", shortSocketPath(t))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeDropServer{ln: ln, drops: drops}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakeDropServer) serve(conn net.Conn) {
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return
	}
	f.mu.Lock()
	f.requests++
	drop := f.requests <= f.drops
	f.mu.Unlock()
	if drop {
		return
	}
	id := strings.TrimSpace(string(line))
	_, _ = conn.Write([]byte(`{"id":"` + idFromRequest(id) + `","result":{"status":"ok"}}` + "\n"))
}

// idFromRequest extracts the "id" field value from a request line.
func idFromRequest(line string) string {
	const key = `"id":"`
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	rest := line[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func (f *fakeDropServer) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func TestMutatingCallNotRetriedOnTransportFailure(t *testing.T) {
	f := startFakeDropServer(t, 1)
	client, err := ipc.NewClient(f.ln.Addr().String())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.RestoreItem(ctx, "abc", ""); err == nil {
		t.Fatal("RestoreItem with dropped response: want error, got nil")
	}
	if got := f.requestCount(); got != 1 {
		t.Errorf("RestoreItem sent %d requests, want exactly 1 (no retry)", got)
	}

	// PurgeItem must also not be retried.
	f2 := startFakeDropServer(t, 1)
	client2, err := ipc.NewClient(f2.ln.Addr().String())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client2.Close()

	if err := client2.PurgeItem(ctx, "abc"); err == nil {
		t.Fatal("PurgeItem with dropped response: want error, got nil")
	}
	if got := f2.requestCount(); got != 1 {
		t.Errorf("PurgeItem sent %d requests, want exactly 1 (no retry)", got)
	}
}

func TestIdempotentCallRetriedOnTransportFailure(t *testing.T) {
	f := startFakeDropServer(t, 1)
	client, err := ipc.NewClient(f.ln.Addr().String())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping after dropped response: want retry success, got %v", err)
	}
	if got := f.requestCount(); got != 2 {
		t.Errorf("Ping sent %d requests, want 2 (one retry)", got)
	}
}
