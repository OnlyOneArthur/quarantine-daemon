//go:build linux

package ipc_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
)

// TestPeerCredAuthorizesSameUID verifies that a same-UID client passes
// SO_PEERCRED authentication and can complete an RPC.
func TestPeerCredAuthorizesSameUID(t *testing.T) {
	v := newVault(t)
	sock, _ := startServer(t, v, ipc.StaticStatusProvider{})

	client, err := ipc.NewClient(sock)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.GetStatus(ctx); err != nil {
		t.Fatalf("GetStatus under peercred auth: %v", err)
	}
}

// TestPeerCredRawConnectionAccepted checks the raw wire path: a same-UID
// connection that sends a valid request receives a normal response rather
// than being closed by the authentication check.
func TestPeerCredRawConnectionAccepted(t *testing.T) {
	v := newVault(t)
	sock, _ := startServer(t, v, ipc.StaticStatusProvider{})

	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(`{"id":"raw-1","method":"GetStatus"}` + "\n")); err != nil {
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
	if resp.ID != "raw-1" || resp.Error != nil {
		t.Fatalf("expected successful response, got %+v", resp)
	}
}
