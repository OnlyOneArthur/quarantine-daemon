//go:build darwin

package ipc_test

import (
	"context"
	"testing"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
)

// TestPeerCredAuthorizesSameUIDDarwin verifies that a same-UID client passes
// LOCAL_PEERCRED authentication and can complete an RPC on macOS.
func TestPeerCredAuthorizesSameUIDDarwin(t *testing.T) {
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
		t.Fatalf("GetStatus under LOCAL_PEERCRED auth: %v", err)
	}
}
