//go:build darwin

package ipc

import (
	"net"
	"testing"
)

func TestPeerCredDarwinNonUnixConn(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	_, err := peerCred(c1)
	if err == nil {
		t.Fatalf("expected error for non-UnixConn, got nil")
	}
}
