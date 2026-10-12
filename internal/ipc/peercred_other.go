//go:build !linux && !darwin

package ipc

import (
	"errors"
	"net"
)

// ErrPeerCredUnsupported reports that peer credential authentication is not
// available on this platform. The server fails closed: without SO_PEERCRED it
// cannot verify the caller's UID, so every connection is rejected.
var ErrPeerCredUnsupported = errors.New("peer credential authentication is only supported on Linux and macOS")

// peerCred is the non-Linux stub; always fails so the server rejects callers.
func peerCred(conn net.Conn) (uint32, error) {
	return 0, ErrPeerCredUnsupported
}
