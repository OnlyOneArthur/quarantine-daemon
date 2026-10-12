//go:build linux

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCred extracts the peer's process credentials from a Unix domain socket
// connection using SO_PEERCRED. Only valid for SOCK_STREAM Unix sockets.
func peerCred(conn net.Conn) (uid uint32, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("peer credentials require a Unix socket, got %T", conn)
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("extract raw conn: %w", err)
	}
	var ucred *unix.Ucred
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, ctrlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("raw conn control: %w", err)
	}
	if ctrlErr != nil {
		return 0, fmt.Errorf("getsockopt SO_PEERCRED: %w", ctrlErr)
	}
	return ucred.Uid, nil
}
