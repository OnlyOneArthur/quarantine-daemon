//go:build darwin

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCred extracts the peer's process credentials from a Unix domain socket
// connection using LOCAL_PEERCRED. Only valid for SOCK_STREAM Unix sockets.
func peerCred(conn net.Conn) (uid uint32, err error) {
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("extract raw conn: %w", err)
	}
	var cred *unix.Xucred
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, ctrlErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("raw conn control: %w", err)
	}
	if ctrlErr != nil {
		return 0, fmt.Errorf("getsockopt LOCAL_PEERCRED: %w", ctrlErr)
	}
	return cred.Uid, nil
}
