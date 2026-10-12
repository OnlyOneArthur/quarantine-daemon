package tui

import (
	"context"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
)

// Client is the daemon IPC surface the TUI uses. The TUI never touches the vault directly.
type Client interface {
	GetStatus(ctx context.Context) (*ipc.StatusResponse, error)
	ListVault(ctx context.Context) ([]*quarantine.ItemMetadata, error)
	InspectItem(ctx context.Context, id string) (*quarantine.ItemMetadata, error)
	RestoreItem(ctx context.Context, id, destPath string) error
	PurgeItem(ctx context.Context, id string) error
	AddWatchPath(ctx context.Context, path string) error
	Close() error
}

var _ Client = (*ipc.Client)(nil)

// Dialer opens a new daemon connection. The Model calls it at startup and after disconnects.
type Dialer func() (Client, error)

// SocketDialer returns a Dialer connecting to the daemon control socket at socketPath.
func SocketDialer(socketPath string) Dialer {
	return func() (Client, error) {
		c, err := ipc.NewClient(socketPath)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
}
