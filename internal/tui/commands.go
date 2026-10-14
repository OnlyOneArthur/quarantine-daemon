package tui

import (
	"context"
	"errors"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

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

// --- messages ---

type tickMsg time.Time

type connectMsg struct {
	client Client
	err    error
}

type statusMsg struct {
	client Client
	status *ipc.StatusResponse
	err    error
}

type vaultMsg struct {
	client Client
	items  []*quarantine.ItemMetadata
	err    error
}

type inspectMsg struct {
	client Client
	item   *quarantine.ItemMetadata
	err    error
}

type actionMsg struct {
	client Client
	kind   confirmKind
	id     string
	err    error
}

type addWatchMsg struct {
	client Client
	path   string
	err    error
}

// tickCmd is a var so tests can disable the real timer, which would otherwise
// block the command they drain.
var tickCmd = func() tea.Cmd {
	return tea.Tick(RefreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// spinnerTickCmd is a var so tests can stub the spinner timer out, like tickCmd.
var spinnerTickCmd = func(m spinner.Model) tea.Cmd { return m.Tick }

// refreshCmd returns a command that reconnects if needed and reloads state.
func (m *Model) refreshCmd() tea.Cmd {
	if m.client == nil {
		if m.reconnectWait > 0 {
			return nil
		}
		return connectCmd(m.dial)
	}
	if m.pane == paneVault || !m.vaultLoaded {
		return fetchCmd(m.client)
	}
	return statusOnlyCmd(m.client)
}

func connectCmd(dial Dialer) tea.Cmd {
	return func() tea.Msg {
		if dial == nil {
			return connectMsg{err: errors.New("no dialer configured")}
		}
		c, err := dial()
		if err != nil {
			return connectMsg{err: err}
		}
		return connectMsg{client: c}
	}
}

func statusOnlyCmd(c Client) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		st, err := c.GetStatus(ctx)
		return statusMsg{client: c, status: st, err: err}
	}
}

func vaultOnlyCmd(c Client) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		items, err := c.ListVault(ctx)
		return vaultMsg{client: c, items: items, err: err}
	}
}

func fetchCmd(c Client) tea.Cmd {
	return tea.Batch(
		statusOnlyCmd(c),
		vaultOnlyCmd(c),
	)
}

func inspectCmd(c Client, id string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		item, err := c.InspectItem(ctx, id)
		return inspectMsg{client: c, item: item, err: err}
	}
}

func actionCmd(c Client, kind confirmKind, id string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var err error
		switch kind {
		case confirmRestore:
			err = c.RestoreItem(ctx, id, "")
		case confirmPurge:
			err = c.PurgeItem(ctx, id)
		}
		return actionMsg{client: c, kind: kind, id: id, err: err}
	}
}

func addWatchCmd(c Client, path string) tea.Cmd {
	return func() tea.Msg {
		if c == nil {
			return addWatchMsg{client: c, path: path, err: errors.New("not connected")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := c.AddWatchPath(ctx, path)
		return addWatchMsg{client: c, path: path, err: err}
	}
}

// handleConnErr reports whether err is a transport failure; if so it drops the
// client so the tick loop reconnects with backoff. It also rejects replies from
// a connection that is no longer the active client: a slow RPC that completes
// successfully after a reconnect must not mutate current model state.
func (m *Model) handleConnErr(c Client, err error) bool {
	if m.client == nil || c != m.client {
		return true // stale reply from a dropped connection
	}
	if err == nil {
		return false
	}
	m.lastErr = err
	if isTransportErr(err) {
		m.dropClient()
		return true
	}
	return false
}

// isTransportErr treats protocol-level RPC errors as recoverable non-transport
// failures and everything else (dial/IO) as a lost connection.
func isTransportErr(err error) bool {
	var rpcErr *ipc.RPCError
	return !errors.As(err, &rpcErr)
}

func (m *Model) dropClient() {
	if m.client != nil {
		_ = m.client.Close()
	}
	m.client = nil
	m.connected = false
	m.backoff = nextBackoff(m.backoff)
	m.reconnectWait = m.backoff
}

func nextBackoff(cur time.Duration) time.Duration {
	if cur <= 0 {
		return minBackoff
	}
	next := cur * 2
	if next > maxBackoff {
		return maxBackoff
	}
	return next
}
