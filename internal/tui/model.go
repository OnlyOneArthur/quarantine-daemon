// Package tui implements the Bubble Tea terminal client for the quarantined
// daemon. It is a pure IPC client: it never opens the vault directly and talks
// to the daemon exclusively through the Client interface.
package tui

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
)

const (
	// RefreshInterval is how often the dashboard status and vault are reloaded.
	RefreshInterval = 2 * time.Second
	// minBackoff is the first reconnect delay after a failed dial.
	minBackoff = 500 * time.Millisecond
	// maxBackoff caps the exponential reconnect delay.
	maxBackoff = 30 * time.Second
)

type pane int

const (
	paneDashboard pane = iota
	paneVault
	paneInspector
	paneCount
)

func (p pane) String() string {
	switch p {
	case paneDashboard:
		return "Dashboard"
	case paneVault:
		return "Vault"
	case paneInspector:
		return "Inspector"
	default:
		return "?"
	}
}

type confirmKind int

const (
	confirmNone confirmKind = iota
	confirmRestore
	confirmPurge
)

// Model is the Bubble Tea model driving the whole TUI.
type Model struct {
	dial    Dialer
	version string

	client    Client
	connected bool
	lastErr   error

	width  int
	height int

	pane      pane
	cursor    int
	offset    int
	items     []*quarantine.ItemMetadata
	inspected *quarantine.ItemMetadata

	status *ipc.StatusResponse

	pending   confirmKind
	notice    string
	noticeErr bool

	backoff       time.Duration
	reconnectWait time.Duration

	help help.Model
}

// NewModel returns a Model that connects to the daemon using dial. version is
// the TUI/daemon version string shown in the dashboard before the first status
// reply arrives.
func NewModel(dial Dialer, version string) *Model {
	return &Model{
		dial:    dial,
		version: version,
		help:    help.New(),
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
	kind confirmKind
	id   string
	err  error
}

// Init starts the refresh loop.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.refreshCmd(), tickCmd())
}

// tickCmd is a var so tests can disable the real timer, which would otherwise
// block the command they drain.
var tickCmd = func() tea.Cmd {
	return tea.Tick(RefreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// refreshCmd returns a command that reconnects if needed and reloads state.
func (m *Model) refreshCmd() tea.Cmd {
	if m.client == nil {
		if m.reconnectWait > 0 {
			return nil
		}
		return connectCmd(m.dial)
	}
	return fetchCmd(m.client)
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

func fetchCmd(c Client) tea.Cmd {
	return tea.Batch(
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			st, err := c.GetStatus(ctx)
			return statusMsg{client: c, status: st, err: err}
		},
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			items, err := c.ListVault(ctx)
			return vaultMsg{client: c, items: items, err: err}
		},
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
		return actionMsg{kind: kind, id: id, err: err}
	}
}

// Update advances the model. It is intentionally free of tea.Program so tests
// can drive state transitions directly.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.help.Width = msg.Width
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tickMsg:
		if m.client == nil && m.reconnectWait > 0 {
			m.reconnectWait -= RefreshInterval
			return m, tickCmd()
		}
		return m, tea.Batch(m.refreshCmd(), tickCmd())

	case connectMsg:
		if msg.err != nil {
			m.connected = false
			m.lastErr = msg.err
			m.backoff = nextBackoff(m.backoff)
			m.reconnectWait = m.backoff
			return m, nil
		}
		m.client = msg.client
		m.connected = true
		m.lastErr = nil
		m.backoff = 0
		m.reconnectWait = 0
		return m, fetchCmd(msg.client)

	case statusMsg:
		if m.handleConnErr(msg.client, msg.err) {
			return m, nil
		}
		m.status = msg.status
		return m, nil

	case vaultMsg:
		if m.handleConnErr(msg.client, msg.err) {
			return m, nil
		}
		m.items = msg.items
		m.clampCursor()
		return m, nil

	case inspectMsg:
		if m.handleConnErr(msg.client, msg.err) {
			return m, nil
		}
		m.inspected = msg.item
		m.pane = paneInspector
		return m, nil

	case actionMsg:
		if msg.err != nil {
			if m.handleConnErr(m.client, msg.err) {
				return m, nil
			}
			m.setNotice(fmt.Sprintf("%s failed: %v", actionLabel(msg.kind), msg.err), true)
			return m, nil
		}
		m.setNotice(fmt.Sprintf("%s ok: %s", actionLabel(msg.kind), shortID(msg.id)), false)
		if m.client != nil {
			return m, fetchCmd(m.client)
		}
		return m, nil
	}
	return m, nil
}

func actionLabel(k confirmKind) string {
	switch k {
	case confirmRestore:
		return "restore"
	case confirmPurge:
		return "purge"
	default:
		return "action"
	}
}

// handleConnErr reports whether err is a transport failure; if so it drops the
// client so the tick loop reconnects with backoff.
func (m *Model) handleConnErr(c Client, err error) bool {
	if err == nil {
		return false
	}
	if m.client == nil || c != m.client {
		return true // stale reply from a dropped connection
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

func (m *Model) setNotice(s string, isErr bool) {
	m.notice = s
	m.noticeErr = isErr
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.pending != confirmNone {
		return m.handleConfirmKey(msg)
	}
	switch {
	case key.Matches(msg, keys.Quit):
		return m, tea.Quit
	case key.Matches(msg, keys.ViewDashboard):
		m.pane = paneDashboard
		return m, nil
	case key.Matches(msg, keys.ViewVault):
		m.pane = paneVault
		return m, nil
	case key.Matches(msg, keys.ViewInspector):
		return m, m.openInspector()
	case key.Matches(msg, keys.Next):
		m.pane = (m.pane + 1) % paneCount
		return m, nil
	case key.Matches(msg, keys.Up):
		m.moveCursor(-1)
		return m, nil
	case key.Matches(msg, keys.Down):
		m.moveCursor(1)
		return m, nil
	case key.Matches(msg, keys.Open):
		return m, m.openInspector()
	case key.Matches(msg, keys.Back):
		m.pane = paneVault
		return m, nil
	case key.Matches(msg, keys.Restore):
		if m.selected() != nil {
			m.pending = confirmRestore
		}
		return m, nil
	case key.Matches(msg, keys.Purge):
		if m.selected() != nil {
			m.pending = confirmPurge
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, keys.Confirm):
		item := m.selected()
		kind := m.pending
		m.pending = confirmNone
		if item == nil || m.client == nil {
			m.setNotice("not connected", true)
			return m, nil
		}
		return m, actionCmd(m.client, kind, item.ID)
	case key.Matches(msg, keys.Cancel), key.Matches(msg, keys.Quit):
		m.pending = confirmNone
		return m, nil
	}
	return m, nil
}

// openInspector inspects the selected item (or the item already inspected when
// the vault is empty), returning a command.
func (m *Model) openInspector() tea.Cmd {
	if item := m.selected(); item != nil {
		if m.client == nil {
			m.setNotice("not connected", true)
			return nil
		}
		return inspectCmd(m.client, item.ID)
	}
	if m.inspected != nil {
		m.pane = paneInspector
	}
	return nil
}

func (m *Model) selected() *quarantine.ItemMetadata {
	if m.cursor < 0 || m.cursor >= len(m.items) {
		return nil
	}
	return m.items[m.cursor]
}

func (m *Model) moveCursor(delta int) {
	if len(m.items) == 0 {
		return
	}
	m.cursor += delta
	m.clampCursor()
}

func (m *Model) clampCursor() {
	if len(m.items) == 0 {
		m.cursor, m.offset = 0, 0
		return
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor >= len(m.items) {
		m.cursor = len(m.items) - 1
	}
	m.ensureVisible()
}

// ensureVisible keeps the cursor inside the scrollable vault window.
func (m *Model) ensureVisible() {
	visible := m.listHeight()
	if visible < 1 {
		visible = 1
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+visible {
		m.offset = m.cursor - visible + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

func (m *Model) listHeight() int {
	h := m.height - 8
	if h < 1 {
		h = 1
	}
	return h
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// verdictFor derives a coarse verdict label from a quarantine score. Thresholds
// mirror the PKGBUILD scorer (85 quarantine, 50 suspect).
func verdictFor(score int) string {
	switch {
	case score >= 85:
		return "QUARANTINE"
	case score >= 50:
		return "SUSPECT"
	default:
		return "LOW"
	}
}
