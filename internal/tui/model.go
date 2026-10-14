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
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/triage/binary"
)

const (
	// RefreshInterval is how often the dashboard status and vault are reloaded.
	RefreshInterval = 2 * time.Second
	// minBackoff is the first reconnect delay after a failed dial.
	minBackoff = 500 * time.Millisecond
	// maxBackoff caps the exponential reconnect delay.
	maxBackoff      = 30 * time.Second
	customWatchPath = "~/Downloads/PKGBUILD"
)

type pane int

const (
	paneDashboard pane = iota
	paneVault
	paneInspector
	paneWatch
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
	case paneWatch:
		return "Watch Targets"
	default:
		return "?"
	}
}

// WatchPreset describes a selectable directory or file to add to watcher.
type WatchPreset struct {
	Label       string
	Path        string
	Description string
}

var defaultWatchPresets = []WatchPreset{
	{
		Label:       "~/Downloads",
		Path:        "~/Downloads",
		Description: "Default user downloads folder (browser payloads, PKGBUILDs)",
	},
	{
		Label:       "/tmp",
		Path:        "/tmp",
		Description: "System temporary folder (common script drop location)",
	},
	{
		Label:       "~/.cache/yay",
		Path:        "~/.cache/yay",
		Description: "AUR helper (yay) build cache directory",
	},
	{
		Label:       "~/.cache/paru/clone",
		Path:        "~/.cache/paru/clone",
		Description: "AUR helper (paru) git package repositories",
	},
	{
		Label:       "~/Desktop",
		Path:        "~/Desktop",
		Description: "Desktop workspace folder (dropped scripts & files)",
	},
	{
		Label:       "/var/tmp",
		Path:        "/var/tmp",
		Description: "Persistent temporary directory",
	},
	{
		Label:       "[+ Custom path or file...]",
		Path:        "",
		Description: "Specify any custom directory or individual file to monitor",
	},
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

	watchCursor  int
	enteringPath bool
	inputBuffer  string

	status *ipc.StatusResponse

	// quarantineThreshold is the daemon's configured quarantine score boundary,
	// learned from the status reply so the TUI labels scores the same way the
	// daemon does. It defaults to the built-in default until a reply arrives.
	quarantineThreshold int

	pending   confirmKind
	notice    string
	noticeErr bool

	backoff       time.Duration
	reconnectWait time.Duration

	// vaultLoaded is false until the first vaultMsg reply arrives, which is
	// when the vault pane shows its spinner instead of the empty-state frame.
	vaultLoaded bool

	// blinkStep indexes blinkSequence; blinkActive indicates if the blink loop is running.
	blinkStep   int
	blinkActive bool

	// spinActive indicates the spinner tick loop is running.
	spinActive bool

	spin spinner.Model
	help help.Model
}

// NewModel returns a Model that connects to the daemon using dial. version is
// the TUI/daemon version string shown in the dashboard before the first status
// reply arrives.
func NewModel(dial Dialer, version string) *Model {
	return &Model{
		dial:                dial,
		version:             version,
		quarantineThreshold: config.DefaultConfig().Quarantine.ThresholdScore,
		spin:                newSpinner(),
		help:                newHelp(),
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

// blinkMsg advances the eye blink animation.
type blinkMsg time.Time

// Init starts the refresh loop.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.refreshCmd(), tickCmd())
}

// tickCmd is a var so tests can disable the real timer, which would otherwise
// block the command they drain.
var tickCmd = func() tea.Cmd {
	return tea.Tick(RefreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// spinnerTickCmd is a var so tests can stub the spinner timer out, like tickCmd.
var spinnerTickCmd = func(m spinner.Model) tea.Cmd { return m.Tick }

// blinkSequence maps an animation step to an index into eyeFrames (view.go):
// open, look all eight directions (frames 4..11) and back to center, then
// open → half → slit → shut → slit → half; wraps to the open eye and repeats.
var blinkSequence = []int{0, 4, 5, 6, 7, 8, 9, 10, 11, 0, 1, 2, 3, 2, 1}

// blinkDelays is how long each step of blinkSequence is held: a short rest
// on the open eye, one beat per gaze direction, then the shutter.
var blinkDelays = []time.Duration{
	500 * time.Millisecond,
	220 * time.Millisecond, 220 * time.Millisecond, 220 * time.Millisecond, 220 * time.Millisecond,
	220 * time.Millisecond, 220 * time.Millisecond, 220 * time.Millisecond, 220 * time.Millisecond,
	300 * time.Millisecond,
	90 * time.Millisecond,
	70 * time.Millisecond,
	300 * time.Millisecond,
	70 * time.Millisecond,
	90 * time.Millisecond,
}

// blinkTickCmd is a var so tests can stub the blink timer out, like tickCmd.
var blinkTickCmd = func(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return blinkMsg(t) })
}

// spinnerVisible reports whether the active pane shows the spinner: the
// dashboard before the first status reply and the vault before the first vault
// list. Never spins while disconnected.
func (m *Model) spinnerVisible() bool {
	if !m.connected {
		return false
	}
	switch m.pane {
	case paneDashboard:
		return m.status == nil
	case paneVault:
		return !m.vaultLoaded
	case paneWatch:
		return m.status == nil
	default:
		return false
	}
}

// eyeVisible reports whether the dashboard eye emblem is on screen, which is
// also what gates the blink animation: the emblem renders only on the
// dashboard pane and only once the terminal is wide enough for it.
func (m *Model) eyeVisible() bool {
	return m.pane == paneDashboard && m.width >= eyeMinWidth
}

// ensureBlink ensures the eye blink tick loop is active when the eye is
// visible, or stopped when it is off screen.
func (m *Model) ensureBlink(cmd tea.Cmd) tea.Cmd {
	if !m.eyeVisible() {
		m.blinkActive = false
		m.blinkStep = 0
		return cmd
	}
	if m.blinkActive {
		return cmd
	}
	m.blinkActive = true
	tick := blinkTickCmd(blinkDelays[m.blinkStep])
	if cmd == nil {
		return tick
	}
	return tea.Batch(cmd, tick)
}

// ensureSpinner ensures the spinner tick loop is active while the spinner is
// visible, or stopped when it is off screen. Arming only on the transition (and
// re-arming from spinner.TickMsg) keeps one tick chain alive; arming on every
// Update instead spawns a fresh chain per message and spins the CPU.
func (m *Model) ensureSpinner(cmd tea.Cmd) tea.Cmd {
	if !m.spinnerVisible() {
		m.spinActive = false
		return cmd
	}
	if m.spinActive {
		return cmd
	}
	m.spinActive = true
	tick := spinnerTickCmd(m.spin)
	if cmd == nil {
		return tick
	}
	return tea.Batch(cmd, tick)
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

// Update advances the model. It is intentionally free of tea.Program so tests
// can drive state transitions directly.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	model, cmd := m.update(msg)
	if mm, ok := model.(*Model); ok {
		cmd = mm.ensureSpinner(cmd)
		cmd = mm.ensureBlink(cmd)
		return mm, cmd
	}
	return model, cmd
}

func (m *Model) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.help.Width = msg.Width
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tickMsg:
		if m.client == nil && m.reconnectWait > RefreshInterval {
			m.reconnectWait -= RefreshInterval
			return m, tickCmd()
		}
		if m.client == nil {
			// The backoff countdown has expired: reconnect on this tick instead
			// of burning another full RefreshInterval before trying.
			m.reconnectWait = 0
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

	case blinkMsg:
		if !m.eyeVisible() {
			m.blinkActive = false
			m.blinkStep = 0
			return m, nil
		}
		m.blinkStep = (m.blinkStep + 1) % len(blinkSequence)
		return m, blinkTickCmd(blinkDelays[m.blinkStep])

	case spinner.TickMsg:
		if !m.spinnerVisible() {
			m.spinActive = false
			return m, nil
		}
		var tick tea.Cmd
		m.spin, tick = m.spin.Update(msg)
		return m, tick

	case statusMsg:
		if m.handleConnErr(msg.client, msg.err) {
			return m, nil
		}
		if msg.err != nil {
			m.setNotice(fmt.Sprintf("status failed: %v", msg.err), true)
			return m, nil
		}
		m.status = msg.status
		if msg.status != nil && msg.status.ThresholdScore > 0 {
			m.quarantineThreshold = msg.status.ThresholdScore
		}
		return m, nil

	case vaultMsg:
		if m.handleConnErr(msg.client, msg.err) {
			return m, nil
		}
		if msg.err != nil {
			m.setNotice(fmt.Sprintf("vault failed: %v", msg.err), true)
			return m, nil
		}
		m.items = msg.items
		m.vaultLoaded = true
		m.clampCursor()
		return m, nil

	case inspectMsg:
		if m.handleConnErr(msg.client, msg.err) {
			return m, nil
		}
		if msg.err != nil {
			m.setNotice(fmt.Sprintf("inspect failed: %v", msg.err), true)
			return m, nil
		}
		m.inspected = msg.item
		m.pane = paneInspector
		return m, nil

	case actionMsg:
		if msg.err != nil {
			if m.handleConnErr(msg.client, msg.err) {
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

	case addWatchMsg:
		if msg.err != nil {
			if m.handleConnErr(msg.client, msg.err) {
				return m, nil
			}
			m.setNotice(fmt.Sprintf("add watch failed: %v", msg.err), true)
			return m, nil
		}
		m.setNotice(fmt.Sprintf("now watching: %s", msg.path), false)
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

func (m *Model) setNotice(s string, isErr bool) {
	m.notice = s
	m.noticeErr = isErr
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.enteringPath {
		return m.handleInputKey(msg)
	}
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
	case key.Matches(msg, keys.ViewWatch):
		m.pane = paneWatch
		return m, nil
	case key.Matches(msg, keys.AddCustom):
		m.enteringPath = true
		m.inputBuffer = customWatchPath
		return m, nil
	case key.Matches(msg, keys.Help):
		m.help.ShowAll = !m.help.ShowAll
		return m, nil
	case key.Matches(msg, keys.Next):
		m.pane = (m.pane + 1) % paneCount
		return m, nil
	case m.pane == paneWatch:
		switch {
		case key.Matches(msg, keys.Up):
			m.moveWatchCursor(-1)
			return m, nil
		case key.Matches(msg, keys.Down):
			m.moveWatchCursor(1)
			return m, nil
		case key.Matches(msg, keys.Open) || msg.Type == tea.KeySpace:
			if m.watchCursor >= 0 && m.watchCursor < len(defaultWatchPresets) {
				preset := defaultWatchPresets[m.watchCursor]
				if preset.Path == "" {
					m.enteringPath = true
					m.inputBuffer = customWatchPath
					return m, nil
				}
				return m, addWatchCmd(m.client, preset.Path)
			}
			return m, nil
		case key.Matches(msg, keys.Back):
			m.pane = paneVault
			return m, nil
		}
		return m, nil
	case m.pane == paneVault && key.Matches(msg, keys.Up):
		m.moveCursor(-1)
		return m, nil
	case m.pane == paneVault && key.Matches(msg, keys.Down):
		m.moveCursor(1)
		return m, nil
	case m.pane == paneVault && key.Matches(msg, keys.Top):
		m.moveCursor(-len(m.items))
		return m, nil
	case m.pane == paneVault && key.Matches(msg, keys.Bottom):
		m.moveCursor(len(m.items))
		return m, nil
	case m.pane == paneVault && key.Matches(msg, keys.PageUp):
		m.moveCursor(-m.listHeight())
		return m, nil
	case m.pane == paneVault && key.Matches(msg, keys.PageDown):
		m.moveCursor(m.listHeight())
		return m, nil
	case key.Matches(msg, keys.Open):
		return m, m.openInspector()
	case key.Matches(msg, keys.Back):
		m.pane = paneVault
		return m, nil
	case key.Matches(msg, keys.Restore):
		if m.actionItem() != nil {
			m.pending = confirmRestore
		}
		return m, nil
	case key.Matches(msg, keys.Purge):
		if m.actionItem() != nil {
			m.pending = confirmPurge
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, keys.Confirm):
		item := m.actionItem()
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

func (m *Model) handleInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEnter:
		path := m.inputBuffer
		m.enteringPath = false
		m.inputBuffer = ""
		return m, addWatchCmd(m.client, path)
	case tea.KeyEsc:
		m.enteringPath = false
		m.inputBuffer = ""
		return m, nil
	case tea.KeyBackspace:
		if len(m.inputBuffer) > 0 {
			r := []rune(m.inputBuffer)
			m.inputBuffer = string(r[:len(r)-1])
		}
		return m, nil
	case tea.KeySpace:
		m.inputBuffer += " "
		return m, nil
	case tea.KeyRunes:
		m.inputBuffer += string(msg.Runes)
		return m, nil
	}
	return m, nil
}

func (m *Model) moveWatchCursor(delta int) {
	m.watchCursor += delta
	if m.watchCursor < 0 {
		m.watchCursor = 0
	}
	if m.watchCursor >= len(defaultWatchPresets) {
		m.watchCursor = len(defaultWatchPresets) - 1
	}
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

// actionItem is the item visible in the active vault or inspector pane.
func (m *Model) actionItem() *quarantine.ItemMetadata {
	switch m.pane {
	case paneVault:
		return m.selected()
	case paneInspector:
		return m.inspected
	default:
		return nil
	}
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
	// chromeTop (header + tabs + blank) plus the vault title block and the
	// footer (notice + rule + help).
	h := m.height - chromeTop - 5
	if m.notice != "" {
		h--
	}
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

// verdictFor derives a coarse verdict label from a quarantine score, using the
// daemon's configured quarantine threshold and the shared ALERT boundary.
func (m *Model) verdictFor(score int) string {
	switch {
	case score >= m.quarantineThreshold:
		return string(binary.VerdictQuarantine)
	case score >= binary.AlertScoreThreshold:
		return string(binary.VerdictAlert)
	default:
		return string(binary.VerdictPass)
	}
}
