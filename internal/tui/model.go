// Package tui provides the terminal user interface for the quarantine daemon.
package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
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

	quarantineThreshold int

	pending   confirmKind
	notice    string
	noticeErr bool

	backoff       time.Duration
	reconnectWait time.Duration

	vaultLoaded bool
	spinActive  bool

	spin spinner.Model
	help help.Model
}

// NewModel returns a Model that connects to the daemon using dial.
func NewModel(dial Dialer, version string) *Model {
	return &Model{
		dial:                dial,
		version:             version,
		quarantineThreshold: config.DefaultConfig().Quarantine.ThresholdScore,
		spin:                newSpinner(),
		help:                newHelp(),
	}
}

// Init starts the refresh loop.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.refreshCmd(), tickCmd())
}

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

// Update advances the model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	model, cmd := m.update(msg)
	if mm, ok := model.(*Model); ok {
		cmd = mm.ensureSpinner(cmd)
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
		return m.handleTick()
	case connectMsg:
		return m.handleConnect(msg)
	case spinner.TickMsg:
		return m.handleSpinnerTick(msg)
	case statusMsg:
		return m.handleStatus(msg)
	case vaultMsg:
		return m.handleVault(msg)
	case inspectMsg:
		return m.handleInspect(msg)
	case actionMsg:
		return m.handleAction(msg)
	case addWatchMsg:
		return m.handleAddWatch(msg)
	}
	return m, nil
}
