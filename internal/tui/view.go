package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/lipgloss"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/triage/binary"
)

// Palette. Every color is adaptive so the TUI reads correctly on light and dark
// terminals.
var (
	colPrimary   = lipgloss.AdaptiveColor{Light: "#5A3FD6", Dark: "#7D56F4"}
	colAccent    = lipgloss.AdaptiveColor{Light: "#0A7B4F", Dark: "#04B575"}
	colDanger    = lipgloss.AdaptiveColor{Light: "#C1003B", Dark: "#FF5F87"}
	colWarn      = lipgloss.AdaptiveColor{Light: "#9A6A00", Dark: "#FFCC66"}
	colMuted     = lipgloss.AdaptiveColor{Light: "#8A8A94", Dark: "#6C6C78"}
	colText      = lipgloss.AdaptiveColor{Light: "#2A2A33", Dark: "#D7D7DD"}
	colSelBg     = lipgloss.AdaptiveColor{Light: "#E4E4F0", Dark: "#2A2A3C"}
	colBorder    = lipgloss.AdaptiveColor{Light: "#C0C0CC", Dark: "#4A4A5A"}
	colOnPrimary = lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#FFFFFF"}
)

const (
	// chromeTop is the header bar, tab row and blank line above the body.
	chromeTop = 3
	// labelWidth is the left column width of label/value rows.
	labelWidth = 15
	// minPathWidth is the narrowest the ORIGINAL PATH column may get.
	minPathWidth = 16
	// defaultWidth is the layout width used before the first WindowSizeMsg.
	defaultWidth = 100
	// maxFrameWidth caps the centered empty-state and error frames.
	maxFrameWidth = 56
	// modalWidth caps the confirmation modal.
	modalWidth = 60
	// watchBadgeWidth is the fixed cell width of the watch-pane status badge.
	watchBadgeWidth = 10
	// watchLabelWidth is the fixed cell width of a watch-preset label.
	watchLabelWidth = 28
)

var (
	headerBar      = lipgloss.NewStyle().Background(colPrimary).Foreground(colOnPrimary)
	titleStyle     = lipgloss.NewStyle().Bold(true).Foreground(colPrimary)
	activeTabStyle = lipgloss.NewStyle().Bold(true).Foreground(colOnPrimary).Background(colPrimary).Padding(0, 1)
	tabStyle       = lipgloss.NewStyle().Foreground(colMuted).Padding(0, 1)
	labelStyle     = lipgloss.NewStyle().Foreground(colMuted)
	valueStyle     = lipgloss.NewStyle().Foreground(colText)
	keyStyle       = lipgloss.NewStyle().Bold(true).Foreground(colText)
	sectionStyle   = lipgloss.NewStyle().Bold(true).Foreground(colPrimary)
	ruleStyle      = lipgloss.NewStyle().Foreground(colBorder)
	spinnerStyle   = lipgloss.NewStyle().Foreground(colPrimary)
	okStyle        = lipgloss.NewStyle().Foreground(colAccent)
	warnStyle      = lipgloss.NewStyle().Foreground(colWarn)
	errStyle       = lipgloss.NewStyle().Foreground(colDanger)
	dimStyle       = lipgloss.NewStyle().Foreground(colMuted)
)

// newHelp returns the footer help model with palette-aware styles.
func newHelp() help.Model {
	h := help.New()
	h.Styles.ShortKey = lipgloss.NewStyle().Foreground(colPrimary).Bold(true)
	h.Styles.ShortDesc = dimStyle
	h.Styles.ShortSeparator = ruleStyle
	h.Styles.FullKey = h.Styles.ShortKey
	h.Styles.FullDesc = dimStyle
	h.Styles.FullSeparator = ruleStyle
	h.Styles.Ellipsis = dimStyle
	return h
}

// newSpinner returns the loading indicator used by the dashboard and vault.
func newSpinner() spinner.Model {
	return spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(spinnerStyle))
}

// View renders the header, tabs, active pane (or confirmation modal) and footer.
// Every line is clamped to the terminal width when the width is known.
func (m *Model) View() string {
	footer := m.renderFooter()
	bodyH := m.bodyHeight(lipgloss.Height(footer))

	body := m.renderPane()
	if m.pending != confirmNone {
		body = placeCentered(m.renderModal(), m.width, bodyH)
	} else if m.enteringPath {
		body = placeCentered(m.renderInputModal(), m.width, bodyH)
	}
	if m.height > 0 {
		body = cropLines(body, bodyH)
	}

	tabs := m.renderTabs()
	if m.width > 0 {
		tabs = lipgloss.PlaceHorizontal(m.width, lipgloss.Center, tabs)
	}
	out := strings.Join([]string{m.renderHeader(), tabs, "", body, footer}, "\n")
	if m.width <= 0 {
		return out
	}
	return clampLines(out, m.width)
}

// bodyHeight is the number of terminal rows left for the active pane.
func (m *Model) bodyHeight(footerHeight int) int {
	h := m.height - chromeTop - footerHeight
	if h < 0 {
		return 0
	}
	return h
}

// bodyWidth is the usable width for pane content.
func (m *Model) bodyWidth() int {
	if m.width > 0 {
		return m.width
	}
	return defaultWidth
}

// boxWidth returns the width for a framed box, capped at limit and the terminal.
func (m *Model) boxWidth(limit int) int {
	if m.width <= 0 {
		return limit
	}
	return max(8, min(limit, m.width-4))
}

func (m *Model) renderPane() string {
	switch m.pane {
	case paneDashboard:
		return m.renderDashboard()
	case paneVault:
		return m.renderVault()
	case paneInspector:
		return m.renderInspector()
	case paneWatch:
		return m.renderWatchPane()
	}
	return ""
}

func (m *Model) renderHeader() string {
	version := m.version
	if version == "" && m.status != nil {
		version = m.status.Version
	}
	title := headerBar.Bold(true).Render("quarantined") + headerBar.Faint(true).Render(" v"+version)
	right := m.connectionBadge()
	if m.width <= 0 {
		return title + "  " + right
	}
	tw, rw := lipgloss.Width(title), lipgloss.Width(right)
	lead := max(0, min((m.width-tw)/2, m.width-tw-rw-1))
	gap := max(1, m.width-lead-tw-rw)
	pad := func(n int) string { return headerBar.Render(strings.Repeat(" ", n)) }
	return clampLine(pad(lead)+title+pad(gap)+right, m.width)
}

func (m *Model) connectionBadge() string {
	switch {
	case m.connected:
		return headerBar.Foreground(colAccent).Render("● connected")
	case m.reconnectWait > 0:
		return headerBar.Foreground(colWarn).Render(fmt.Sprintf("● reconnecting in %s", m.reconnectWait.Round(time.Second)))
	case m.lastErr != nil:
		return headerBar.Foreground(colDanger).Render("● offline")
	default:
		return headerBar.Faint(true).Render("● connecting")
	}
}

func (m *Model) renderTabs() string {
	tabs := make([]string, 0, paneCount)
	for p := range paneCount {
		label := fmt.Sprintf("%d %s", int(p)+1, p.String())
		if p == m.pane {
			tabs = append(tabs, activeTabStyle.Render(label))
		} else {
			tabs = append(tabs, tabStyle.Render(label))
		}
	}
	return strings.Join(tabs, " ")
}

func (m *Model) renderSpinner(label string) string {
	return m.spin.View() + " " + dimStyle.Render(label+"...")
}

// severityColor colors a score by the same thresholds as verdictFor: the
// daemon's configured quarantine boundary and the shared ALERT boundary.
func (m *Model) severityColor(score int) lipgloss.AdaptiveColor {
	switch {
	case score >= m.quarantineThreshold:
		return colDanger
	case score >= binary.AlertScoreThreshold:
		return colWarn
	default:
		return colMuted
	}
}

// renderFrame draws lines inside a rounded border of total width cells, centered
// in the terminal when its width is known.
func (m *Model) renderFrame(lines []string, border lipgloss.AdaptiveColor, width int) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 1).
		Width(width - 2).
		Render(strings.Join(lines, "\n"))
	if m.width > 0 {
		return lipgloss.PlaceHorizontal(m.width, lipgloss.Center, box)
	}
	return box
}

// renderModal builds the restore/purge confirmation box.
func (m *Model) renderModal() string {
	var title, note string
	var border lipgloss.AdaptiveColor
	switch m.pending {
	case confirmRestore:
		title, border = "Restore item?", colWarn
		note = valueStyle.Render("The item is restored to its original path.")
	case confirmPurge:
		title, border = "Purge item?", colDanger
		note = errStyle.Render("This permanently deletes the quarantined file.")
	default:
		return ""
	}

	boxW := m.boxWidth(modalWidth)
	valueW := boxW - 4 - labelWidth
	lines := []string{lipgloss.NewStyle().Bold(true).Foreground(border).Render(title), ""}
	if item := m.actionItem(); item != nil {
		lines = append(lines,
			fieldRow("id", shortID(item.ID), valueW),
			fieldRow("path", middleTruncate(item.OriginalPath, valueW), valueW),
			fieldRow("score", fmt.Sprintf("%d", item.Score), valueW),
		)
	}
	lines = append(lines, "", note, "",
		keyStyle.Render("[y]")+valueStyle.Render(" confirm   ")+keyStyle.Render("[n]")+valueStyle.Render(" cancel"))
	return m.renderFrame(lines, border, boxW)
}

func (m *Model) renderInputModal() string {
	boxW := m.boxWidth(modalWidth)
	lines := []string{
		titleStyle.Render("Choose File or Directory to Watch"),
		"",
		labelStyle.Render("Enter path: [ ") + valueStyle.Render(m.inputBuffer) + keyStyle.Render("_") + labelStyle.Render(" ]"),
		"",
		dimStyle.Render("Default examples: ~/Downloads, /tmp/malicious.bin, ~/.cache/yay"),
		"",
		keyStyle.Render("[enter]") + valueStyle.Render(" watch   ") + keyStyle.Render("[esc]") + valueStyle.Render(" cancel"),
	}
	return m.renderFrame(lines, colPrimary, boxW)
}

// renderFooter is the notice line, a rule, and the key help.
func (m *Model) renderFooter() string {
	rule := ruleStyle.Render(strings.Repeat("─", m.bodyWidth()))
	help := m.help.View(keys)
	if m.notice != "" {
		return m.renderNotice() + "\n" + rule + "\n" + help
	}
	return rule + "\n" + help
}

func (m *Model) renderNotice() string {
	if m.notice == "" {
		return ""
	}
	if m.noticeErr {
		return errStyle.Render("! " + m.notice)
	}
	return okStyle.Render("✓ " + m.notice)
}
