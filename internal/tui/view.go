package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	activeTabStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("229")).Background(lipgloss.Color("62")).Padding(0, 1)
	tabStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)
	labelStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	valueStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	selectedStyle  = lipgloss.NewStyle().Background(lipgloss.Color("236")).Bold(true)
	okStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	errStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	dimStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

// View renders the current pane plus the status/notice and help footer.
func (m *Model) View() string {
	var b strings.Builder
	b.WriteString(m.renderTabs())
	b.WriteString("\n")
	switch m.pane {
	case paneDashboard:
		b.WriteString(m.renderDashboard())
	case paneVault:
		b.WriteString(m.renderVault())
	case paneInspector:
		b.WriteString(m.renderInspector())
	}
	b.WriteString("\n")
	if notice := m.renderNotice(); notice != "" {
		b.WriteString(notice)
		b.WriteString("\n")
	}
	b.WriteString(m.renderConfirm())
	b.WriteString(m.help.View(keys))
	return b.String()
}

func (m *Model) renderTabs() string {
	var tabs []string
	for p := paneDashboard; p < paneCount; p++ {
		label := fmt.Sprintf("%d %s", int(p)+1, p.String())
		if p == m.pane {
			tabs = append(tabs, activeTabStyle.Render(label))
		} else {
			tabs = append(tabs, tabStyle.Render(label))
		}
	}
	left := strings.Join(tabs, " ")
	right := m.connectionBadge()
	gap := "  "
	if m.width > 0 {
		w := m.width - lipgloss.Width(left) - lipgloss.Width(right)
		if w > 0 {
			gap = strings.Repeat(" ", w)
		}
	}
	return left + gap + right
}

func (m *Model) connectionBadge() string {
	if m.connected {
		return okStyle.Render("● connected")
	}
	if m.lastErr != nil {
		return errStyle.Render("● disconnected")
	}
	return dimStyle.Render("● connecting")
}

func (m *Model) renderDashboard() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Host Quarantine Daemon") + "\n\n")

	if !m.connected {
		b.WriteString(errStyle.Render("daemon unreachable") + "\n")
		if m.lastErr != nil {
			b.WriteString(labelStyle.Render("error") + "   " + m.lastErr.Error() + "\n")
		}
		b.WriteString(dimStyle.Render(fmt.Sprintf("retrying in %s", m.reconnectWait)) + "\n")
		return b.String()
	}
	if m.status == nil {
		b.WriteString(dimStyle.Render("loading status…") + "\n")
		return b.String()
	}

	rows := [][2]string{
		{"version", m.status.Version},
		{"uptime", formatUptime(m.status.Uptime)},
		{"scanned", fmt.Sprintf("%d", m.status.ScannedCount)},
		{"quarantined", fmt.Sprintf("%d", m.status.QuarantineCount)},
		{"watched paths", strings.Join(m.status.WatchPaths, ", ")},
	}
	for _, r := range rows {
		b.WriteString(labelStyle.Width(15).Render(r[0]) + valueStyle.Render(r[1]) + "\n")
	}
	if len(m.status.WatchPaths) == 0 {
		b.WriteString(dimStyle.Render("no watched paths configured") + "\n")
	}
	return b.String()
}

func (m *Model) renderVault() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(fmt.Sprintf("Vault — %d item(s)", len(m.items))) + "\n\n")

	if len(m.items) == 0 {
		b.WriteString(dimStyle.Render("vault is empty") + "\n")
		return b.String()
	}

	header := fmt.Sprintf("%-9s %-11s %6s %-30s %-20s %9s %s",
		"ID", "VERDICT", "SCORE", "ORIGINAL PATH", "QUARANTINED", "SIZE", "PKG")
	b.WriteString(labelStyle.Render(header) + "\n")

	visible := m.listHeight()
	end := m.offset + visible
	if end > len(m.items) {
		end = len(m.items)
	}
	for i := m.offset; i < end; i++ {
		item := m.items[i]
		verdict := verdictFor(item.Score)
		line := fmt.Sprintf("%-9s %-11s %6d %-30s %-20s %9s %s",
			shortID(item.ID),
			verdict,
			item.Score,
			truncate(item.OriginalPath, 30),
			item.QuarantinedAt.Format("2006-01-02 15:04:05"),
			humanBytes(item.Size),
			pkgFlag(item.IsPKGBUILD),
		)
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("▸ "+line) + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
	}
	if end < len(m.items) {
		b.WriteString(dimStyle.Render(fmt.Sprintf("… %d more", len(m.items)-end)) + "\n")
	}
	return b.String()
}

func (m *Model) renderInspector() string {
	if m.inspected == nil {
		return titleStyle.Render("Inspector") + "\n\n" + dimStyle.Render("select an item in the vault and press enter")
	}
	it := m.inspected
	var b strings.Builder
	b.WriteString(titleStyle.Render("Inspector — "+shortID(it.ID)) + "\n\n")

	rows := [][2]string{
		{"full id", it.ID},
		{"sha256", it.SHA256},
		{"original path", it.OriginalPath},
		{"original mode", it.OriginalMode.String()},
		{"score", fmt.Sprintf("%d", it.Score)},
		{"size", humanBytes(it.Size)},
		{"uid/gid", fmt.Sprintf("%d/%d", it.UID, it.GID)},
		{"pkgbuild", pkgFlag(it.IsPKGBUILD)},
		{"mod time", it.ModTime.Format(time.RFC3339)},
		{"quarantined", it.QuarantinedAt.Format(time.RFC3339)},
		{"triggers", listOrNone(it.Triggers)},
		{"categories", listOrNone(it.CategoriesHit)},
		{"dampeners", listOrNone(it.DampenersApplied)},
	}
	for _, r := range rows {
		b.WriteString(labelStyle.Width(15).Render(r[0]) + valueStyle.Render(r[1]) + "\n")
	}
	return b.String()
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

func (m *Model) renderConfirm() string {
	if m.pending == confirmNone {
		return ""
	}
	item := m.selected()
	target := ""
	if item != nil {
		target = fmt.Sprintf("%s (%s)", shortID(item.ID), item.OriginalPath)
	}
	var verb string
	switch m.pending {
	case confirmRestore:
		verb = "restore to original path"
	case confirmPurge:
		verb = "permanently purge"
	}
	return errStyle.Render(fmt.Sprintf("%s %s? [y]es / [n]o", verb, target)) + "\n"
}

func pkgFlag(isPKGBUILD bool) string {
	if isPKGBUILD {
		return "yes"
	}
	return "-"
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func formatUptime(seconds float64) string {
	d := time.Duration(seconds * float64(time.Second))
	d = d.Round(time.Second)
	return d.String()
}
