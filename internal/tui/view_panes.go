package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/triage/binary"
)

func (m *Model) renderDashboard() string {
	var b strings.Builder
	b.WriteString(m.renderDashboardHeader() + "\n\n")

	if !m.connected {
		return b.String() + m.renderOfflineFrame()
	}
	if m.status == nil {
		b.WriteString(m.renderSpinner("loading status") + "\n")
		return b.String()
	}

	stats := lipgloss.JoinHorizontal(lipgloss.Top,
		statBlock("uptime", formatUptime(m.status.Uptime), valueStyle),
		"    ",
		statBlock("scanned", fmt.Sprintf("%d", m.status.ScannedCount), okStyle),
		"    ",
		statBlock("quarantined", fmt.Sprintf("%d", m.status.QuarantineCount), errStyle),
	)
	b.WriteString(stats + "\n\n")
	b.WriteString(labelStyle.Width(labelWidth).Render("version") + valueStyle.Render(m.status.Version) + "\n\n")

	b.WriteString(labelStyle.Render("watched paths") + "\n")
	if len(m.status.WatchPaths) == 0 {
		b.WriteString(dimStyle.Render("no watched paths configured") + "\n")
	}
	for _, p := range m.status.WatchPaths {
		b.WriteString(dimStyle.Render("• "+p) + "\n")
	}
	return b.String()
}

// renderDashboardHeader renders the dashboard masthead title.
func (m *Model) renderDashboardHeader() string {
	return titleStyle.Render("Host Quarantine Daemon")
}

// statBlock renders a dim label above a bold value for the dashboard stat row.
func statBlock(label, value string, st lipgloss.Style) string {
	return labelStyle.Render(label) + "\n" + st.Bold(true).Render(value)
}

type vaultColumn struct {
	title string
	width int
	right bool
	cell  func(it *quarantine.ItemMetadata, m *Model, w int) (string, lipgloss.Style)
}

func vaultColumns(width int) []vaultColumn {
	idCol := vaultColumn{title: "ID", width: 8, cell: func(it *quarantine.ItemMetadata, _ *Model, _ int) (string, lipgloss.Style) {
		return shortID(it.ID), lipgloss.NewStyle()
	}}
	verdictCol := vaultColumn{title: "VERDICT", width: 12, cell: func(it *quarantine.ItemMetadata, m *Model, _ int) (string, lipgloss.Style) {
		st := lipgloss.NewStyle().Foreground(m.severityColor(it.Score))
		if it.Score >= binary.AlertScoreThreshold {
			st = st.Bold(true)
		}
		return m.verdictFor(it.Score), st
	}}
	scoreCol := vaultColumn{title: "SCORE", width: 5, right: true, cell: func(it *quarantine.ItemMetadata, m *Model, _ int) (string, lipgloss.Style) {
		return fmt.Sprintf("%d", it.Score), lipgloss.NewStyle().Foreground(m.severityColor(it.Score))
	}}
	pathCol := vaultColumn{title: "ORIGINAL PATH", width: 0, cell: func(it *quarantine.ItemMetadata, _ *Model, w int) (string, lipgloss.Style) {
		return shortPath(it.OriginalPath, w), lipgloss.NewStyle()
	}}
	timeCol := vaultColumn{title: "QUARANTINED", width: 19, cell: func(it *quarantine.ItemMetadata, _ *Model, _ int) (string, lipgloss.Style) {
		return it.QuarantinedAt.Format("2006-01-02 15:04:05"), lipgloss.NewStyle()
	}}
	sizeCol := vaultColumn{title: "SIZE", width: 9, right: true, cell: func(it *quarantine.ItemMetadata, _ *Model, _ int) (string, lipgloss.Style) {
		return humanBytes(it.Size), lipgloss.NewStyle()
	}}
	pkgCol := vaultColumn{title: "PKG", width: 3, cell: func(it *quarantine.ItemMetadata, _ *Model, _ int) (string, lipgloss.Style) {
		return pkgFlag(it.IsPKGBUILD), lipgloss.NewStyle()
	}}

	switch {
	case width >= 88:
		return []vaultColumn{idCol, verdictCol, scoreCol, pathCol, timeCol, sizeCol, pkgCol}
	case width >= 76:
		return []vaultColumn{idCol, verdictCol, scoreCol, pathCol, timeCol, sizeCol}
	case width >= 60:
		return []vaultColumn{idCol, verdictCol, scoreCol, pathCol}
	default:
		return []vaultColumn{idCol, scoreCol, pathCol}
	}
}

func (m *Model) vaultPathWidth(cols []vaultColumn) int {
	used := 2 + len(cols) - 1
	for _, c := range cols {
		used += c.width
	}
	return max(minPathWidth, m.bodyWidth()-used)
}

func (m *Model) renderVault() string {
	var b strings.Builder
	end := min(m.offset+m.listHeight(), len(m.items))
	if len(m.items) == 0 {
		b.WriteString(titleStyle.Render("Vault") + "\n\n")
	} else {
		b.WriteString(titleStyle.Render(fmt.Sprintf("Vault — showing %d–%d of %d", m.offset+1, end, len(m.items))) + "\n\n")
	}

	switch {
	case m.connected && !m.vaultLoaded:
		b.WriteString(m.renderSpinner("loading vault") + "\n")
		return b.String()
	case len(m.items) == 0:
		lines := []string{valueStyle.Bold(true).Render("Vault is empty"), "", dimStyle.Render("Nothing has been quarantined yet.")}
		if m.connected {
			lines = append(lines, dimStyle.Render("Drop a suspicious file into a watched directory to see it here."))
		}
		b.WriteString(m.renderFrame(lines, colBorder, m.boxWidth(maxFrameWidth)))
		return b.String()
	}

	cols := vaultColumns(m.bodyWidth())
	pathW := m.vaultPathWidth(cols)
	cells := make([]string, 0, len(cols))
	for _, c := range cols {
		w := c.width
		if w == 0 {
			w = pathW
		}
		cells = append(cells, padCell(c.title, w, c.right))
	}
	b.WriteString("  ")
	b.WriteString(labelStyle.Bold(true).Render(strings.Join(cells, " ")))
	b.WriteByte('\n')
	b.WriteString(ruleStyle.Render(strings.Repeat("─", m.bodyWidth())))
	b.WriteByte('\n')

	for i := m.offset; i < end; i++ {
		b.WriteString(m.renderVaultRow(m.items[i], cols, pathW, i == m.cursor))
		b.WriteByte('\n')
	}
	if end < len(m.items) {
		b.WriteString(dimStyle.Render(fmt.Sprintf("... %d more", len(m.items)-end)))
		b.WriteByte('\n')
	}
	return b.String()
}

func (m *Model) renderVaultRow(item *quarantine.ItemMetadata, cols []vaultColumn, pathW int, selected bool) string {
	base := lipgloss.NewStyle()
	marker := "  "
	if selected {
		base = base.Background(colSelBg)
		marker = base.Foreground(colPrimary).Bold(true).Render("▸ ")
	}
	cells := make([]string, 0, len(cols))
	for _, c := range cols {
		w := c.width
		if w == 0 {
			w = pathW
		}
		txt, style := c.cell(item, m, w)
		cellStyle := base.Inherit(style)
		cells = append(cells, cellStyle.Render(padCell(txt, w, c.right)))
	}
	row := marker + strings.Join(cells, base.Render(" "))
	if selected {
		if pad := m.bodyWidth() - lipgloss.Width(row); pad > 0 {
			row += base.Render(strings.Repeat(" ", pad))
		}
	}
	return row
}

func (m *Model) renderInspector() string {
	title := titleStyle.Render("Inspector")
	if m.inspected != nil {
		title = titleStyle.Render("Inspector — " + shortID(m.inspected.ID))
	}
	if !m.connected {
		return title + "\n\n" + m.renderOfflineFrame()
	}
	if m.inspected == nil {
		lines := []string{valueStyle.Bold(true).Render("No item selected"), "", dimStyle.Render("Select an item in the vault and press enter.")}
		return title + "\n\n" + m.renderFrame(lines, colBorder, m.boxWidth(maxFrameWidth))
	}

	it := m.inspected
	valueW := m.bodyWidth() - labelWidth
	var b strings.Builder
	b.WriteString(title + "\n\n")
	b.WriteString(m.renderSection("Identity",
		fieldRow("full id", it.ID, valueW),
		fieldRow("sha256", it.SHA256, valueW),
		fieldRow("original path", it.OriginalPath, valueW),
		fieldRow("original mode", it.OriginalMode.String(), valueW),
	))
	b.WriteString(m.renderSection("Assessment",
		fieldRow("score", fmt.Sprintf("%d", it.Score), valueW),
		fieldRow("verdict", m.verdictFor(it.Score), valueW),
		listRows("triggers", it.Triggers, valueW, errStyle),
		listRows("categories", it.CategoriesHit, valueW, dimStyle),
		listRows("dampeners", it.DampenersApplied, valueW, dimStyle),
	))
	b.WriteString(m.renderSection("Provenance",
		fieldRow("size", humanBytes(it.Size), valueW),
		fieldRow("uid/gid", fmt.Sprintf("%d/%d", it.UID, it.GID), valueW),
		fieldRow("pkgbuild", pkgFlag(it.IsPKGBUILD), valueW),
		fieldRow("mod time", it.ModTime.Format(time.RFC3339), valueW),
		fieldRow("quarantined", it.QuarantinedAt.Format(time.RFC3339), valueW),
	))
	return b.String()
}

// renderSection renders a titled block of rows followed by a blank line.
func (m *Model) renderSection(name string, rows ...string) string {
	return sectionStyle.Render(name) + "\n" +
		ruleStyle.Render(strings.Repeat("─", m.bodyWidth())) + "\n" +
		strings.Join(rows, "\n") + "\n\n"
}

// fieldRow renders a dim label beside a value. Long values wrap and indent
// continuation lines by labelWidth (15).
func fieldRow(label, value string, valueW int) string {
	if valueW <= 0 {
		return labelStyle.Width(labelWidth).Render(label) + valueStyle.Render(value)
	}
	rendered := valueStyle.MaxWidth(valueW).Render(value)
	lines := strings.Split(rendered, "\n")
	lines[0] = labelStyle.Width(labelWidth).Render(label) + lines[0]
	indent := strings.Repeat(" ", labelWidth)
	for i := 1; i < len(lines); i++ {
		lines[i] = indent + lines[i]
	}
	return strings.Join(lines, "\n")
}

// listRows renders one bullet per item under label, or "(none)" when empty.
func listRows(label string, items []string, valueW int, bullet lipgloss.Style) string {
	if len(items) == 0 {
		return fieldRow(label, "(none)", valueW)
	}
	rows := make([]string, 0, len(items))
	for i, item := range items {
		name := ""
		if i == 0 {
			name = label
		}
		rows = append(rows, labelStyle.Width(labelWidth).Render(name)+bullet.Render(clampLine("• "+item, valueW)))
	}
	return strings.Join(rows, "\n")
}

// renderOfflineFrame is the inspector's disconnected state: the last error and
// the time until the next reconnect attempt.
func (m *Model) renderOfflineFrame() string {
	lines := []string{errStyle.Bold(true).Render("Daemon unreachable")}
	if m.lastErr != nil {
		lines = append(lines, dimStyle.Render("error: "+m.lastErr.Error()))
	}
	lines = append(lines, warnStyle.Render(fmt.Sprintf("retry in %s", m.reconnectWait)))
	return m.renderFrame(lines, colWarn, m.boxWidth(maxFrameWidth))
}
