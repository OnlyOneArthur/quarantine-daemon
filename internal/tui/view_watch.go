package tui

import (
	"path/filepath"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
)

func (m *Model) renderWatchPane() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Watch Targets — choose which file or directory to monitor") + "\n\n")

	if !m.connected {
		return b.String() + m.renderOfflineFrame()
	}
	if m.status == nil {
		b.WriteString(m.renderSpinner("loading watch targets") + "\n")
		return b.String()
	}

	b.WriteString(m.renderWatchActive())
	b.WriteString(m.renderWatchPresets())
	b.WriteString(m.renderWatchGuide())

	return b.String()
}

func (m *Model) renderWatchActive() string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Active Watchers") + "\n")
	if len(m.status.WatchPaths) == 0 {
		b.WriteString(dimStyle.Render("  no watched paths configured") + "\n")
	} else {
		for _, p := range m.status.WatchPaths {
			b.WriteString(okStyle.Render("  ✔ ") + valueStyle.Render(p) + "\n")
		}
	}
	b.WriteString("\n")
	return b.String()
}

func (m *Model) renderWatchPresets() string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Presets") + "\n")
	for i, preset := range defaultWatchPresets {
		cursor := "  "
		if i == m.watchCursor {
			cursor = titleStyle.Render("▸ ")
		}
		badgeText := "[+ watch ]"
		badgeStyle := dimStyle
		if preset.Path != "" && m.isWatched(preset.Path) {
			badgeText = "[✔ active]"
			badgeStyle = okStyle
		}
		statusBadge := badgeStyle.Render(padCell(badgeText, watchBadgeWidth, false))

		labelStyle := valueStyle
		if i == m.watchCursor {
			labelStyle = keyStyle
		}
		label := labelStyle.Render(padCell(preset.Label, watchLabelWidth, false))

		desc := dimStyle.Render(preset.Description)
		row := cursor + statusBadge + " " + label + " " + desc
		b.WriteString(clampLine(row, m.bodyWidth()) + "\n")
	}
	b.WriteString("\n")
	return b.String()
}

func (m *Model) renderWatchGuide() string {
	guideLines := []string{
		sectionStyle.Render("Default Examples"),
		"",
		valueStyle.Render("Common watched directories:"),
		dimStyle.Render("  • ~/Downloads          - browser downloads and PKGBUILD payloads"),
		dimStyle.Render("  • /tmp                 - common script drop location"),
		dimStyle.Render("  • ~/.cache/yay         - AUR helper build cache directory"),
		"",
		valueStyle.Render("Target specific files directly:"),
		dimStyle.Render("  • " + customWatchPath + " - track Arch package builds before makepkg"),
		dimStyle.Render("  • /tmp/malicious.bin   - track specific high-risk executable drops"),
	}
	return m.renderFrame(guideLines, colBorder, m.boxWidth(maxFrameWidth))
}

func (m *Model) isWatched(path string) bool {
	if m.status == nil || path == "" {
		return false
	}
	target := filepath.Clean(config.ExpandHome(path))
	for _, wp := range m.status.WatchPaths {
		if filepath.Clean(config.ExpandHome(wp)) == target {
			return true
		}
	}
	return false
}
