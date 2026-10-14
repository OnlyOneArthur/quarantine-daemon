package tui

import (
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// shortPath fits p into width cells. Too-long paths become ".../<parent>/<base>";
// if even that does not fit, the middle is elided so the file name survives.
func shortPath(p string, width int) string {
	if lipgloss.Width(p) <= width {
		return p
	}
	parts := strings.Split(p, "/")
	tail := p
	if n := len(parts); n >= 2 {
		tail = "…/" + parts[n-2] + "/" + parts[n-1]
	}
	if lipgloss.Width(tail) <= width {
		return tail
	}
	return middleTruncate(tail, width)
}

// middleTruncate shortens s to at most width runes, eliding the middle with "…".
func middleTruncate(s string, width int) string {
	r := []rune(s)
	switch {
	case width <= 0:
		return ""
	case len(r) <= width:
		return s
	case width == 1:
		return "…"
	}
	head := (width - 1) / 2
	tail := width - 1 - head
	return string(r[:head]) + "…" + string(r[len(r)-tail:])
}

// padCell pads s to width cells, right-aligned when right is set.
func padCell(s string, width int, right bool) string {
	gap := width - lipgloss.Width(s)
	if gap <= 0 {
		return s
	}
	if right {
		return strings.Repeat(" ", gap) + s
	}
	return s + strings.Repeat(" ", gap)
}

// placeCentered centers overlay in a width×height area. Without known size it
// returns overlay unchanged.
func placeCentered(overlay string, width, height int) string {
	if width <= 0 || height <= 0 {
		return overlay
	}
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, overlay)
}

func pkgFlag(isPKGBUILD bool) string {
	if isPKGBUILD {
		return "yes"
	}
	return "-"
}

// padding helpers: clampLine guarantees the rendered line fits width cells.
// It is ANSI-aware (lipgloss MaxWidth), so styled text is cut safely.
func clampLine(line string, width int) string {
	if width <= 0 || lipgloss.Width(line) <= width {
		return line
	}
	return lipgloss.NewStyle().MaxWidth(width).Render(line)
}

func clampLines(s string, width int) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = clampLine(line, width)
	}
	return strings.Join(lines, "\n")
}

func cropLines(s string, n int) string {
	if n <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[:n], "\n")
}

func formatUptime(seconds float64) string {
	d := time.Duration(seconds * float64(time.Second))
	d = d.Round(time.Second)
	return d.String()
}
