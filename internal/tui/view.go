package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/lipgloss"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
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
	// eyeMinWidth is the narrowest terminal that can show the dashboard's eye
	// emblem without crowding or overflowing. Below it the plain text title is
	// used instead.
	eyeMinWidth = 48
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

	// eyeStyle draws the almond lid and filled iris; pupilStyle draws the
	// single bright pupil so the emblem appears to look back at the operator.
	eyeStyle   = lipgloss.NewStyle().Foreground(colPrimary)
	pupilStyle = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
)

// eyeFrames holds the dashboard's single-eye emblem at four degrees of
// closure: open, half-lidded, a slit, and fully shut. Every frame is exactly
// eyeArtWidth cells wide and eyeArtHeight rows tall, so the emblem never
// shifts shape as the blink animation cycles through them (blinkSequence in
// model.go maps a blink step to a frame index).
//
// The eye is drawn with Unicode block elements (▄ ▀ █) around a bright ●
// pupil; styleEyeLine paints lid and iris in colPrimary, pupil in colAccent.
const (
	// eyeArtWidth and eyeArtHeight are the fixed size of every frame.
	eyeArtWidth  = 40
	eyeArtHeight = 9
)

var eyeBlinkFrames = [][]string{
	{
		"                                        ",
		"                                        ",
		"       ▄▄▄█████████████████████████     ",
		"    ▄██▀▀▄▄▄█▀▀▀▄ ▄█████        ▄██     ",
		"    ▀ ▄▄█▀▀     ████●███    ▄▄▄█▀▀      ",
		"     ██▄        ████████▄▄█▀▀           ",
		"       ▀▀▀▀▀▀███▀▀▀▀▀▀▀                 ",
		"                                        ",
		"                                        ",
	},
	{
		"                                        ",
		"                                        ",
		"       ▄▄▄█████████████████████████     ",
		"    ▄██▀▀     ▄▄▄▄▄█████▀▀▀▀▀▀▀████     ",
		"    ▀   ▄▄██▀▀▀▀████●███▄▄▄▄█▀▀▀        ",
		"     ████▄▄▄▄▄▄▄███▀▀▀▀▀▀               ",
		"                                        ",
		"                                        ",
		"                                        ",
	},
	{
		"                                        ",
		"                                        ",
		"       ▄▄▄█████████████████████████     ",
		"    ▄██▀▀              ▄▄▄▄▄▄▄▄▄▄▄      ",
		"    ▀      ▄▄▄▄▄████●██▀▀▀▀▀▀           ",
		"      ▀▀▀▀▀▀▀▀▀▀                        ",
		"                                        ",
		"                                        ",
		"                                        ",
	},
	{
		"                                        ",
		"                                        ",
		"       ▄▄▄█████████████████████████     ",
		"    ▄██▀▀                               ",
		"    ▀               ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄     ",
		"      ▄▄▄▄▀▀▀▀▀▀▀▀▀▀                    ",
		"     ▀                                  ",
		"                                        ",
		"                                        ",
	},
}

// The iris of eyeBlinkFrames[0]: rows irisRowLo..irisRowHi, cols irisColLo..
// irisColHi. The ● pupil sits at (pupilRow, pupilCol) inside it.
const (
	irisRowLo, irisRowHi = 3, 5
	irisColLo, irisColHi = 16, 23
	pupilRow, pupilCol   = 4, 20
)

// gazeSpots are the (row, col) shifts of the whole iris+pupil for the eight
// look directions, clockwise from right: R, DR, D, DL, L, UL, U, UR.
var gazeSpots = [8][2]int{
	{0, 3}, {1, 2}, {1, 0}, {1, -3}, {0, -4}, {-1, -3}, {-1, 0}, {-1, 2},
}

// gazeFrame returns the open eye with the whole iris (and its pupil) shifted by
// (dr, dc). Iris cells only land on empty eye-white cells inside the iris rows,
// so the lids stay put and the iris is clipped by them.
func gazeFrame(open []string, dr, dc int) []string {
	grid := make([][]rune, len(open))
	for i, l := range open {
		grid[i] = []rune(l)
	}
	type cell struct {
		r, c int
		ch   rune
	}
	var iris []cell
	for r := irisRowLo; r <= irisRowHi; r++ {
		for c := irisColLo; c <= irisColHi; c++ {
			if ch := grid[r][c]; ch == '█' || ch == '●' {
				iris = append(iris, cell{r, c, ch})
				grid[r][c] = ' '
			}
		}
	}
	for _, ic := range iris {
		r, c := ic.r+dr, ic.c+dc
		if r < irisRowLo || r > irisRowHi || c < 0 || c >= len(grid[r]) {
			continue
		}
		if ic.ch == '●' || grid[r][c] == ' ' {
			grid[r][c] = ic.ch
		}
	}
	out := make([]string, len(grid))
	for i, g := range grid {
		out[i] = string(g)
	}
	return out
}

// eyeFrames = 4 blink frames (0 open, 1 half, 2 slit, 3 shut) followed by 8
// open-eye gaze frames (4..11, order of gazeSpots). blinkSequence (model.go)
// indexes into this.
var eyeFrames = func() [][]string {
	frames := append([][]string{}, eyeBlinkFrames...)
	for _, s := range gazeSpots {
		frames = append(frames, gazeFrame(eyeBlinkFrames[0], s[0], s[1]))
	}
	return frames
}()

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
	bodyH := m.bodyHeight()

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
func (m *Model) bodyHeight() int {
	h := m.height - chromeTop - lipgloss.Height(m.renderFooter())
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

// boxWidth returns the width for a framed box, capped at max and the terminal.
func (m *Model) boxWidth(max int) int {
	if m.width <= 0 {
		return max
	}
	w := m.width - 4
	if w > max {
		w = max
	}
	if w < 8 {
		w = 8
	}
	return w
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
	// Title centered in the bar; shifted left only if the badge would collide.
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
	for p := paneDashboard; p < paneCount; p++ {
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

// renderDashboardHeader is the dashboard's masthead: the eye emblem on wide
// terminals, or the plain text title on narrow ones (and before the first
// WindowSizeMsg, when the width is unknown).
func (m *Model) renderDashboardHeader() string {
	if m.eyeVisible() {
		return m.renderEyeArt() + "\n" +
			lipgloss.PlaceHorizontal(m.bodyWidth(), lipgloss.Center, dimStyle.Render("host quarantine daemon"))
	}
	return titleStyle.Render("Host Quarantine Daemon")
}

// renderEyeArt centers the current blink frame within the pane. Every frame is
// a fixed size, so only the frame itself changes as the animation advances.
func (m *Model) renderEyeArt() string {
	lines := eyeFrames[blinkSequence[m.blinkStep]]
	rendered := make([]string, len(lines))
	for i, line := range lines {
		rendered[i] = styleEyeLine(line)
	}
	return lipgloss.PlaceHorizontal(m.bodyWidth(), lipgloss.Center, strings.Join(rendered, "\n"))
}

// styleEyeLine paints a lid/iris line in colPrimary, switching the pupil rune to
// colAccent. Runs are styled in bulk to keep the ANSI output small.
func styleEyeLine(line string) string {
	parts := strings.Split(line, "●")
	if len(parts) == 1 {
		return eyeStyle.Render(line)
	}
	var b strings.Builder
	for i, part := range parts {
		if i > 0 {
			b.WriteString(pupilStyle.Render("●"))
		}
		if part != "" {
			b.WriteString(eyeStyle.Render(part))
		}
	}
	return b.String()
}

// statBlock renders a dim label above a bold value for the dashboard stat row.
func statBlock(label, value string, st lipgloss.Style) string {
	return labelStyle.Render(label) + "\n" + st.Bold(true).Render(value)
}

// vaultField is one column of the vault table.
type vaultField int

const (
	fieldID vaultField = iota
	fieldVerdict
	fieldScore
	fieldPath
	fieldQuarantined
	fieldSize
	fieldPKG
)

// vaultFields returns the columns that fit width, dropping the least important
// first: PKG below 88, SIZE and QUARANTINED below 76, VERDICT below 60.
func vaultFields(width int) []vaultField {
	switch {
	case width >= 88:
		return []vaultField{fieldID, fieldVerdict, fieldScore, fieldPath, fieldQuarantined, fieldSize, fieldPKG}
	case width >= 76:
		return []vaultField{fieldID, fieldVerdict, fieldScore, fieldPath, fieldQuarantined, fieldSize}
	case width >= 60:
		return []vaultField{fieldID, fieldVerdict, fieldScore, fieldPath}
	default:
		return []vaultField{fieldID, fieldScore, fieldPath}
	}
}

func (f vaultField) title() string {
	switch f {
	case fieldID:
		return "ID"
	case fieldVerdict:
		return "VERDICT"
	case fieldScore:
		return "SCORE"
	case fieldPath:
		return "ORIGINAL PATH"
	case fieldQuarantined:
		return "QUARANTINED"
	case fieldSize:
		return "SIZE"
	default:
		return "PKG"
	}
}

// width is the fixed column width; the path column is flexible and reports 0.
func (f vaultField) width() int {
	switch f {
	case fieldID:
		return 8
	case fieldVerdict:
		return 12
	case fieldScore:
		return 5
	case fieldQuarantined:
		return 19
	case fieldSize:
		return 9
	case fieldPKG:
		return 3
	default:
		return 0
	}
}

func (f vaultField) rightAligned() bool {
	return f == fieldScore || f == fieldSize
}

// vaultPathWidth gives the ORIGINAL PATH column all width left after the other
// columns, the selection marker and the gaps between columns.
func (m *Model) vaultPathWidth(fields []vaultField) int {
	used := 2 + len(fields) - 1
	for _, f := range fields {
		used += f.width()
	}
	return max(minPathWidth, m.bodyWidth()-used)
}

func columnWidth(f vaultField, pathW int) int {
	if f == fieldPath {
		return pathW
	}
	return f.width()
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

	fields := vaultFields(m.bodyWidth())
	pathW := m.vaultPathWidth(fields)
	cells := make([]string, 0, len(fields))
	for _, f := range fields {
		cells = append(cells, padCell(f.title(), columnWidth(f, pathW), f.rightAligned()))
	}
	b.WriteString("  " + labelStyle.Bold(true).Render(strings.Join(cells, " ")) + "\n")
	b.WriteString(ruleStyle.Render(strings.Repeat("─", m.bodyWidth())) + "\n")

	for i := m.offset; i < end; i++ {
		b.WriteString(m.renderVaultRow(m.items[i], fields, pathW, i == m.cursor) + "\n")
	}
	if end < len(m.items) {
		b.WriteString(dimStyle.Render(fmt.Sprintf("... %d more", len(m.items)-end)) + "\n")
	}
	return b.String()
}

func (m *Model) renderVaultRow(item *quarantine.ItemMetadata, fields []vaultField, pathW int, selected bool) string {
	base := lipgloss.NewStyle()
	marker := "  "
	if selected {
		base = base.Background(colSelBg)
		marker = base.Foreground(colPrimary).Bold(true).Render("▸ ")
	}
	cells := make([]string, 0, len(fields))
	for _, f := range fields {
		cells = append(cells, renderVaultCell(base, item, f, pathW))
	}
	row := marker + strings.Join(cells, base.Render(" "))
	if selected {
		if pad := m.bodyWidth() - lipgloss.Width(row); pad > 0 {
			row += base.Render(strings.Repeat(" ", pad))
		}
	}
	return row
}

const (
	// quarantineScore and suspectScore are the verdict thresholds, mirroring
	// the PKGBUILD scorer.
	quarantineScore = 85
	suspectScore    = 50
)

// severityColor colors a score by the same thresholds as verdictFor.
func severityColor(score int) lipgloss.AdaptiveColor {
	switch {
	case score >= quarantineScore:
		return colDanger
	case score >= suspectScore:
		return colWarn
	default:
		return colMuted
	}
}

func renderVaultCell(base lipgloss.Style, item *quarantine.ItemMetadata, f vaultField, pathW int) string {
	w := columnWidth(f, pathW)
	style := base
	var text string
	switch f {
	case fieldID:
		text = shortID(item.ID)
	case fieldVerdict:
		text = verdictFor(item.Score)
		style = style.Foreground(severityColor(item.Score))
		if item.Score >= suspectScore {
			style = style.Bold(true)
		}
	case fieldScore:
		text = fmt.Sprintf("%d", item.Score)
		style = style.Foreground(severityColor(item.Score))
	case fieldPath:
		text = shortPath(item.OriginalPath, w)
	case fieldQuarantined:
		text = item.QuarantinedAt.Format("2006-01-02 15:04:05")
	case fieldSize:
		text = humanBytes(item.Size)
	case fieldPKG:
		text = pkgFlag(item.IsPKGBUILD)
	}
	return style.Render(padCell(text, w, f.rightAligned()))
}

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
		fieldRow("verdict", verdictFor(it.Score), valueW),
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
	if item := m.selected(); item != nil {
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

	b.WriteString(sectionStyle.Render("Active Watchers") + "\n")
	if len(m.status.WatchPaths) == 0 {
		b.WriteString(dimStyle.Render("  no watched paths configured") + "\n")
	} else {
		for _, p := range m.status.WatchPaths {
			b.WriteString(okStyle.Render("  ✔ ") + valueStyle.Render(p) + "\n")
		}
	}
	b.WriteString("\n")

	b.WriteString(sectionStyle.Render("Presets") + "\n")
	for i, preset := range defaultWatchPresets {
		cursor := "  "
		if i == m.watchCursor {
			cursor = titleStyle.Render("▸ ")
		}
		// Pad the PLAIN badge and label text to fixed cell widths, then style.
		// Padding the already-styled string would count ANSI bytes and misalign
		// the columns.
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

	guideLines := []string{
		sectionStyle.Render("Default Examples"),
		"",
		valueStyle.Render("Common watched directories:"),
		dimStyle.Render("  • ~/Downloads          - browser downloads and PKGBUILD payloads"),
		dimStyle.Render("  • /tmp                 - common script drop location"),
		dimStyle.Render("  • ~/.cache/yay         - AUR helper build cache directory"),
		"",
		valueStyle.Render("Target specific files directly:"),
		dimStyle.Render("  • ~/Downloads/PKGBUILD - track Arch package builds before makepkg"),
		dimStyle.Render("  • /tmp/malicious.bin   - track specific high-risk executable drops"),
	}
	b.WriteString(m.renderFrame(guideLines, colBorder, m.boxWidth(maxFrameWidth)))

	return b.String()
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

// placeCentered centers overlay in a width×height area. Without known size it
// returns overlay unchanged.
func placeCentered(overlay string, width, height int) string {
	if width <= 0 || height <= 0 {
		return overlay
	}
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, overlay)
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
