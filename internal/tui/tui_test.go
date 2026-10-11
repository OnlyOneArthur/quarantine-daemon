package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
)

// fakeClient is an in-memory Client stand-in so tests need no Unix socket.
type fakeClient struct {
	status    *ipc.StatusResponse
	items     []*quarantine.ItemMetadata
	itemsByID map[string]*quarantine.ItemMetadata

	statusErr  error
	listErr    error
	inspectErr error
	restoreErr error
	purgeErr   error

	restored []string
	purged   []string
	added    []string
	pings    int
	closed   bool
}

func newFakeClient() *fakeClient {
	return &fakeClient{itemsByID: map[string]*quarantine.ItemMetadata{}}
}

func (f *fakeClient) Ping(ctx context.Context) error {
	f.pings++
	return nil
}

func (f *fakeClient) GetStatus(ctx context.Context) (*ipc.StatusResponse, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	if f.status == nil {
		return &ipc.StatusResponse{}, nil
	}
	return f.status, nil
}

func (f *fakeClient) ListVault(ctx context.Context) ([]*quarantine.ItemMetadata, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.items, nil
}

func (f *fakeClient) InspectItem(ctx context.Context, id string) (*quarantine.ItemMetadata, error) {
	if f.inspectErr != nil {
		return nil, f.inspectErr
	}
	it, ok := f.itemsByID[id]
	if !ok {
		return nil, &ipc.RPCError{Code: "ITEM_NOT_FOUND", Message: id}
	}
	return it, nil
}

func (f *fakeClient) RestoreItem(ctx context.Context, id, destPath string) error {
	if f.restoreErr != nil {
		return f.restoreErr
	}
	f.restored = append(f.restored, id)
	return nil
}

func (f *fakeClient) PurgeItem(ctx context.Context, id string) error {
	if f.purgeErr != nil {
		return f.purgeErr
	}
	f.purged = append(f.purged, id)
	return nil
}

func (f *fakeClient) AddWatchPath(ctx context.Context, path string) error {
	f.added = append(f.added, path)
	return nil
}

func (f *fakeClient) Close() error {
	f.closed = true
	return nil
}

// drain executes a Cmd tree (tea.Batch/tea.Sequence included) and returns all
// resulting messages, so tests can drive Update without a tea.Program.
func drain(t *testing.T, cmd tea.Cmd) []tea.Msg {
	t.Helper()
	if cmd == nil {
		return nil
	}
	msg := cmd()
	if msg == nil {
		return nil
	}
	if batch, ok := msg.(tea.BatchMsg); ok {
		var out []tea.Msg
		for _, c := range batch {
			out = append(out, drain(t, c)...)
		}
		return out
	}
	return []tea.Msg{msg}
}

// feed applies cmd and then every command it produces, breadth-first, until
// the tree settles. This mirrors tea.Program's event loop without starting one.
func feed(t *testing.T, m *Model, cmd tea.Cmd) (tea.Model, tea.Cmd) {
	t.Helper()
	cur := tea.Model(m)
	var last tea.Cmd
	queue := drain(t, cmd)
	for len(queue) > 0 {
		msg := queue[0]
		queue = queue[1:]
		cur, last = cur.Update(msg)
		if last != nil {
			queue = append(queue, drain(t, last)...)
		}
	}
	return cur, last
}

func sampleItem(id string) *quarantine.ItemMetadata {
	return &quarantine.ItemMetadata{
		ID:               id,
		SHA256:           "deadbeef" + id,
		OriginalPath:     "/usr/bin/" + id,
		OriginalMode:     0o755,
		UID:              0,
		GID:              0,
		ModTime:          time.Unix(1700000000, 0),
		QuarantinedAt:    time.Unix(1700000100, 0),
		Score:            92,
		Triggers:         []string{"exec-from-tmp"},
		CategoriesHit:    []string{"execution"},
		DampenersApplied: []string{"go-binary"},
		Size:             4096,
		IsPKGBUILD:       false,
	}
}

// startModel runs Init to completion, returning the settled model. The real
// tick timer is disabled so drainage never blocks; tick behavior is exercised by
// feeding tickMsg directly.
func startModel(t *testing.T, f *fakeClient) *Model {
	t.Helper()
	origTick := tickCmd
	tickCmd = func() tea.Cmd { return nil }
	t.Cleanup(func() { tickCmd = origTick })
	origBlink := blinkTickCmd
	blinkTickCmd = func(d time.Duration) tea.Cmd { return nil }
	t.Cleanup(func() { blinkTickCmd = origBlink })

	m := NewModel(func() (Client, error) { return f, nil }, "test")
	cur, _ := feed(t, m, m.Init())
	got, ok := cur.(*Model)
	if !ok {
		t.Fatalf("Update returned %T, want *Model", cur)
	}
	return got
}

func connectedModel(t *testing.T, f *fakeClient) *Model {
	t.Helper()
	got := startModel(t, f)
	if !got.connected {
		t.Fatalf("model not connected after Init: lastErr=%v", got.lastErr)
	}
	return got
}

func TestInitConnectsAndLoadsState(t *testing.T) {
	f := newFakeClient()
	f.status = &ipc.StatusResponse{Version: "1.2.3", Uptime: 61, ScannedCount: 5, QuarantineCount: 2, WatchPaths: []string{"/tmp"}}
	f.items = []*quarantine.ItemMetadata{sampleItem("aaaa1111"), sampleItem("bbbb2222")}
	f.itemsByID["aaaa1111"] = f.items[0]

	m := connectedModel(t, f)
	if m.client != f {
		t.Fatal("client not installed")
	}
	if m.status == nil || m.status.Version != "1.2.3" {
		t.Fatalf("status not loaded: %+v", m.status)
	}
	if len(m.items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(m.items))
	}
}

func TestNavigationClampsAndWraps(t *testing.T) {
	f := newFakeClient()
	f.items = []*quarantine.ItemMetadata{sampleItem("aaaa1111"), sampleItem("bbbb2222")}
	m := connectedModel(t, f)

	m.moveCursor(-1)
	if m.cursor != 0 {
		t.Fatalf("cursor should clamp at 0, got %d", m.cursor)
	}
	m.moveCursor(5)
	if m.cursor != 1 {
		t.Fatalf("cursor should clamp at last index, got %d", m.cursor)
	}

	// tab cycles panes: dashboard -> vault -> inspector -> dashboard
	m.pane = paneDashboard
	for want := paneVault; ; want = (want + 1) % paneCount {
		cur, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = cur.(*Model)
		if m.pane != want {
			t.Fatalf("tab: pane=%v want %v", m.pane, want)
		}
		if want == paneDashboard {
			break
		}
	}
}

func TestVaultViewRendersColumns(t *testing.T) {
	f := newFakeClient()
	f.items = []*quarantine.ItemMetadata{sampleItem("abcd1234")}
	m := connectedModel(t, f)
	m.pane = paneVault
	out := m.View()
	for _, want := range []string{"Vault", "abcd1234", "QUARANTINE", "/usr/bin/abcd1234", "PKG"} {
		if !strings.Contains(out, want) {
			t.Errorf("vault view missing %q\n%s", want, out)
		}
	}
}

func TestInspectorOpensSelectedItem(t *testing.T) {
	f := newFakeClient()
	item := sampleItem("abcd1234")
	f.items = []*quarantine.ItemMetadata{item}
	f.itemsByID[item.ID] = item
	m := connectedModel(t, f)

	cur, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = cur.(*Model)
	cur, _ = feed(t, m, cmd)
	m = cur.(*Model)

	if m.pane != paneInspector {
		t.Fatalf("expected inspector pane, got %v", m.pane)
	}
	if m.inspected == nil || m.inspected.ID != item.ID {
		t.Fatalf("inspected item not set: %+v", m.inspected)
	}
	out := m.View()
	for _, want := range []string{"Inspector", item.SHA256, "triggers", "exec-from-tmp", "dampeners", "go-binary"} {
		if !strings.Contains(out, want) {
			t.Errorf("inspector view missing %q\n%s", want, out)
		}
	}

	// esc returns to the vault list.
	cur, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = cur.(*Model)
	if m.pane != paneVault {
		t.Fatalf("esc should return to vault, got %v", m.pane)
	}
}

func TestRestoreRequiresConfirmation(t *testing.T) {
	f := newFakeClient()
	item := sampleItem("abcd1234")
	f.items = []*quarantine.ItemMetadata{item}
	m := connectedModel(t, f)

	// r arms the confirmation, no RPC yet.
	cur, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	m = cur.(*Model)
	if m.pending != confirmRestore {
		t.Fatalf("pending=%v want confirmRestore", m.pending)
	}
	if len(f.restored) != 0 {
		t.Fatal("restore fired before confirmation")
	}
	if !strings.Contains(m.View(), "restore") {
		t.Fatalf("confirmation prompt not rendered:\n%s", m.View())
	}

	// n cancels.
	cur, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m = cur.(*Model)
	if m.pending != confirmNone || len(f.restored) != 0 {
		t.Fatalf("cancel failed: pending=%v restored=%v", m.pending, f.restored)
	}

	// r then y performs the restore.
	cur, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	m = cur.(*Model)
	cur, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = cur.(*Model)
	cur, _ = feed(t, m, cmd)
	m = cur.(*Model)
	if len(f.restored) != 1 || f.restored[0] != item.ID {
		t.Fatalf("restore not executed: %v", f.restored)
	}
	if m.noticeErr {
		t.Fatalf("unexpected error notice: %s", m.notice)
	}
}

func TestPurgeRequiresConfirmation(t *testing.T) {
	f := newFakeClient()
	item := sampleItem("abcd1234")
	f.items = []*quarantine.ItemMetadata{item}
	m := connectedModel(t, f)

	cur, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	m = cur.(*Model)
	if m.pending != confirmPurge {
		t.Fatalf("pending=%v want confirmPurge", m.pending)
	}
	cur, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = cur.(*Model)
	cur, _ = feed(t, m, cmd)
	m = cur.(*Model)
	if len(f.purged) != 1 || f.purged[0] != item.ID {
		t.Fatalf("purge not executed: %v", f.purged)
	}
}

func TestRestoreErrorSurfacesNotice(t *testing.T) {
	f := newFakeClient()
	item := sampleItem("abcd1234")
	f.items = []*quarantine.ItemMetadata{item}
	f.restoreErr = &ipc.RPCError{Code: "DEST_BUSY", Message: "destination busy"}
	m := connectedModel(t, f)

	cur, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	m = cur.(*Model)
	cur, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = cur.(*Model)
	cur, _ = feed(t, m, cmd)
	m = cur.(*Model)
	if !m.noticeErr || !strings.Contains(m.notice, "destination busy") {
		t.Fatalf("error notice missing: err=%v notice=%q", m.noticeErr, m.notice)
	}
	// A protocol error must not drop the connection.
	if !m.connected {
		t.Fatal("RPC error should not disconnect")
	}
}

func TestTransportErrorTriggersReconnectBackoff(t *testing.T) {
	f := newFakeClient()
	f.items = []*quarantine.ItemMetadata{sampleItem("abcd1234")}
	f.listErr = errors.New("broken pipe")
	m := startModel(t, f)

	// Init already delivered a transport error via the batched fetch.
	if m.connected {
		t.Fatal("transport error should disconnect")
	}
	if m.client != nil {
		t.Fatal("client should be dropped")
	}
	if !f.closed {
		t.Fatal("dropped client should be closed")
	}
	if m.reconnectWait != minBackoff {
		t.Fatalf("reconnectWait=%v want %v", m.reconnectWait, minBackoff)
	}

	// A tick while waiting decrements the backoff and does not reconnect yet.
	m.reconnectWait = maxBackoff
	cur, _ := m.Update(tickMsg(time.Now()))
	m = cur.(*Model)
	if m.reconnectWait != maxBackoff-RefreshInterval {
		t.Fatalf("reconnectWait=%v want %v", m.reconnectWait, maxBackoff-RefreshInterval)
	}
	if m.client != nil {
		t.Fatal("must not reconnect while backoff pending")
	}
	// Re-arm a deterministic tick so the reschedule assertion cannot block.
	tickCmd = func() tea.Cmd {
		return func() tea.Msg { return tickMsg(time.Time{}) }
	}
	_, cmd := m.Update(tickMsg(time.Now()))
	if cmd == nil {
		t.Fatal("tick should reschedule a refresh + tick")
	}
	got := drain(t, cmd)
	var sawTick bool
	for _, msg := range got {
		if _, ok := msg.(tickMsg); ok {
			sawTick = true
		}
	}
	if !sawTick {
		t.Fatalf("tick should reschedule, got %#v", got)
	}
}

func TestNextBackoffDoublesAndCaps(t *testing.T) {
	if got := nextBackoff(0); got != minBackoff {
		t.Fatalf("nextBackoff(0)=%v want %v", got, minBackoff)
	}
	if got := nextBackoff(minBackoff); got != 2*minBackoff {
		t.Fatalf("nextBackoff(%v)=%v", minBackoff, got)
	}
	if got := nextBackoff(maxBackoff); got != maxBackoff {
		t.Fatalf("backoff should cap at %v, got %v", maxBackoff, got)
	}
}

func TestQuitKey(t *testing.T) {
	f := newFakeClient()
	m := connectedModel(t, f)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd == nil {
		t.Fatal("q should return tea.Quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("q returned %T, want tea.QuitMsg", cmd())
	}
}

func TestEmptyVaultViews(t *testing.T) {
	f := newFakeClient()
	m := connectedModel(t, f)
	for _, p := range []pane{paneDashboard, paneVault, paneInspector} {
		m.pane = p
		if out := m.View(); out == "" {
			t.Errorf("pane %v rendered empty", p)
		}
	}
	// No selection: restore/purge keys are inert.
	cur, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	m = cur.(*Model)
	if m.pending != confirmNone {
		t.Fatal("restore should be inert with no selection")
	}
}

func TestVerdictFor(t *testing.T) {
	cases := map[int]string{10: "LOW", 60: "SUSPECT", 90: "QUARANTINE"}
	for score, want := range cases {
		if got := verdictFor(score); got != want {
			t.Errorf("verdictFor(%d)=%q want %q", score, got, want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{512: "512B", 4096: "4.0KB"}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d)=%q want %q", in, got, want)
		}
	}
}

func TestWatchPaneSelectPreset(t *testing.T) {
	f := newFakeClient()
	f.status = &ipc.StatusResponse{
		WatchPaths: []string{"/tmp"},
	}
	m := connectedModel(t, f)

	// Switch to watch pane via '4' key
	cur, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("4")})
	m = cur.(*Model)
	if m.pane != paneWatch {
		t.Fatalf("expected paneWatch, got %v", m.pane)
	}

	// Move cursor down and up
	cur, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = cur.(*Model)
	if m.watchCursor != 1 {
		t.Fatalf("expected watchCursor=1, got %d", m.watchCursor)
	}

	cur, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	m = cur.(*Model)
	if m.watchCursor != 0 {
		t.Fatalf("expected watchCursor=0, got %d", m.watchCursor)
	}

	// Select preset 0 (~/Downloads) with enter
	cur, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = cur.(*Model)
	cur, _ = feed(t, m, cmd)
	m = cur.(*Model)

	if len(f.added) != 1 || f.added[0] != "~/Downloads" {
		t.Fatalf("expected f.added to have [~/Downloads], got %v", f.added)
	}
	if !strings.Contains(m.notice, "now watching: ~/Downloads") {
		t.Fatalf("notice missing success string: %q", m.notice)
	}
}

func TestWatchPaneAddCustomPath(t *testing.T) {
	f := newFakeClient()
	m := connectedModel(t, f)
	m.pane = paneWatch

	// Press 'a' to enter custom path mode
	cur, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	m = cur.(*Model)
	if !m.enteringPath {
		t.Fatal("expected enteringPath=true")
	}
	if m.inputBuffer != "~/Downloads/PKGBUILD" {
		t.Fatalf("expected initial buffer ~/Downloads/PKGBUILD, got %q", m.inputBuffer)
	}

	// Delete some runes
	cur, _ = m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	m = cur.(*Model)
	if m.inputBuffer != "~/Downloads/PKGBUIL" {
		t.Fatalf("expected backspace to remove rune, got %q", m.inputBuffer)
	}

	// Append character
	cur, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("D")})
	m = cur.(*Model)
	if m.inputBuffer != "~/Downloads/PKGBUILD" {
		t.Fatalf("expected 'D' appended, got %q", m.inputBuffer)
	}

	// Submit with enter
	cur, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = cur.(*Model)
	cur, _ = feed(t, m, cmd)
	m = cur.(*Model)

	if m.enteringPath {
		t.Fatal("expected enteringPath=false after enter")
	}
	if m.inputBuffer != "" {
		t.Fatalf("expected inputBuffer cleared, got %q", m.inputBuffer)
	}
	if len(f.added) != 1 || f.added[0] != "~/Downloads/PKGBUILD" {
		t.Fatalf("expected f.added to have [~/Downloads/PKGBUILD], got %v", f.added)
	}
}

func TestWatchPaneCancelCustomInput(t *testing.T) {
	f := newFakeClient()
	m := connectedModel(t, f)
	m.pane = paneWatch

	cur, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	m = cur.(*Model)
	if !m.enteringPath {
		t.Fatal("expected enteringPath=true")
	}

	// Cancel with esc
	cur, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = cur.(*Model)
	if m.enteringPath {
		t.Fatal("expected enteringPath=false after esc")
	}
	if m.inputBuffer != "" {
		t.Fatalf("expected inputBuffer cleared, got %q", m.inputBuffer)
	}
	if len(f.added) != 0 {
		t.Fatalf("expected no paths added on cancel, got %v", f.added)
	}
}

func TestWatchPaneCustomPresetSelect(t *testing.T) {
	f := newFakeClient()
	m := connectedModel(t, f)
	m.pane = paneWatch
	m.watchCursor = len(defaultWatchPresets) - 1 // custom preset

	// Press space on custom preset
	cur, _ := m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = cur.(*Model)
	if !m.enteringPath {
		t.Fatal("expected enteringPath=true on custom preset space")
	}
	if m.inputBuffer != "~/Downloads/PKGBUILD" {
		t.Fatalf("expected initial buffer ~/Downloads/PKGBUILD, got %q", m.inputBuffer)
	}
}

func TestIsWatched(t *testing.T) {
	m := &Model{
		status: &ipc.StatusResponse{
			WatchPaths: []string{"/var/tmp"},
		},
	}

	// Suffix false positive: /var/tmp must NOT match /tmp preset
	if m.isWatched("/tmp") {
		t.Fatal("expected /tmp not to match when only /var/tmp is watched")
	}

	// Exact match must match
	if !m.isWatched("/var/tmp") {
		t.Fatal("expected /var/tmp to match when /var/tmp is watched")
	}

	// Empty candidate or nil status
	if m.isWatched("") {
		t.Fatal("expected empty path to return false")
	}
	nilModel := &Model{}
	if nilModel.isWatched("/var/tmp") {
		t.Fatal("expected nil status to return false")
	}
}

// newBlinkModel builds a wide dashboard model with the blink tick stubbed, so
// tests drive blinkMsg by hand. It does not go through startModel because that
// helper installs its own blink stub before the emblem is ever on screen.
func newBlinkModel(t *testing.T, width, height int) *Model {
	t.Helper()
	orig := blinkTickCmd
	blinkTickCmd = func(d time.Duration) tea.Cmd { return func() tea.Msg { return nil } }
	t.Cleanup(func() { blinkTickCmd = orig })

	m := NewModel(func() (Client, error) { return newFakeClient(), nil }, "test")
	m.pane = paneDashboard
	cur, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	got, ok := cur.(*Model)
	if !ok {
		t.Fatalf("Update returned %T, want *Model", cur)
	}
	return got
}

// TestBlinkSequenceAdvances asserts the eye blink walks blinkSequence end to
// end and wraps, and that every step schedules the delay blinkDelays declares.
// The emblem must also come up already open, not mid-shutter.
func TestBlinkSequenceAdvances(t *testing.T) {
	var delays []time.Duration
	orig := blinkTickCmd
	blinkTickCmd = func(d time.Duration) tea.Cmd {
		delays = append(delays, d)
		return func() tea.Msg { return nil }
	}
	t.Cleanup(func() { blinkTickCmd = orig })

	m := NewModel(func() (Client, error) { return newFakeClient(), nil }, "test")
	m.pane = paneDashboard
	cur, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = cur.(*Model)

	if !m.blinkActive {
		t.Fatal("blink loop not started on wide dashboard")
	}
	if m.blinkStep != 0 {
		t.Fatalf("blinkStep = %d, want 0 (eye starts open)", m.blinkStep)
	}
	if len(delays) != 1 || delays[0] != blinkDelays[0] {
		t.Fatalf("first blink delay = %v, want [%v]", delays, blinkDelays[0])
	}

	var frames []int
	for range blinkSequence {
		frames = append(frames, blinkSequence[m.blinkStep])
		cur, cmd := m.Update(blinkMsg(time.Now()))
		var ok bool
		if m, ok = cur.(*Model); !ok {
			t.Fatalf("Update returned %T, want *Model", cur)
		}
		if cmd == nil {
			t.Fatalf("blink tick not rescheduled at step %d", m.blinkStep)
		}
	}
	if m.blinkStep != 0 {
		t.Errorf("blinkStep = %d after a full cycle, want wrap to 0", m.blinkStep)
	}
	if got := fmt.Sprint(frames); got != "[0 1 2 3 2 1]" {
		t.Errorf("blink frames = %s, want [0 1 2 3 2 1] (open to shut and back)", got)
	}
	if len(delays) != len(blinkDelays)+1 {
		t.Fatalf("recorded %d delays, want %d", len(delays), len(blinkDelays)+1)
	}
	for i, want := range blinkDelays {
		if delays[i] != want {
			t.Errorf("delay[%d] = %v, want %v", i, delays[i], want)
		}
	}
}

// TestBlinkStopsWhenEyeHidden asserts leaving the dashboard stops the blink
// loop and resets it, and that a tick already in flight cannot restart it.
func TestBlinkStopsWhenEyeHidden(t *testing.T) {
	m := newBlinkModel(t, 100, 30)
	m.blinkStep = 3

	cur, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	var ok bool
	if m, ok = cur.(*Model); !ok {
		t.Fatalf("Update returned %T, want *Model", cur)
	}
	if m.pane != paneVault {
		t.Fatalf("pane = %v, want vault", m.pane)
	}
	if m.blinkActive {
		t.Error("blink loop still active after leaving dashboard")
	}
	if m.blinkStep != 0 {
		t.Errorf("blinkStep = %d after leaving dashboard, want 0", m.blinkStep)
	}
	if _, cmd := m.Update(blinkMsg(time.Now())); cmd != nil {
		t.Error("in-flight blink tick rescheduled while eye off screen")
	}
}

// TestBlinkResumesAfterLeavingAndReturning asserts the loop starts again when
// the dashboard comes back, and that a narrow terminal never starts it.
func TestBlinkResumesAfterLeavingAndReturning(t *testing.T) {
	m := newBlinkModel(t, 100, 30)
	cur, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	m = cur.(*Model)
	if m.blinkActive {
		t.Fatal("blink loop survived leaving the dashboard")
	}

	cur, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	m = cur.(*Model)
	if m.pane != paneDashboard {
		t.Fatalf("pane = %v, want dashboard", m.pane)
	}
	if !m.blinkActive {
		t.Error("blink loop did not restart on return to dashboard")
	}
	if cmd == nil {
		t.Error("no blink tick returned on return to dashboard")
	}

	narrow := newBlinkModel(t, 40, 18)
	if narrow.blinkActive {
		t.Error("blink loop started on a terminal too narrow for the emblem")
	}
}
