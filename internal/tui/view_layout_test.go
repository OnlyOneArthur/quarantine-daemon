package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
)

func makeFakeItems() (string, []*quarantine.ItemMetadata) {
	longPath := "/var/tmp/very/deep/nested/path/to/some/obscure/and/deeply/located/archive/malicious_payload_with_a_very_long_filename.sh"
	items := []*quarantine.ItemMetadata{
		{
			ID:               "a1b2c3d4",
			SHA256:           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			OriginalPath:     longPath,
			OriginalMode:     0o755,
			UID:              1000,
			GID:              1000,
			ModTime:          time.Unix(1700000000, 0),
			QuarantinedAt:    time.Unix(1700000100, 0),
			Score:            95,
			Triggers:         []string{"suspicious-network-socket-connect-to-unknown-external-host-during-installation", "reverse-shell-detected-in-postinstall-hook"},
			CategoriesHit:    []string{"persistence", "exfiltration", "execution"},
			DampenersApplied: []string{"none"},
			Size:             1048576,
			IsPKGBUILD:       true,
		},
		{
			ID:               "deadbeef",
			SHA256:           "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			OriginalPath:     "/etc/systemd/system/multi-user.target.wants/backdoor_service_file_installed_by_attacker.service",
			OriginalMode:     0o644,
			UID:              0,
			GID:              0,
			ModTime:          time.Unix(1700000200, 0),
			QuarantinedAt:    time.Unix(1700000300, 0),
			Score:            60,
			Triggers:         []string{"systemd-unit-modification"},
			CategoriesHit:    []string{"persistence"},
			DampenersApplied: []string{},
			Size:             512,
			IsPKGBUILD:       false,
		},
		{
			ID:               "cafe1234",
			SHA256:           "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
			OriginalPath:     "/usr/local/bin/crypto_miner",
			OriginalMode:     0o755,
			UID:              1000,
			GID:              1000,
			ModTime:          time.Unix(1700000400, 0),
			QuarantinedAt:    time.Unix(1700000500, 0),
			Score:            15,
			Triggers:         []string{},
			CategoriesHit:    []string{},
			DampenersApplied: []string{},
			Size:             2048,
			IsPKGBUILD:       false,
		},
	}
	return longPath, items
}

func assertLayoutSafety(t *testing.T, label string, out string, width, height int) {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		w := lipgloss.Width(line)
		if w > width {
			t.Errorf("[%s %dx%d] line %d exceeds width %d (got %d):\n%q", label, width, height, i, width, w, line)
		}
	}
	if len(lines) > height {
		t.Errorf("[%s %dx%d] line count %d exceeds height %d", label, width, height, len(lines), height)
	}
}

func TestViewHeadlessLayout(t *testing.T) {
	sizes := []struct {
		width  int
		height int
	}{
		{width: 120, height: 40},
		{width: 100, height: 30},
		{width: 80, height: 24},
		{width: 60, height: 20},
		{width: 40, height: 18},
	}

	longPath, items := makeFakeItems()

	for _, sz := range sizes {
		t.Run(szLabel(sz.width, sz.height), func(t *testing.T) {
			f := newFakeClient()
			f.status = &ipc.StatusResponse{
				Version:         "0.4.0",
				Uptime:          3600,
				ScannedCount:    142,
				QuarantineCount: 3,
				WatchPaths:      []string{"/var/tmp", "/tmp"},
			}
			f.items = items
			for _, it := range items {
				f.itemsByID[it.ID] = it
			}

			// 1. Vault view populated
			m := connectedModel(t, f)
			m.pane = paneVault
			cur, _ := m.Update(tea.WindowSizeMsg{Width: sz.width, Height: sz.height})
			m = cur.(*Model)

			out := m.View()

			assertLayoutSafety(t, "vault-populated", out, sz.width, sz.height)

			// Header badge text present
			if !strings.Contains(out, "● connected") {
				t.Errorf("header badge missing connected text:\n%s", out)
			}
			// Tab labels present
			for _, tab := range []string{"1 Dashboard", "2 Vault", "3 Inspector"} {
				if !strings.Contains(out, tab) {
					t.Errorf("tab %q missing:\n%s", tab, out)
				}
			}
			// Selected row marker present
			if !strings.Contains(out, "▸") {
				t.Errorf("selected row marker '▸' missing:\n%s", out)
			}
			// Long path truncated
			if strings.Contains(out, longPath) {
				t.Errorf("expected long path to be truncated, but raw full path was rendered:\n%s", out)
			}

			// Print the 100x30 render to stdout once for visual inspection
			if sz.width == 100 && sz.height == 30 {
				t.Logf("Eyeball render (100x30 populated vault):\n%s", out)
			}

			// 2. Empty-vault state
			fEmpty := newFakeClient()
			fEmpty.status = f.status
			fEmpty.items = nil
			mEmpty := connectedModel(t, fEmpty)
			mEmpty.pane = paneVault
			cur, _ = mEmpty.Update(tea.WindowSizeMsg{Width: sz.width, Height: sz.height})
			mEmpty = cur.(*Model)
			outEmpty := mEmpty.View()
			assertLayoutSafety(t, "vault-empty", outEmpty, sz.width, sz.height)
			if !strings.Contains(outEmpty, "Vault is empty") {
				t.Errorf("empty vault message missing:\n%s", outEmpty)
			}

			// 3. Disconnected state
			mDisc := NewModel(func() (Client, error) {
				return nil, errors.New("daemon connection refused")
			}, "test")
			mDisc.pane = paneDashboard
			cur, _ = mDisc.Update(tea.WindowSizeMsg{Width: sz.width, Height: sz.height})
			mDisc = cur.(*Model)
			// Trigger reconnect/offline state
			mDisc.connected = false
			mDisc.lastErr = errors.New("daemon connection refused")
			outDisc := mDisc.View()
			assertLayoutSafety(t, "dashboard-disconnected", outDisc, sz.width, sz.height)
			if !strings.Contains(outDisc, "offline") && !strings.Contains(outDisc, "reconnecting") {
				t.Errorf("disconnected badge missing offline/reconnecting:\n%s", outDisc)
			}

			// 4. Confirmation modal state (both restore and purge)
			mPurge := connectedModel(t, f)
			mPurge.pane = paneVault
			cur, _ = mPurge.Update(tea.WindowSizeMsg{Width: sz.width, Height: sz.height})
			mPurge = cur.(*Model)
			cur, _ = mPurge.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
			mPurge = cur.(*Model)
			outPurge := mPurge.View()
			assertLayoutSafety(t, "confirm-modal-purge", outPurge, sz.width, sz.height)
			if !strings.Contains(outPurge, "Purge item?") {
				t.Errorf("purge modal missing title:\n%s", outPurge)
			}

			mRestore := connectedModel(t, f)
			mRestore.pane = paneVault
			cur, _ = mRestore.Update(tea.WindowSizeMsg{Width: sz.width, Height: sz.height})
			mRestore = cur.(*Model)
			cur, _ = mRestore.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
			mRestore = cur.(*Model)
			outRestore := mRestore.View()
			assertLayoutSafety(t, "confirm-modal-restore", outRestore, sz.width, sz.height)
			if !strings.Contains(outRestore, "Restore item?") {
				t.Errorf("restore modal missing title:\n%s", outRestore)
			}

			// 5. Watch pane across all screen sizes
			mWatch := connectedModel(t, f)
			mWatch.pane = paneWatch
			cur, _ = mWatch.Update(tea.WindowSizeMsg{Width: sz.width, Height: sz.height})
			mWatch = cur.(*Model)
			outWatch := mWatch.View()
			assertLayoutSafety(t, "watch-pane", outWatch, sz.width, sz.height)
			if !strings.Contains(outWatch, "Watch Targets") {
				t.Errorf("watch pane missing title:\n%s", outWatch)
			}
			if !strings.Contains(outWatch, "Active Watchers") {
				t.Errorf("watch pane missing active watchers section:\n%s", outWatch)
			}

			// 6. Watch pane custom input modal across all screen sizes
			mInput := connectedModel(t, f)
			mInput.pane = paneWatch
			mInput.enteringPath = true
			mInput.inputBuffer = "~/Downloads/PKGBUILD"
			cur, _ = mInput.Update(tea.WindowSizeMsg{Width: sz.width, Height: sz.height})
			mInput = cur.(*Model)
			outInput := mInput.View()
			assertLayoutSafety(t, "watch-input-modal", outInput, sz.width, sz.height)
			if sz.width >= 50 {
				if !strings.Contains(outInput, "Choose File or Directory to Watch") {
					t.Errorf("input modal missing title:\n%s", outInput)
				}
			} else {
				if !strings.Contains(outInput, "Choose File") {
					t.Errorf("input modal missing title:\n%s", outInput)
				}
			}
			if !strings.Contains(outInput, "Enter path:") {
				t.Errorf("input modal missing prompt:\n%s", outInput)
			}
		})
	}
}

func dashboardModel(t *testing.T, width, height int) *Model {
	t.Helper()
	f := newFakeClient()
	f.status = &ipc.StatusResponse{
		Version:         "0.4.0",
		Uptime:          3600,
		ScannedCount:    142,
		QuarantineCount: 3,
		WatchPaths:      []string{"/var/tmp", "/tmp"},
	}
	m := connectedModel(t, f)
	m.pane = paneDashboard
	cur, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	return cur.(*Model)
}

// TestDashboardEyeArt asserts the eye emblem renders on wide terminals and
// falls back to the plain text title on narrow ones, with layout safety in
// both cases.
func TestDashboardEyeArt(t *testing.T) {
	t.Run("wide-100x30", func(t *testing.T) {
		m := dashboardModel(t, 100, 30)
		out := m.View()
		t.Logf("Eyeball render (100x30 dashboard):\n%s", out)
		assertLayoutSafety(t, "dashboard-eye", out, 100, 30)

		for _, rune := range []string{"▀", "█", "●"} {
			if !strings.Contains(out, rune) {
				t.Errorf("dashboard eye art missing distinctive rune %q:\n%s", rune, out)
			}
		}
		if !strings.Contains(out, "host quarantine daemon") {
			t.Errorf("dashboard eye caption missing:\n%s", out)
		}
		if strings.Contains(out, "Host Quarantine Daemon") {
			t.Errorf("wide dashboard should show eye art, not the plain text title:\n%s", out)
		}
	})

	t.Run("narrow-40x18", func(t *testing.T) {
		m := dashboardModel(t, 40, 18)
		out := m.View()
		t.Logf("Eyeball render (40x18 dashboard fallback):\n%s", out)
		assertLayoutSafety(t, "dashboard-fallback", out, 40, 18)

		if !strings.Contains(out, "Host Quarantine Daemon") {
			t.Errorf("narrow dashboard should fall back to the text title:\n%s", out)
		}
		if strings.Contains(out, "█") {
			t.Errorf("narrow dashboard must not render the eye art:\n%s", out)
		}
	})

	t.Run("unknown-width", func(t *testing.T) {
		f := newFakeClient()
		m := connectedModel(t, f)
		m.pane = paneDashboard
		// No WindowSizeMsg: width is still 0.
		out := m.View()
		if !strings.Contains(out, "Host Quarantine Daemon") {
			t.Errorf("dashboard with unknown width should fall back to the text title:\n%s", out)
		}
		if strings.Contains(out, "█") {
			t.Errorf("dashboard with unknown width must not render the eye art:\n%s", out)
		}
	})
}

// TestEyeArtOnlyOnDashboard asserts the emblem is exclusive to the dashboard
// pane and never bleeds into Vault, Inspector or Watch.
func TestEyeArtOnlyOnDashboard(t *testing.T) {
	_, items := makeFakeItems()
	for _, pane := range []struct {
		name string
		pane pane
	}{
		{"vault", paneVault},
		{"inspector", paneInspector},
		{"watch", paneWatch},
	} {
		t.Run(pane.name, func(t *testing.T) {
			f := newFakeClient()
			f.status = &ipc.StatusResponse{Version: "0.4.0", WatchPaths: []string{"/tmp"}}
			f.items = items
			m := connectedModel(t, f)
			m.pane = pane.pane
			cur, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
			m = cur.(*Model)
			out := m.View()
			assertLayoutSafety(t, pane.name, out, 100, 30)
			if strings.Contains(out, "█") {
				t.Errorf("eye art leaked into %s pane:\n%s", pane.name, out)
			}
		})
	}
}

// TestEyeFramesUniform asserts every blink frame is exactly eyeArtWidth cells
// wide and eyeArtHeight rows tall. The emblem is centered by measuring the
// block, so a single ragged frame would make the eye twitch sideways mid-blink.
func TestEyeFramesUniform(t *testing.T) {
	if len(eyeFrames) != 12 {
		t.Fatalf("eyeFrames has %d frames, want 12 (open, half, slit, shut, 8 gaze)", len(eyeFrames))
	}
	for i, frame := range eyeFrames {
		if len(frame) != eyeArtHeight {
			t.Errorf("frame %d has %d rows, want %d", i, len(frame), eyeArtHeight)
		}
		for r, line := range frame {
			if w := lipgloss.Width(line); w != eyeArtWidth {
				t.Errorf("frame %d row %d is %d cells wide, want %d: %q", i, r, w, eyeArtWidth, line)
			}
		}
	}
}

// TestEyeFramesDistinct asserts no two blink frames render identically, so the
// animation is actually visible rather than a still emblem.
func TestEyeFramesDistinct(t *testing.T) {
	seen := map[string]int{}
	for i, frame := range eyeFrames {
		key := strings.Join(frame, "|")
		if prev, dup := seen[key]; dup {
			t.Errorf("frame %d is identical to frame %d", i, prev)
		}
		seen[key] = i
	}
}

// TestEyeArtRendersEveryBlinkFrame asserts renderEyeArt follows blinkStep
// through blinkSequence and stays layout-safe at every step.
func TestEyeArtRendersEveryBlinkFrame(t *testing.T) {
	m := dashboardModel(t, 100, 30)
	var prev string
	for step := range blinkSequence {
		m.blinkStep = step
		out := m.View()
		assertLayoutSafety(t, szLabel(100, 30), out, 100, 30)
		if !strings.Contains(out, "host quarantine daemon") {
			t.Errorf("blink step %d lost the eye caption", step)
		}
		if step > 0 && out == prev {
			t.Errorf("blink step %d renders identical to step %d", step, step-1)
		}
		prev = out
	}
}

func szLabel(w, h int) string {
	return fmt.Sprintf("%dx%d", w, h)
}
