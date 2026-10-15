package tui

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
)

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.enteringPath {
		return m.handleInputKey(msg)
	}
	if m.pending != confirmNone {
		return m.handleConfirmKey(msg)
	}
	if cmd, handled := m.handleGlobalKey(msg); handled {
		return m, cmd
	}
	if m.pane == paneWatch {
		return m, m.handleWatchKey(msg)
	}
	if m.pane == paneVault {
		if m.handleVaultKey(msg) {
			return m, nil
		}
	}
	return m, m.handleActionKey(msg)
}

func (m *Model) handleGlobalKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch {
	case key.Matches(msg, keys.Quit):
		return tea.Quit, true
	case key.Matches(msg, keys.ViewDashboard):
		m.pane = paneDashboard
		return nil, true
	case key.Matches(msg, keys.ViewVault):
		m.pane = paneVault
		if m.client != nil {
			return vaultOnlyCmd(m.client), true
		}
		return nil, true
	case key.Matches(msg, keys.ViewInspector):
		return m.openInspector(), true
	case key.Matches(msg, keys.ViewWatch):
		m.pane = paneWatch
		return nil, true
	case key.Matches(msg, keys.AddCustom):
		m.enteringPath = true
		m.inputBuffer = customWatchPath
		return nil, true
	case key.Matches(msg, keys.Help):
		m.help.ShowAll = !m.help.ShowAll
		return nil, true
	case key.Matches(msg, keys.Next):
		m.pane = (m.pane + 1) % paneCount
		if m.pane == paneVault && m.client != nil {
			return vaultOnlyCmd(m.client), true
		}
		return nil, true
	}
	return nil, false
}

func (m *Model) handleWatchKey(msg tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(msg, keys.Up):
		m.moveWatchCursor(-1)
	case key.Matches(msg, keys.Down):
		m.moveWatchCursor(1)
	case key.Matches(msg, keys.Open) || msg.Type == tea.KeySpace:
		if m.watchCursor >= 0 && m.watchCursor < len(defaultWatchPresets) {
			preset := defaultWatchPresets[m.watchCursor]
			if preset.Path == "" {
				m.enteringPath = true
				m.inputBuffer = customWatchPath
				return nil
			}
			return addWatchCmd(m.client, preset.Path)
		}
	case key.Matches(msg, keys.Back):
		m.pane = paneVault
	}
	return nil
}

func (m *Model) handleVaultKey(msg tea.KeyMsg) bool {
	switch {
	case key.Matches(msg, keys.Up):
		m.moveCursor(-1)
		return true
	case key.Matches(msg, keys.Down):
		m.moveCursor(1)
		return true
	case key.Matches(msg, keys.Top):
		m.moveCursor(-len(m.items))
		return true
	case key.Matches(msg, keys.Bottom):
		m.moveCursor(len(m.items))
		return true
	case key.Matches(msg, keys.PageUp):
		m.moveCursor(-m.listHeight())
		return true
	case key.Matches(msg, keys.PageDown):
		m.moveCursor(m.listHeight())
		return true
	}
	return false
}

func (m *Model) handleActionKey(msg tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(msg, keys.Open):
		return m.openInspector()
	case key.Matches(msg, keys.Back):
		m.pane = paneVault
	case key.Matches(msg, keys.Restore):
		if m.actionItem() != nil {
			m.pending = confirmRestore
		}
	case key.Matches(msg, keys.Purge):
		if m.actionItem() != nil {
			m.pending = confirmPurge
		}
	}
	return nil
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
	if len(defaultWatchPresets) == 0 {
		m.watchCursor = 0
		return
	}
	m.watchCursor = min(len(defaultWatchPresets)-1, max(0, m.watchCursor+delta))
}

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
	m.cursor = min(len(m.items)-1, max(0, m.cursor))
	m.ensureVisible()
}

func (m *Model) ensureVisible() {
	visible := max(m.listHeight(), 1)
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+visible {
		m.offset = m.cursor - visible + 1
	}
	m.offset = max(m.offset, 0)
}

func (m *Model) listHeight() int {
	h := m.height - chromeTop - 5
	if m.notice != "" {
		h--
	}
	return max(h, 1)
}
