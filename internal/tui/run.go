package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// Run starts the full-screen TUI against the daemon reached through dial and
// blocks until the user quits.
func Run(dial Dialer, version string) error {
	m := NewModel(dial, version)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	if m.client != nil {
		_ = m.client.Close()
	}
	return err
}
