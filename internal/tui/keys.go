package tui

import "github.com/charmbracelet/bubbles/key"

type keyMap struct {
	Up            key.Binding
	Down          key.Binding
	Open          key.Binding
	Back          key.Binding
	Next          key.Binding
	ViewDashboard key.Binding
	ViewVault     key.Binding
	ViewInspector key.Binding
	Restore       key.Binding
	Purge         key.Binding
	Confirm       key.Binding
	Cancel        key.Binding
	Quit          key.Binding
}

var keys = keyMap{
	Up:            key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:          key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Open:          key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "inspect")),
	Back:          key.NewBinding(key.WithKeys("esc", "backspace"), key.WithHelp("esc", "back to vault")),
	Next:          key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next pane")),
	ViewDashboard: key.NewBinding(key.WithKeys("1"), key.WithHelp("1", "dashboard")),
	ViewVault:     key.NewBinding(key.WithKeys("2"), key.WithHelp("2", "vault")),
	ViewInspector: key.NewBinding(key.WithKeys("3"), key.WithHelp("3", "inspector")),
	Restore:       key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "restore")),
	Purge:         key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "purge")),
	Confirm:       key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "confirm")),
	Cancel:        key.NewBinding(key.WithKeys("n", "esc"), key.WithHelp("n/esc", "cancel")),
	Quit:          key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
}

// ShortHelp implements help.KeyMap for the footer line.
func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Open, k.Back, k.Next, k.Restore, k.Purge, k.Quit}
}

// FullHelp implements help.KeyMap for the expanded help view.
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Open, k.Back},
		{k.ViewDashboard, k.ViewVault, k.ViewInspector, k.Next},
		{k.Restore, k.Purge, k.Confirm, k.Cancel, k.Quit},
	}
}
