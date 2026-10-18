package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/triage"
)

func (m *Model) handleTick() (tea.Model, tea.Cmd) {
	if m.client == nil && m.reconnectWait > RefreshInterval {
		m.reconnectWait -= RefreshInterval
		return m, tickCmd()
	}
	if m.client == nil {
		m.reconnectWait = 0
	}
	return m, tea.Batch(m.refreshCmd(), tickCmd())
}

func (m *Model) handleConnect(msg connectMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		m.connected = false
		m.lastErr = msg.err
		m.backoff = nextBackoff(m.backoff)
		m.reconnectWait = m.backoff
		return m, nil
	}
	m.client = msg.client
	m.connected = true
	m.lastErr = nil
	m.backoff = 0
	m.reconnectWait = 0
	return m, fetchCmd(msg.client)
}

func (m *Model) handleSpinnerTick(msg spinner.TickMsg) (tea.Model, tea.Cmd) {
	if !m.spinnerVisible() {
		m.spinActive = false
		return m, nil
	}
	var tick tea.Cmd
	m.spin, tick = m.spin.Update(msg)
	return m, tick
}

func (m *Model) handleStatus(msg statusMsg) (tea.Model, tea.Cmd) {
	if m.handleConnErr(msg.client, msg.err) {
		return m, nil
	}
	if msg.err != nil {
		m.setNotice(fmt.Sprintf("status failed: %v", msg.err), true)
		return m, nil
	}
	m.status = msg.status
	if msg.status != nil && msg.status.ThresholdScore > 0 {
		m.quarantineThreshold = msg.status.ThresholdScore
	}
	return m, nil
}

func (m *Model) handleVault(msg vaultMsg) (tea.Model, tea.Cmd) {
	if m.handleConnErr(msg.client, msg.err) {
		return m, nil
	}
	if msg.err != nil {
		m.setNotice(fmt.Sprintf("vault failed: %v", msg.err), true)
		return m, nil
	}
	m.items = msg.items
	m.vaultLoaded = true
	m.clampCursor()
	return m, nil
}

func (m *Model) handleInspect(msg inspectMsg) (tea.Model, tea.Cmd) {
	if m.handleConnErr(msg.client, msg.err) {
		return m, nil
	}
	if msg.err != nil {
		m.setNotice(fmt.Sprintf("inspect failed: %v", msg.err), true)
		return m, nil
	}
	m.inspected = msg.item
	m.pane = paneInspector
	return m, nil
}

func (m *Model) handleAction(msg actionMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		if m.handleConnErr(msg.client, msg.err) {
			return m, nil
		}
		m.setNotice(fmt.Sprintf("%s failed: %v", actionLabel(msg.kind), msg.err), true)
		return m, nil
	}
	m.setNotice(fmt.Sprintf("%s ok: %s", actionLabel(msg.kind), shortID(msg.id)), false)
	if m.client != nil {
		return m, fetchCmd(m.client)
	}
	return m, nil
}

func (m *Model) handleAddWatch(msg addWatchMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		if m.handleConnErr(msg.client, msg.err) {
			return m, nil
		}
		m.setNotice(fmt.Sprintf("add watch failed: %v", msg.err), true)
		return m, nil
	}
	m.setNotice(fmt.Sprintf("now watching: %s", msg.path), false)
	if m.client != nil {
		return m, fetchCmd(m.client)
	}
	return m, nil
}

func actionLabel(k confirmKind) string {
	switch k {
	case confirmRestore:
		return "restore"
	case confirmPurge:
		return "purge"
	default:
		return "action"
	}
}

func (m *Model) setNotice(s string, isErr bool) {
	m.notice = s
	m.noticeErr = isErr
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func (m *Model) verdictFor(score int) string {
	switch {
	case score >= m.quarantineThreshold:
		return string(triage.VerdictQuarantine)
	case score >= triage.AlertScoreThreshold:
		return string(triage.VerdictAlert)
	default:
		return string(triage.VerdictPass)
	}
}
