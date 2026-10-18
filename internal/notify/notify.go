// Package notify provides desktop notification dispatch via notify-send or busctl
// for quarantine actions and threat alerts.
package notify

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Urgency levels for desktop notifications.
const (
	UrgencyLow      = "low"
	UrgencyNormal   = "normal"
	UrgencyCritical = "critical"
)

// Notification represents a desktop notification payload.
type Notification struct {
	Title    string
	Body     string
	Urgency  string
	Icon     string
	Category string
}

// Config controls notification behavior.
type Config struct {
	Enabled  bool
	MinScore int
}

// Notifier delivers desktop notifications.
type Notifier interface {
	NotifyQuarantine(ctx context.Context, path string, score int, triggers []string) error
	NotifyAlert(ctx context.Context, path string, score int, triggers []string) error
	Send(ctx context.Context, n Notification) error
}

// runner is an abstraction over command execution for testing.
type runner func(ctx context.Context, name string, args ...string) error

func defaultRunner(ctx context.Context, name string, args ...string) error {
	var cmd *exec.Cmd
	switch name {
	case "notify-send":
		cmd = exec.CommandContext(ctx, "notify-send", args...)
	case "busctl":
		cmd = exec.CommandContext(ctx, "busctl", args...)
	default:
		return fmt.Errorf("unsupported notification command: %s", name)
	}
	return cmd.Run()
}

// DesktopNotifier sends notifications via notify-send or busctl.
type DesktopNotifier struct {
	cfg        Config
	logger     *slog.Logger
	runCmd     runner
	lookPath   func(string) (string, error)
	mu         sync.Mutex
	recentSend map[string]time.Time
}

// New creates a new DesktopNotifier.
func New(cfg Config, logger *slog.Logger) *DesktopNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &DesktopNotifier{
		cfg:        cfg,
		logger:     logger,
		runCmd:     defaultRunner,
		lookPath:   exec.LookPath,
		recentSend: make(map[string]time.Time),
	}
}

// NotifyQuarantine formats and sends a high-priority notification for a quarantined file.
func (d *DesktopNotifier) NotifyQuarantine(ctx context.Context, path string, score int, triggers []string) error {
	if !d.cfg.Enabled || score < d.cfg.MinScore {
		return nil
	}

	fileName := filepath.Base(path)
	title := fmt.Sprintf("⚠️ File Quarantined: %s", fileName)

	triggerSummary := ""
	if len(triggers) > 0 {
		maxShow := min(len(triggers), 3)
		triggerSummary = fmt.Sprintf("\nTriggers: %s", strings.Join(triggers[:maxShow], ", "))
		if len(triggers) > maxShow {
			triggerSummary += fmt.Sprintf(" (+%d more)", len(triggers)-maxShow)
		}
	}

	body := fmt.Sprintf("Threat Score: %d/100\nPath: %s%s", score, path, triggerSummary)

	return d.Send(ctx, Notification{
		Title:    title,
		Body:     body,
		Urgency:  UrgencyCritical,
		Icon:     "security-high",
		Category: "security.quarantine",
	})
}

// NotifyAlert formats and sends a warning notification for a detected threat.
func (d *DesktopNotifier) NotifyAlert(ctx context.Context, path string, score int, triggers []string) error {
	if !d.cfg.Enabled || score < d.cfg.MinScore {
		return nil
	}

	fileName := filepath.Base(path)
	title := fmt.Sprintf("Threat Alert: %s", fileName)

	triggerSummary := ""
	if len(triggers) > 0 {
		maxShow := min(len(triggers), 3)
		triggerSummary = fmt.Sprintf("\nTriggers: %s", strings.Join(triggers[:maxShow], ", "))
	}

	body := fmt.Sprintf("Threat Score: %d/100\nPath: %s%s", score, path, triggerSummary)

	return d.Send(ctx, Notification{
		Title:    title,
		Body:     body,
		Urgency:  UrgencyNormal,
		Icon:     "dialog-warning",
		Category: "security.alert",
	})
}

// Send dispatches the notification to the desktop notification daemon.
func (d *DesktopNotifier) Send(ctx context.Context, n Notification) error {
	if !d.cfg.Enabled {
		return nil
	}

	// Rate-limit deduplication: do not send identical title+body within 3 seconds
	d.mu.Lock()
	key := n.Title + "|" + n.Body
	now := time.Now()
	if last, ok := d.recentSend[key]; ok && now.Sub(last) < 3*time.Second {
		d.mu.Unlock()
		return nil
	}
	d.recentSend[key] = now
	// Clean old entries
	for k, t := range d.recentSend {
		if now.Sub(t) > 10*time.Second {
			delete(d.recentSend, k)
		}
	}
	d.mu.Unlock()

	// Ensure desktop session is available
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		d.logger.Debug("desktop environment not detected; skipping notification", "title", n.Title)
		return nil
	}

	// Bound timeout to prevent hanging the pipeline
	sendCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if _, err := d.lookPath("notify-send"); err == nil {
		args := []string{
			"-a", "quarantined",
			"-u", n.Urgency,
			"-i", n.Icon,
		}
		if n.Category != "" {
			args = append(args, "-c", n.Category)
		}
		args = append(args, n.Title, n.Body)
		if err := d.runCmd(sendCtx, "notify-send", args...); err != nil {
			d.logger.Debug("notify-send failed", "error", err)
			return err
		}
		return nil
	}

	if _, err := d.lookPath("busctl"); err == nil {
		args := []string{
			"--user", "call",
			"org.freedesktop.Notifications",
			"/org/freedesktop/Notifications",
			"org.freedesktop.Notifications",
			"Notify",
			"susssasa{sv}i",
			"quarantined",
			"0",
			n.Icon,
			n.Title,
			n.Body,
			"0",
			"0",
			"--",
			"-1",
		}
		if err := d.runCmd(sendCtx, "busctl", args...); err != nil {
			d.logger.Debug("busctl notify failed", "error", err)
			return err
		}
		return nil
	}

	d.logger.Debug("neither notify-send nor busctl found in PATH")
	return nil
}
