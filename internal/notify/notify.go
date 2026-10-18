// Package notify provides desktop notification dispatch via notify-send or busctl
// for quarantine actions and threat alerts.
package notify

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultExpireTimeoutMs is the default notification auto-dismiss delay (10 seconds).
const DefaultExpireTimeoutMs = 10000

//go:embed assets/eye-normal.png
var eyeNormalPNG []byte

//go:embed assets/eye-danger.png
var eyeDangerPNG []byte

// Urgency levels for desktop notifications.
const (
	UrgencyLow      = "low"
	UrgencyNormal   = "normal"
	UrgencyCritical = "critical"
)

// Notification represents a desktop notification payload.
type Notification struct {
	Title           string
	Body            string
	Urgency         string
	Icon            string
	Category        string
	ExpireTimeoutMs int
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
type runner func(ctx context.Context, name string, args ...string) (string, error)

func defaultRunner(ctx context.Context, name string, args ...string) (string, error) {
	var cmd *exec.Cmd
	switch name {
	case "notify-send":
		cmd = exec.CommandContext(ctx, "notify-send", args...)
	case "busctl":
		cmd = exec.CommandContext(ctx, "busctl", args...)
	case "osascript":
		cmd = exec.CommandContext(ctx, "osascript", args...)
	case "powershell":
		cmd = exec.CommandContext(ctx, "powershell", args...)
	default:
		return "", fmt.Errorf("unsupported notification command: %s", name)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// DesktopNotifier sends notifications via notify-send or busctl.
type DesktopNotifier struct {
	cfg            Config
	logger         *slog.Logger
	runCmd         runner
	lookPath       func(string) (string, error)
	iconNormalPath string
	iconDangerPath string
	mu             sync.Mutex
	recentSend     map[string]time.Time
}

// New creates a new DesktopNotifier.
func New(cfg Config, logger *slog.Logger) *DesktopNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	d := &DesktopNotifier{
		cfg:        cfg,
		logger:     logger,
		runCmd:     defaultRunner,
		lookPath:   exec.LookPath,
		recentSend: make(map[string]time.Time),
	}
	d.initIcons()
	return d
}

func (d *DesktopNotifier) scheduleDismissal(id uint32, delay time.Duration) {
	time.AfterFunc(delay, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := d.lookPath("busctl"); err == nil {
			_, _ = d.runCmd(ctx, "busctl", "--user", "call",
				"org.freedesktop.Notifications",
				"/org/freedesktop/Notifications",
				"org.freedesktop.Notifications",
				"CloseNotification", "u", strconv.FormatUint(uint64(id), 10))
		}
	})
}

func (d *DesktopNotifier) initIcons() {
	cacheDir, err := os.UserCacheDir()
	if err != nil || cacheDir == "" {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "quarantined", "icons")
	if err := os.MkdirAll(dir, 0755); err != nil {
		d.logger.Debug("unable to create icon directory", "error", err)
		return
	}

	normalPath := filepath.Clean(filepath.Join(dir, "eye-normal.png"))
	dangerPath := filepath.Clean(filepath.Join(dir, "eye-danger.png"))

	if len(eyeNormalPNG) > 0 {
		if err := os.WriteFile(normalPath, eyeNormalPNG, 0644); err == nil {
			d.iconNormalPath = normalPath
		}
	}
	if len(eyeDangerPNG) > 0 {
		if err := os.WriteFile(dangerPath, eyeDangerPNG, 0644); err == nil {
			d.iconDangerPath = dangerPath
		}
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

	icon := d.iconDangerPath
	if icon == "" {
		icon = "security-high"
	}

	return d.Send(ctx, Notification{
		Title:           title,
		Body:            body,
		Urgency:         UrgencyNormal,
		Icon:            icon,
		Category:        "security.quarantine",
		ExpireTimeoutMs: DefaultExpireTimeoutMs,
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

	icon := d.iconNormalPath
	if icon == "" {
		icon = "dialog-warning"
	}

	return d.Send(ctx, Notification{
		Title:           title,
		Body:            body,
		Urgency:         UrgencyNormal,
		Icon:            icon,
		Category:        "security.alert",
		ExpireTimeoutMs: DefaultExpireTimeoutMs,
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

	// Ensure desktop session is available on Linux/Unix
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
			d.logger.Debug("desktop environment not detected; skipping notification", "title", n.Title)
			return nil
		}
	}

	expireMs := n.ExpireTimeoutMs
	if expireMs <= 0 {
		expireMs = DefaultExpireTimeoutMs
	}

	// Bound timeout to prevent hanging the pipeline
	sendCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// macOS dispatch via native osascript
	if runtime.GOOS == "darwin" {
		if _, err := d.lookPath("osascript"); err == nil {
			script := fmt.Sprintf(`display notification %q with title %q`, n.Body, n.Title)
			if _, err := d.runCmd(sendCtx, "osascript", "-e", script); err != nil {
				d.logger.Debug("osascript notification failed", "error", err)
				return err
			}
			return nil
		}
	}

	// Windows dispatch via PowerShell toast / balloon
	if runtime.GOOS == "windows" {
		if _, err := d.lookPath("powershell"); err == nil {
			safeTitle := strings.ReplaceAll(n.Title, "'", "''")
			safeBody := strings.ReplaceAll(n.Body, "'", "''")
			psCmd := fmt.Sprintf(`[void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); $obj=New-Object System.Windows.Forms.NotifyIcon; $obj.Icon=[System.Drawing.SystemIcons]::Warning; $obj.BalloonTipIcon='Warning'; $obj.BalloonTipTitle='%s'; $obj.BalloonTipText='%s'; $obj.Visible=$True; $obj.ShowBalloonTip(%d)`, safeTitle, safeBody, expireMs)
			if _, err := d.runCmd(sendCtx, "powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd); err != nil {
				d.logger.Debug("powershell notification failed", "error", err)
				return err
			}
			return nil
		}
	}

	if _, err := d.lookPath("notify-send"); err == nil {
		args := []string{
			"-p",
			"-a", "quarantined",
			"-u", n.Urgency,
			"-t", strconv.Itoa(expireMs),
			"-i", n.Icon,
		}
		if n.Category != "" {
			args = append(args, "-c", n.Category)
		}
		args = append(args, n.Title, n.Body)
		out, err := d.runCmd(sendCtx, "notify-send", args...)
		if err != nil {
			d.logger.Debug("notify-send failed", "error", err)
			return err
		}
		if id, parseErr := strconv.ParseUint(strings.TrimSpace(out), 10, 32); parseErr == nil && id > 0 {
			d.scheduleDismissal(uint32(id), time.Duration(expireMs)*time.Millisecond)
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
			strconv.Itoa(expireMs),
		}
		out, err := d.runCmd(sendCtx, "busctl", args...)
		if err != nil {
			d.logger.Debug("busctl notify failed", "error", err)
			return err
		}
		fields := strings.Fields(out)
		if len(fields) >= 2 && fields[0] == "u" {
			if id, parseErr := strconv.ParseUint(fields[1], 10, 32); parseErr == nil && id > 0 {
				d.scheduleDismissal(uint32(id), time.Duration(expireMs)*time.Millisecond)
			}
		}
		return nil
	}

	d.logger.Debug("neither notify-send nor busctl found in PATH")
	return nil
}
