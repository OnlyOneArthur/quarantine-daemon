// Package notify implements unit tests for desktop notifications.
package notify

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestNotifyDisabled(t *testing.T) {
	called := false
	n := New(Config{Enabled: false, MinScore: 50}, nil)
	n.runCmd = func(ctx context.Context, name string, args ...string) (string, error) {
		called = true
		return "", nil
	}

	err := n.NotifyQuarantine(context.Background(), "/tmp/bad.elf", 100, []string{"evasion"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Error("expected runCmd not to be called when disabled")
	}
}

func TestNotifyScoreBelowThreshold(t *testing.T) {
	called := false
	n := New(Config{Enabled: true, MinScore: 80}, nil)
	n.runCmd = func(ctx context.Context, name string, args ...string) (string, error) {
		called = true
		return "", nil
	}

	err := n.NotifyAlert(context.Background(), "/tmp/alert.elf", 50, []string{"high_entropy"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Error("expected runCmd not to be called when score < MinScore")
	}
}

func TestNotifySendExecution(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")

	var invokedCmd string
	var invokedArgs []string

	n := New(Config{Enabled: true, MinScore: 50}, nil)
	n.lookPath = func(name string) (string, error) {
		if name == "notify-send" {
			return "/usr/bin/notify-send", nil
		}
		return "", errors.New("not found")
	}
	n.runCmd = func(ctx context.Context, name string, args ...string) (string, error) {
		invokedCmd = name
		invokedArgs = args
		return "101\n", nil
	}

	err := n.NotifyQuarantine(context.Background(), "/tmp/malware.exe", 95, []string{"pe_upx_packed", "entropy_high"})
	if err != nil {
		t.Fatalf("NotifyQuarantine failed: %v", err)
	}

	if invokedCmd != "notify-send" {
		t.Errorf("expected notify-send, got %s", invokedCmd)
	}

	foundApp := false
	foundUrgency := false
	foundTitle := false
	foundDangerIcon := false
	foundTimeout := false
	foundPrintID := false
	for i, arg := range invokedArgs {
		if arg == "-p" {
			foundPrintID = true
		}
		if arg == "-a" && i+1 < len(invokedArgs) && invokedArgs[i+1] == "quarantined" {
			foundApp = true
		}
		if arg == "-u" && i+1 < len(invokedArgs) && invokedArgs[i+1] == "normal" {
			foundUrgency = true
		}
		if arg == "-t" && i+1 < len(invokedArgs) && invokedArgs[i+1] == "10000" {
			foundTimeout = true
		}
		if arg == "-i" && i+1 < len(invokedArgs) && strings.Contains(invokedArgs[i+1], "eye-danger.png") {
			foundDangerIcon = true
		}
		if strings.Contains(arg, "malware.exe") {
			foundTitle = true
		}
	}

	if !foundApp || !foundUrgency || !foundTitle || !foundDangerIcon || !foundTimeout || !foundPrintID {
		t.Errorf("args missing required fields: %v", invokedArgs)
	}
}

func TestBusctlFallback(t *testing.T) {
	t.Setenv("DISPLAY", ":0")

	var invokedCmd string
	var invokedArgs []string

	n := New(Config{Enabled: true, MinScore: 50}, nil)
	n.lookPath = func(name string) (string, error) {
		if name == "notify-send" {
			return "", errors.New("not found")
		}
		if name == "busctl" {
			return "/usr/bin/busctl", nil
		}
		return "", errors.New("not found")
	}
	n.runCmd = func(ctx context.Context, name string, args ...string) (string, error) {
		invokedCmd = name
		invokedArgs = args
		return "u 102\n", nil
	}

	err := n.NotifyAlert(context.Background(), "/tmp/test.sh", 60, []string{"curl_pipe_sh"})
	if err != nil {
		t.Fatalf("NotifyAlert failed: %v", err)
	}

	if invokedCmd != "busctl" {
		t.Errorf("expected busctl, got %s", invokedCmd)
	}
	if len(invokedArgs) < 16 || invokedArgs[0] != "--user" || invokedArgs[1] != "call" {
		t.Errorf("unexpected busctl args: %v", invokedArgs)
	}
	// Check that the normal eye icon was passed to busctl (argument index 9 in busctl call)
	if !strings.Contains(invokedArgs[9], "eye-normal.png") {
		t.Errorf("expected eye-normal.png in busctl args[9], got %q", invokedArgs[9])
	}
	// Check that the expire timeout is 10000 ms (argument index 15)
	if invokedArgs[15] != "10000" {
		t.Errorf("expected busctl expire timeout 10000 ms, got %q", invokedArgs[15])
	}
}

func TestDeduplication(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/bus")

	callCount := 0
	n := New(Config{Enabled: true, MinScore: 50}, nil)
	n.lookPath = func(name string) (string, error) {
		return "/usr/bin/notify-send", nil
	}
	n.runCmd = func(ctx context.Context, name string, args ...string) (string, error) {
		callCount++
		return "103\n", nil
	}

	for i := 0; i < 5; i++ {
		_ = n.NotifyQuarantine(context.Background(), "/tmp/dupe.exe", 100, []string{"evasion"})
	}

	if callCount != 1 {
		t.Errorf("expected 1 call due to deduplication, got %d", callCount)
	}
}

func TestNoDesktopEnvironment(t *testing.T) {
	_ = os.Unsetenv("DISPLAY")
	_ = os.Unsetenv("WAYLAND_DISPLAY")
	_ = os.Unsetenv("DBUS_SESSION_BUS_ADDRESS")

	called := false
	n := New(Config{Enabled: true, MinScore: 50}, nil)
	n.lookPath = func(name string) (string, error) {
		return "/usr/bin/notify-send", nil
	}
	n.runCmd = func(ctx context.Context, name string, args ...string) (string, error) {
		called = true
		return "", nil
	}

	err := n.NotifyQuarantine(context.Background(), "/tmp/test.exe", 100, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Error("expected no notification without desktop environment")
	}
}

func TestCustomExpireTimeout(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")

	var invokedArgs []string
	n := New(Config{Enabled: true, MinScore: 50}, nil)
	n.lookPath = func(name string) (string, error) {
		return "/usr/bin/notify-send", nil
	}
	n.runCmd = func(ctx context.Context, name string, args ...string) (string, error) {
		invokedArgs = args
		return "104\n", nil
	}

	err := n.Send(context.Background(), Notification{
		Title:           "Custom Timeout",
		Body:            "Test body",
		Urgency:         UrgencyNormal,
		ExpireTimeoutMs: 5000,
	})
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	foundTimeout := false
	for i, arg := range invokedArgs {
		if arg == "-t" && i+1 < len(invokedArgs) && invokedArgs[i+1] == "5000" {
			foundTimeout = true
		}
	}
	if !foundTimeout {
		t.Errorf("expected -t 5000 in args, got %v", invokedArgs)
	}
}
