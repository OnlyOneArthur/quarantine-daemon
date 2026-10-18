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
	n.runCmd = func(ctx context.Context, name string, args ...string) error {
		called = true
		return nil
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
	n.runCmd = func(ctx context.Context, name string, args ...string) error {
		called = true
		return nil
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
	n.runCmd = func(ctx context.Context, name string, args ...string) error {
		invokedCmd = name
		invokedArgs = args
		return nil
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
	for i, arg := range invokedArgs {
		if arg == "-a" && i+1 < len(invokedArgs) && invokedArgs[i+1] == "quarantined" {
			foundApp = true
		}
		if arg == "-u" && i+1 < len(invokedArgs) && invokedArgs[i+1] == "critical" {
			foundUrgency = true
		}
		if strings.Contains(arg, "malware.exe") {
			foundTitle = true
		}
	}

	if !foundApp || !foundUrgency || !foundTitle {
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
	n.runCmd = func(ctx context.Context, name string, args ...string) error {
		invokedCmd = name
		invokedArgs = args
		return nil
	}

	err := n.NotifyAlert(context.Background(), "/tmp/test.sh", 60, []string{"curl_pipe_sh"})
	if err != nil {
		t.Fatalf("NotifyAlert failed: %v", err)
	}

	if invokedCmd != "busctl" {
		t.Errorf("expected busctl, got %s", invokedCmd)
	}
	if len(invokedArgs) < 5 || invokedArgs[0] != "--user" || invokedArgs[1] != "call" {
		t.Errorf("unexpected busctl args: %v", invokedArgs)
	}
}

func TestDeduplication(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/bus")

	callCount := 0
	n := New(Config{Enabled: true, MinScore: 50}, nil)
	n.lookPath = func(name string) (string, error) {
		return "/usr/bin/notify-send", nil
	}
	n.runCmd = func(ctx context.Context, name string, args ...string) error {
		callCount++
		return nil
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
	n.runCmd = func(ctx context.Context, name string, args ...string) error {
		called = true
		return nil
	}

	err := n.NotifyQuarantine(context.Background(), "/tmp/test.exe", 100, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Error("expected no notification without desktop environment")
	}
}
