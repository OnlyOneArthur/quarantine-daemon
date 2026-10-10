package logger

import (
	"bytes"
	"strings"
	"testing"
)

func TestInitLogger(t *testing.T) {
	buf := &bytes.Buffer{}
	l := Init("debug", buf)
	l.Debug("debug message", "key", "val")
	l.Info("info message")

	out := buf.String()
	if !strings.Contains(out, "debug message") {
		t.Errorf("expected debug message in log, got: %s", out)
	}
	if !strings.Contains(out, "key=val") {
		t.Errorf("expected key=val in log, got: %s", out)
	}
}

func TestLevelFiltering(t *testing.T) {
	buf := &bytes.Buffer{}
	l := Init("warn", buf)
	l.Info("ignored info")
	l.Warn("warning message")

	out := buf.String()
	if strings.Contains(out, "ignored info") {
		t.Errorf("expected info message to be filtered out, got: %s", out)
	}
	if !strings.Contains(out, "warning message") {
		t.Errorf("expected warning message in log, got: %s", out)
	}
}
