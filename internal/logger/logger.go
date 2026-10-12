package logger

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Init initializes and returns a structured slog.Logger.
func Init(levelStr string, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}

	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewTextHandler(w, opts)
	l := slog.New(handler)
	return l
}
