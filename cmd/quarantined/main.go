package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/logger"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/tui"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/watcher"
)

const Version = "0.1.0-dev"

func main() {
	configPath := flag.String("config", "", "path to config.toml")
	logLevel := flag.String("log-level", "", "override log level (debug, info, warn, error)")
	showVersion := flag.Bool("version", false, "print version and exit")
	tuiMode := flag.Bool("tui", false, "run the Bubble Tea terminal client instead of the daemon")
	flag.Parse()

	if *showVersion {
		fmt.Printf("quarantined %s\n", Version)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	if *logLevel != "" {
		cfg.Service.LogLevel = *logLevel
	}

	if *tuiMode {
		if err := tui.Run(tui.SocketDialer(cfg.Service.SocketPath), Version); err != nil {
			fmt.Fprintf(os.Stderr, "tui failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	log := logger.Init(cfg.Service.LogLevel, os.Stderr)
	log.Info("starting host quarantine daemon",
		"version", Version,
		"vault_dir", cfg.Quarantine.VaultDir,
		"watch_paths", cfg.Paths.Watch,
		"log_level", cfg.Service.LogLevel,
	)

	if err := run(cfg, log); err != nil {
		log.Error("daemon failed", "error", err)
		os.Exit(1)
	}
}

// run wires vault, watcher, pipeline and IPC server, and blocks until SIGINT/SIGTERM.
func run(cfg *config.Config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	vault, err := quarantine.New(cfg.Quarantine.VaultDir)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}
	defer func() { _ = vault.Close() }()
	vault.SetLimits(cfg.Quarantine.MaxVaultSizeMB, cfg.Quarantine.RetentionDays)
	if err := vault.Sweep(); err != nil {
		return fmt.Errorf("sweep vault: %w", err)
	}

	w, err := watcher.New(watcher.Config{
		Roots:            cfg.Paths.Watch,
		IgnoreExtensions: cfg.Paths.IgnoreExtensions,
		DebounceDelay:    time.Duration(cfg.Service.PollIntervalMs) * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("start watcher: %w", err)
	}

	p := newPipeline(cfg, vault, log)
	ctrl := newDaemonController(p, w, cfg, Version)

	srv := ipc.NewServer(cfg.Service.SocketPath, vault, ctrl)
	srv.SetWatchManager(ctrl)
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- srv.Start(ctx)
	}()

	log.Info("daemon running", "socket", cfg.Service.SocketPath)

	sweepTicker := time.NewTicker(time.Hour)
	defer sweepTicker.Stop()
	var loopErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-sweepTicker.C:
			if err := vault.Sweep(); err != nil {
				log.Error("vault retention sweep failed", "error", err)
			}
		case err := <-srvErr:
			if err != nil {
				loopErr = fmt.Errorf("ipc server: %w", err)
			}
			break loop
		case ev, ok := <-w.Events():
			if !ok {
				loopErr = errors.New("watcher event channel closed")
				break loop
			}
			if _, err := p.handlePath(ev.Path); err != nil {
				log.Error("pipeline error", "path", ev.Path, "error", err)
			}
		case err, ok := <-w.Errors():
			if ok {
				log.Warn("watcher error", "error", err)
			}
		}
	}

	log.Info("shutting down host quarantine daemon")
	if err := srv.Stop(); err != nil {
		log.Error("stop ipc server", "error", err)
	}
	if err := w.Close(); err != nil {
		log.Error("close watcher", "error", err)
	}
	log.Info("shutdown complete", "scanned", p.scanned.Load(), "quarantined", p.quarantined.Load())
	return loopErr
}
