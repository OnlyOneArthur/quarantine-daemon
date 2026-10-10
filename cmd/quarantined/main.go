package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/logger"
)

const Version = "0.1.0-dev"

func main() {
	configPath := flag.String("config", "", "path to config.toml")
	logLevel := flag.String("log-level", "", "override log level (debug, info, warn, error)")
	showVersion := flag.Bool("version", false, "print version and exit")
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

	log := logger.Init(cfg.Service.LogLevel, os.Stderr)
	log.Info("starting host quarantine daemon",
		"version", Version,
		"vault_dir", cfg.Quarantine.VaultDir,
		"watch_paths", cfg.Paths.Watch,
		"log_level", cfg.Service.LogLevel,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("daemon initialized (phase 1 skeleton), awaiting shutdown signal")
	<-ctx.Done()

	log.Info("shutting down host quarantine daemon")
}
