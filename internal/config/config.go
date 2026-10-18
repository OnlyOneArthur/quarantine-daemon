// Package config loads and validates the quarantined daemon TOML configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Config is the root configuration document.
type Config struct {
	Service       ServiceConfig      `toml:"service"`
	Paths         PathsConfig        `toml:"paths"`
	Binary        BinaryConfig       `toml:"triage_binary"`
	PKGBUILD      PKGBUILDConfig     `toml:"triage_pkgbuild"`
	Quarantine    QuarantineConfig   `toml:"quarantine"`
	Notifications NotificationConfig `toml:"notifications"`
}

// ServiceConfig controls logging and the IPC socket.
type ServiceConfig struct {
	LogLevel       string `toml:"log_level"`
	PollIntervalMs int    `toml:"poll_interval_ms"`
	SocketPath     string `toml:"socket_path"`
}

// PathsConfig lists the directories to watch and extensions to ignore.
type PathsConfig struct {
	Watch            []string `toml:"watch"`
	IgnoreExtensions []string `toml:"ignore_extensions"`
}

// BinaryConfig tunes native-binary triage.
type BinaryConfig struct {
	Enabled          bool    `toml:"enabled"`
	EntropyThreshold float64 `toml:"entropy_threshold"`
	MaxScanSizeMB    int64   `toml:"max_scan_size_mb"`
}

// PKGBUILDConfig tunes PKGBUILD and install-scriptlet triage.
type PKGBUILDConfig struct {
	Enabled               bool `toml:"enabled"`
	BlockUntrustedSources bool `toml:"block_untrusted_sources"`
	FlagSkipChecksums     bool `toml:"flag_skip_checksums"`
}

// QuarantineConfig controls the vault directory and retention policy.
type QuarantineConfig struct {
	VaultDir       string `toml:"vault_dir"`
	ThresholdScore int    `toml:"threshold_score"`
	MaxVaultSizeMB int64  `toml:"max_vault_size_mb"`
	RetentionDays  int    `toml:"retention_days"`
}

// NotificationConfig controls desktop notifications.
type NotificationConfig struct {
	Enabled  bool `toml:"enabled"`
	MinScore int  `toml:"min_score"`
}

// ExpandHome replaces leading "~/" with the user's home directory.
func ExpandHome(path string) string {
	if strings.HasPrefix(path, "~/") || path == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			if path == "~" {
				return filepath.Clean(home)
			}
			return filepath.Clean(filepath.Join(home, filepath.Clean(path[2:])))
		}
	}
	return filepath.Clean(path)
}

// DefaultConfig returns the built-in defaults, rooted at the user's home.
func DefaultConfig() *Config {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	vaultDir := filepath.Clean(filepath.Join(home, ".local", "share", "quarantined", "vault"))

	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = filepath.Clean(filepath.Join(home, ".local", "state"))
	}
	socketPath := filepath.Clean(filepath.Join(runtimeDir, "quarantined.sock"))

	return &Config{
		Service: ServiceConfig{
			LogLevel:       "info",
			PollIntervalMs: 300,
			SocketPath:     socketPath,
		},
		Paths: PathsConfig{
			Watch: []string{
				filepath.Clean(filepath.Join(home, "Downloads")),
				"/tmp",
				filepath.Clean(filepath.Join(home, ".cache", "yay")),
				filepath.Clean(filepath.Join(home, ".cache", "paru", "clone")),
			},
			IgnoreExtensions: []string{".crdownload", ".part", ".tmp"},
		},
		Binary: BinaryConfig{
			Enabled:          true,
			EntropyThreshold: 7.3,
			MaxScanSizeMB:    64,
		},
		PKGBUILD: PKGBUILDConfig{
			Enabled:               true,
			BlockUntrustedSources: true,
			FlagSkipChecksums:     true,
		},
		Quarantine: QuarantineConfig{
			VaultDir:       vaultDir,
			ThresholdScore: 85,
			MaxVaultSizeMB: 1024,
			RetentionDays:  14,
		},
		Notifications: NotificationConfig{
			Enabled:  true,
			MinScore: 50,
		},
	}
}

// Load loads configuration from a TOML file. If path is empty, DefaultConfig() is returned.
//
// Relative paths in the file (watch entries, vault_dir, socket_path) are resolved against the
// directory holding the config file, so a checked-in config runs from any working directory.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}

	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config toml: %w", err)
	}

	baseDir := filepath.Dir(cleanPath)
	if abs, err := filepath.Abs(baseDir); err == nil {
		baseDir = abs
	}

	// Expand paths: environment variables and "~" first, then anchor anything still relative to the config file.
	resolve := func(p string) string {
		if p == "" {
			return ""
		}
		p = os.ExpandEnv(p)
		p = ExpandHome(p)
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Clean(filepath.Join(baseDir, p))
	}
	for i, p := range cfg.Paths.Watch {
		cfg.Paths.Watch[i] = resolve(p)
	}
	cfg.Quarantine.VaultDir = resolve(cfg.Quarantine.VaultDir)
	cfg.Service.SocketPath = resolve(cfg.Service.SocketPath)
	if cfg.Quarantine.VaultDir == "" || cfg.Service.SocketPath == "" {
		return nil, fmt.Errorf("vault_dir and socket_path must not be empty")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate rejects out-of-range values that would silently disable a subsystem
// (for example a threshold_score above 100 makes VerdictQuarantine unreachable).
func (c *Config) validate() error {
	if c.Quarantine.ThresholdScore < 0 || c.Quarantine.ThresholdScore > 100 {
		return fmt.Errorf("quarantine.threshold_score must be between 0 and 100, got %d", c.Quarantine.ThresholdScore)
	}
	if c.Quarantine.MaxVaultSizeMB < 0 {
		return fmt.Errorf("quarantine.max_vault_size_mb must not be negative, got %d", c.Quarantine.MaxVaultSizeMB)
	}
	if c.Quarantine.RetentionDays < 0 {
		return fmt.Errorf("quarantine.retention_days must not be negative, got %d", c.Quarantine.RetentionDays)
	}
	if c.Service.PollIntervalMs <= 0 {
		return fmt.Errorf("service.poll_interval_ms must be positive, got %d", c.Service.PollIntervalMs)
	}
	if c.Binary.MaxScanSizeMB <= 0 {
		return fmt.Errorf("triage_binary.max_scan_size_mb must be positive, got %d", c.Binary.MaxScanSizeMB)
	}
	if c.Binary.EntropyThreshold < 0 || c.Binary.EntropyThreshold > 8 {
		return fmt.Errorf("triage_binary.entropy_threshold must be between 0 and 8, got %g", c.Binary.EntropyThreshold)
	}
	if c.Notifications.MinScore < 0 || c.Notifications.MinScore > 100 {
		return fmt.Errorf("notifications.min_score must be between 0 and 100, got %d", c.Notifications.MinScore)
	}
	return nil
}
