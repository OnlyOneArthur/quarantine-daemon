package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Service.PollIntervalMs != 300 {
		t.Errorf("expected 300ms, got %d", cfg.Service.PollIntervalMs)
	}
	if cfg.Quarantine.ThresholdScore != 85 {
		t.Errorf("expected 85 threshold, got %d", cfg.Quarantine.ThresholdScore)
	}
	if !cfg.Binary.Enabled {
		t.Errorf("expected binary triage enabled")
	}
}

func TestLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	tomlData := []byte(`
[service]
log_level = "debug"
poll_interval_ms = 100

[quarantine]
threshold_score = 90
`)

	if err := os.WriteFile(cfgPath, tomlData, 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Service.LogLevel != "debug" {
		t.Errorf("expected log_level 'debug', got '%s'", cfg.Service.LogLevel)
	}
	if cfg.Service.PollIntervalMs != 100 {
		t.Errorf("expected poll_interval_ms 100, got %d", cfg.Service.PollIntervalMs)
	}
	if cfg.Quarantine.ThresholdScore != 90 {
		t.Errorf("expected threshold_score 90, got %d", cfg.Quarantine.ThresholdScore)
	}
	// Defaults preserved
	if cfg.Binary.MaxScanSizeMB != 64 {
		t.Errorf("expected default MaxScanSizeMB 64, got %d", cfg.Binary.MaxScanSizeMB)
	}
}
