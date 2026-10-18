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

func TestLoadConfig_MissingFileErrors(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "nope.toml")

	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected error for missing config file, got nil")
	}

	// An empty path still means "use defaults" — that is the documented
	// no-config invocation, not a missing file.
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load empty path failed: %v", err)
	}
	if cfg.Quarantine.ThresholdScore != 85 {
		t.Errorf("expected default threshold 85, got %d", cfg.Quarantine.ThresholdScore)
	}
}

func TestLoadConfig_EmptyPathsRejected(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	tomlData := []byte(`
[service]
socket_path = ""

[quarantine]
vault_dir = ""
`)
	if err := os.WriteFile(cfgPath, tomlData, 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected error for empty vault_dir/socket_path, got nil")
	}
}

func TestLoadConfig_RejectsOutOfRangeValues(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"threshold above 100", "[quarantine]\nthreshold_score = 200\n"},
		{"negative threshold", "[quarantine]\nthreshold_score = -1\n"},
		{"negative vault size", "[quarantine]\nmax_vault_size_mb = -5\n"},
		{"negative retention", "[quarantine]\nretention_days = -1\n"},
		{"zero poll interval", "[service]\npoll_interval_ms = 0\n"},
		{"zero scan size", "[triage_binary]\nmax_scan_size_mb = 0\n"},
		{"entropy above 8", "[triage_binary]\nentropy_threshold = 9.5\n"},
		{"notification min_score above 100", "[notifications]\nmin_score = 101\n"},
		{"negative notification min_score", "[notifications]\nmin_score = -1\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(cfgPath, []byte(tc.body), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			if _, err := Load(cfgPath); err == nil {
				t.Fatalf("Load accepted invalid config: %s", tc.body)
			}
		})
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
	if cfg.Binary.MaxScanSizeMB != 64 {
		t.Errorf("expected default MaxScanSizeMB 64, got %d", cfg.Binary.MaxScanSizeMB)
	}
}

func TestLoadConfig_RelativePaths(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	tomlData := []byte(`
[service]
socket_path = "sub/daemon.sock"

[paths]
watch = ["watch_a", "watch_b"]

[quarantine]
vault_dir = "vault"
`)
	if err := os.WriteFile(cfgPath, tomlData, 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	expectedVault := filepath.Join(tmpDir, "vault")
	if cfg.Quarantine.VaultDir != expectedVault {
		t.Errorf("expected vault %q, got %q", expectedVault, cfg.Quarantine.VaultDir)
	}
	expectedSocket := filepath.Join(tmpDir, "sub", "daemon.sock")
	if cfg.Service.SocketPath != expectedSocket {
		t.Errorf("expected socket %q, got %q", expectedSocket, cfg.Service.SocketPath)
	}
	if len(cfg.Paths.Watch) != 2 || cfg.Paths.Watch[0] != filepath.Join(tmpDir, "watch_a") {
		t.Errorf("expected watch[0] %q, got %v", filepath.Join(tmpDir, "watch_a"), cfg.Paths.Watch)
	}
}

func TestLoadConfig_EnvVarExpansion(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TEST_DAEMON_RUNTIME", tmpDir)

	cfgPath := filepath.Join(tmpDir, "config.toml")
	tomlData := []byte(`
[service]
socket_path = "$TEST_DAEMON_RUNTIME/daemon.sock"

[quarantine]
vault_dir = "$TEST_DAEMON_RUNTIME/vault"
`)
	if err := os.WriteFile(cfgPath, tomlData, 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	expectedVault := filepath.Join(tmpDir, "vault")
	if cfg.Quarantine.VaultDir != expectedVault {
		t.Errorf("expected vault %q, got %q", expectedVault, cfg.Quarantine.VaultDir)
	}
	expectedSocket := filepath.Join(tmpDir, "daemon.sock")
	if cfg.Service.SocketPath != expectedSocket {
		t.Errorf("expected socket %q, got %q", expectedSocket, cfg.Service.SocketPath)
	}
}
