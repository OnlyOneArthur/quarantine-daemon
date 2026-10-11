package main

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/triage/binary"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/triage/pkgbuild"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/watcher"
)

// scanResult is the triage outcome normalized across binary and PKGBUILD scorers.
type scanResult struct {
	Score      int
	Verdict    string
	Triggers   []string
	Categories []string
	Dampeners  []string
}

// pipeline routes watched files to the matching triage engine and quarantines
// files whose verdict is QUARANTINE at or above the configured threshold.
type pipeline struct {
	cfg         *config.Config
	vault       *quarantine.Vault
	log         *slog.Logger
	scanned     atomic.Int64
	quarantined atomic.Int64
}

func newPipeline(cfg *config.Config, vault *quarantine.Vault, log *slog.Logger) *pipeline {
	return &pipeline{cfg: cfg, vault: vault, log: log}
}

// handlePath triages one regular file. It returns the vault metadata when the file
// was quarantined, or nil when the file was skipped or left in place (PASS/ALERT).
func (p *pipeline) handlePath(path string) (*quarantine.ItemMetadata, error) {
	maxBytes := p.cfg.Binary.MaxScanSizeMB * 1024 * 1024

	sf, err := fsutil.OpenSafe(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = sf.Close() }()

	if sf.Size > maxBytes {
		p.log.Info("skipping oversize file", "path", path, "size", sf.Size, "max_bytes", maxBytes)
		return nil, nil
	}

	data, err := fsutil.ReadBounded(sf.File, maxBytes)
	if errors.Is(err, fsutil.ErrExceedsMaxScanSize) {
		p.log.Info("skipping oversize file", "path", path, "max_bytes", maxBytes)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	res, ok, err := p.triage(data, path)
	if err != nil {
		return nil, fmt.Errorf("triage %s: %w", path, err)
	}
	if !ok {
		return nil, nil
	}
	p.scanned.Add(1)

	p.log.Info("triage complete", "path", path, "verdict", res.Verdict, "score", res.Score, "triggers", res.Triggers)

	if res.Verdict != string(binary.VerdictQuarantine) || res.Score < p.cfg.Quarantine.ThresholdScore {
		return nil, nil
	}

	meta, err := p.vault.QuarantineFile(path, res.Score, res.Triggers, res.Categories, res.Dampeners)
	if err != nil {
		return nil, fmt.Errorf("quarantine %s: %w", path, err)
	}
	p.quarantined.Add(1)
	p.log.Warn("file quarantined", "path", path, "id", meta.ID, "score", meta.Score)
	return meta, nil
}

// triage selects the engine for path. ok is false when the file kind is disabled by config.
func (p *pipeline) triage(data []byte, path string) (res scanResult, ok bool, err error) {
	base := filepath.Base(path)
	isPKGBUILD := base == "PKGBUILD"
	isInstall := strings.HasSuffix(base, ".install")

	if isPKGBUILD || isInstall {
		if !p.cfg.PKGBUILD.Enabled {
			return scanResult{}, false, nil
		}
		var pr *pkgbuild.TriageResult
		if isPKGBUILD {
			pr, err = pkgbuild.TriagePKGBUILD(data, path, p.cfg)
		} else {
			pr, err = pkgbuild.TriageInstallScript(data, path, p.cfg)
		}
		if err != nil {
			return scanResult{}, false, err
		}
		names := make([]string, 0, len(pr.Triggers))
		for _, tr := range pr.Triggers {
			names = append(names, tr.Name)
		}
		return scanResult{
			Score:      pr.Score,
			Verdict:    string(pr.Verdict),
			Triggers:   names,
			Categories: pr.CategoriesHit,
			Dampeners:  pr.DampenersApplied,
		}, true, nil
	}

	if !p.cfg.Binary.Enabled {
		return scanResult{}, false, nil
	}
	br, err := binary.TriageBinary(data, path, p.cfg)
	if err != nil {
		return scanResult{}, false, err
	}
	names := make([]string, 0, len(br.Triggers))
	for _, tr := range br.Triggers {
		names = append(names, tr.Name)
	}
	return scanResult{
		Score:      br.Score,
		Verdict:    string(br.Verdict),
		Triggers:   names,
		Categories: br.CategoriesHit,
		Dampeners:  br.DampenersApplied,
	}, true, nil
}

// daemonController implements ipc.StatusProvider and ipc.WatchManager.
type daemonController struct {
	pipeline  *pipeline
	watcher   *watcher.Watcher
	cfg       *config.Config
	startedAt time.Time
	version   string
	mu        sync.Mutex
}

func newDaemonController(p *pipeline, w *watcher.Watcher, cfg *config.Config, version string) *daemonController {
	return &daemonController{
		pipeline:  p,
		watcher:   w,
		cfg:       cfg,
		startedAt: time.Now(),
		version:   version,
	}
}

func (d *daemonController) Status() ipc.StatusResponse {
	d.mu.Lock()
	defer d.mu.Unlock()
	return ipc.StatusResponse{
		Uptime:          time.Since(d.startedAt).Seconds(),
		Version:         d.version,
		ScannedCount:    d.pipeline.scanned.Load(),
		QuarantineCount: d.pipeline.quarantined.Load(),
		WatchPaths:      append([]string(nil), d.cfg.Paths.Watch...),
	}
}

func (d *daemonController) AddWatchPath(path string) error {
	clean := filepath.Clean(config.ExpandHome(path))
	if err := d.watcher.AddRoot(clean); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, p := range d.cfg.Paths.Watch {
		if p == clean {
			return nil
		}
	}
	d.cfg.Paths.Watch = append(d.cfg.Paths.Watch, clean)
	return nil
}
