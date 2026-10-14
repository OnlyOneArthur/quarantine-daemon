// Package quarantine manages the content-addressed vault: quarantining files,
// listing/inspecting them, restoring originals and sweeping expired entries.
package quarantine

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
)

const lockName = "vault.lock"

// ErrItemNotFound is returned when a vault id has no metadata sidecar.
var (
	ErrItemNotFound       = errors.New("quarantine item not found")
	ErrInvalidSource      = errors.New("invalid source file")
	ErrAlreadyQuarantined = errors.New("content already quarantined")
)

// Vault is a concurrency-safe quarantine store rooted at a directory.
type Vault struct {
	dir            string
	lockFile       *os.File
	mu             sync.Mutex
	maxVaultSizeMB int64
	retentionDays  int

	// usedBytes caches the total artifact bytes so the size cap does not have to
	// stat every artifact on each quarantine. It is -1 when unknown and is
	// invalidated on open, by SetLimits, and by any operation that removes
	// artifacts (Sweep, Purge, Restore).
	usedBytes int64
}

// New creates or opens a quarantine vault at vaultDir with 0700 permissions.
func New(vaultDir string) (*Vault, error) {
	if strings.TrimSpace(vaultDir) == "" {
		return nil, errors.New("vault directory cannot be empty")
	}

	dir := filepath.Clean(vaultDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create vault dir %s: %w", dir, err)
	}
	_ = os.Chmod(dir, 0700)

	lockPath := filepath.Join(dir, lockName)
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open vault lock %s: %w", lockPath, err)
	}

	return &Vault{dir: dir, lockFile: lockFile, usedBytes: -1}, nil
}

// SetLimits configures the artifact size cap and retention period. Nonpositive
// values disable the corresponding limit.
func (v *Vault) SetLimits(maxVaultSizeMB int64, retentionDays int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.maxVaultSizeMB = maxVaultSizeMB
	v.retentionDays = retentionDays
	// The cap changed; the cached total must be rebuilt before it is trusted.
	v.usedBytes = -1
}

// Close releases the vault lock handle.
func (v *Vault) Close() error {
	if v.lockFile != nil {
		return v.lockFile.Close()
	}
	return nil
}

// withLock serializes an operation across processes (flock) and goroutines (mutex).
func (v *Vault) withLock(fn func() error) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	unlock, err := fsutil.LockFile(v.lockFile)
	if err != nil {
		return fmt.Errorf("acquire vault lock: %w", err)
	}
	defer func() { _ = unlock() }()

	return fn()
}

// checkSizeCap counts artifacts (including orphaned ones) before moving the source.
// Sidecars and the lock file are not quarantined payload bytes.
func (v *Vault) checkSizeCap(size int64) error {
	if v.maxVaultSizeMB <= 0 || v.maxVaultSizeMB > math.MaxInt64/(1024*1024) {
		return nil
	}
	maxBytes := v.maxVaultSizeMB * 1024 * 1024
	if v.usedBytes < 0 {
		used, err := v.rebuildUsedBytes()
		if err != nil {
			return err
		}
		v.usedBytes = used
	}
	if size > maxBytes-v.usedBytes {
		return fmt.Errorf("vault size cap exceeded (%d MB)", v.maxVaultSizeMB)
	}
	return nil
}

// rebuildUsedBytes sums the sizes of every artifact in the vault directory,
// including orphans with no metadata sidecar.
func (v *Vault) rebuildUsedBytes() (int64, error) {
	entries, err := os.ReadDir(v.dir)
	if err != nil {
		return 0, fmt.Errorf("read vault dir: %w", err)
	}
	var used int64
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != 64 || !isHex64(name) || !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, fmt.Errorf("stat vault artifact %s: %w", name, err)
		}
		used += info.Size()
	}
	return used, nil
}

// Sweep purges items older than the configured retention period.
func (v *Vault) Sweep() error {
	return v.withLock(func() error {
		if v.retentionDays <= 0 {
			return nil
		}
		cutoff := time.Now().UTC().AddDate(0, 0, -v.retentionDays)
		entries, err := os.ReadDir(v.dir)
		if err != nil {
			return fmt.Errorf("read vault dir: %w", err)
		}
		managed, err := v.sweepManaged(entries, cutoff)
		if err != nil {
			return err
		}
		if err := v.sweepOrphans(entries, managed, cutoff); err != nil {
			return err
		}
		// Artifacts were removed: drop the cached total so the next quarantine
		// rebuilds it instead of trusting a now-stale figure.
		v.usedBytes = -1
		return nil
	})
}

func (v *Vault) sweepManaged(entries []os.DirEntry, cutoff time.Time) (map[string]struct{}, error) {
	managed := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), metaSuffix) {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), metaSuffix)
		managed[id] = struct{}{}
		meta, err := v.readMeta(entry.Name())
		if err != nil {
			continue
		}
		if meta.ID != id || !meta.QuarantinedAt.Before(cutoff) {
			continue
		}
		if err := os.Remove(v.artifactPath(id)); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("remove expired artifact %s: %w", id, err)
		}
		if err := os.Remove(v.metaPath(id)); err != nil {
			return nil, fmt.Errorf("remove expired metadata %s: %w", id, err)
		}
	}
	return managed, nil
}

func (v *Vault) sweepOrphans(entries []os.DirEntry, managed map[string]struct{}, cutoff time.Time) error {
	// Artifacts with no sidecar (e.g. left by a crash between the move and the
	// metadata write) are invisible to every other operation, so they would
	// occupy vault quota forever. Age them out on the same retention schedule.
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || len(name) != 64 || !isHex64(name) || !entry.Type().IsRegular() {
			continue
		}
		if _, ok := managed[name]; ok {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(v.dir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove orphaned artifact %s: %w", name, err)
		}
	}
	return nil
}

// List returns metadata for all quarantined items, newest first.
func (v *Vault) List() ([]*ItemMetadata, error) {
	var items []*ItemMetadata
	err := v.withLock(func() error {
		entries, err := os.ReadDir(v.dir)
		if err != nil {
			return fmt.Errorf("read vault dir: %w", err)
		}
		items = make([]*ItemMetadata, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), metaSuffix) {
				continue
			}
			meta, err := v.readMeta(entry.Name())
			if err != nil {
				continue
			}
			items = append(items, meta)
		}
		slices.SortFunc(items, func(a, b *ItemMetadata) int {
			if a.QuarantinedAt.Equal(b.QuarantinedAt) {
				return strings.Compare(a.ID, b.ID)
			}
			if a.QuarantinedAt.After(b.QuarantinedAt) {
				return -1
			}
			return 1
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

// Inspect returns metadata for a single item by ID.
func (v *Vault) Inspect(id string) (*ItemMetadata, error) {
	var meta *ItemMetadata
	err := v.withLock(func() error {
		m, err := v.readMetaByID(id)
		if err != nil {
			return err
		}
		meta = m
		return nil
	})
	if err != nil {
		return nil, err
	}
	return meta, nil
}

// Purge permanently deletes the artifact and sidecar for id.
func (v *Vault) Purge(id string) error {
	return v.withLock(func() error {
		if _, err := v.readMetaByID(id); err != nil {
			return err
		}
		if err := os.Remove(v.artifactPath(id)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove artifact: %w", err)
		}
		if err := os.Remove(v.metaPath(id)); err != nil {
			return fmt.Errorf("remove meta: %w", err)
		}
		v.usedBytes = -1
		return nil
	})
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range 64 {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
