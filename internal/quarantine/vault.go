package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
)

const (
	metaSuffix = ".meta.json"
	lockName   = "vault.lock"
)

var (
	ErrItemNotFound  = errors.New("quarantine item not found")
	ErrInvalidSource = errors.New("invalid source file")
)

// ItemMetadata is the persisted sidecar describing a quarantined artifact.
type ItemMetadata struct {
	ID               string      `json:"id"`
	SHA256           string      `json:"sha256"`
	OriginalPath     string      `json:"original_path"`
	OriginalMode     os.FileMode `json:"original_mode"`
	UID              int         `json:"uid"`
	GID              int         `json:"gid"`
	ModTime          time.Time   `json:"mod_time"`
	QuarantinedAt    time.Time   `json:"quarantined_at"`
	Score            int         `json:"score"`
	Triggers         []string    `json:"triggers"`
	CategoriesHit    []string    `json:"categories_hit"`
	DampenersApplied []string    `json:"dampeners_applied"`
	Size             int64       `json:"size"`
	IsPKGBUILD       bool        `json:"is_pkgbuild"`
}

// Vault is a concurrency-safe quarantine store rooted at a directory.
type Vault struct {
	dir            string
	lockFile       *os.File
	mu             sync.Mutex
	maxVaultSizeMB int64
	retentionDays  int
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

	return &Vault{dir: dir, lockFile: lockFile}, nil
}

// SetLimits configures the artifact size cap and retention period. Nonpositive
// values disable the corresponding limit.
func (v *Vault) SetLimits(maxVaultSizeMB int64, retentionDays int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.maxVaultSizeMB = maxVaultSizeMB
	v.retentionDays = retentionDays
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

// QuarantineFile moves srcPath into the vault, neutralizes its permissions (0000), and
// writes a metadata sidecar (0600). For PKGBUILD sources a blocking stub replaces the original.
func (v *Vault) QuarantineFile(srcPath string, score int, triggers []string, categories []string, dampeners []string) (*ItemMetadata, error) {
	cleanSrc := filepath.Clean(srcPath)

	sf, err := fsutil.OpenSafe(cleanSrc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSource, err)
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, sf.File); err != nil {
		_ = sf.Close()
		return nil, fmt.Errorf("hash source: %w", err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	modTime := time.Now().UTC()
	if fi, statErr := sf.File.Stat(); statErr == nil {
		modTime = fi.ModTime()
	}

	dev, ino := sf.Dev, sf.Ino
	size, mode := sf.Size, sf.Mode
	uid, gid := sf.UID, sf.GID
	_ = sf.Close()

	artifactPath := v.artifactPath(hash)
	meta := &ItemMetadata{
		ID:               hash,
		SHA256:           hash,
		OriginalPath:     cleanSrc,
		OriginalMode:     mode,
		UID:              uid,
		GID:              gid,
		ModTime:          modTime,
		QuarantinedAt:    time.Now().UTC(),
		Score:            score,
		Triggers:         nonNilSlice(triggers),
		CategoriesHit:    nonNilSlice(categories),
		DampenersApplied: nonNilSlice(dampeners),
		Size:             size,
		IsPKGBUILD:       isPKGBUILD(cleanSrc),
	}

	err = v.withLock(func() error {
		if err := v.checkSizeCap(hash, size); err != nil {
			return err
		}
		if err := moveFile(cleanSrc, dev, ino, artifactPath, v.dir); err != nil {
			return fmt.Errorf("move to vault: %w", err)
		}

		if err := neutralizePerms(artifactPath); err != nil {
			return fmt.Errorf("neutralize artifact (file preserved at %s): %w", artifactPath, err)
		}

		if meta.IsPKGBUILD {
			if err := writePKGBUILDStub(cleanSrc); err != nil {
				return fmt.Errorf("write PKGBUILD stub (file preserved at %s): %w", artifactPath, err)
			}
		}

		if err := v.writeMeta(meta); err != nil {
			return fmt.Errorf("write meta (file preserved at %s): %w", artifactPath, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return meta, nil
}

// checkSizeCap counts artifacts (including orphaned ones) before moving the source.
// Sidecars and the lock file are not quarantined payload bytes.
func (v *Vault) checkSizeCap(id string, size int64) error {
	if v.maxVaultSizeMB <= 0 || v.maxVaultSizeMB > math.MaxInt64/(1024*1024) {
		return nil
	}
	maxBytes := v.maxVaultSizeMB * 1024 * 1024
	entries, err := os.ReadDir(v.dir)
	if err != nil {
		return fmt.Errorf("read vault dir: %w", err)
	}
	var used int64
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != 64 || name == id {
			continue // a matching hash replaces its existing artifact
		}
		if _, err := hex.DecodeString(name); err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat vault artifact %s: %w", name, err)
		}
		if info.Mode().IsRegular() {
			if info.Size() > maxBytes-used {
				return fmt.Errorf("vault size cap exceeded (%d MB)", v.maxVaultSizeMB)
			}
			used += info.Size()
		}
	}
	if size > maxBytes-used {
		return fmt.Errorf("vault size cap exceeded (%d MB)", v.maxVaultSizeMB)
	}
	return nil
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
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), metaSuffix) {
				continue
			}
			id := strings.TrimSuffix(entry.Name(), metaSuffix)
			meta, err := v.readMeta(entry.Name())
			if err != nil {
				return fmt.Errorf("read vault metadata %s: %w", id, err)
			}
			if meta.ID != id || !meta.QuarantinedAt.Before(cutoff) {
				continue
			}
			if err := os.Remove(v.artifactPath(id)); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove expired artifact %s: %w", id, err)
			}
			if err := os.Remove(v.metaPath(id)); err != nil {
				return fmt.Errorf("remove expired metadata %s: %w", id, err)
			}
		}
		return nil
	})
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
		sort.Slice(items, func(i, j int) bool {
			if items[i].QuarantinedAt.Equal(items[j].QuarantinedAt) {
				return items[i].ID < items[j].ID
			}
			return items[i].QuarantinedAt.After(items[j].QuarantinedAt)
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

// Restore safely restores an item to customDestPath, or its OriginalPath when empty.
func (v *Vault) Restore(id string, customDestPath string) error {
	return v.withLock(func() error {
		meta, err := v.readMetaByID(id)
		if err != nil {
			return err
		}

		dest := meta.OriginalPath
		if strings.TrimSpace(customDestPath) != "" {
			dest = filepath.Clean(customDestPath)
		}

		artifactPath := v.artifactPath(meta.ID)
		if _, err := os.Stat(artifactPath); err != nil {
			return fmt.Errorf("%w: artifact missing: %s", ErrItemNotFound, artifactPath)
		}

		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return fmt.Errorf("create dest dir: %w", err)
		}

		// Reject special files before reading a PKGBUILD stub or creating the destination.
		if fi, err := os.Lstat(dest); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: destination is a symlink: %s", fsutil.ErrSymlinkNotAllowed, dest)
			}
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("%w: destination: %s", fsutil.ErrNotRegularFile, dest)
			}
			if meta.IsPKGBUILD && fi.Size() == int64(len(stubBody)) {
				data, rErr := os.ReadFile(dest)
				if rErr == nil && string(data) == stubBody {
					if err := os.Remove(dest); err != nil {
						return fmt.Errorf("remove PKGBUILD stub: %w", err)
					}
				}
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect destination: %w", err)
		}

		dst, err := fsutil.OpenSafeCreate(dest, meta.OriginalMode)
		if err != nil {
			return fmt.Errorf("create destination: %w", err)
		}

		// Temporarily elevate artifact permissions in vault (0400)
		if err := os.Chmod(artifactPath, 0400); err != nil {
			_ = dst.Close()
			_ = os.Remove(dest)
			return fmt.Errorf("elevate artifact perms: %w", err)
		}

		restoreSuccess := false
		defer func() {
			if !restoreSuccess {
				_ = neutralizePerms(artifactPath)
				_ = dst.Close()
				_ = os.Remove(dest)
			}
		}()

		src, err := fsutil.OpenSafe(artifactPath)
		if err != nil {
			return fmt.Errorf("open artifact: %w", err)
		}
		if _, err := io.Copy(dst, src.File); err != nil {
			_ = src.Close()
			return fmt.Errorf("copy artifact: %w", err)
		}
		if err := src.Close(); err != nil {
			return fmt.Errorf("close artifact: %w", err)
		}
		if err := dst.Sync(); err != nil {
			return fmt.Errorf("sync destination: %w", err)
		}
		if err := dst.Close(); err != nil {
			return fmt.Errorf("close destination: %w", err)
		}

		if err := os.Chmod(dest, meta.OriginalMode); err != nil {
			return fmt.Errorf("restore mode: %w", err)
		}
		if err := os.Chtimes(dest, meta.ModTime, meta.ModTime); err != nil {
			return fmt.Errorf("restore modtime: %w", err)
		}

		restoreSuccess = true

		if err := os.Remove(artifactPath); err != nil {
			return fmt.Errorf("remove artifact: %w", err)
		}
		if err := os.Remove(v.metaPath(meta.ID)); err != nil {
			return fmt.Errorf("remove meta: %w", err)
		}
		return nil
	})
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
		return nil
	})
}

func (v *Vault) metaPath(id string) string {
	return filepath.Join(v.dir, id+metaSuffix)
}

func (v *Vault) writeMeta(meta *ItemMetadata) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(v.dir, ".tmp-meta-*")
	if err != nil {
		return fmt.Errorf("create temp meta: %w", err)
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, v.metaPath(meta.ID))
}

func (v *Vault) readMeta(fileName string) (*ItemMetadata, error) {
	data, err := os.ReadFile(filepath.Join(v.dir, fileName))
	if err != nil {
		return nil, err
	}
	var meta ItemMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func (v *Vault) readMetaByID(id string) (*ItemMetadata, error) {
	meta, err := v.readMeta(id + metaSuffix)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrItemNotFound
		}
		return nil, err
	}
	return meta, nil
}

// artifactPath is the vault location of the neutralized artifact for id.
func (v *Vault) artifactPath(id string) string {
	return filepath.Join(v.dir, id)
}

func nonNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	res := make([]string, len(s))
	copy(res, s)
	return res
}

// isPKGBUILD reports whether path is an Arch build manifest requiring stub neutralization.
func isPKGBUILD(path string) bool {
	return filepath.Base(path) == "PKGBUILD"
}

// stubBody is the blocking decoy written over a quarantined PKGBUILD.
const stubBody = `# Quarantined by quarantined daemon
echo "ERROR: PKGBUILD blocked due to high-confidence security threat (Score >= 85)" >&2
exit 1
`

func writePKGBUILDStub(path string) error {
	tmpPath := path + ".quarantined.tmp"
	if err := os.WriteFile(tmpPath, []byte(stubBody), 0755); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
