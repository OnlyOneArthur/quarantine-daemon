// Package quarantine manages the content-addressed vault: quarantining files,
// listing/inspecting them, restoring originals and sweeping expired entries.
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

// ErrItemNotFound is returned when a vault id has no metadata sidecar.
var (
	ErrItemNotFound       = errors.New("quarantine item not found")
	ErrInvalidSource      = errors.New("invalid source file")
	ErrAlreadyQuarantined = errors.New("content already quarantined")
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

// QuarantineFile moves srcPath into the vault, neutralizes its permissions (0000), and
// writes a metadata sidecar (0600). For PKGBUILD sources a blocking stub replaces the original.
func (v *Vault) QuarantineFile(srcPath string, score int, triggers []string, categories []string, dampeners []string) (*ItemMetadata, error) {
	cleanSrc := filepath.Clean(srcPath)

	sf, err := fsutil.OpenSafe(cleanSrc)
	if err != nil {
		// Wrap with ErrInvalidSource while preserving the underlying cause so
		// callers can still errors.Is/As against it.
		return nil, fmt.Errorf("%w: %w", ErrInvalidSource, err)
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
		if _, err := os.Lstat(artifactPath); err == nil {
			return ErrAlreadyQuarantined
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect existing artifact: %w", err)
		}
		if _, err := os.Lstat(v.metaPath(hash)); err == nil {
			return ErrAlreadyQuarantined
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect existing metadata: %w", err)
		}
		if err := v.checkSizeCap(size); err != nil {
			return err
		}
		if err := moveFile(cleanSrc, dev, ino, artifactPath, v.dir); err != nil {
			return fmt.Errorf("move to vault: %w", err)
		}

		// Any failure past the move would leave the artifact in the vault with no
		// metadata sidecar: invisible to List/Inspect/Restore/Purge and blocking a
		// later quarantine of the same content (ErrAlreadyQuarantined). Roll the
		// artifact back to the source path so the file stays where it was.
		rollback := func(err error) error {
			if rbErr := rollbackArtifact(artifactPath, cleanSrc, meta.OriginalMode); rbErr != nil {
				return fmt.Errorf("%w (rollback to %s failed: %w; artifact left at %s)", err, cleanSrc, rbErr, artifactPath)
			}
			return err
		}

		if err := neutralizePerms(artifactPath); err != nil {
			return rollback(fmt.Errorf("neutralize artifact: %w", err))
		}

		if meta.IsPKGBUILD {
			if err := writePKGBUILDStub(cleanSrc); err != nil {
				return rollback(fmt.Errorf("write PKGBUILD stub: %w", err))
			}
		}

		if err := v.writeMeta(meta); err != nil {
			return rollback(fmt.Errorf("write meta: %w", err))
		}
		// Keep the cached usage in step with the artifact this quarantine adds.
		// checkSizeCap rebuilt the total (including this file) only when the cache
		// was invalid, so guard against double counting.
		if v.usedBytes >= 0 {
			v.usedBytes += size
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
				return fmt.Errorf("remove expired artifact %s: %w", id, err)
			}
			if err := os.Remove(v.metaPath(id)); err != nil {
				return fmt.Errorf("remove expired metadata %s: %w", id, err)
			}
		}
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
		// Artifacts were removed: drop the cached total so the next quarantine
		// rebuilds it instead of trusting a now-stale figure.
		v.usedBytes = -1
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

		// Refuse untrusted or missing parent directories. In a trusted directory,
		// other users cannot replace a stage file or destination between checks.
		if err := checkRestoreParent(filepath.Dir(dest)); err != nil {
			return fmt.Errorf("restore destination parent: %w", err)
		}

		var stub os.FileInfo
		if fi, err := os.Lstat(dest); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: destination is a symlink: %s", fsutil.ErrSymlinkNotAllowed, dest)
			}
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("%w: destination: %s", fsutil.ErrNotRegularFile, dest)
			}
			if !meta.IsPKGBUILD || dest != meta.OriginalPath || fi.Size() != int64(len(stubBody)) {
				return fmt.Errorf("destination already exists: %s", dest)
			}
			sf, err := fsutil.OpenSafe(dest)
			if err != nil {
				return fmt.Errorf("inspect PKGBUILD stub: %w", err)
			}
			data, readErr := io.ReadAll(sf.File)
			closeErr := sf.Close()
			if readErr != nil || closeErr != nil || string(data) != stubBody {
				return fmt.Errorf("destination is not the original PKGBUILD stub: %s", dest)
			}
			stub = fi
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect destination: %w", err)
		}

		dst, err := os.CreateTemp(filepath.Dir(dest), ".quarantine-restore-*")
		if err != nil {
			return fmt.Errorf("stage destination: %w", err)
		}
		stage := dst.Name()
		defer func() { _ = dst.Close(); _ = os.Remove(stage) }()

		// Temporarily elevate artifact permissions in vault (0400).
		if err := os.Chmod(artifactPath, 0400); err != nil {
			return fmt.Errorf("elevate artifact perms: %w", err)
		}
		defer func() { _ = neutralizePerms(artifactPath) }()

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
		if err := os.Chtimes(stage, meta.ModTime, meta.ModTime); err != nil {
			return fmt.Errorf("restore modtime: %w", err)
		}
		if err := dst.Sync(); err != nil {
			return fmt.Errorf("sync staged destination: %w", err)
		}

		if stub != nil {
			fi, err := os.Lstat(dest)
			if err != nil || !os.SameFile(stub, fi) {
				return fmt.Errorf("PKGBUILD stub changed before restore: %s", dest)
			}
			if err := os.Rename(stage, dest); err != nil {
				return fmt.Errorf("replace PKGBUILD stub: %w", err)
			}
		} else if err := os.Link(stage, dest); err != nil {
			return fmt.Errorf("publish destination: %w", err)
		}

		// Keep the stage private until publication: the original mode might
		// grant other users write access while the file is still being prepared.
		if err := dst.Chmod(meta.OriginalMode); err != nil {
			return fmt.Errorf("restore mode: %w", err)
		}
		if err := dst.Sync(); err != nil {
			return fmt.Errorf("sync published destination: %w", err)
		}
		if err := dst.Close(); err != nil {
			return fmt.Errorf("close destination: %w", err)
		}

		// Leave the original vault entry if removal fails after publication.
		if err := neutralizePerms(artifactPath); err != nil {
			return fmt.Errorf("neutralize restored artifact: %w", err)
		}
		if err := os.Remove(artifactPath); err != nil {
			return fmt.Errorf("remove artifact: %w", err)
		}
		if err := os.Remove(v.metaPath(meta.ID)); err != nil {
			return fmt.Errorf("remove meta: %w", err)
		}
		v.usedBytes = -1
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
		v.usedBytes = -1
		return nil
	})
}

func (v *Vault) metaPath(id string) string {
	return filepath.Join(v.dir, id+metaSuffix)
}

// rollbackArtifact moves a vault artifact back to dest after a post-move failure,
// restoring the original permission bits so the file is left as it was found.
func rollbackArtifact(artifactPath, dest string, mode os.FileMode) error {
	_ = os.Chmod(artifactPath, mode.Perm())
	return os.Rename(artifactPath, dest)
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
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pkgbuild-stub-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	if _, err := tmp.WriteString(stubBody); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
