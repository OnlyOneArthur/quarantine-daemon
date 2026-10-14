package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
)

type sourceFileInfo struct {
	cleanSrc string
	hash     string
	modTime  time.Time
	dev      uint64
	ino      uint64
	size     int64
	mode     os.FileMode
	uid      int
	gid      int
}

func readSourceInfo(srcPath string) (*sourceFileInfo, error) {
	cleanSrc := filepath.Clean(srcPath)
	sf, err := fsutil.OpenSafe(cleanSrc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSource, err)
	}
	defer func() { _ = sf.Close() }()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, sf.File); err != nil {
		return nil, fmt.Errorf("hash source: %w", err)
	}

	modTime := sf.ModTime
	if modTime.IsZero() {
		modTime = time.Now().UTC()
	}

	return &sourceFileInfo{
		cleanSrc: cleanSrc,
		hash:     hex.EncodeToString(hasher.Sum(nil)),
		modTime:  modTime,
		dev:      sf.Dev,
		ino:      sf.Ino,
		size:     sf.Size,
		mode:     sf.Mode,
		uid:      sf.UID,
		gid:      sf.GID,
	}, nil
}

// QuarantineFile moves srcPath into the vault, neutralizes its permissions (0000), and
// writes a metadata sidecar (0600). For PKGBUILD sources a blocking stub replaces the original.
func (v *Vault) QuarantineFile(srcPath string, score int, triggers []string, categories []string, dampeners []string) (*ItemMetadata, error) {
	src, err := readSourceInfo(srcPath)
	if err != nil {
		return nil, err
	}

	meta := &ItemMetadata{
		ID:               src.hash,
		SHA256:           src.hash,
		OriginalPath:     src.cleanSrc,
		OriginalMode:     src.mode,
		UID:              src.uid,
		GID:              src.gid,
		ModTime:          src.modTime,
		QuarantinedAt:    time.Now().UTC(),
		Score:            score,
		Triggers:         nonNilSlice(triggers),
		CategoriesHit:    nonNilSlice(categories),
		DampenersApplied: nonNilSlice(dampeners),
		Size:             src.size,
		IsPKGBUILD:       isPKGBUILD(src.cleanSrc),
	}

	if err := v.withLock(func() error {
		return v.commitQuarantine(src, meta)
	}); err != nil {
		return nil, err
	}

	return meta, nil
}

func (v *Vault) commitQuarantine(src *sourceFileInfo, meta *ItemMetadata) error {
	artifactPath := v.artifactPath(src.hash)
	if _, err := os.Lstat(artifactPath); err == nil {
		return ErrAlreadyQuarantined
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect existing artifact: %w", err)
	}
	if _, err := os.Lstat(v.metaPath(src.hash)); err == nil {
		return ErrAlreadyQuarantined
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect existing metadata: %w", err)
	}
	if err := v.checkSizeCap(src.size); err != nil {
		return err
	}
	if err := moveFile(src.cleanSrc, src.dev, src.ino, artifactPath, v.dir); err != nil {
		return fmt.Errorf("move to vault: %w", err)
	}

	if err := v.finalizeQuarantine(src, meta, artifactPath); err != nil {
		if rbErr := rollbackArtifact(artifactPath, src.cleanSrc, meta.OriginalMode); rbErr != nil {
			return fmt.Errorf("%w (rollback to %s failed: %w; artifact left at %s)", err, src.cleanSrc, rbErr, artifactPath)
		}
		return err
	}

	if v.usedBytes >= 0 {
		v.usedBytes += src.size
	}
	return nil
}

func (v *Vault) finalizeQuarantine(src *sourceFileInfo, meta *ItemMetadata, artifactPath string) error {
	if err := neutralizePerms(artifactPath); err != nil {
		return fmt.Errorf("neutralize artifact: %w", err)
	}
	if meta.IsPKGBUILD {
		if err := writePKGBUILDStub(src.cleanSrc); err != nil {
			return fmt.Errorf("write PKGBUILD stub: %w", err)
		}
	}
	if err := v.writeMeta(meta); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}
	return nil
}
