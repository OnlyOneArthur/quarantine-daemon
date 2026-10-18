package quarantine

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
)

// Restore safely restores an item to customDestPath, or its OriginalPath when empty.
func (v *Vault) Restore(id string, customDestPath string) error {
	if !isHex64(id) {
		return ErrItemNotFound
	}
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

		if err := checkRestoreParent(filepath.Dir(dest)); err != nil {
			return fmt.Errorf("restore destination parent: %w", err)
		}

		stub, err := checkRestoreDestination(dest, meta)
		if err != nil {
			return err
		}

		stage, dst, err := stageRestoreArtifact(artifactPath, dest, meta)
		if err != nil {
			return err
		}
		defer func() { _ = dst.Close(); _ = os.Remove(stage) }()

		if err := publishRestoredFile(stage, dest, stub, dst, meta); err != nil {
			return err
		}

		return v.cleanupRestoredVaultItem(artifactPath, meta.ID)
	})
}

func checkRestoreDestination(dest string, meta *ItemMetadata) (os.FileInfo, error) {
	fi, err := os.Lstat(dest)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("inspect destination: %w", err)
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: destination is a symlink: %s", fsutil.ErrSymlinkNotAllowed, dest)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: destination: %s", fsutil.ErrNotRegularFile, dest)
	}
	if !meta.IsPKGBUILD || dest != meta.OriginalPath || fi.Size() != int64(len(stubBody)) {
		return nil, fmt.Errorf("destination already exists: %s", dest)
	}
	sf, err := fsutil.OpenSafe(dest)
	if err != nil {
		return nil, fmt.Errorf("inspect PKGBUILD stub: %w", err)
	}
	data, readErr := io.ReadAll(sf.File)
	closeErr := sf.Close()
	if readErr != nil || closeErr != nil || string(data) != stubBody {
		return nil, fmt.Errorf("destination is not the original PKGBUILD stub: %s", dest)
	}
	return fi, nil
}

func stageRestoreArtifact(artifactPath, dest string, meta *ItemMetadata) (string, *os.File, error) {
	dst, err := os.CreateTemp(filepath.Dir(dest), ".quarantine-restore-*")
	if err != nil {
		return "", nil, fmt.Errorf("stage destination: %w", err)
	}
	stage := dst.Name()

	if err := os.Chmod(artifactPath, 0400); err != nil {
		_ = dst.Close()
		_ = os.Remove(stage)
		return "", nil, fmt.Errorf("elevate artifact perms: %w", err)
	}
	defer func() { _ = neutralizePerms(artifactPath) }()

	if err := copyArtifactContent(artifactPath, dst, stage, meta); err != nil {
		_ = dst.Close()
		_ = os.Remove(stage)
		return "", nil, err
	}
	return stage, dst, nil
}

func copyArtifactContent(artifactPath string, dst *os.File, stage string, meta *ItemMetadata) error {
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
	return nil
}

func publishRestoredFile(stage, dest string, stub os.FileInfo, dst *os.File, meta *ItemMetadata) error {
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

	cleanupOnErr := func() {
		if stub == nil {
			_ = os.Remove(dest)
		}
	}

	if err := dst.Chmod(meta.OriginalMode); err != nil {
		cleanupOnErr()
		return fmt.Errorf("restore mode: %w", err)
	}
	if err := dst.Sync(); err != nil {
		cleanupOnErr()
		return fmt.Errorf("sync published destination: %w", err)
	}
	if err := dst.Close(); err != nil {
		cleanupOnErr()
		return fmt.Errorf("close destination: %w", err)
	}
	return nil
}

func (v *Vault) cleanupRestoredVaultItem(artifactPath, id string) error {
	if err := neutralizePerms(artifactPath); err != nil {
		return fmt.Errorf("neutralize restored artifact: %w", err)
	}
	if err := os.Remove(artifactPath); err != nil {
		return fmt.Errorf("remove artifact: %w", err)
	}
	if err := os.Remove(v.metaPath(id)); err != nil {
		return fmt.Errorf("remove meta: %w", err)
	}
	v.usedBytes = -1
	return nil
}
