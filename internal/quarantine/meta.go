package quarantine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"time"
)

const metaSuffix = ".meta.json"

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

func (v *Vault) metaPath(id string) string {
	return filepath.Join(v.dir, id+metaSuffix)
}

// artifactPath is the vault location of the neutralized artifact for id.
func (v *Vault) artifactPath(id string) string {
	return filepath.Join(v.dir, id)
}

func (v *Vault) writeMeta(meta *ItemMetadata) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(v.dir, ".tmp-meta-*", v.metaPath(meta.ID), data, 0600)
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

func nonNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
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

func writeAtomic(dir, pattern, dest string, data []byte, perm os.FileMode) (retErr error) {
	tmpFile, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if retErr != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, dest)
}

func writePKGBUILDStub(path string) error {
	return writeAtomic(filepath.Dir(path), ".pkgbuild-stub-*", path, []byte(stubBody), 0755)
}

// rollbackArtifact moves a vault artifact back to dest after a post-move failure,
// restoring the original permission bits so the file is left as it was found.
func rollbackArtifact(artifactPath, dest string, mode os.FileMode) error {
	os.Chmod(artifactPath, mode.Perm())
	return os.Rename(artifactPath, dest)
}
