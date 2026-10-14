//go:build unix

package quarantine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// checkRestoreParent accepts only a non-symlink directory chain owned by root
// or the daemon. Group/other-writable directories are rejected except for
// root-owned sticky directories such as /tmp.
func checkRestoreParent(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	current := "/"
	parts := strings.FieldsFunc(abs, func(r rune) bool { return r == '/' })
	segments := make([]string, 0, len(parts)+1)
	segments = append(segments, "/")
	for _, p := range parts {
		current = filepath.Join(current, p)
		segments = append(segments, current)
	}

	for _, seg := range segments {
		fi, err := os.Lstat(seg)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", seg, err)
		}
		if err := checkDir(seg, fi); err != nil {
			return err
		}
	}
	return nil
}

func checkDir(path string, fi os.FileInfo) error {
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("untrusted restore parent: %s", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) {
		return fmt.Errorf("restore parent not owned by root or daemon: %s", path)
	}
	if fi.Mode().Perm()&0022 != 0 {
		// Only a root-owned sticky directory (e.g. /tmp) may be writable by
		// other users.
		if st.Uid != 0 || fi.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("restore parent is writable by other users: %s", path)
		}
	}
	return nil
}
