//go:build !unix

package quarantine

import (
	"fmt"
	"os"
	"path/filepath"
)

// checkRestoreParent checks destination parent directory on non-POSIX systems.
func checkRestoreParent(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("untrusted restore parent: %s", abs)
	}
	return nil
}
