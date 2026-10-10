package fsutil

import (
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	ErrNotRegularFile     = errors.New("not a regular file")
	ErrSymlinkNotAllowed  = errors.New("symlink not allowed")
	ErrExceedsMaxScanSize = errors.New("file exceeds maximum allowed scan size")
)

type SafeFile struct {
	File   *os.File
	Path   string
	Dev    uint64
	Ino    uint64
	Size   int64
	Blocks int64
	Mode   os.FileMode
	UID    int
	GID    int
}

func (sf *SafeFile) Close() error {
	if sf.File != nil {
		return sf.File.Close()
	}
	return nil
}

// IsSparse reports whether the file appears to be sparse (allocated blocks * 512 < logical size).
func (sf *SafeFile) IsSparse() bool {
	if sf.Size <= 4096 {
		return false
	}
	allocatedBytes := sf.Blocks * 512
	return allocatedBytes < sf.Size
}

// ReadBounded reads at most maxBytes from r. If r has more data than maxBytes,
// it returns ErrExceedsMaxScanSize along with data read up to maxBytes.
func ReadBounded(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("invalid maxBytes limit")
	}

	lr := io.LimitReader(r, maxBytes+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read bounded: %w", err)
	}

	if int64(len(buf)) > maxBytes {
		return buf[:maxBytes], ErrExceedsMaxScanSize
	}

	return buf, nil
}
