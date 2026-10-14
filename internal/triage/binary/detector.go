package binary

import (
	"bytes"
	"encoding/binary"
)

// Format represents the detected binary or script format.
type Format string

// Format values returned by DetectFormat.
const (
	// FormatUnknown means the magic bytes matched no known format.
	FormatUnknown Format = "unknown"
	FormatELF     Format = "elf"
	FormatPE      Format = "pe"
	FormatMachO   Format = "macho"
	FormatScript  Format = "script"
)

// DetectFormat identifies the file format based on magic bytes.
func DetectFormat(data []byte) Format {
	if len(data) < 2 {
		return FormatUnknown
	}

	// Shebang: #!
	if data[0] == '#' && data[1] == '!' {
		return FormatScript
	}

	// ELF: \x7fELF
	if len(data) >= 4 && bytes.Equal(data[:4], []byte("\x7fELF")) {
		return FormatELF
	}

	// Mach-O magics (32-bit, 64-bit, FAT / Universal)
	if len(data) >= 4 {
		magic := binary.BigEndian.Uint32(data[:4])
		switch magic {
		case 0xFEEDFACE, 0xCEFAEDFE, // Mach-O 32-bit (BE, LE)
			0xFEEDFACF, 0xCFFAEDFE: // Mach-O 64-bit (BE, LE)
			return FormatMachO
		case 0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA:
			// Java classes share CAFEBABE; require a complete FAT arch table.
			if len(data) < 8 {
				return FormatUnknown
			}
			var narch uint64
			if magic == 0xBEBAFECA || magic == 0xBFBAFECA {
				narch = uint64(binary.LittleEndian.Uint32(data[4:8]))
			} else {
				narch = uint64(binary.BigEndian.Uint32(data[4:8]))
			}
			archSize := uint64(20)
			if magic == 0xCAFEBABF || magic == 0xBFBAFECA {
				archSize = 32
			}
			if narch > 0 && narch <= (uint64(len(data))-8)/archSize {
				return FormatMachO
			}
		}
	}

	// PE: MZ header
	if data[0] == 'M' && data[1] == 'Z' {
		if len(data) >= 0x40 {
			peOffset := binary.LittleEndian.Uint32(data[0x3C:0x40])
			// Compare in uint64: on 32-bit platforms int(peOffset) would overflow
			// for offsets above 0x7FFFFFFB and could panic on the slice below.
			if uint64(peOffset)+4 <= uint64(len(data)) {
				if bytes.Equal(data[peOffset:peOffset+4], []byte("PE\x00\x00")) {
					return FormatPE
				}
			} else if peOffset > 0 && peOffset < 10*1024*1024 {
				// Truncated preview with plausible PE offset
				return FormatPE
			}
		} else {
			// Short slice with MZ prefix
			return FormatPE
		}
	}

	return FormatUnknown
}
