package binary

import (
	"bytes"
	"debug/macho"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/triage/entropy"
)

// MachOAnalysis holds all findings from static analysis of a Mach-O binary.
type MachOAnalysis struct {
	TextEntropy            float64
	HasRWXSegments         bool
	HasUPX                 bool
	SuspiciousCapabilities []string
	SuspiciousIOCs         []string
}

// AnalyzeMachO analyzes a macOS Mach-O binary using debug/macho.
func AnalyzeMachO(data []byte) (*MachOAnalysis, error) {
	analysis := &MachOAnalysis{}

	if bytes.Contains(data, []byte("UPX!")) {
		analysis.HasUPX = true
	}

	f, err := macho.NewFile(bytes.NewReader(data))
	if err == nil {
		defer func() { _ = f.Close() }()

		for _, load := range f.Loads {
			if seg, ok := load.(*macho.Segment); ok {
				// Prot: 1=R, 2=W, 4=X -> 7=RWX. Maxprot is only the ceiling the
				// kernel will allow, not the actual mapping; use current protection.
				if seg.Prot&7 == 7 {
					analysis.HasRWXSegments = true
				}
				if seg.Name == "__TEXT" {
					segData, err := seg.Data()
					if err == nil && len(segData) > 0 {
						analysis.TextEntropy = entropy.Calculate(segData)
					}
				}
			}
		}
	} else {
		// Fallback for FAT binaries or truncated headers
		analysis.TextEntropy = entropy.Calculate(data)
	}

	for _, capability := range capStrings {
		if bytes.Contains(data, []byte(capability)) {
			analysis.SuspiciousCapabilities = append(analysis.SuspiciousCapabilities, capability)
		}
	}
	analysis.SuspiciousIOCs = scanRawIOCs(data)

	return analysis, nil
}
