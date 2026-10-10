package binary

import (
	"bytes"
	"debug/macho"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/triage/entropy"
)

type MachOAnalysis struct {
	TextEntropy    float64
	HasRWXSegments bool
	HasUPX         bool
}

// AnalyzeMachO analyzes a macOS Mach-O binary using debug/macho.
func AnalyzeMachO(data []byte) (*MachOAnalysis, error) {
	analysis := &MachOAnalysis{}

	if bytes.Contains(data, []byte("UPX!")) {
		analysis.HasUPX = true
	}

	f, err := macho.NewFile(bytes.NewReader(data))
	if err == nil {
		defer f.Close()

		for _, load := range f.Loads {
			if seg, ok := load.(*macho.Segment); ok {
				// Prot: 1=R, 2=W, 4=X -> 7=RWX
				if seg.Maxprot&7 == 7 || seg.Prot&7 == 7 {
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

	return analysis, nil
}
