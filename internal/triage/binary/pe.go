package binary

import (
	"bytes"
	"debug/pe"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/triage/entropy"
)

type PEAnalysis struct {
	TextEntropy            float64
	HasRWXSections         bool
	HasUPX                 bool
	SuspiciousCapabilities []string
	SuspiciousIOCs         []string
}

// AnalyzePE analyzes a Windows PE binary using Go standard library debug/pe.
func AnalyzePE(data []byte) (*PEAnalysis, error) {
	analysis := &PEAnalysis{}

	// Check UPX marker
	if bytes.Contains(data, []byte("UPX!")) {
		analysis.HasUPX = true
	}

	f, err := pe.NewFile(bytes.NewReader(data))
	if err == nil {
		defer f.Close()

		for _, sec := range f.Sections {
			// Check for RWX sections: IMAGE_SCN_MEM_EXECUTE (0x20000000) & IMAGE_SCN_MEM_WRITE (0x80000000)
			const (
				IMAGE_SCN_MEM_EXECUTE = 0x20000000
				IMAGE_SCN_MEM_WRITE   = 0x80000000
			)
			if sec.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 && sec.Characteristics&IMAGE_SCN_MEM_WRITE != 0 {
				analysis.HasRWXSections = true
			}

			if sec.Name == ".text" || sec.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 {
				secData, err := sec.Data()
				if err == nil && len(secData) > 0 {
					analysis.TextEntropy = entropy.Calculate(secData)
				}
			}
		}

		// Check imported symbols
		symbols, err := f.ImportedSymbols()
		if err == nil {
			for _, sym := range symbols {
				switch sym {
				case "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC":
					analysis.SuspiciousCapabilities = append(analysis.SuspiciousCapabilities, sym)
				}
			}
		}
	} else {
		// Fallback for truncated/corrupted PE headers
		analysis.TextEntropy = entropy.Calculate(data)
	}

	for _, capability := range capStrings {
		if bytes.Contains(data, []byte(capability)) {
			present := false
			for _, existing := range analysis.SuspiciousCapabilities {
				if existing == capability {
					present = true
					break
				}
			}
			if !present {
				analysis.SuspiciousCapabilities = append(analysis.SuspiciousCapabilities, capability)
			}
		}
	}
	analysis.SuspiciousIOCs = scanRawIOCs(data)

	return analysis, nil
}
