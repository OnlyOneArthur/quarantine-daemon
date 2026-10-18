package binary

import (
	"bytes"
	"debug/pe"
	"slices"
)

// PEAnalysis holds all findings from static analysis of a PE binary.
type PEAnalysis struct {
	TextEntropy            float64
	HasRWXSections         bool
	HasUPX                 bool
	SuspiciousCapabilities []string
	SuspiciousIOCs         []string
}

// AnalyzePE analyzes a Windows PE binary using Go standard library debug/pe.
func AnalyzePE(data []byte) (*PEAnalysis, error) {
	analysis := &PEAnalysis{
		HasUPX: bytes.Contains(data, []byte("UPX!")),
	}

	f, err := pe.NewFile(bytes.NewReader(data))
	if err == nil {
		defer func() {
			f.Close()
		}()
		inspectPESections(f.Sections, data, analysis)
		inspectPEImports(f, analysis)
	} else {
		// Fallback for truncated/corrupted PE headers
		analysis.TextEntropy = CalculateEntropy(data)
	}

	appendRawPECapabilities(data, analysis)
	analysis.SuspiciousIOCs = scanRawIOCs(data)

	return analysis, nil
}

func inspectPESections(sections []*pe.Section, data []byte, analysis *PEAnalysis) {
	const (
		imageScnMemExecute = 0x20000000
		imageScnMemWrite   = 0x80000000
		maxEntropyBytes    = 64 * 1024 * 1024
	)
	var fallbackEntropy float64
	var hasFallback, hasText bool

	for _, sec := range sections {
		if sec.Characteristics&imageScnMemExecute != 0 && sec.Characteristics&imageScnMemWrite != 0 {
			analysis.HasRWXSections = true
		}

		if sec.Name == ".text" || sec.Characteristics&imageScnMemExecute != 0 {
			if sec.Offset >= uint32(len(data)) {
				continue
			}
			secSize := min(sec.Size, uint32(maxEntropyBytes))
			end := sec.Offset + secSize
			if end < sec.Offset || end > uint32(len(data)) {
				end = uint32(len(data))
			}
			secData := data[sec.Offset:end]
			if len(secData) > 0 {
				if sec.Name == ".text" {
					analysis.TextEntropy = CalculateEntropy(secData)
					hasText = true
				} else if !hasFallback {
					fallbackEntropy = CalculateEntropy(secData)
					hasFallback = true
				}
			}
		}
	}
	if !hasText && hasFallback {
		analysis.TextEntropy = fallbackEntropy
	}
}

func inspectPEImports(f *pe.File, analysis *PEAnalysis) {
	symbols, err := f.ImportedSymbols()
	if err != nil {
		return
	}
	for _, sym := range symbols {
		switch sym {
		case "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC":
			analysis.SuspiciousCapabilities = append(analysis.SuspiciousCapabilities, sym)
		}
	}
}

func appendRawPECapabilities(data []byte, analysis *PEAnalysis) {
	for i, c := range capBytes {
		if bytes.Contains(data, c) {
			capability := capStrings[i]
			if !slices.Contains(analysis.SuspiciousCapabilities, capability) {
				analysis.SuspiciousCapabilities = append(analysis.SuspiciousCapabilities, capability)
			}
		}
	}
}
