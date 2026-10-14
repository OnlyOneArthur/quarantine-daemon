package binary

import (
	"bytes"
	"debug/elf"
	"errors"
	"slices"
	"strings"
)

// ErrNotELF is returned when data does not contain a valid ELF image.
var (
	ErrNotELF       = errors.New("not an ELF binary")
	ErrELFTruncated = errors.New("ELF binary truncated")
)

// ELFAnalysis holds all findings from static analysis of an ELF binary.
type ELFAnalysis struct {
	CorruptedSectionHeaders bool
	HasValidPTLoad          bool
	HasExecutableStack      bool
	HasRWXSegments          bool
	HasUPX                  bool
	TextEntropy             float64
	TextSectionFound        bool
	SuspiciousCapabilities  []string
	SuspiciousIOCs          []string
	IsGoBinary              bool
	IsRustBinary            bool
}

// AnalyzeELF safely parses and inspects an ELF binary using debug/elf
// and raw header parsing for corrupted section headers.
func AnalyzeELF(data []byte) (*ELFAnalysis, error) {
	if len(data) < 4 || !bytes.Equal(data[:4], []byte("\x7fELF")) {
		return nil, ErrNotELF
	}

	analysis := &ELFAnalysis{}

	// 1. Try standard parsing via debug/elf
	f, err := elf.NewFile(bytes.NewReader(data))
	if err == nil {
		defer func() { _ = f.Close() }()
		analyzeWithDebugELF(f, data, analysis)
	}

	// 2. Fallback check for raw headers if debug/elf did not find PT_LOAD
	if !analysis.HasValidPTLoad {
		_ = parseRawELFHeaders(data, analysis)
	}

	// 3. Fallback entropy calculation if .text section was not found
	if !analysis.TextSectionFound {
		analysis.TextEntropy = CalculateEntropy(data)
	}

	// 4. Raw byte inspection for UPX, compiler signatures, capabilities, and IOCs
	inspectRawBytes(data, analysis)

	return analysis, nil
}

func analyzeWithDebugELF(f *elf.File, data []byte, analysis *ELFAnalysis) {
	inspectELFProgramHeaders(f.Progs, analysis)
	inspectELFTextSection(f.Section(".text"), data, analysis)
	inspectELFSections(f.Sections, analysis)
	inspectELFSymbols(f, analysis)
}

func inspectELFProgramHeaders(progs []*elf.Prog, analysis *ELFAnalysis) {
	for _, prog := range progs {
		switch prog.Type {
		case elf.PT_LOAD:
			analysis.HasValidPTLoad = true

			// Check for RWX segment
			if (prog.Flags&(elf.PF_R|elf.PF_W|elf.PF_X)) == (elf.PF_R|elf.PF_W|elf.PF_X) ||
				(prog.Flags&(elf.PF_W|elf.PF_X)) == (elf.PF_W|elf.PF_X) {
				analysis.HasRWXSegments = true
			}

		case elf.PT_GNU_STACK:
			if prog.Flags&elf.PF_X != 0 {
				analysis.HasExecutableStack = true
			}
		}
	}
}

func inspectELFTextSection(sec *elf.Section, data []byte, analysis *ELFAnalysis) {
	// Calculate entropy strictly on .text section if present. Slice the already
	// resident data buffer instead of copying the section through io.ReadAll,
	// which would allocate up to 64MiB on every scan. Compressed sections are
	// skipped because their on-disk bytes are not the real code.
	if sec == nil || sec.Size == 0 || sec.Flags&elf.SHF_COMPRESSED != 0 {
		return
	}
	const maxEntropyBytes = 64 * 1024 * 1024
	start, end := sec.Offset, sec.Offset+sec.Size
	if sec.Size > maxEntropyBytes {
		end = start + maxEntropyBytes
	}
	if start < uint64(len(data)) && end >= start && end <= uint64(len(data)) {
		analysis.TextSectionFound = true
		if end > start {
			analysis.TextEntropy = CalculateEntropy(data[start:end])
		}
	}
}

func inspectELFSections(sections []*elf.Section, analysis *ELFAnalysis) {
	for _, s := range sections {
		if strings.HasPrefix(s.Name, "UPX") || strings.HasPrefix(s.Name, ".upx") {
			analysis.HasUPX = true
		}
		if s.Name == ".gopclntab" || s.Name == ".gosymtab" || s.Name == ".note.go.buildid" {
			analysis.IsGoBinary = true
		}
		if s.Name == ".rustc" {
			analysis.IsRustBinary = true
		}
	}
}

func inspectELFSymbols(f *elf.File, analysis *ELFAnalysis) {
	if symbols, err := f.Symbols(); err == nil {
		for _, sym := range symbols {
			checkSymbol(sym.Name, analysis)
		}
	}

	if dynsyms, err := f.DynamicSymbols(); err == nil {
		for _, sym := range dynsyms {
			checkSymbol(sym.Name, analysis)
		}
	}

	if imported, err := f.ImportedSymbols(); err == nil {
		for _, sym := range imported {
			checkSymbol(sym.Name, analysis)
		}
	}
}

func checkSymbol(name string, analysis *ELFAnalysis) {
	if strings.Contains(name, "runtime.main") || strings.Contains(name, "runtime.goexit") {
		analysis.IsGoBinary = true
	}
	if strings.Contains(name, "rust_panic") || strings.Contains(name, "__rust_alloc") || strings.Contains(name, "core::panicking") {
		analysis.IsRustBinary = true
	}

	checkCapabilityString(name, analysis)
}

func checkCapabilityString(str string, analysis *ELFAnalysis) {
	for _, t := range capStrings {
		if strings.Contains(str, t) {
			addCapability(analysis, t)
		}
	}
}

func addCapability(analysis *ELFAnalysis, capability string) {
	if slices.Contains(analysis.SuspiciousCapabilities, capability) {
		return
	}
	analysis.SuspiciousCapabilities = append(analysis.SuspiciousCapabilities, capability)
}

func addIOC(analysis *ELFAnalysis, ioc string) {
	if slices.Contains(analysis.SuspiciousIOCs, ioc) {
		return
	}
	analysis.SuspiciousIOCs = append(analysis.SuspiciousIOCs, ioc)
}

func inspectRawBytes(data []byte, analysis *ELFAnalysis) {
	// UPX marker
	if bytes.Contains(data, []byte("UPX!")) {
		analysis.HasUPX = true
	}

	// Go runtime signature
	if bytes.Contains(data, []byte("runtime.main")) ||
		bytes.Contains(data, []byte("Go build ID:")) ||
		bytes.Contains(data, []byte("runtime.goexit")) {
		analysis.IsGoBinary = true
	}

	// Rust runtime signature
	if bytes.Contains(data, []byte("rust_panic")) ||
		bytes.Contains(data, []byte("__rust_alloc")) ||
		bytes.Contains(data, []byte("core::panicking")) ||
		bytes.Contains(data, []byte("std::rt::lang_start")) {
		analysis.IsRustBinary = true
	}

	// High-risk process injection & memory execution primitives in raw strings
	for i, c := range capBytes {
		if bytes.Contains(data, c) {
			addCapability(analysis, capStrings[i])
		}
	}

	for _, ioc := range scanRawIOCs(data) {
		addIOC(analysis, ioc)
	}
}
