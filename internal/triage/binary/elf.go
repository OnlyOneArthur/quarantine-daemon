package binary

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/triage/entropy"
)

var (
	ErrNotELF       = errors.New("not an ELF binary")
	ErrELFTruncated = errors.New("ELF binary truncated")

	ipv4Regex   = regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	iocPatterns = []string{"/dev/tcp/", "sh -i", "bash -i", "| sh", "| bash", "|/bin/sh", "|/bin/bash"}
	capStrings  = []string{"memfd_create", "process_vm_writev", "VirtualAllocEx", "ptrace"}
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
		defer f.Close()
		analyzeWithDebugELF(f, analysis)
	}

	// 2. Fallback check for raw headers if debug/elf did not find PT_LOAD
	if !analysis.HasValidPTLoad {
		_ = parseRawELFHeaders(data, analysis)
	}

	// 3. Fallback entropy calculation if .text section was not found
	if !analysis.TextSectionFound {
		analysis.TextEntropy = entropy.Calculate(data)
	}

	// 4. Raw byte inspection for UPX, compiler signatures, capabilities, and IOCs
	inspectRawBytes(data, analysis)

	return analysis, nil
}

func analyzeWithDebugELF(f *elf.File, analysis *ELFAnalysis) {
	for _, prog := range f.Progs {
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

	// Calculate entropy strictly on .text section if present
	sec := f.Section(".text")
	if sec != nil && sec.Size > 0 {
		analysis.TextSectionFound = true
		r := io.LimitReader(sec.Open(), 64*1024*1024)
		textData, err := io.ReadAll(r)
		if err == nil && len(textData) > 0 {
			analysis.TextEntropy = entropy.Calculate(textData)
		}
	}

	// Check section names for UPX
	for _, s := range f.Sections {
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

	// Inspect symbols
	symbols, err := f.Symbols()
	if err == nil {
		for _, sym := range symbols {
			name := sym.Name
			checkSymbol(name, analysis)
		}
	}

	// Inspect dynamic symbols
	dynsyms, err := f.DynamicSymbols()
	if err == nil {
		for _, sym := range dynsyms {
			name := sym.Name
			checkSymbol(name, analysis)
		}
	}

	// Inspect imported symbols
	imported, err := f.ImportedSymbols()
	if err == nil {
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
	targets := []string{"memfd_create", "process_vm_writev", "VirtualAllocEx", "ptrace", "socket", "connect"}
	for _, t := range targets {
		if strings.Contains(str, t) {
			addCapability(analysis, t)
		}
	}
}

func addCapability(analysis *ELFAnalysis, cap string) {
	for _, existing := range analysis.SuspiciousCapabilities {
		if existing == cap {
			return
		}
	}
	analysis.SuspiciousCapabilities = append(analysis.SuspiciousCapabilities, cap)
}

func addIOC(analysis *ELFAnalysis, ioc string) {
	for _, existing := range analysis.SuspiciousIOCs {
		if existing == ioc {
			return
		}
	}
	analysis.SuspiciousIOCs = append(analysis.SuspiciousIOCs, ioc)
}

func parseRawELFHeaders(data []byte, analysis *ELFAnalysis) error {
	if len(data) < 16 {
		return ErrELFTruncated
	}

	eiClass := data[4]
	eiData := data[5]

	var byteOrder binary.ByteOrder
	switch eiData {
	case 1:
		byteOrder = binary.LittleEndian
	case 2:
		byteOrder = binary.BigEndian
	default:
		return errors.New("unknown ELF endianness")
	}

	switch eiClass {
	case 1: // 32-bit
		if len(data) < 52 {
			return ErrELFTruncated
		}
		phoff := uint64(byteOrder.Uint32(data[28:32]))
		shoff := uint64(byteOrder.Uint32(data[32:36]))
		phentsize := int(byteOrder.Uint16(data[42:44]))
		phnum := int(byteOrder.Uint16(data[44:46]))
		shentsize := int(byteOrder.Uint16(data[46:48]))
		shnum := int(byteOrder.Uint16(data[48:50]))

		if phnum > 0 && phoff > 0 && phentsize >= 32 {
			for i := 0; i < phnum; i++ {
				// Offsets stay in uint64: phoff comes from the file and can overflow int.
				poff := phoff + uint64(i)*uint64(phentsize)
				if poff < phoff || poff+32 < poff || poff+32 > uint64(len(data)) {
					break
				}
				off := int(poff)
				pType := byteOrder.Uint32(data[off : off+4])
				pOffset := uint64(byteOrder.Uint32(data[off+4 : off+8]))
				pFilesz := uint64(byteOrder.Uint32(data[off+16 : off+20]))
				pFlags := byteOrder.Uint32(data[off+24 : off+28])

				if pType == 1 { // PT_LOAD
					analysis.HasValidPTLoad = true

					if pFlags&1 != 0 && !analysis.TextSectionFound { // PF_X
						if pFilesz > 0 && pOffset <= uint64(len(data)) && pFilesz <= uint64(len(data))-pOffset {
							analysis.TextEntropy = entropy.Calculate(data[pOffset : pOffset+pFilesz])
							analysis.TextSectionFound = true
						}
					}

					if (pFlags & 3) == 3 { // PF_X | PF_W
						analysis.HasRWXSegments = true
					}
				} else if pType == 0x6474e551 { // PT_GNU_STACK
					if pFlags&1 != 0 { // PF_X
						analysis.HasExecutableStack = true
					}
				}
			}
		}

		// Check if section header table is corrupted/missing despite valid PT_LOAD
		if analysis.HasValidPTLoad {
			if sectionTableInvalid(shoff, shnum, shentsize, len(data)) {
				analysis.CorruptedSectionHeaders = true
			}
		}

	case 2: // 64-bit
		if len(data) < 64 {
			return ErrELFTruncated
		}
		phoff := byteOrder.Uint64(data[32:40])
		shoff := byteOrder.Uint64(data[40:48])
		phentsize := int(byteOrder.Uint16(data[54:56]))
		phnum := int(byteOrder.Uint16(data[56:58]))
		shentsize := int(byteOrder.Uint16(data[58:60]))
		shnum := int(byteOrder.Uint16(data[60:62]))

		if phnum > 0 && phoff > 0 && phentsize >= 56 {
			for i := 0; i < phnum; i++ {
				// Offsets stay in uint64: phoff comes from the file and can overflow int.
				poff := phoff + uint64(i)*uint64(phentsize)
				if poff < phoff || poff+56 < poff || poff+56 > uint64(len(data)) {
					break
				}
				off := int(poff)
				pType := byteOrder.Uint32(data[off : off+4])
				pFlags := byteOrder.Uint32(data[off+4 : off+8])
				pOffset := byteOrder.Uint64(data[off+8 : off+16])
				pFilesz := byteOrder.Uint64(data[off+32 : off+40])

				if pType == 1 { // PT_LOAD
					analysis.HasValidPTLoad = true

					if pFlags&1 != 0 && !analysis.TextSectionFound { // PF_X
						if pFilesz > 0 && pOffset <= uint64(len(data)) && pFilesz <= uint64(len(data))-pOffset {
							analysis.TextEntropy = entropy.Calculate(data[pOffset : pOffset+pFilesz])
							analysis.TextSectionFound = true
						}
					}

					if (pFlags & 3) == 3 { // PF_X | PF_W
						analysis.HasRWXSegments = true
					}
				} else if pType == 0x6474e551 { // PT_GNU_STACK
					if pFlags&1 != 0 { // PF_X
						analysis.HasExecutableStack = true
					}
				}
			}
		}

		// Check if section header table is corrupted/missing despite valid PT_LOAD
		if analysis.HasValidPTLoad {
			if sectionTableInvalid(shoff, shnum, shentsize, len(data)) {
				analysis.CorruptedSectionHeaders = true
			}
		}

	default:
		return errors.New("unknown ELF class")
	}

	return nil
}

// sectionTableInvalid reports whether the section header table is missing or
// points outside the file. All arithmetic stays in uint64: shoff is
// attacker-controlled and can wrap or go negative when cast to int.
func sectionTableInvalid(shoff uint64, shnum, shentsize, dataLen int) bool {
	if shoff == 0 || shoff > uint64(dataLen) || shnum == 0 || shentsize <= 0 {
		return true
	}
	return uint64(shnum)*uint64(shentsize) > uint64(dataLen)-shoff
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
	for _, s := range capStrings {
		if bytes.Contains(data, []byte(s)) {
			addCapability(analysis, s)
		}
	}

	for _, ioc := range scanRawIOCs(data) {
		addIOC(analysis, ioc)
	}
}

// scanRawIOCs inspects bytes for shell payloads and non-private C2 IPv4 addresses.
func scanRawIOCs(data []byte) []string {
	var iocs []string
	for _, p := range iocPatterns {
		if bytes.Contains(data, []byte(p)) {
			iocs = append(iocs, p)
		}
	}

	// Non-private C2 IP detection
	matches := ipv4Regex.FindAll(data, 100)
	for _, m := range matches {
		ipStr := string(m)
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			continue
		}
		// Skip unspecified, loopback, private, link-local, multicast, or broadcast
		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
			continue
		}
		if ip.To4()[0] == 0 || ipStr == "255.255.255.255" {
			continue
		}
		// Skip common public DNS resolvers and benign infrastructure
		switch ipStr {
		case "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220":
			continue
		}
		ioc := "public-c2-ip:" + ipStr
		found := false
		for _, existing := range iocs {
			if existing == ioc {
				found = true
				break
			}
		}
		if !found {
			iocs = append(iocs, ioc)
		}
	}
	return iocs
}
