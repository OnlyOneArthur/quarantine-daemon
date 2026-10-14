// Package binary triages native executables (ELF, PE, Mach-O) and scripts.
package binary

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand"
	"reflect"
	"regexp"
	"testing"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
)

// writeLE writes data to buf in little-endian order. A bytes.Buffer never
// fails, so the error is intentionally discarded.
func writeLE(buf *bytes.Buffer, data any) {
	_ = binary.Write(buf, binary.LittleEndian, data)
}

func buildMinimalELF64(phdrs []progHeader, shoff uint64, shnum uint16, payload []byte) []byte {
	buf := new(bytes.Buffer)

	// ELF Ident
	ident := [16]byte{0x7f, 'E', 'L', 'F', 2 /* 64-bit */, 1 /* LSB */, 1 /* EV_CURRENT */}
	buf.Write(ident[:])

	// Header fields
	writeLE(buf, uint16(2))          // e_type: ET_EXEC
	writeLE(buf, uint16(0x3e))       // e_machine: x86_64
	writeLE(buf, uint32(1))          // e_version: EV_CURRENT
	writeLE(buf, uint64(0x400000))   // e_entry
	writeLE(buf, uint64(64))         // e_phoff: 64
	writeLE(buf, shoff)              // e_shoff
	writeLE(buf, uint32(0))          // e_flags
	writeLE(buf, uint16(64))         // e_ehsize
	writeLE(buf, uint16(56))         // e_phentsize
	writeLE(buf, uint16(len(phdrs))) // e_phnum
	writeLE(buf, uint16(64))         // e_shentsize
	writeLE(buf, shnum)              // e_shnum
	writeLE(buf, uint16(0))          // e_shstrndx

	// Program Headers
	for _, ph := range phdrs {
		writeLE(buf, ph.pType)
		writeLE(buf, ph.pFlags)
		writeLE(buf, ph.pOffset)
		writeLE(buf, ph.pVaddr)
		writeLE(buf, ph.pPaddr)
		writeLE(buf, ph.pFilesz)
		writeLE(buf, ph.pMemsz)
		writeLE(buf, ph.pAlign)
	}

	if len(payload) > 0 {
		buf.Write(payload)
	}

	return buf.Bytes()
}

type progHeader struct {
	pType   uint32
	pFlags  uint32
	pOffset uint64
	pVaddr  uint64
	pPaddr  uint64
	pFilesz uint64
	pMemsz  uint64
	pAlign  uint64
}

func TestDetector(t *testing.T) {
	// ELF
	elfData := []byte("\x7fELF\x02\x01\x01\x00")
	if got := DetectFormat(elfData); got != FormatELF {
		t.Fatalf("expected FormatELF, got %s", got)
	}

	// Shebang
	shebangData := []byte("#!/bin/bash\necho hello\n")
	if got := DetectFormat(shebangData); got != FormatScript {
		t.Fatalf("expected FormatScript, got %s", got)
	}

	// Mach-O
	macho64BE := []byte{0xfe, 0xed, 0xfa, 0xcf, 0x00, 0x00}
	if got := DetectFormat(macho64BE); got != FormatMachO {
		t.Fatalf("expected FormatMachO, got %s", got)
	}

	// Universal FAT with one complete 20-byte arch entry.
	machoFat := make([]byte, 28)
	binary.BigEndian.PutUint32(machoFat[0:4], 0xCAFEBABE)
	binary.BigEndian.PutUint32(machoFat[4:8], 1)           // nfat_arch
	binary.BigEndian.PutUint32(machoFat[8:12], 0x01000007) // CPU_TYPE_X86_64
	binary.BigEndian.PutUint32(machoFat[12:16], 3)         // CPU_SUBTYPE_X86_64_ALL
	binary.BigEndian.PutUint32(machoFat[16:20], 0x1000)    // offset
	binary.BigEndian.PutUint32(machoFat[20:24], 0x1000)    // size
	binary.BigEndian.PutUint32(machoFat[24:28], 12)        // align
	if got := DetectFormat(machoFat); got != FormatMachO {
		t.Fatalf("expected FormatMachO, got %s", got)
	}

	// A Java class file shares the CAFEBABE magic but has no FAT arch table.
	javaClass := []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01, 0x00, 0x02}
	if got := DetectFormat(javaClass); got != FormatUnknown {
		t.Fatalf("expected FormatUnknown for Java class, got %s", got)
	}

	// PE
	peData := make([]byte, 128, 128+len("PE\x00\x00padding"))
	peData[0] = 'M'
	peData[1] = 'Z'
	binary.LittleEndian.PutUint32(peData[0x3C:0x40], 0x80)
	peData = append(peData, []byte("PE\x00\x00padding")...)
	if got := DetectFormat(peData); got != FormatPE {
		t.Fatalf("expected FormatPE, got %s", got)
	}

	// Unknown
	unknownData := []byte("plain text file contents")
	if got := DetectFormat(unknownData); got != FormatUnknown {
		t.Fatalf("expected FormatUnknown, got %s", got)
	}
}

func TestCleanBinary(t *testing.T) {
	// Clean binary: normal PT_LOAD (RX), Go runtime signatures, no RWX, no UPX, no IOCs
	phdrs := []progHeader{
		{
			pType:   1, // PT_LOAD
			pFlags:  5, // PF_R | PF_X
			pOffset: 64 + 56,
			pVaddr:  0x400000,
			pPaddr:  0x400000,
			pFilesz: 100,
			pMemsz:  100,
			pAlign:  0x1000,
		},
	}
	payload := []byte("runtime.main clean application payload text section")
	binData := buildMinimalELF64(phdrs, 0, 0, payload)

	cfg := config.DefaultConfig()
	res, err := TriageBinary(binData, "/tmp/clean_app", cfg)
	if err != nil {
		t.Fatalf("triage failed: %v", err)
	}

	if res.Verdict != VerdictPass {
		t.Fatalf("expected clean binary to PASS, got %s (score=%d)", res.Verdict, res.Score)
	}
	if !res.IsGoBinary {
		t.Fatalf("expected Go binary detection")
	}
}

func TestCorruptedSectionHeadersEvasion(t *testing.T) {
	// PT_LOAD valid, but section header points out of bounds (deliberate evasion)
	phdrs := []progHeader{
		{
			pType:   1, // PT_LOAD
			pFlags:  5, // PF_R | PF_X
			pOffset: 64 + 56,
			pVaddr:  0x400000,
			pFilesz: 50,
			pMemsz:  50,
		},
	}
	// e_shoff pointing beyond file length with non-zero e_shnum
	binData := buildMinimalELF64(phdrs, 999999, 10, []byte("payload"))

	cfg := config.DefaultConfig()
	res, err := TriageBinary(binData, "/tmp/evasion_app", cfg)
	if err != nil {
		t.Fatalf("triage failed: %v", err)
	}

	hasEvasionTrigger := false
	for _, tr := range res.Triggers {
		if tr.Name == "corrupted_section_headers_evasion" {
			hasEvasionTrigger = true
			if tr.ScoreWeight != 40 {
				t.Fatalf("expected evasion score 40, got %d", tr.ScoreWeight)
			}
		}
	}

	if !hasEvasionTrigger {
		t.Fatalf("expected corrupted_section_headers_evasion trigger")
	}
}

func TestExecutableStackAndRWX(t *testing.T) {
	phdrs := []progHeader{
		{
			pType:   1, // PT_LOAD
			pFlags:  7, // RWX: PF_R | PF_W | PF_X
			pOffset: 64 + 56*2,
			pVaddr:  0x400000,
			pFilesz: 50,
			pMemsz:  50,
		},
		{
			pType:  0x6474e551, // PT_GNU_STACK
			pFlags: 1,          // PF_X
		},
	}
	binData := buildMinimalELF64(phdrs, 0, 0, []byte("payload"))

	cfg := config.DefaultConfig()
	res, err := TriageBinary(binData, "/tmp/rwx_app", cfg)
	if err != nil {
		t.Fatalf("triage failed: %v", err)
	}

	var hasStack, hasRWX bool
	for _, tr := range res.Triggers {
		if tr.Name == "executable_stack" {
			hasStack = true
		}
		if tr.Name == "rwx_segment" {
			hasRWX = true
		}
	}

	if !hasStack {
		t.Fatalf("expected executable_stack trigger")
	}
	if !hasRWX {
		t.Fatalf("expected rwx_segment trigger")
	}
}

func TestEntropyAndUPX(t *testing.T) {
	// Create high entropy payload
	randomBytes := make([]byte, 4096)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("failed to read random bytes: %v", err)
	}

	phdrs := []progHeader{
		{
			pType:   1,
			pFlags:  5,
			pOffset: 64 + 56,
			pVaddr:  0x400000,
			pFilesz: uint64(len(randomBytes)),
			pMemsz:  uint64(len(randomBytes)),
		},
	}
	// Prepend UPX! marker to payload
	copy(randomBytes[:4], []byte("UPX!"))

	binData := buildMinimalELF64(phdrs, 0, 0, randomBytes)

	cfg := config.DefaultConfig()
	res, err := TriageBinary(binData, "/tmp/upx_app", cfg)
	if err != nil {
		t.Fatalf("triage failed: %v", err)
	}

	var hasUPX, hasEntropy bool
	for _, tr := range res.Triggers {
		if tr.Name == "upx_packed" {
			hasUPX = true
		}
		if tr.Name == "high_text_entropy" {
			hasEntropy = true
		}
	}

	if !hasUPX {
		t.Fatalf("expected upx_packed trigger")
	}
	if !hasEntropy {
		t.Fatalf("expected high_text_entropy trigger")
	}
}

func TestCorrelatedMultiCategoryQuarantine(t *testing.T) {
	// Threat binary with triggers in 3 independent categories:
	// 1. Structure: corrupted section headers (+40)
	// 2. Capabilities: memfd_create (+20), ptrace (+20)
	// 3. IOC: /dev/tcp/ reverse shell string (+35)
	// Total score = 40 + 20 + 20 + 35 = 115 -> clamped to 100.
	// Categories hit >= 2 -> QUARANTINE!
	phdrs := []progHeader{
		{
			pType:   1,
			pFlags:  5,
			pOffset: 64 + 56,
			pVaddr:  0x400000,
			pFilesz: 100,
			pMemsz:  100,
		},
	}
	payload := []byte("memfd_create ptrace reverse /dev/tcp/1.2.3.4/4444")
	binData := buildMinimalELF64(phdrs, 99999, 5, payload)

	cfg := config.DefaultConfig()
	res, err := TriageBinary(binData, "/tmp/threat_binary", cfg)
	if err != nil {
		t.Fatalf("triage failed: %v", err)
	}

	if res.Verdict != VerdictQuarantine {
		t.Fatalf("expected QUARANTINE verdict, got %s (score=%d)", res.Verdict, res.Score)
	}
	if len(res.CategoriesHit) < 2 {
		t.Fatalf("expected at least 2 categories hit, got %v", res.CategoriesHit)
	}
}

func TestSingleCategoryDoesNotQuarantine(t *testing.T) {
	// Only 1 category: Structure (corrupted header + executable stack + RWX)
	// Score would be 40 + 35 + 35 = 110, BUT only CategoryStructure hit!
	// Rule: "Requires triggers from at least 2 independent risk categories to quarantine."
	// Should be downgraded to ALERT with score capped at threshold - 1 (84).
	phdrs := []progHeader{
		{
			pType:   1,
			pFlags:  7, // RWX
			pOffset: 64 + 56*2,
			pVaddr:  0x400000,
			pFilesz: 50,
			pMemsz:  50,
		},
		{
			pType:  0x6474e551, // PT_GNU_STACK
			pFlags: 1,          // PF_X
		},
	}
	binData := buildMinimalELF64(phdrs, 99999, 5, []byte("clean payload"))

	cfg := config.DefaultConfig()
	res, err := TriageBinary(binData, "/tmp/structure_only", cfg)
	if err != nil {
		t.Fatalf("triage failed: %v", err)
	}

	if res.Verdict != VerdictAlert {
		t.Fatalf("expected ALERT verdict due to single category limitation, got %s (score=%d)", res.Verdict, res.Score)
	}
	if res.Score >= 85 {
		t.Fatalf("expected score capped below 85, got %d", res.Score)
	}
	if len(res.CategoriesHit) != 1 {
		t.Fatalf("expected exactly 1 category hit, got %v", res.CategoriesHit)
	}
}

func TestRustDampener(t *testing.T) {
	phdrs := []progHeader{
		{
			pType:   1,
			pFlags:  5,
			pOffset: 64 + 56,
			pVaddr:  0x400000,
			pFilesz: 100,
			pMemsz:  100,
		},
	}
	// Contains rust_panic and memfd_create (+20)
	payload := []byte("rust_panic memfd_create")
	binData := buildMinimalELF64(phdrs, 0, 0, payload)

	cfg := config.DefaultConfig()
	res, err := TriageBinary(binData, "/tmp/rust_app", cfg)
	if err != nil {
		t.Fatalf("triage failed: %v", err)
	}

	if !res.IsRustBinary {
		t.Fatalf("expected Rust binary detection")
	}
	// Score: 20 (memfd_create) - 25 (Rust dampener) = -5 -> clamped to 0.
	if res.Score != 0 {
		t.Fatalf("expected score 0 after dampener, got %d", res.Score)
	}
}

func TestPETriage(t *testing.T) {
	// Minimal DOS header starting with MZ pointing to PE signature
	data := make([]byte, 256)
	copy(data, []byte("MZ"))
	// Point e_lfanew at 0x3C to 0x80
	data[0x3C] = 0x80
	data[0x80] = 'P'
	data[0x81] = 'E'
	copy(data[0x90:], []byte("UPX!"))

	cfg := config.DefaultConfig()
	res, err := TriageBinary(data, "/tmp/sample.exe", cfg)
	if err != nil {
		t.Fatalf("TriageBinary failed: %v", err)
	}

	if res.Format != FormatPE {
		t.Fatalf("expected FormatPE, got %s", res.Format)
	}
	if len(res.Triggers) == 0 {
		t.Fatalf("expected UPX trigger")
	}
}

// buildMachO64 emits a minimal 64-bit Mach-O with a single LC_SEGMENT_64 whose
// maximum protection and initial protection are set independently.
func buildMachO64(segName string, maxprot, initprot uint32) []byte {
	buf := new(bytes.Buffer)
	buf.Write([]byte{0xcf, 0xfa, 0xed, 0xfe}) // magic MH_MAGIC_64
	writeLE(buf, uint32(0x01000007))          // cputype x86_64
	writeLE(buf, uint32(3))                   // cpusubtype
	writeLE(buf, uint32(2))                   // filetype MH_EXECUTE
	writeLE(buf, uint32(1))                   // ncmds
	writeLE(buf, uint32(72))                  // sizeofcmds
	writeLE(buf, uint32(0))                   // flags
	writeLE(buf, uint32(0))                   // reserved

	writeLE(buf, uint32(0x19)) // LC_SEGMENT_64
	writeLE(buf, uint32(72))   // cmdsize
	name := make([]byte, 16)
	copy(name, segName)
	buf.Write(name)
	writeLE(buf, uint64(0)) // vmaddr
	writeLE(buf, uint64(0)) // vmsize
	writeLE(buf, uint64(0)) // fileoff
	writeLE(buf, uint64(0)) // filesize
	writeLE(buf, maxprot)
	writeLE(buf, initprot)
	writeLE(buf, uint32(0)) // nsects
	writeLE(buf, uint32(0)) // flags

	return buf.Bytes()
}

func TestAnalyzeELFRejectsWrappingSectionTable(t *testing.T) {
	// shoff = 0xffffffffffffffff: uint64(shnum*shentsize) added to it wraps to a
	// small value, so the old int()-based guard treated the table as in-bounds.
	phdrs := []progHeader{{pType: 1, pFlags: 5, pOffset: 64 + 56, pFilesz: 8}}
	data := buildMinimalELF64(phdrs, ^uint64(0), 10, []byte("payload"))
	analysis, err := AnalyzeELF(data)
	if err != nil {
		t.Fatalf("AnalyzeELF: %v", err)
	}
	if !analysis.CorruptedSectionHeaders {
		t.Fatalf("wrapping section table not flagged corrupted")
	}
}

func TestMachOMaxprotAloneIsNotRWX(t *testing.T) {
	// A segment the kernel merely permits to become RWX (maxprot 7) but that is
	// currently mapped RX (initprot 5) is how normal __TEXT segments look.
	data := buildMachO64("__TEXT", 7, 5)
	analysis, err := AnalyzeMachO(data)
	if err != nil {
		t.Fatalf("AnalyzeMachO: %v", err)
	}
	if analysis.HasRWXSegments {
		t.Fatalf("maxprot 7 / initprot 5 reported as RWX segment")
	}

	cfg := config.DefaultConfig()
	res, err := TriageBinary(data, "/tmp/benign.macho", cfg)
	if err != nil {
		t.Fatalf("TriageBinary: %v", err)
	}
	for _, tr := range res.Triggers {
		if tr.Name == "rwx_segment" {
			t.Fatalf("benign Mach-O scored rwx_segment: %v", res.Triggers)
		}
	}
}

func TestMachOInitprotRWXIsDetected(t *testing.T) {
	data := buildMachO64("__TEXT", 7, 7)
	analysis, err := AnalyzeMachO(data)
	if err != nil {
		t.Fatalf("AnalyzeMachO: %v", err)
	}
	if !analysis.HasRWXSegments {
		t.Fatalf("initprot 7 not reported as RWX segment")
	}
}

func TestAnalyzeELFRejectsHostileProgramHeaderOffset(t *testing.T) {
	data := buildMinimalELF64([]progHeader{{pType: 1, pFlags: 5, pFilesz: 16}}, 0, 0, []byte("payload"))
	// e_phoff high bit set: int(phoff) goes negative without the uint64 guard.
	for i, b := range []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80} {
		data[32+i] = b
	}
	analysis, err := AnalyzeELF(data)
	if err != nil {
		t.Fatalf("AnalyzeELF: %v", err)
	}
	if analysis.TextSectionFound {
		t.Fatalf("hostile phoff parsed a text section")
	}
}

func TestAnalyzeELFRejectsWrappingSegmentBounds(t *testing.T) {
	phdrs := []progHeader{{
		pType:   1, // PT_LOAD
		pFlags:  5, // PF_R | PF_X
		pOffset: ^uint64(0),
		pFilesz: 100,
	}}
	data := buildMinimalELF64(phdrs, 0, 0, []byte("payload"))
	analysis, err := AnalyzeELF(data)
	if err != nil {
		t.Fatalf("AnalyzeELF: %v", err)
	}
	if analysis.TextSectionFound {
		t.Fatalf("wrapping pOffset/pFilesz parsed a text section")
	}
}

func TestScanRawIOCsIPv4Compatibility(t *testing.T) {
	data := []byte("x1.2.3.4 8.8.8.8 256.1.1.1 1.2.3.4.5 01.2.3.4 1.2.3.04 1.2.3.4:443 1.2.3.4\n")
	got := scanRawIOCs(data)
	want := []string{"public-c2-ip:1.2.3.4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scanRawIOCs() = %v, want %v", got, want)
	}
}

func TestIPv4ScannerMatchesPreviousRegexp(t *testing.T) {
	previous := regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	for _, data := range [][]byte{
		[]byte("1.2.3.4 01.2.3.4 1.2.3.04 256.1.1.1 1.2.3.4.5 _1.2.3.4 1.2.3.4x 0.0.0.0"),
		[]byte("1.2.3.4 1.2.3.4 1.2.3.4 1.2.3.4"),
		bytes.Repeat([]byte("1.2.3.4 "), 101),
		[]byte("001.002.003.004 199.249.255.255 255.256.1.1 1.2.3.444 é1.2.3.4"),
	} {
		for _, limit := range []int{1, 2, 100} {
			var got []string
			forEachIPv4(data, limit, func(m []byte) { got = append(got, string(m)) })
			var want []string
			for _, m := range previous.FindAll(data, limit) {
				want = append(want, string(m))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%q limit %d: got %v, want %v", data, limit, got, want)
			}
		}
	}
	// Deterministic malformed and embedded candidates catch boundary and prefix drift.
	rng := mathrand.New(mathrand.NewSource(1))
	alphabet := []byte("0123456789._a!é")
	for trial := 0; trial < 1000; trial++ {
		data := make([]byte, 256)
		for i := range data {
			data[i] = alphabet[rng.Intn(len(alphabet))]
		}
		got := make([]string, 0, 4)
		forEachIPv4(data, 100, func(m []byte) { got = append(got, string(m)) })
		want := make([]string, 0, 4)
		for _, m := range previous.FindAll(data, 100) {
			want = append(want, string(m))
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("trial %d data %q: got %v, want %v", trial, data, got, want)
		}
	}
}

func TestPEAndMachOScanRawIOCs(t *testing.T) {
	peData := make([]byte, 256)
	copy(peData, "MZ")
	peData[0x3c] = 0x80
	copy(peData[0x80:], "PE\x00\x00")
	copy(peData[0xa0:], "/dev/tcp/1.2.3.4/4444 memfd_create")

	machoData := make([]byte, 256)
	copy(machoData, []byte{0xcf, 0xfa, 0xed, 0xfe})
	copy(machoData[64:], "/dev/tcp/1.2.3.4/4444 memfd_create")

	for _, tc := range []struct {
		name   string
		data   []byte
		format Format
	}{
		{"PE", peData, FormatPE},
		{"MachO", machoData, FormatMachO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := TriageBinary(tc.data, "/tmp/sample", config.DefaultConfig())
			if err != nil {
				t.Fatalf("TriageBinary: %v", err)
			}
			if res.Format != tc.format {
				t.Fatalf("format = %s, want %s", res.Format, tc.format)
			}
			var shellIOC, ipIOC, capability bool
			for _, tr := range res.Triggers {
				if tr.Name == "ioc_payload" && tr.ScoreWeight == 35 {
					shellIOC = shellIOC || bytes.Contains([]byte(tr.Description), []byte("/dev/tcp/"))
					ipIOC = ipIOC || bytes.Contains([]byte(tr.Description), []byte("public-c2-ip:1.2.3.4"))
				}
				capability = capability || bytes.Contains([]byte(tr.Name), []byte("memfd_create"))
			}
			if !shellIOC || !ipIOC || !capability {
				t.Fatalf("missing shell IOC, C2 IP, or raw capability: %v", res.Triggers)
			}
		})
	}
}

func TestScriptIOCListIncludesPipedBinSh(t *testing.T) {
	res, err := TriageBinary([]byte("#!/bin/sh\necho payload|/bin/sh\n"), "/tmp/sample.sh", config.DefaultConfig())
	if err != nil {
		t.Fatalf("TriageBinary: %v", err)
	}
	if res.Format != FormatScript {
		t.Fatalf("format = %s, want script", res.Format)
	}
	for _, tr := range res.Triggers {
		if tr.Name == "ioc_payload" && tr.ScoreWeight == 35 && bytes.Contains([]byte(tr.Description), []byte("|/bin/sh")) {
			return
		}
	}
	t.Fatalf("missing |/bin/sh IOC trigger: %v", res.Triggers)
}

func TestMachOTriage(t *testing.T) {
	// Mach-O 64-bit magic (0xfeedfacf)
	data := make([]byte, 256)
	data[0] = 0xcf
	data[1] = 0xfa
	data[2] = 0xed
	data[3] = 0xfe
	copy(data[64:], []byte("UPX!"))

	cfg := config.DefaultConfig()
	res, err := TriageBinary(data, "/tmp/sample.macho", cfg)
	if err != nil {
		t.Fatalf("TriageBinary failed: %v", err)
	}

	if res.Format != FormatMachO {
		t.Fatalf("expected FormatMachO, got %s", res.Format)
	}
	if len(res.Triggers) == 0 {
		t.Fatalf("expected UPX trigger")
	}
}
