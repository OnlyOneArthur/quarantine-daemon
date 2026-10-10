package binary

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
)

func buildMinimalELF64(phdrs []progHeader, shoff uint64, shnum uint16, payload []byte) []byte {
	buf := new(bytes.Buffer)

	// ELF Ident
	ident := [16]byte{0x7f, 'E', 'L', 'F', 2 /* 64-bit */, 1 /* LSB */, 1 /* EV_CURRENT */}
	buf.Write(ident[:])

	// Header fields
	binary.Write(buf, binary.LittleEndian, uint16(2))          // e_type: ET_EXEC
	binary.Write(buf, binary.LittleEndian, uint16(0x3e))       // e_machine: x86_64
	binary.Write(buf, binary.LittleEndian, uint32(1))          // e_version: EV_CURRENT
	binary.Write(buf, binary.LittleEndian, uint64(0x400000))   // e_entry
	binary.Write(buf, binary.LittleEndian, uint64(64))         // e_phoff: 64
	binary.Write(buf, binary.LittleEndian, shoff)              // e_shoff
	binary.Write(buf, binary.LittleEndian, uint32(0))          // e_flags
	binary.Write(buf, binary.LittleEndian, uint16(64))         // e_ehsize
	binary.Write(buf, binary.LittleEndian, uint16(56))         // e_phentsize
	binary.Write(buf, binary.LittleEndian, uint16(len(phdrs))) // e_phnum
	binary.Write(buf, binary.LittleEndian, uint16(64))         // e_shentsize
	binary.Write(buf, binary.LittleEndian, shnum)              // e_shnum
	binary.Write(buf, binary.LittleEndian, uint16(0))          // e_shstrndx

	// Program Headers
	for _, ph := range phdrs {
		binary.Write(buf, binary.LittleEndian, ph.pType)
		binary.Write(buf, binary.LittleEndian, ph.pFlags)
		binary.Write(buf, binary.LittleEndian, ph.pOffset)
		binary.Write(buf, binary.LittleEndian, ph.pVaddr)
		binary.Write(buf, binary.LittleEndian, ph.pPaddr)
		binary.Write(buf, binary.LittleEndian, ph.pFilesz)
		binary.Write(buf, binary.LittleEndian, ph.pMemsz)
		binary.Write(buf, binary.LittleEndian, ph.pAlign)
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

	machoFat := []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00}
	if got := DetectFormat(machoFat); got != FormatMachO {
		t.Fatalf("expected FormatMachO, got %s", got)
	}

	// PE
	peData := make([]byte, 128)
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
data[0x80] = 'P'; data[0x81] = 'E'
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
