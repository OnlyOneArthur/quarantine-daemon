package binary

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
)

// TestBinaryFixtures exercises the synthetic corpus in testdata/binary,
// testdata/entropy and testdata/scripts against the real triage engine. The
// fixtures are minimal, hand-built artifacts (ELF/PE headers, entropy blobs,
// scripts) that isolate individual detectors so regressions are attributable to
// a single signal.
func TestBinaryFixtures(t *testing.T) {
	cfg := config.DefaultConfig()

	tests := []struct {
		subdir          string
		file            string
		expectedFormat  Format
		expectedVerdict Verdict
		minScore        int
		maxScore        int
		wantTriggers    []string
	}{
		{subdir: "binary", file: "elf_clean", expectedFormat: FormatELF, expectedVerdict: VerdictPass, minScore: 0, maxScore: 0},
		{subdir: "binary", file: "elf_corrupted_header", expectedFormat: FormatELF, expectedVerdict: VerdictPass, minScore: 40, maxScore: 40, wantTriggers: []string{"corrupted_section_headers_evasion"}},
		{subdir: "binary", file: "elf_executable_stack", expectedFormat: FormatELF, expectedVerdict: VerdictPass, minScore: 35, maxScore: 35, wantTriggers: []string{"executable_stack"}},
		{subdir: "binary", file: "elf_rwx_segment", expectedFormat: FormatELF, expectedVerdict: VerdictPass, minScore: 35, maxScore: 35, wantTriggers: []string{"rwx_segment"}},
		{subdir: "binary", file: "elf_ioc_reverse_shell", expectedFormat: FormatELF, expectedVerdict: VerdictAlert, minScore: 50, maxScore: 50, wantTriggers: []string{"ioc_payload"}},
		{subdir: "binary", file: "elf_malicious_combined", expectedFormat: FormatELF, expectedVerdict: VerdictQuarantine, minScore: 85, maxScore: 100, wantTriggers: []string{"corrupted_section_headers_evasion", "rwx_segment", "injection_api_memfd_create", "injection_api_ptrace", "ioc_payload"}},
		{subdir: "binary", file: "pe_rwx", expectedFormat: FormatPE, expectedVerdict: VerdictPass, minScore: 35, maxScore: 35, wantTriggers: []string{"pe_rwx_section"}},
		{subdir: "binary", file: "pe_malicious_combined", expectedFormat: FormatPE, expectedVerdict: VerdictAlert, minScore: 50, maxScore: 84, wantTriggers: []string{"pe_rwx_section", "pe_high_entropy", "upx_packed"}},
		{subdir: "entropy", file: "high_entropy.bin", expectedVerdict: VerdictPass, minScore: 25, maxScore: 25, wantTriggers: []string{"high_entropy"}},
		{subdir: "entropy", file: "low_entropy.bin", expectedVerdict: VerdictPass, minScore: 0, maxScore: 0},
		{subdir: "scripts", file: "benign_script.sh", expectedVerdict: VerdictPass, minScore: 0, maxScore: 0},
		{subdir: "scripts", file: "benign_text.txt", expectedVerdict: VerdictPass, minScore: 0, maxScore: 0},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			path := filepath.Join("..", "..", "..", "testdata", tt.subdir, tt.file)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture %s: %v", path, err)
			}

			res, err := TriageBinary(data, tt.file, cfg)
			if err != nil {
				t.Fatalf("triage failed for %s: %v", tt.file, err)
			}

			if tt.expectedFormat != "" && res.Format != tt.expectedFormat {
				t.Errorf("format = %s, want %s", res.Format, tt.expectedFormat)
			}
			if res.Verdict != tt.expectedVerdict {
				t.Errorf("verdict = %s, want %s (score=%d)", res.Verdict, tt.expectedVerdict, res.Score)
			}
			if res.Score < tt.minScore || res.Score > tt.maxScore {
				t.Errorf("score = %d, want [%d, %d]", res.Score, tt.minScore, tt.maxScore)
			}

			triggerNames := make(map[string]bool)
			for _, tr := range res.Triggers {
				triggerNames[tr.Name] = true
			}
			for _, want := range tt.wantTriggers {
				if !triggerNames[want] {
					t.Errorf("missing expected trigger %q, got: %v", want, res.Triggers)
				}
			}
		})
	}
}
