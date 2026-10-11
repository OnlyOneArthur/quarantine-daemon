package pkgbuild

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
)

func TestPKGBUILDFixtures(t *testing.T) {
	cfg := config.DefaultConfig()

	tests := []struct {
		name            string
		fixtureFile     string
		expectedVerdict Verdict
		minScore        int
		maxScore        int
		wantTriggers    []string
		wantCategories  []string
	}{
		{
			name:            "Clean standard package",
			fixtureFile:     "clean_standard.PKGBUILD",
			expectedVerdict: VerdictPass,
			minScore:        0,
			maxScore:        0,
		},
		{
			name:            "Clean VCS git package with SKIP checksums",
			fixtureFile:     "clean_vcs_git.PKGBUILD",
			expectedVerdict: VerdictPass,
			minScore:        0,
			maxScore:        0,
		},
		{
			name:            "Malicious remote execution triggers",
			fixtureFile:     "malicious_remote_exec.PKGBUILD",
			expectedVerdict: VerdictQuarantine,
			minScore:        85,
			maxScore:        100,
			wantTriggers: []string{
				"pipe_network_to_shell",
				"eval_execution",
				"dev_tcp_udp_socket",
			},
			wantCategories: []string{"remote_execution"},
		},
		{
			name:            "Malicious system file tampering triggers",
			fixtureFile:     "malicious_sys_tamper.PKGBUILD",
			expectedVerdict: VerdictQuarantine,
			minScore:        85,
			maxScore:        100,
			wantTriggers: []string{
				"critical_system_file_tampering",
				"path_tampering_outside_staging",
			},
			wantCategories: []string{"path_tampering"},
		},
		{
			name:            "Malicious C2 and raw IP / Discord CDN source",
			fixtureFile:     "malicious_c2_source.PKGBUILD",
			expectedVerdict: VerdictQuarantine,
			minScore:        85,
			maxScore:        100,
			wantTriggers: []string{
				"untrusted_source_raw_ip",
				"untrusted_source_discord_cdn",
			},
			wantCategories: []string{"untrusted_source"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("..", "..", "..", "testdata", "pkgbuild", tt.fixtureFile)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture %s: %v", path, err)
			}

			res, err := TriagePKGBUILD(data, tt.fixtureFile, cfg)
			if err != nil {
				t.Fatalf("triage failed for %s: %v", tt.fixtureFile, err)
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

			catNames := make(map[string]bool)
			for _, c := range res.CategoriesHit {
				catNames[c] = true
			}
			for _, wantCat := range tt.wantCategories {
				if !catNames[wantCat] {
					t.Errorf("missing expected category %q, got: %v", wantCat, res.CategoriesHit)
				}
			}
		})
	}
}
