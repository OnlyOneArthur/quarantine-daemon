package binary

import (
	"os"
	"testing"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
)

func TestSelfScan(t *testing.T) {
	data, err := os.ReadFile("../../../bin/quarantined")
	if err != nil {
		t.Skip("bin/quarantined not found")
	}
	cfg := config.DefaultConfig()
	res, err := TriageBinary(data, "../../../bin/quarantined", cfg)
	if err != nil {
		t.Fatalf("triage failed: %v", err)
	}
	t.Logf("Self-Scan Verdict: %s, Score: %d, Categories: %v", res.Verdict, res.Score, res.CategoriesHit)
	for _, tr := range res.Triggers {
		t.Logf("  Trigger: %s (%s): %d", tr.Name, tr.Category, tr.ScoreWeight)
	}
	if res.Verdict == VerdictQuarantine {
		t.Fatalf("Self-scan triggered QUARANTINE on the daemon itself!")
	}
}
