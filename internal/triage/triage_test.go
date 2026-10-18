package triage_test

import (
	"testing"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/triage"
)

func TestVerdictConstants(t *testing.T) {
	if triage.VerdictPass != "PASS" {
		t.Errorf("VerdictPass = %q, want PASS", triage.VerdictPass)
	}
	if triage.VerdictAlert != "ALERT" {
		t.Errorf("VerdictAlert = %q, want ALERT", triage.VerdictAlert)
	}
	if triage.VerdictQuarantine != "QUARANTINE" {
		t.Errorf("VerdictQuarantine = %q, want QUARANTINE", triage.VerdictQuarantine)
	}
	if triage.AlertScoreThreshold != 50 {
		t.Errorf("AlertScoreThreshold = %d, want 50", triage.AlertScoreThreshold)
	}
}
