// Package triage defines common verdict contracts, scan results, and scanner interfaces
// used across static analysis pipelines in the quarantine system.
package triage

import "context"

// Verdict defines the triage action verdict.
type Verdict string

// Verdict values ordered from least to most severe.
const (
	VerdictPass       Verdict = "PASS"
	VerdictAlert      Verdict = "ALERT"
	VerdictQuarantine Verdict = "QUARANTINE"
)

// AlertScoreThreshold is the score at or above which a result is reported as an
// ALERT even when the quarantine threshold is not reached.
const AlertScoreThreshold = 50

// Result represents the standardized result of static analysis.
type Result struct {
	Score            int
	Verdict          Verdict
	Triggers         []string
	CategoriesHit    []string
	DampenersApplied []string
}

// Scanner defines the contract for format-specific static analysis engines.
type Scanner interface {
	Match(path string, data []byte) bool
	Scan(ctx context.Context, path string, data []byte) (*Result, error)
}
