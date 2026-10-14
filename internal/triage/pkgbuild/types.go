package pkgbuild

import "mvdan.cc/sh/v3/syntax"

// Verdict defines the triage action verdict.
type Verdict string

// Verdict values ordered from least to most severe.
const (
	VerdictPass       Verdict = "PASS"
	VerdictAlert      Verdict = "ALERT"
	VerdictQuarantine Verdict = "QUARANTINE"
)

// Threat categories.
const (
	CategoryRemoteExecution = "remote_execution"
	CategoryPathTampering   = "path_tampering"
	CategoryUntrustedSource = "untrusted_source"
	CategoryIntegrity       = "integrity"
)

// Scope constants.
const (
	ScopeRoot             = "root"
	ScopeFunction         = "function"
	ScopeInstallScriptlet = "install_scriptlet"
)

// ThreatTrigger records a single security rule hit with its category, name, description, score weight, line number, and scope.
type ThreatTrigger struct {
	Category    string `json:"category"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ScoreWeight int    `json:"score_weight"`
	Line        int    `json:"line"`
	Scope       string `json:"scope"`
}

// TriageResult contains the final threat score, verdict, and supporting evidence.
type TriageResult struct {
	Path             string          `json:"path"`
	Score            int             `json:"score"`
	Verdict          Verdict         `json:"verdict"`
	Triggers         []ThreatTrigger `json:"triggers"`
	CategoriesHit    []string        `json:"categories_hit"`
	DampenersApplied []string        `json:"dampeners_applied"`
	IsVCSPackage     bool            `json:"is_vcs_package"`
	ExtractedSources []string        `json:"extracted_sources"`
}

// Analysis holds the parsed AST and extracted metadata from a PKGBUILD or install scriptlet.
type Analysis struct {
	File     *syntax.File
	Pkgname  string
	Pkgnames []string
	Source   []string
	// SourceLines holds the line number of each Source entry, parallel to Source.
	SourceLines     []int
	Sha256sums      []string
	Sha512sums      []string
	Md5sums         []string
	Install         string
	IsVCSPackage    bool
	IsInstallScript bool
	InstallAnalysis *Analysis
}
