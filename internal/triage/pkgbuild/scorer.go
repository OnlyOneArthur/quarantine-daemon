package pkgbuild

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
)

// ScorePKGBUILD computes the threat score, verdict, and supporting metadata for an analyzed PKGBUILD.
func ScorePKGBUILD(analysis *Analysis, cfg *config.Config, path string) *TriageResult {
	if analysis == nil {
		return &TriageResult{
			Path:             path,
			Score:            0,
			Verdict:          VerdictPass,
			Triggers:         []ThreatTrigger{},
			CategoriesHit:    []string{},
			DampenersApplied: []string{},
			ExtractedSources: []string{},
		}
	}

	triggers, dampeners := collectAnalysisTriggers(analysis, cfg)
	score, verdict, categoriesHit := calculateVerdict(triggers, cfg)
	uniqueDampeners := deduplicateDampeners(dampeners)

	extractedSources := analysis.Source
	if extractedSources == nil {
		extractedSources = []string{}
	}

	if triggers == nil {
		triggers = []ThreatTrigger{}
	}

	return &TriageResult{
		Path:             path,
		Score:            score,
		Verdict:          verdict,
		Triggers:         triggers,
		CategoriesHit:    categoriesHit,
		DampenersApplied: uniqueDampeners,
		IsVCSPackage:     analysis.IsVCSPackage,
		ExtractedSources: extractedSources,
	}
}

func collectAnalysisTriggers(analysis *Analysis, cfg *config.Config) ([]ThreatTrigger, []string) {
	triggers, dampeners := AnalyzeAST(analysis, cfg)
	if analysis.InstallAnalysis != nil {
		installTriggers, installDampeners := AnalyzeAST(analysis.InstallAnalysis, cfg)
		triggers = append(triggers, installTriggers...)
		dampeners = append(dampeners, installDampeners...)
	}
	return triggers, dampeners
}

func calculateVerdict(triggers []ThreatTrigger, cfg *config.Config) (int, Verdict, []string) {
	score := 0
	catMap := make(map[string]struct{})
	for _, tr := range triggers {
		score += tr.ScoreWeight
		catMap[tr.Category] = struct{}{}
	}

	if score > 100 {
		score = 100
	}

	threshold := 85
	if cfg != nil && cfg.Quarantine.ThresholdScore > 0 {
		threshold = cfg.Quarantine.ThresholdScore
	}

	verdict := VerdictPass
	if score >= threshold {
		verdict = VerdictQuarantine
	} else if score >= 50 {
		verdict = VerdictAlert
	}

	categoriesHit := make([]string, 0, len(catMap))
	for cat := range catMap {
		categoriesHit = append(categoriesHit, cat)
	}
	sort.Strings(categoriesHit)

	return score, verdict, categoriesHit
}

func deduplicateDampeners(dampeners []string) []string {
	dampenerSet := make(map[string]struct{})
	var unique []string
	for _, d := range dampeners {
		if _, ok := dampenerSet[d]; !ok {
			dampenerSet[d] = struct{}{}
			unique = append(unique, d)
		}
	}
	if unique == nil {
		return []string{}
	}
	return unique
}

// TriagePKGBUILD parses and triages a PKGBUILD script, checking for accompanying .install files.
func TriagePKGBUILD(data []byte, path string, cfg *config.Config) (*TriageResult, error) {
	analysis, err := ParsePKGBUILD(data, path)
	if err != nil {
		return nil, err
	}

	if analysis.Install != "" && path != "" {
		var maxMB int64
		if cfg != nil {
			maxMB = cfg.Binary.MaxScanSizeMB
		}
		if installAnalysis := loadInstallScriptlet(filepath.Dir(path), analysis.Install, maxMB); installAnalysis != nil {
			analysis.InstallAnalysis = installAnalysis
		}
	}

	return ScorePKGBUILD(analysis, cfg, path), nil
}

func loadInstallScriptlet(dir, install string, maxScanMB int64) *Analysis {
	installPath := filepath.Clean(filepath.Join(dir, install))
	rel, err := filepath.Rel(dir, installPath)
	if err != nil || strings.HasPrefix(rel, "..") || rel == "." {
		return nil
	}

	sf, err := fsutil.OpenSafe(installPath)
	if err != nil {
		return nil
	}
	defer sf.Close()

	maxBytes := int64(4 * 1024 * 1024)
	if maxScanMB > 0 {
		maxBytes = maxScanMB * 1024 * 1024
	}

	installData, err := fsutil.ReadBounded(sf.File, maxBytes)
	if err != nil {
		return nil
	}

	installAnalysis, err := ParseInstallScript(installData, installPath)
	if err != nil {
		return nil
	}
	return installAnalysis
}

// TriageInstallScript parses and triages an Arch *.install scriptlet directly.
func TriageInstallScript(data []byte, path string, cfg *config.Config) (*TriageResult, error) {
	analysis, err := ParseInstallScript(data, path)
	if err != nil {
		return nil, err
	}
	return ScorePKGBUILD(analysis, cfg, path), nil
}
