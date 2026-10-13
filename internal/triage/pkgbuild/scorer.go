package pkgbuild

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
)

// ScorePKGBUILD computes the threat score, verdict, and supporting metadata for an analyzed PKGBUILD.
func ScorePKGBUILD(analysis *PKGBUILDAnalysis, cfg *config.Config, path string) *TriageResult {
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

	triggers, dampeners := AnalyzeAST(analysis, cfg)

	if analysis.InstallAnalysis != nil {
		installTriggers, installDampeners := AnalyzeAST(analysis.InstallAnalysis, cfg)
		triggers = append(triggers, installTriggers...)
		dampeners = append(dampeners, installDampeners...)
	}

	// Compute composite score
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

	dampenerSet := make(map[string]struct{})
	var uniqueDampeners []string
	for _, d := range dampeners {
		if _, ok := dampenerSet[d]; !ok {
			dampenerSet[d] = struct{}{}
			uniqueDampeners = append(uniqueDampeners, d)
		}
	}
	if uniqueDampeners == nil {
		uniqueDampeners = []string{}
	}

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

// TriagePKGBUILD parses and triages a PKGBUILD script, checking for accompanying .install files.
func TriagePKGBUILD(data []byte, path string, cfg *config.Config) (*TriageResult, error) {
	analysis, err := ParsePKGBUILD(data, path)
	if err != nil {
		return nil, err
	}

	// If install scriptlet specified in PKGBUILD, check for accompanying .install file in directory
	if analysis.Install != "" && path != "" {
		dir := filepath.Dir(path)
		installPath := filepath.Clean(filepath.Join(dir, analysis.Install))
		rel, err := filepath.Rel(dir, installPath)
		if err == nil && !strings.HasPrefix(rel, "..") && rel != "." {
			if sf, err := fsutil.OpenSafe(installPath); err == nil {
				maxBytes := int64(4 * 1024 * 1024)
				if cfg != nil && cfg.Binary.MaxScanSizeMB > 0 {
					maxBytes = cfg.Binary.MaxScanSizeMB * 1024 * 1024
				}
				if installData, err := fsutil.ReadBounded(sf.File, maxBytes); err == nil {
					if installAnalysis, err := ParseInstallScript(installData, installPath); err == nil {
						analysis.InstallAnalysis = installAnalysis
					}
				}
				_ = sf.Close()
			}
		}
	}

	return ScorePKGBUILD(analysis, cfg, path), nil
}

// TriageInstallScript parses and triages an Arch *.install scriptlet directly.
func TriageInstallScript(data []byte, path string, cfg *config.Config) (*TriageResult, error) {
	analysis, err := ParseInstallScript(data, path)
	if err != nil {
		return nil, err
	}
	return ScorePKGBUILD(analysis, cfg, path), nil
}
