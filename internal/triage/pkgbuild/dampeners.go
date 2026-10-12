package pkgbuild

import (
	"path/filepath"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"mvdan.cc/sh/v3/syntax"
)

// HasStagingVariable returns true if a syntax.Word references $pkgdir, ${pkgdir}, $srcdir, or ${srcdir}.
func HasStagingVariable(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		if checkPartStaging(part) {
			return true
		}
	}
	return false
}

func checkPartStaging(part syntax.WordPart) bool {
	switch p := part.(type) {
	case *syntax.ParamExp:
		if p.Param != nil && (p.Param.Value == "pkgdir" || p.Param.Value == "srcdir") {
			return true
		}
	case *syntax.DblQuoted:
		for _, sub := range p.Parts {
			if checkPartStaging(sub) {
				return true
			}
		}
	case *syntax.Lit:
		val := p.Value
		if strings.Contains(val, "$pkgdir") || strings.Contains(val, "${pkgdir}") ||
			strings.Contains(val, "$srcdir") || strings.Contains(val, "${srcdir}") {
			return true
		}
	}
	return false
}

// HasStagingPrefix returns true if the raw path string references packaging staging variables.
func HasStagingPrefix(path string) bool {
	return strings.Contains(path, "$pkgdir") || strings.Contains(path, "${pkgdir}") ||
		strings.Contains(path, "$srcdir") || strings.Contains(path, "${srcdir}")
}

// stagingTarget resolves literal traversal after a leading staging variable.
// An escaped target is returned as an absolute path for system-path checks.
func stagingTarget(path string) (target string, within bool) {
	for _, prefix := range []string{"${pkgdir}", "$pkgdir", "${srcdir}", "$srcdir"} {
		if path != prefix && !strings.HasPrefix(path, prefix+"/") {
			continue
		}
		resolved := filepath.Clean("/staging" + strings.TrimPrefix(path, prefix))
		if resolved == "/staging" || strings.HasPrefix(resolved, "/staging/") {
			return resolved, true
		}
		return resolved, false
	}
	return path, false
}

// EvaluateIntegrity applies VCS dampening or flags missing/SKIP checksums on static sources.
func EvaluateIntegrity(analysis *PKGBUILDAnalysis, cfg *config.Config) ([]ThreatTrigger, []string) {
	var triggers []ThreatTrigger
	var dampeners []string

	if analysis.IsInstallScript {
		return triggers, dampeners
	}

	flagSkip := true
	if cfg != nil {
		flagSkip = cfg.PKGBUILD.FlagSkipChecksums
	}

	if analysis.IsVCSPackage {
		dampeners = append(dampeners, "vcs_package_dampener (exempt sha256sums=SKIP)")
		return triggers, dampeners
	}

	if !flagSkip {
		return triggers, dampeners
	}

	if len(analysis.Source) == 0 {
		return triggers, dampeners
	}

	hasChecksums := len(analysis.Sha256sums) > 0 || len(analysis.Sha512sums) > 0 || len(analysis.Md5sums) > 0
	if !hasChecksums {
		triggers = append(triggers, ThreatTrigger{
			Category:    CategoryIntegrity,
			Name:        "non_vcs_missing_checksums",
			Description: "Non-VCS package missing integrity checksums for static source",
			ScoreWeight: 15,
			Line:        1,
			Scope:       ScopeRoot,
		})
		return triggers, dampeners
	}

	hasSkip := false
	checkSkip := func(sums []string) {
		for _, s := range sums {
			clean := strings.Trim(s, `'"`)
			if strings.EqualFold(clean, "SKIP") {
				hasSkip = true
				return
			}
		}
	}

	checkSkip(analysis.Sha256sums)
	if !hasSkip {
		checkSkip(analysis.Sha512sums)
	}
	if !hasSkip {
		checkSkip(analysis.Md5sums)
	}

	if hasSkip {
		triggers = append(triggers, ThreatTrigger{
			Category:    CategoryIntegrity,
			Name:        "non_vcs_skip_checksum",
			Description: "Non-VCS package with static source specifies sha256sums=('SKIP')",
			ScoreWeight: 15,
			Line:        1,
			Scope:       ScopeRoot,
		})
	}

	return triggers, dampeners
}
