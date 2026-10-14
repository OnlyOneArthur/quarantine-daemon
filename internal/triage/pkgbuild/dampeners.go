// Package pkgbuild triages PKGBUILD and install-scriptlet files for malicious
// build directives.
package pkgbuild

import (
	"path/filepath"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
)

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
func EvaluateIntegrity(analysis *Analysis, cfg *config.Config) ([]ThreatTrigger, []string) {
	if analysis.IsInstallScript {
		return nil, nil
	}

	if analysis.IsVCSPackage {
		return nil, []string{"vcs_package_dampener (exempt sha256sums=SKIP)"}
	}

	flagSkip := true
	if cfg != nil {
		flagSkip = cfg.PKGBUILD.FlagSkipChecksums
	}

	if !flagSkip || len(analysis.Source) == 0 {
		return nil, nil
	}

	return evaluateSourceChecksums(analysis)
}

func evaluateSourceChecksums(analysis *Analysis) ([]ThreatTrigger, []string) {
	if !hasAnyChecksums(analysis) {
		return []ThreatTrigger{{
			Category:    CategoryIntegrity,
			Name:        "non_vcs_missing_checksums",
			Description: "Non-VCS package missing integrity checksums for static source",
			ScoreWeight: 15,
			Line:        1,
			Scope:       ScopeRoot,
		}}, nil
	}

	if hasSkipChecksum(analysis.Sha256sums, analysis.Sha512sums, analysis.Md5sums) {
		return []ThreatTrigger{{
			Category:    CategoryIntegrity,
			Name:        "non_vcs_skip_checksum",
			Description: "Non-VCS package with static source specifies sha256sums=('SKIP')",
			ScoreWeight: 15,
			Line:        1,
			Scope:       ScopeRoot,
		}}, nil
	}

	return nil, nil
}

func hasAnyChecksums(analysis *Analysis) bool {
	return len(analysis.Sha256sums) > 0 || len(analysis.Sha512sums) > 0 || len(analysis.Md5sums) > 0
}

func hasSkipChecksum(checksumSets ...[]string) bool {
	for _, sums := range checksumSets {
		for _, s := range sums {
			if strings.EqualFold(strings.Trim(s, `'"`), "SKIP") {
				return true
			}
		}
	}
	return false
}
