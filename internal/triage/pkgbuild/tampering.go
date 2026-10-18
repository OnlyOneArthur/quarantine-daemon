package pkgbuild

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func checkTamperingCommand(cmdName string, args []*syntax.Word, line int, scope string, triggers *[]ThreatTrigger, addDampener func(string)) {
	switch cmdName {
	case "cp", "mv", "install", "rm", "tee":
		checkCopyMoveTampering(args, line, scope, triggers, addDampener)
	case "sed":
		checkSedTampering(args, line, scope, triggers, addDampener)
	case "ln":
		checkSymlinkTampering(args, line, scope, triggers, addDampener)
	}
}

func checkCopyMoveTampering(args []*syntax.Word, line int, scope string, triggers *[]ThreatTrigger, addDampener func(string)) {
	targetDir, rest := splitTargetDirectory(args[1:])
	if targetDir != "" {
		checkPathTarget(nil, targetDir, line, scope, triggers, addDampener)
	}
	for _, arg := range rest {
		val := WordToString(arg)
		if strings.HasPrefix(val, "-") {
			continue
		}
		checkPathTarget(arg, val, line, scope, triggers, addDampener)
	}
}

func checkSedTampering(args []*syntax.Word, line int, scope string, triggers *[]ThreatTrigger, addDampener func(string)) {
	hasInPlace := false
	for _, arg := range args[1:] {
		val := WordToString(arg)
		if strings.HasPrefix(val, "-i") || strings.HasPrefix(val, "--in-place") {
			hasInPlace = true
			break
		}
	}
	if !hasInPlace {
		return
	}
	for _, arg := range args[1:] {
		val := WordToString(arg)
		if strings.HasPrefix(val, "-") {
			continue
		}
		checkPathTarget(arg, val, line, scope, triggers, addDampener)
	}
}

func checkSymlinkTampering(args []*syntax.Word, line int, scope string, triggers *[]ThreatTrigger, addDampener func(string)) {
	hasSymlink := false
	for _, arg := range args[1:] {
		val := WordToString(arg)
		if strings.HasPrefix(val, "-s") || val == "--symbolic" {
			hasSymlink = true
			break
		}
	}
	if !hasSymlink {
		return
	}
	for _, arg := range args[1:] {
		val := WordToString(arg)
		if strings.HasPrefix(val, "-") {
			continue
		}
		checkPathTarget(arg, val, line, scope, triggers, addDampener)
	}
}

// splitTargetDirectory extracts the value of `-t DIR`, `-tDIR`,
// `--target-directory DIR` or `--target-directory=DIR` from a command's
// arguments, returning the directory (empty when absent) and the arguments with
// any consumed flag/value removed.
func splitTargetDirectory(args []*syntax.Word) (string, []*syntax.Word) {
	rest := make([]*syntax.Word, 0, len(args))
	for i := 0; i < len(args); i++ {
		val := WordToString(args[i])
		switch {
		case val == "-t" || val == "--target-directory":
			if i+1 < len(args) {
				i++
				return WordToString(args[i]), append(rest, args[i+1:]...)
			}
		case strings.HasPrefix(val, "--target-directory="):
			return strings.TrimPrefix(val, "--target-directory="), append(rest, args[i+1:]...)
		case strings.HasPrefix(val, "-t") && len(val) > 2:
			return val[2:], append(rest, args[i+1:]...)
		default:
			rest = append(rest, args[i])
		}
	}
	return "", rest
}

func checkPathTarget(_ *syntax.Word, rawPath string, line int, scope string, triggers *[]ThreatTrigger, addDampener func(string)) {
	if HasStagingPrefix(rawPath) {
		resolved, within := stagingTarget(rawPath)
		if within {
			addDampener("packaging_staging_dampener (path within packaging staging variables)")
			return
		}
		rawPath = resolved
	}

	isSys, isCrit := matchSystemPath(rawPath)
	if !isSys {
		return
	}

	*triggers = append(*triggers, ThreatTrigger{
		Category:    CategoryPathTampering,
		Name:        "path_tampering_outside_staging",
		Description: "Target path modifies system filesystem outside staging variables: " + rawPath,
		ScoreWeight: 50,
		Line:        line,
		Scope:       scope,
	})

	if isCrit {
		*triggers = append(*triggers, ThreatTrigger{
			Category:    CategoryPathTampering,
			Name:        "critical_system_file_tampering",
			Description: "Critical authentication or system configuration targeted: " + rawPath,
			ScoreWeight: 40,
			Line:        line,
			Scope:       scope,
		})
	}
}

func matchSystemPath(raw string) (matched bool, isCritical bool) {
	clean := strings.Trim(raw, `'"`)
	if strings.HasPrefix(clean, "$HOME") {
		clean = "~" + strings.TrimPrefix(clean, "$HOME")
	} else if strings.HasPrefix(clean, "${HOME}") {
		clean = "~" + strings.TrimPrefix(clean, "${HOME}")
	}

	if strings.HasPrefix(clean, "/") {
		clean = filepath.Clean(clean)
	} else if strings.HasPrefix(clean, "~/") {
		clean = "~/" + filepath.Clean(strings.TrimPrefix(clean, "~/"))
	}

	criticalExactOrPrefix := []string{
		"/etc/sudoers",
		"/etc/sudoers.d",
		"/etc/shadow",
		"/etc/passwd",
		"/root",
		"~/.ssh",
	}

	for _, p := range criticalExactOrPrefix {
		if clean == p || strings.HasPrefix(clean, p+"/") {
			return true, true
		}
		if p == "~/.ssh" && (strings.HasPrefix(clean, "/home/") || strings.HasPrefix(clean, "/root/")) && strings.Contains(clean, "/.ssh") {
			return true, true
		}
	}

	otherExactOrPrefix := []string{
		"/boot",
		"~/.bashrc",
		"~/.config/autostart",
		"/etc/ld.so.preload",
		"/etc/ld.so.conf",
		"/etc/crontab",
	}

	for _, p := range otherExactOrPrefix {
		if clean == p || strings.HasPrefix(clean, p+"/") {
			return true, false
		}
		if p == "~/.bashrc" && (strings.HasPrefix(clean, "/home/") || strings.HasPrefix(clean, "/root/")) && strings.HasSuffix(clean, "/.bashrc") {
			return true, false
		}
		if p == "~/.config/autostart" && (strings.HasPrefix(clean, "/home/") || strings.HasPrefix(clean, "/root/")) && strings.Contains(clean, "/.config/autostart") {
			return true, false
		}
	}

	return false, false
}
