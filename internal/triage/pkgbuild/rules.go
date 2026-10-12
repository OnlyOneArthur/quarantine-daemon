package pkgbuild

import (
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"mvdan.cc/sh/v3/syntax"
)

var legitimateForges = map[string]struct{}{
	"github.com":       {},
	"gitlab.com":       {},
	"codeberg.org":     {},
	"archlinux.org":    {},
	"gnu.org":          {},
	"savannah.gnu.org": {},
	"sourceforge.net":  {},
	"pypi.org":         {},
	"crates.io":        {},
	"cpan.org":         {},
	"kernel.org":       {},
}

var urlShorteners = map[string]struct{}{
	"bit.ly":      {},
	"t.co":        {},
	"tinyurl.com": {},
	"is.gd":       {},
	"buff.ly":     {},
}

var pastebinSites = map[string]struct{}{
	"pastebin.com": {},
	"hastebin.com": {},
	"ghostbin.com": {},
}

var discordCDNs = map[string]struct{}{
	"cdn.discordapp.com":   {},
	"media.discordapp.net": {},
}

// CheckUntrustedSources inspects extracted source URLs in source=() for security risks.
func CheckUntrustedSources(analysis *PKGBUILDAnalysis, cfg *config.Config) []ThreatTrigger {
	var triggers []ThreatTrigger
	if len(analysis.Source) == 0 {
		return triggers
	}

	blockPolicy := true
	if cfg != nil {
		blockPolicy = cfg.PKGBUILD.BlockUntrustedSources
	}

	untrustedCount := 0

	for _, src := range analysis.Source {
		rawURL := src
		if idx := strings.Index(rawURL, "::"); idx != -1 {
			// Only treat "::" as a VCS name separator (pkgname::url); never
			// strip when it appears after the URL scheme (e.g. IPv6 literals).
			if scheme := strings.Index(rawURL, "://"); scheme == -1 || idx < scheme {
				rawURL = rawURL[idx+2:]
			}
		}
		for _, proto := range []string{"git+", "svn+", "hg+", "bzr+"} {
			if strings.HasPrefix(rawURL, proto) {
				rawURL = strings.TrimPrefix(rawURL, proto)
				break
			}
		}

		u, err := url.Parse(rawURL)
		if err != nil || u == nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			continue
		}

		if isLegitimateForge(host) {
			continue
		}

		// 1. Raw IP address (IPv4 or IPv6)
		if ip := net.ParseIP(host); ip != nil {
			description := "Source URL uses raw IPv4 address: " + host
			if ip.To4() == nil {
				description = "Source URL uses raw IPv6 address: " + host
			}
			triggers = append(triggers, ThreatTrigger{
				Category:    CategoryUntrustedSource,
				Name:        "untrusted_source_raw_ip",
				Description: description,
				ScoreWeight: 30,
				Line:        1,
				Scope:       ScopeRoot,
			})
			untrustedCount++
			continue
		}

		// 2. URL Shorteners
		if isHostMatch(host, urlShorteners) {
			triggers = append(triggers, ThreatTrigger{
				Category:    CategoryUntrustedSource,
				Name:        "untrusted_source_shortener",
				Description: "Source URL uses URL shortener: " + host,
				ScoreWeight: 30,
				Line:        1,
				Scope:       ScopeRoot,
			})
			untrustedCount++
			continue
		}

		// 3. Pastebin sites
		if isHostMatch(host, pastebinSites) {
			triggers = append(triggers, ThreatTrigger{
				Category:    CategoryUntrustedSource,
				Name:        "untrusted_source_pastebin",
				Description: "Source URL hosted on pastebin service: " + host,
				ScoreWeight: 30,
				Line:        1,
				Scope:       ScopeRoot,
			})
			untrustedCount++
			continue
		}

		// 4. Discord CDN
		if isHostMatch(host, discordCDNs) {
			triggers = append(triggers, ThreatTrigger{
				Category:    CategoryUntrustedSource,
				Name:        "untrusted_source_discord_cdn",
				Description: "Source URL hosted on Discord CDN: " + host,
				ScoreWeight: 30,
				Line:        1,
				Scope:       ScopeRoot,
			})
			untrustedCount++
			continue
		}
	}

	if untrustedCount > 0 && blockPolicy {
		triggers = append(triggers, ThreatTrigger{
			Category:    CategoryUntrustedSource,
			Name:        "untrusted_source_blocked",
			Description: "Untrusted source link flagged by daemon security policy",
			ScoreWeight: 25,
			Line:        1,
			Scope:       ScopeRoot,
		})
	}

	return triggers
}

func isLegitimateForge(host string) bool {
	if _, ok := legitimateForges[host]; ok {
		return true
	}
	for forge := range legitimateForges {
		if strings.HasSuffix(host, "."+forge) {
			return true
		}
	}
	return false
}

func isHostMatch(host string, hosts map[string]struct{}) bool {
	if _, ok := hosts[host]; ok {
		return true
	}
	for h := range hosts {
		if strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// AnalyzeAST scans the AST of a PKGBUILD or install scriptlet for threat triggers.
func AnalyzeAST(analysis *PKGBUILDAnalysis, cfg *config.Config) ([]ThreatTrigger, []string) {
	var triggers []ThreatTrigger
	var dampeners []string
	dampenerSet := make(map[string]struct{})

	addDampener := func(d string) {
		if _, exists := dampenerSet[d]; !exists {
			dampenerSet[d] = struct{}{}
			dampeners = append(dampeners, d)
		}
	}

	// 1. Check sources
	sourceTriggers := CheckUntrustedSources(analysis, cfg)
	triggers = append(triggers, sourceTriggers...)

	// 2. Check checksum dampeners / integrity
	integrityTriggers, integrityDampeners := EvaluateIntegrity(analysis, cfg)
	triggers = append(triggers, integrityTriggers...)
	for _, d := range integrityDampeners {
		addDampener(d)
	}

	// 3. AST Traversal
	WalkScope(analysis.File, analysis.IsInstallScript, func(node syntax.Node, scope string) bool {
		if node == nil {
			return false
		}

		switch n := node.(type) {
		case *syntax.CallExpr:
			checkCallExpr(n, scope, &triggers, addDampener)
		case *syntax.BinaryCmd:
			checkBinaryCmd(n, scope, &triggers)
		case *syntax.CmdSubst:
			checkCmdSubst(n, analysis.File, scope, &triggers)
		case *syntax.Stmt:
			checkStmtRedirs(n, scope, &triggers, addDampener)
		}

		return true
	})

	return triggers, dampeners
}

func isNetworkTool(name string) bool {
	switch name {
	case "curl", "wget", "fetch", "nc", "netcat", "socat":
		return true
	default:
		return false
	}
}

func isShell(name string) bool {
	switch name {
	case "sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby":
		return true
	default:
		return false
	}
}

func getCallCommand(call *syntax.CallExpr) (cmdName string, cleanArgs []*syntax.Word) {
	if call == nil || len(call.Args) == 0 {
		return "", nil
	}
	args := call.Args
	for len(args) > 1 {
		base := filepath.Base(WordToString(args[0]))
		if base == "sudo" || base == "exec" || base == "nohup" {
			args = args[1:]
		} else {
			break
		}
	}
	return filepath.Base(WordToString(args[0])), args
}

func checkCallExpr(call *syntax.CallExpr, scope string, triggers *[]ThreatTrigger, addDampener func(string)) {
	cmdName, args := getCallCommand(call)
	if cmdName == "" {
		return
	}
	line := int(call.Pos().Line())

	// A. Remote execution: eval
	if cmdName == "eval" {
		*triggers = append(*triggers, ThreatTrigger{
			Category:    CategoryRemoteExecution,
			Name:        "eval_execution",
			Description: "Dynamic command execution via eval",
			ScoreWeight: 40,
			Line:        line,
			Scope:       scope,
		})
	}

	// B. Remote execution: base64 -d
	if cmdName == "base64" {
		for _, arg := range args[1:] {
			val := WordToString(arg)
			if val == "-d" || val == "-D" || val == "--decode" {
				*triggers = append(*triggers, ThreatTrigger{
					Category:    CategoryRemoteExecution,
					Name:        "base64_decode_exec",
					Description: "Deobfuscation and execution attempt via base64 decode",
					ScoreWeight: 40,
					Line:        line,
					Scope:       scope,
				})
				break
			}
		}
	}

	// C. Remote execution: /dev/tcp or /dev/udp in args
	hasDevSocket := false
	for _, arg := range args {
		val := WordToString(arg)
		if strings.Contains(val, "/dev/tcp") || strings.Contains(val, "/dev/udp") {
			hasDevSocket = true
			break
		}
	}
	if hasDevSocket {
		*triggers = append(*triggers, ThreatTrigger{
			Category:    CategoryRemoteExecution,
			Name:        "dev_tcp_udp_socket",
			Description: "Direct network socket connection via /dev/tcp or /dev/udp",
			ScoreWeight: 45,
			Line:        line,
			Scope:       scope,
		})
		if isShell(cmdName) {
			*triggers = append(*triggers, ThreatTrigger{
				Category:    CategoryRemoteExecution,
				Name:        "reverse_shell_redirect",
				Description: "Interactive shell connected to network socket",
				ScoreWeight: 40,
				Line:        line,
				Scope:       scope,
			})
		}
	}

	// D. System integrity tampering commands: cp, mv, install, rm, sed -i, ln -s, tee
	checkTamperingCommand(cmdName, args, line, scope, triggers, addDampener)
}

func checkTamperingCommand(cmdName string, args []*syntax.Word, line int, scope string, triggers *[]ThreatTrigger, addDampener func(string)) {
	switch cmdName {
	case "cp", "mv", "install", "rm", "tee":
		for _, arg := range args[1:] {
			val := WordToString(arg)
			if strings.HasPrefix(val, "-") {
				continue
			}
			checkPathTarget(arg, val, line, scope, triggers, addDampener)
		}
	case "sed":
		hasInPlace := false
		for _, arg := range args[1:] {
			val := WordToString(arg)
			if strings.HasPrefix(val, "-i") || val == "--in-place" {
				hasInPlace = true
				break
			}
		}
		if hasInPlace {
			for _, arg := range args[1:] {
				val := WordToString(arg)
				if strings.HasPrefix(val, "-") {
					continue
				}
				checkPathTarget(arg, val, line, scope, triggers, addDampener)
			}
		}
	case "ln":
		hasSymlink := false
		for _, arg := range args[1:] {
			val := WordToString(arg)
			if strings.HasPrefix(val, "-s") || val == "--symbolic" {
				hasSymlink = true
				break
			}
		}
		if hasSymlink {
			for _, arg := range args[1:] {
				val := WordToString(arg)
				if strings.HasPrefix(val, "-") {
					continue
				}
				checkPathTarget(arg, val, line, scope, triggers, addDampener)
			}
		}
	}
}

func checkStmtRedirs(stmt *syntax.Stmt, scope string, triggers *[]ThreatTrigger, addDampener func(string)) {
	if stmt == nil || len(stmt.Redirs) == 0 {
		return
	}
	line := int(stmt.Pos().Line())

	for _, r := range stmt.Redirs {
		if r == nil || r.Word == nil {
			continue
		}
		targetVal := WordToString(r.Word)

		// Check /dev/tcp or /dev/udp redirection
		if strings.Contains(targetVal, "/dev/tcp") || strings.Contains(targetVal, "/dev/udp") {
			*triggers = append(*triggers, ThreatTrigger{
				Category:    CategoryRemoteExecution,
				Name:        "dev_tcp_udp_socket",
				Description: "Direct network socket connection via redirection to /dev/tcp or /dev/udp",
				ScoreWeight: 45,
				Line:        line,
				Scope:       scope,
			})
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
				cmd, _ := getCallCommand(call)
				if isShell(cmd) {
					*triggers = append(*triggers, ThreatTrigger{
						Category:    CategoryRemoteExecution,
						Name:        "reverse_shell_redirect",
						Description: "Interactive shell redirected to network socket",
						ScoreWeight: 40,
						Line:        line,
						Scope:       scope,
					})
				}
			}
		}

		// Check output redirections >, >>
		if r.Op == syntax.RdrOut || r.Op == syntax.AppOut || r.Op == syntax.RdrAll || r.Op == syntax.AppAll {
			checkPathTarget(r.Word, targetVal, line, scope, triggers, addDampener)
		}
	}
}

func checkPathTarget(w *syntax.Word, rawPath string, line int, scope string, triggers *[]ThreatTrigger, addDampener func(string)) {
	if HasStagingVariable(w) || HasStagingPrefix(rawPath) {
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

func checkBinaryCmd(binCmd *syntax.BinaryCmd, scope string, triggers *[]ThreatTrigger) {
	if binCmd.Op != syntax.Pipe && binCmd.Op != syntax.PipeAll {
		return
	}

	line := int(binCmd.Pos().Line())
	stages := collectPipelineStages(binCmd)
	if len(stages) < 2 {
		return
	}

	netToolFound := false
	pipedToShell := false

	for i, stage := range stages {
		cmd, _ := getCallCommand(stage)
		if isNetworkTool(cmd) {
			netToolFound = true
		}
		if netToolFound && i > 0 && isShell(cmd) {
			pipedToShell = true
			break
		}
	}

	if pipedToShell {
		*triggers = append(*triggers, ThreatTrigger{
			Category:    CategoryRemoteExecution,
			Name:        "pipe_network_to_shell",
			Description: "Pipeline piping network download tool into shell interpreter",
			ScoreWeight: 45,
			Line:        line,
			Scope:       scope,
		})

		switch scope {
		case ScopeRoot:
			*triggers = append(*triggers, ThreatTrigger{
				Category:    CategoryRemoteExecution,
				Name:        "root_scope_network_execution",
				Description: "Network download and execution during PKGBUILD root-scope sourcing",
				ScoreWeight: 45,
				Line:        line,
				Scope:       scope,
			})
		case ScopeFunction:
			*triggers = append(*triggers, ThreatTrigger{
				Category:    CategoryRemoteExecution,
				Name:        "function_network_execution",
				Description: "Network download and execution inside function scope",
				ScoreWeight: 40,
				Line:        line,
				Scope:       scope,
			})
		case ScopeInstallScriptlet:
			*triggers = append(*triggers, ThreatTrigger{
				Category:    CategoryRemoteExecution,
				Name:        "install_scriptlet_network_execution",
				Description: "Network download and execution inside install scriptlet",
				ScoreWeight: 45,
				Line:        line,
				Scope:       scope,
			})
		}
	}
}

func collectPipelineStages(node syntax.Node) []*syntax.CallExpr {
	var stages []*syntax.CallExpr
	var walkStages func(n syntax.Node)
	walkStages = func(n syntax.Node) {
		switch cmd := n.(type) {
		case *syntax.BinaryCmd:
			if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
				walkStages(cmd.X)
				walkStages(cmd.Y)
				return
			}
		case *syntax.Stmt:
			walkStages(cmd.Cmd)
			return
		case *syntax.Subshell:
			for _, s := range cmd.Stmts {
				walkStages(s)
			}
			return
		case *syntax.CallExpr:
			stages = append(stages, cmd)
			return
		}
	}
	walkStages(node)
	return stages
}

func checkCmdSubst(subst *syntax.CmdSubst, file *syntax.File, scope string, triggers *[]ThreatTrigger) {
	if !cmdSubstOutputExecuted(file, subst) {
		return
	}
	line := int(subst.Pos().Line())
	foundNet := false

	syntax.Walk(subst, func(node syntax.Node) bool {
		if node == nil {
			return false
		}
		if call, ok := node.(*syntax.CallExpr); ok {
			cmd, _ := getCallCommand(call)
			if isNetworkTool(cmd) {
				foundNet = true
				return false
			}
		}
		return true
	})

	if foundNet {
		*triggers = append(*triggers, ThreatTrigger{
			Category:    CategoryRemoteExecution,
			Name:        "cmdsubst_network_download",
			Description: "Command substitution executing network download",
			ScoreWeight: 45,
			Line:        line,
			Scope:       scope,
		})
	}
}

func nodeAncestors(file *syntax.File, target syntax.Node) []syntax.Node {
	var stack []syntax.Node
	var ancestors []syntax.Node
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		if node == target {
			ancestors = append(ancestors, stack...)
			return false
		}
		stack = append(stack, node)
		return true
	})
	return ancestors
}

func cmdSubstOutputExecuted(file *syntax.File, target *syntax.CmdSubst) bool {
	ancestors := nodeAncestors(file, target)
	var word *syntax.Word
	var call *syntax.CallExpr
	var stmt *syntax.Stmt
	for i := len(ancestors) - 1; i >= 0; i-- {
		switch n := ancestors[i].(type) {
		case *syntax.Word:
			if word == nil {
				word = n
			}
		case *syntax.CallExpr:
			if call == nil {
				call = n
			}
		case *syntax.Stmt:
			if stmt == nil {
				stmt = n
			}
		}
	}
	if word == nil || call == nil || len(call.Args) == 0 {
		return false
	}
	cmd, _ := getCallCommand(call)
	if cmd == "eval" || call.Args[0] == word {
		return true
	}
	if stmt == nil {
		return false
	}
	stages := collectPipelineStages(stmt)
	for i, stage := range stages {
		if stage != call {
			continue
		}
		for _, later := range stages[i+1:] {
			name, _ := getCallCommand(later)
			if isShell(name) {
				return true
			}
		}
	}
	return false
}
