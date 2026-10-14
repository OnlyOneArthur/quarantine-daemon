package pkgbuild

import (
	"path/filepath"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"mvdan.cc/sh/v3/syntax"
)

// AnalyzeAST scans the AST of a PKGBUILD or install scriptlet for threat triggers.
func AnalyzeAST(analysis *Analysis, cfg *config.Config) ([]ThreatTrigger, []string) {
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

	// 2. Check checksum dampeners / integrity
	integrityTriggers, integrityDampeners := EvaluateIntegrity(analysis, cfg)

	triggers := make([]ThreatTrigger, 0, len(sourceTriggers)+len(integrityTriggers))
	triggers = append(triggers, sourceTriggers...)
	triggers = append(triggers, integrityTriggers...)
	for _, d := range integrityDampeners {
		addDampener(d)
	}

	// 3. AST Traversal. The ancestor chain is threaded through so command/process
	// substitution checks do not have to re-walk the whole AST per occurrence.
	WalkScopeAncestors(analysis.File, analysis.IsInstallScript, func(node syntax.Node, scope string, ancestors []syntax.Node) bool {
		if node == nil {
			return false
		}

		switch n := node.(type) {
		case *syntax.CallExpr:
			checkCallExpr(n, scope, &triggers, addDampener)
		case *syntax.BinaryCmd:
			checkBinaryCmd(n, scope, &triggers)
		case *syntax.CmdSubst:
			checkCmdSubst(n, ancestors, scope, &triggers)
		case *syntax.ProcSubst:
			checkProcSubst(n, ancestors, scope, &triggers)
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

	checkCallEval(cmdName, line, scope, triggers)
	checkCallBase64(cmdName, args, line, scope, triggers)
	checkCallDevSocket(cmdName, args, line, scope, triggers)
	checkTamperingCommand(cmdName, args, line, scope, triggers, addDampener)
}

func checkCallEval(cmdName string, line int, scope string, triggers *[]ThreatTrigger) {
	if cmdName != "eval" {
		return
	}
	*triggers = append(*triggers, ThreatTrigger{
		Category:    CategoryRemoteExecution,
		Name:        "eval_execution",
		Description: "Dynamic command execution via eval",
		ScoreWeight: 40,
		Line:        line,
		Scope:       scope,
	})
}

func checkCallBase64(cmdName string, args []*syntax.Word, line int, scope string, triggers *[]ThreatTrigger) {
	if cmdName != "base64" {
		return
	}
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

func checkCallDevSocket(cmdName string, args []*syntax.Word, line int, scope string, triggers *[]ThreatTrigger) {
	hasDevSocket := false
	for _, arg := range args {
		val := WordToString(arg)
		if strings.Contains(val, "/dev/tcp") || strings.Contains(val, "/dev/udp") {
			hasDevSocket = true
			break
		}
	}
	if !hasDevSocket {
		return
	}
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
