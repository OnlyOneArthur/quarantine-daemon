package pkgbuild

import (
	"bytes"
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ParsePKGBUILD parses a PKGBUILD script and extracts top-level variables and metadata.
func ParsePKGBUILD(data []byte, path string) (*Analysis, error) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(bytes.NewReader(data), path)
	if err != nil {
		return nil, fmt.Errorf("parse pkgbuild bash ast: %w", err)
	}

	analysis := &Analysis{
		File: file,
	}

	extractTopLevelVariables(analysis, file)
	analysis.IsVCSPackage = checkIsVCSPackage(analysis)

	return analysis, nil
}

// ParseInstallScript parses an Arch *.install scriptlet file.
func ParseInstallScript(data []byte, path string) (*Analysis, error) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(bytes.NewReader(data), path)
	if err != nil {
		return nil, fmt.Errorf("parse install scriptlet bash ast: %w", err)
	}

	analysis := &Analysis{
		File:            file,
		IsInstallScript: true,
	}

	extractTopLevelVariables(analysis, file)
	return analysis, nil
}

// WordToString converts a syntax.Word into a string representation.
func WordToString(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var sb strings.Builder
	for _, part := range w.Parts {
		appendWordPart(&sb, part)
	}
	return sb.String()
}

func appendWordPart(sb *strings.Builder, part syntax.WordPart) {
	switch p := part.(type) {
	case *syntax.Lit:
		sb.WriteString(p.Value)
	case *syntax.SglQuoted:
		sb.WriteString(p.Value)
	case *syntax.DblQuoted:
		for _, sub := range p.Parts {
			appendWordPart(sb, sub)
		}
	case *syntax.ParamExp:
		if p.Param != nil {
			sb.WriteString("${" + p.Param.Value + "}")
		}
	case *syntax.CmdSubst:
		sb.WriteString("$(cmd)")
	case *syntax.ProcSubst:
		sb.WriteString("<(cmd)")
	}
}

func extractTopLevelVariables(analysis *Analysis, file *syntax.File) {
	for _, stmt := range file.Stmts {
		if stmt == nil || stmt.Cmd == nil {
			continue
		}

		switch cmd := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			if len(cmd.Args) == 0 {
				for _, assign := range cmd.Assigns {
					processAssign(analysis, assign)
				}
			}
		case *syntax.DeclClause:
			for _, assign := range cmd.Args {
				processAssign(analysis, assign)
			}
		}
	}
}

func processAssign(analysis *Analysis, assign *syntax.Assign) {
	if assign == nil || assign.Name == nil {
		return
	}
	varName := assign.Name.Value

	line := 0
	if pos := assign.Pos(); pos.IsValid() {
		line = int(pos.Line())
	}

	var vals []string
	var lines []int
	if assign.Value != nil {
		vals = append(vals, WordToString(assign.Value))
		lines = append(lines, line)
	} else if assign.Array != nil {
		for _, elem := range assign.Array.Elems {
			if elem != nil && elem.Value != nil {
				vals = append(vals, WordToString(elem.Value))
				valueLine := line
				if pos := elem.Value.Pos(); pos.IsValid() {
					valueLine = int(pos.Line())
				}
				lines = append(lines, valueLine)
			}
		}
	}

	assignVariable(analysis, varName, vals, assign.Append, lines)
}

func assignVariable(analysis *Analysis, name string, vals []string, isAppend bool, lines []int) {
	firstVal := ""
	if len(vals) > 0 {
		firstVal = vals[0]
	}

	switch {
	case name == "pkgname":
		if isAppend {
			analysis.Pkgnames = append(analysis.Pkgnames, vals...)
		} else {
			analysis.Pkgnames = vals
		}
		if len(analysis.Pkgnames) > 0 {
			analysis.Pkgname = analysis.Pkgnames[0]
		}
	case name == "install":
		if !isAppend || analysis.Install == "" {
			analysis.Install = firstVal
		}
	case name == "source" || strings.HasPrefix(name, "source_"):
		if isAppend {
			analysis.Source = append(analysis.Source, vals...)
		} else {
			analysis.Source = vals
			analysis.SourceLines = analysis.SourceLines[:0]
		}
		analysis.SourceLines = append(analysis.SourceLines, lines...)
	case name == "sha256sums" || strings.HasPrefix(name, "sha256sums_"):
		if isAppend {
			analysis.Sha256sums = append(analysis.Sha256sums, vals...)
		} else {
			analysis.Sha256sums = vals
		}
	case name == "sha512sums" || strings.HasPrefix(name, "sha512sums_"):
		if isAppend {
			analysis.Sha512sums = append(analysis.Sha512sums, vals...)
		} else {
			analysis.Sha512sums = vals
		}
	case name == "md5sums" || strings.HasPrefix(name, "md5sums_"):
		if isAppend {
			analysis.Md5sums = append(analysis.Md5sums, vals...)
		} else {
			analysis.Md5sums = vals
		}
	}
}

func checkIsVCSPackage(analysis *Analysis) bool {
	suffixes := []string{"-git", "-hg", "-svn", "-cvs", "-bzr"}
	checkSuffix := func(name string) bool {
		for _, s := range suffixes {
			if strings.HasSuffix(name, s) {
				return true
			}
		}
		return false
	}

	if checkSuffix(analysis.Pkgname) {
		return true
	}
	for _, name := range analysis.Pkgnames {
		if checkSuffix(name) {
			return true
		}
	}
	return false
}

// WalkScopeAncestors is WalkScope with the current node's ancestor chain
// (root first, immediate parent last) passed to the visitor. The slice aliases
// internal walk state: it is only valid for the duration of the call and must
// not be retained.
func WalkScopeAncestors(file *syntax.File, isInstallScript bool, visitor func(node syntax.Node, scope string, ancestors []syntax.Node) bool) {
	if file == nil {
		return
	}

	if isInstallScript {
		var stack []syntax.Node
		syntax.Walk(file, func(node syntax.Node) bool {
			if node == nil {
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				return false
			}
			if !visitor(node, ScopeInstallScriptlet, stack) {
				return false
			}
			stack = append(stack, node)
			return true
		})
		return
	}

	var stack []syntax.Node
	funcDepth := 0

	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if _, ok := top.(*syntax.FuncDecl); ok {
					funcDepth--
				}
			}
			return false
		}

		currentScope := ScopeRoot
		if funcDepth > 0 {
			currentScope = ScopeFunction
		}

		if !visitor(node, currentScope, stack) {
			return false
		}

		stack = append(stack, node)
		if _, ok := node.(*syntax.FuncDecl); ok {
			funcDepth++
		}

		return true
	})
}
