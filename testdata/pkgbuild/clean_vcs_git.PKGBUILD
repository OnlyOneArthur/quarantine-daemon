# Maintainer: Arch User <user@example.org>
pkgname=clean-tool-git
pkgver=0.1.0.r42.g1a2b3c4
pkgrel=1
pkgdesc="A standard benign VCS git package"
arch=('x86_64')
url="https://github.com/example/clean-tool"
license=('Apache-2.0')
makedepends=('git')
source=("git+https://github.com/example/clean-tool.git")
sha256sums=('SKIP')

pkgver() {
    cd "$srcdir/clean-tool"
    git describe --long --tags | sed 's/\([^-]*-g\)/r\1/;s/-/./g'
}

build() {
    cd "$srcdir/clean-tool"
    make
}

package() {
    cd "$srcdir/clean-tool"
    install -Dm755 clean-tool "$pkgdir/usr/bin/clean-tool"
}
