# Maintainer: Arch User <user@example.org>
pkgname=clean-app
pkgver=1.0.0
pkgrel=1
pkgdesc="A standard benign package"
arch=('x86_64')
url="https://github.com/example/clean-app"
license=('MIT')
source=("https://github.com/example/clean-app/releases/download/v${pkgver}/clean-app-${pkgver}.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

build() {
    cd "$srcdir/$pkgname-$pkgver"
    make
}

package() {
    cd "$srcdir/$pkgname-$pkgver"
    install -Dm755 clean-app "$pkgdir/usr/bin/clean-app"
}
