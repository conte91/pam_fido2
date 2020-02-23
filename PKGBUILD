# Maintainer: Simone Baratta <simone at ttclabs dot me>

pkgname=pam-fido2
pkgver=r20.1adebfd
pkgrel=1
pkgdesc='Secure passwordless authentication for PAM using FIDO2 devices.'
arch=('i686' 'x86_64')
url="https://github.com/Conte91/pam_fido2"
license=('other')
depends=('libcbor')
makedepends=('git' 'meson' 'ninja')
optdepends=()
provides=()
source=('git+https://github.com/Conte91/pam_fido2')

sha256sums=('SKIP')


pkgver() {
	cd "${srcdir}/pam_fido2"
	printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
	cd "$srcdir/pam_fido2/"
	git submodule init
	git submodule update
	meson build
	ninja -C build
}

package() {
	mkdir -p "${pkgdir}/usr/lib/security"
	mkdir -p "${pkgdir}/usr/bin"
	mkdir -p "${pkgdir}/etc/fido2"
	cd "$srcdir/pam_fido2/"
	install -m644 "etc/config" "${pkgdir}/etc/fido2/config"
	install -m755 "build/fido2_tool" "${pkgdir}/usr/bin/fido2_tool"
	install -m755 "build/libpam_fido2.so" "${pkgdir}/usr/lib/security/pam_fido2.so"
}
