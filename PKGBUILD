# Maintainer: Serkan Sunel <serkan.sunel@gmail.com>
pkgname=heimdall
pkgver=0.9.8
pkgrel=1
pkgdesc="Interactive curses-based port and process viewer"
arch=('any')
url="https://github.com/sunels/heimdall"
license=('MIT')
depends=('python' 'python-psutil' 'iproute2' 'procps-ng')
makedepends=('python-setuptools')
source=("https://github.com/sunels/heimdall/archive/refs/tags/v${pkgver}.tar.gz")
sha256sums=('SKIP') # User should update this with actual hash

package() {
  cd "$srcdir/$pkgname-$pkgver"
  python setup.py install --root="$pkgdir/" --optimize=1 --skip-build
}
