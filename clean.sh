#!/usr/bin/env bash

set -euo pipefail

echo "=== Heimdall proje temizliği başlıyor ==="

# Geçici build klasörleri
rm -rf .pybuild build dist deb_dist *.egg-info .eggs .pytest_cache

# Python bytecode ve cache
find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
find . -type f -name '*.py[co]' -delete 2>/dev/null || true
find . -type f -name '*~' -delete 2>/dev/null || true

# debian paketleme kalıntıları (kaynak dosyaları korumak için dikkatli)
if [[ -d debian ]]; then
    echo "debian/ klasöründe temizlik yapılıyor (kontrol et!)"
    rm -f debian/files debian/*.debhelper debian/*.substvars debian/*.log debian/debhelper-build-stamp
    # debian/control, rules, compat gibi dosyaları korumak için yukarıdakileri silmeyiz
fi

# İsteğe bağlı – ekran görüntüleri ve logo
# rm -f pp-*.png logo.png

# .idea klasörünü korumak istiyorsan yorum satırına al
# rm -rf .idea

echo ""
echo "Kalan dosyalar:"
ls -A -l --group-directories-first

echo ""
echo "Temizlik tamamlandı."
echo "Önemli dosyalar: heimdall.py, setup.py, README.md, LICENSE, debian/ (paketleme dosyaları)"