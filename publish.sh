#!/bin/bash
# PhishLens-TR - PyPI yayınlama betiği
# Kullanım: ./publish.sh [testpypi|pypi]

set -e

TARGET="${1:-pypi}"

echo "==> PhishLens-TR PyPI Yayınlama"
echo "    Hedef: $TARGET"
echo ""

# build ve twine kurulumu
echo "==> Araçları kontrol ediyor..."
pip install -q build twine

# Önceki build temizliği
echo "==> Önceki build temizleniyor..."
rm -rf dist/ build/ src/*.egg-info 2>/dev/null || true

# Paket oluşturma
echo "==> Paket oluşturuluyor (sdist + wheel)..."
python -m build

# Yükleme
if [ "$TARGET" = "testpypi" ]; then
    echo "==> TestPyPI'ye yükleniyor..."
    python -m twine upload --repository testpypi dist/*
else
    echo "==> PyPI'ye yükleniyor..."
    python -m twine upload dist/*
fi

echo ""
echo "==> Tamamlandı: phishlens-tr $TARGET üzerinde yayında."
echo "    Kurulum: pip install phishlens-tr"
