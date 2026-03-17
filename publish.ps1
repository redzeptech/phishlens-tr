# PhishLens-TR - PyPI yayınlama betiği (Windows PowerShell)
# Kullanım: .\publish.ps1 [testpypi|pypi]

$ErrorActionPreference = "Stop"
$Target = if ($args[0]) { $args[0] } else { "pypi" }

Write-Host "==> PhishLens-TR PyPI Yayınlama"
Write-Host "    Hedef: $Target"
Write-Host ""

Write-Host "==> Araçları kontrol ediyor..."
pip install -q build twine

Write-Host "==> Önceki build temizleniyor..."
Remove-Item -Recurse -Force dist, build -ErrorAction SilentlyContinue
Get-ChildItem -Path src -Filter "*.egg-info" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force

Write-Host "==> Paket oluşturuluyor (sdist + wheel)..."
python -m build

if ($Target -eq "testpypi") {
    Write-Host "==> TestPyPI'ye yükleniyor..."
    python -m twine upload --repository testpypi dist/*
} else {
    Write-Host "==> PyPI'ye yükleniyor..."
    python -m twine upload dist/*
}

Write-Host ""
Write-Host "==> Tamamlandı: phishlens-tr $Target üzerinde yayında."
Write-Host "    Kurulum: pip install phishlens-tr"
