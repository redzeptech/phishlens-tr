# PhishLens TR - Tek komutla başlatma (Windows)
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
docker compose up -d
Write-Host "PhishLens TR: http://localhost:8501"
