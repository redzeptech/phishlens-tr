#!/bin/bash
# PhishLens TR - Tek komutla başlatma
set -e
[ -f .env ] || cp .env.example .env
docker compose up -d
echo "PhishLens TR: http://localhost:8501"
