# Kurulum Rehberi

## Gereksinimler

- **Python 3.10+**
- pip (Python paket yöneticisi)

## Adım 1: Repoyu Klonlama

```bash
git clone https://github.com/your-org/phishlens-tr.git
cd phishlens-tr
```

## Adım 2: Sanal Ortam (Önerilir)

```bash
# Sanal ortam oluştur
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

## Adım 3: Paketi ve Bağımlılıkları Yükleme

```bash
pip install -e .
```

Bu komut `pyproject.toml` üzerinden paketi editable modda yükler ve tüm bağımlılıkları kurar.

## Adım 4: API Yapılandırması (Opsiyonel)

VirusTotal, AbuseIPDB veya OpenAI kullanacaksanız:

```bash
cp .env.example .env
# .env dosyasını düzenleyin
```

Detaylar için [Yapılandırma](Yapilandirma.md) sayfasına bakın.

## Adım 5: Çalıştırma

```bash
python main.py
```

## Docker ile Kurulum

```bash
cp .env.example .env
docker compose up -d
```

Tarayıcıda **http://localhost:8501** açılır.
