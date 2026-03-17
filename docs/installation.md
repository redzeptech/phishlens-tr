# Kurulum

## Gereksinimler

- Python 3.10+

## pip ile Kurulum

### 1. Repoyu klonlayın

```bash
git clone https://github.com/your-org/phishlens-tr.git
cd phishlens-tr
```

### 2. Sanal ortam oluşturun (önerilir)

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

### 3. Paketi yükleyin

```bash
pip install -e .
```

Bu komut paketi editable modda kurar ve `phishlens` komutunu kullanılabilir hale getirir.

### 4. API yapılandırması (opsiyonel)

```bash
cp .env.example .env
# .env dosyasını düzenleyin (VirusTotal, AbuseIPDB, OpenAI anahtarları)
```

---

## Docker ile Kurulum

### Tek komut

```bash
# Linux/macOS
chmod +x run.sh && ./run.sh

# Windows (PowerShell)
.\run.ps1
```

### Manuel Docker

```bash
cp .env.example .env
docker compose up -d
```

Tarayıcıda **http://localhost:8501** adresinde Streamlit web arayüzü açılır. Geçmiş verisi `phishlens_data` volume'da saklanır.
