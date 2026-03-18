
## Kurulum
Python 3 yeterlidir.

## Çalıştırma
```bash
python phishlens.py
## Rapor Kaydı
Raporu otomatik isimle kaydetmek için:
```bash
python phishlens.py
python phishlens.py --output rapor.txt
## Rapor Kaydı
Raporu belirli bir dosya adına kaydetmek için:
```bash
python phishlens.py --output rapor.txt


---

## 4) Test et (Windows terminal)

Repo klasöründe:

```bash
python phishlens.py
python phishlens.py --output rapor.txt
**Commit changes…**
Update README for report export
## Sorumluluk Reddi
Bu araç eğitim ve farkındalık amaçlıdır. Adli incelemenin, hukuki değerlendirmenin veya uzman analizinin yerini tutmaz.
=======
<p align="center">
  <img src="assets/banner.png" alt="PhishLens-TR Banner" width="700">
</p>

<h1 align="center">🛡️ PhishLens-TR</h1>
<p align="center">
  <strong>Gelişmiş Oltalama Analiz ve İstihbarat Aracı</strong>
</p>
<p align="center">
  Türkiye odaklı, kural tabanlı phishing tespiti · Eğitim amaçlı siber güvenlik platformu
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License"></a>
  <a href="https://github.com/your-org/phishlens-tr"><img src="https://img.shields.io/github/stars/your-org/phishlens-tr?style=for-the-badge&logo=github" alt="GitHub stars"></a>
  <a href="https://github.com/your-org/phishlens-tr/issues"><img src="https://img.shields.io/github/issues/your-org/phishlens-tr?style=for-the-badge&logo=github" alt="Open issues"></a>
  <img src="https://img.shields.io/badge/Made%20with-Python-3776AB?style=for-the-badge&logo=python" alt="Made with Python">
  <img src="https://img.shields.io/badge/PhishTank-Protected-ff6b6b?style=for-the-badge" alt="PhishTank Protected">
  <img src="https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/your-org/phishlens-tr/main/assets/stats.json&label=Captured%20Phish&query=%24.malicious&color=dc3545&style=for-the-badge" alt="Captured Phish">
</p>

<p align="center">
  <a href="https://github.com/your-org/phishlens-tr/wiki">📚 Wiki Dokümantasyonu</a>
</p>

---

## 🎥 Demo Videosu

![PhishLens Demo](assets/demo.mp4)

*Veo tarafından üretilen 30 saniyelik hızlı tanıtım.*

---

## 🚀 Öne Çıkan Özellikler

| Özellik | Açıklama |
|---------|----------|
| 🔍 **Canlı Tehdit Beslemeleri** | OpenPhish ve PhishTank üzerinden anlık güncellenen veri tabanı |
| 📊 **PDF Raporlama** | FPDF2 ile profesyonel istatistik raporları, risk çubukları ve özet tablolar |
| 🎨 **Rich Terminal** | Renkli, tablolu ve ilerleme çubuklu konsol çıktıları |
| 🔗 **Heuristik URL Analizi** | Homograph, subdomain, TLD, uzunluk ve rastgele karakter tespiti |
| 📧 **E-posta Analizi** | .eml dosyaları, SPF/DKIM/DMARC ve gönderici IP kontrolü |
| 🤖 **AI Destekli Analiz** | %50–%70 risk bandında LLM (OpenAI/Ollama) ile doğal dil açıklaması |
| 🇹🇷 **Türkiye Odaklı** | Banka, kargo, e-devlet temalı phishing kuralları ve Türkçe dil desteği |
| 📈 **İstatistik Motoru** | Analiz geçmişi, en çok taklit edilen kurumlar ve risk oranları |

---

## 📸 Görünüm

### Terminal Analizi

Rich ile renkli tablo ve risk çubuğu çıktısı:

```bash
python main.py --stats
```


> 💡 **İpucu:** `terminal_snap.png` eklemek için `python main.py --stats` çalıştırıp terminal ekran görüntüsü alın ve `assets/terminal_snap.png` olarak kaydedin.

### PDF İstatistik Raporu

```bash
python main.py --export-pdf
```


> 💡 **İpucu:** Oluşturulan PDF'in ilk sayfasının ekran görüntüsünü `assets/report_sample.png` olarak kaydedin.

---

## 🛠️ Kurulum

**Gereksinimler:** Python 3.10+

```bash
# Repoyu klonlayın
git clone https://github.com/your-org/phishlens-tr.git
cd phishlens-tr

# Sanal ortam (önerilir)
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/macOS

# Paketi ve bağımlılıkları yükleyin (src layout)
pip install -e .
# veya: pip install -r requirements.txt && pip install -e .
```

### 🔑 API Yapılandırması (Opsiyonel)

VirusTotal, AbuseIPDB ve OpenAI için:

```bash
cp .env.example .env
# .env dosyasını düzenleyin
```

---

## 📦 Kullanım

### İnteraktif Analiz

```bash
python main.py
```

### İstatistik Raporu (Terminal)

```bash
python main.py --stats
```

### PDF Rapor Oluşturma

```bash
python main.py --export-pdf
```

### .eml Dosyasından Analiz

```bash
python main.py -f süpheli.eml
```

### Raporu Dosyaya Kaydetme

```bash
python main.py -o rapor.txt
```

### Tüm CLI Seçenekleri

| Seçenek | Açıklama |
|---------|----------|
| `-o`, `--output` | Rapor dosya adı |
| `--no-prompt` | Rapor kaydı sorusu sorma |
| `--no-api` | VirusTotal/AbuseIPDB çağrılarını atla |
| `--llm` | %50–%70 risk bandında AI açıklaması |
| `--no-history` | Analiz geçmişini history.db'ye kaydetme |
| `--no-log` | Log dosyasına kaydetme |
| `-f`, `--file` | .eml dosyasından analiz |
| `--stats` | İstatistik raporunu göster |
| `--export-pdf` | PDF rapor oluştur |

---

## 🌐 Web Arayüzü

Streamlit ile modern web arayüzü:

```bash
streamlit run app.py
```

Tarayıcıda **http://localhost:8501** açılır.

---

## 🐳 Docker

```bash
# Linux/macOS
chmod +x run.sh && ./run.sh

# Windows (PowerShell)
.\run.ps1

# veya doğrudan
cp .env.example .env
docker compose up -d
```

---

## 📚 Wiki

Detaylı dokümantasyon için [GitHub Wiki](https://github.com/your-org/phishlens-tr/wiki) sayfasını ziyaret edin:

- [Kurulum](wiki/Kurulum.md)
- [Yapılandırma](wiki/Yapilandirma.md)
- [Özellikler](wiki/Ozellikler.md)
- [CLI Referansı](wiki/CLI-Referansi.md)
- [Sorun Giderme](wiki/Sorun-Giderme.md)

---

## 📁 Proje Yapısı (src layout)

```
phishlens-tr/
├── src/
│   └── phishlens/       # Ana paket
│       ├── engine/      # URL, metin analizi, API entegrasyonu
│       ├── data/        # keywords.json, tehdit beslemeleri
│       ├── utils/       # logger, stats, exporter, file_log, console
│       ├── scanner.py   # Merkezi tarayıcı
│       ├── rules.py     # Phishing kuralları
│       ├── core.py      # CLI mantığı
│       ├── apis.py      # VirusTotal, AbuseIPDB
│       ├── eml_parser.py, email_auth.py, db.py, ...
│       └── __init__.py
├── assets/              # README görselleri, stats.json
├── wiki/                # Wiki dokümantasyonu
├── logs/                # analysis_history.jsonl, phishlens_YYYY-MM-DD.log
├── reports/             # PDF raporları
├── app.py               # Streamlit web arayüzü
├── main.py              # Giriş noktası
├── pyproject.toml       # Paket yapılandırması
├── tests/
├── requirements.txt
└── README.md
```

---

## 🧪 Testler

```bash
pip install -e .
pytest tests/ -v
```

---

## 🤝 Katkıda Bulunma

1. **Fork** edin ve **clone** alın
2. Yeni bir **branch** oluşturun: `git checkout -b feature/yeni-ozellik`
3. Değişikliklerinizi **commit** edin: `git commit -m "feat: yeni özellik eklendi"`
4. **Push** edin: `git push origin feature/yeni-ozellik`
5. **Pull Request** açın

---

## ⚠️ Sorumluluk Reddi

Bu araç **eğitim ve farkındalık** amaçlıdır. Adli incelemenin, hukuki değerlendirmenin veya uzman analizinin yerini tutmaz.

---

## 🇬🇧 English

PhishLens-TR is a **rule-based phishing analysis tool** for education and awareness. It detects social engineering indicators, suspicious URLs, and Turkey-specific bank/courier phishing patterns. Features include live threat feeds (OpenPhish, PhishTank), heuristic URL analysis, PDF reporting, and AI-assisted explanations.

```bash
pip install -r requirements.txt
python main.py --stats      # View statistics
python main.py --export-pdf # Generate PDF report
```

---

## 📜 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

> **Not:** GitHub badge'lerindeki `your-org` kısmını kendi kullanıcı/organizasyon adınızla değiştirin.

---

<!-- PHISHLENS_WEEKLY_STATS_START -->
### 📊 Haftalık Özet (Son 7 Gün)

| Metrik | Değer |
|--------|-------|
| Toplam Tarama | 2 |
| Yakalanan Tehdit | 2 |
| Güvenli | 0 |
| Tehdit Oranı | %100.0 |
| Güvenlik Skoru | %0.0 |

**En Çok Taklit Edilen Kurumlar:**
- Garanti: 1
- Banka: 1

<!-- PHISHLENS_WEEKLY_STATS_END -->
>>>>>>> 225d027 (Initial release: v1.0.0 - Full Phishing Analysis Suite)
