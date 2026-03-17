# Özellikler

## Analiz Türleri

### 1. Metin Analizi (Content)
- Şüpheli kelimeler (acil, hemen, ödeme, vb.)
- Resmi kurum çağrışımları (ptt, banka, edevlet)
- Regex kuralları (IBAN doğrulama, kargo takip, vb.)
- Duygu ve risk skoru (anahtar kelime yoğunluğu, büyük harf oranı)

### 2. URL Analizi
- Şüpheli TLD'ler (.xyz, .top, .click vb.)
- Domain benzerliği (Levenshtein / typosquatting)
- Heuristik kontroller:
  - Homograph saldırıları
  - URL'de @ sembolü
  - Fazla subdomain
  - Uzun URL
  - Rastgele karakter dizileri

### 3. E-posta Analizi (.eml)
- SPF, DKIM, DMARC kontrolü
- Gönderici IP ve domain analizi

### 4. Tehdit Beslemeleri
- OpenPhish
- PhishTank
- Cache ile güncel veri

## Raporlama

| Çıktı | Komut |
|-------|-------|
| Terminal istatistikleri | `--stats` |
| PDF rapor | `--export-pdf` |
| Tarih bazlı log | `logs/phishlens_YYYY-MM-DD.log` |
| Analiz geçmişi | `logs/analysis_history.jsonl` |

## Risk Seviyeleri

- **DÜŞÜK:** Skor 0–4
- **ORTA:** Skor 5–8
- **YÜKSEK:** Skor 9+
