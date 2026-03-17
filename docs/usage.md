# Kullanım Rehberi

Terminal komutlarının detaylı açıklamaları ve örnek çıktıları.

## Genel Kullanım

```bash
phishlens [SEÇENEKLER]
```

---

## --stats

Analiz geçmişi istatistiklerini gösterir. `logs/analysis_history.jsonl` dosyasından veri okur.

### Açıklama

- Toplam analiz sayısı
- Tespit edilen oltalama (malicious) sayısı
- Güvenli (safe) sayısı
- Başarı oranı (%)
- En çok eşleşen tehdit kaynağı
- En çok taklit edilen 3 kurum (pasta grafiği benzeri)

### Örnek

```bash
phishlens --stats
```

### Örnek Çıktı

```
           PhishLens TR - Analiz İstatistikleri
┌────────────────────────────────────┬────────────────────┐
│ Metrik                             │              Değer │
├────────────────────────────────────┼────────────────────┤
│ Toplam Analiz Sayısı               │                 82 │
│ Tespit Edilen Oltalama (Malicious) │                 48 │
│ Güvenli (Safe)                     │                 34 │
│ Başarı Oranı (%)                   │              58.5% │
│ En Çok Eşleşen Tehdit Kaynağı      │ Regex (40 eşleşme) │
└────────────────────────────────────┴────────────────────┘

Risk Oranı -----------------------                     59%

┌──────────────────────── En Çok Taklit Edilen 3 Kurum ────────────────────────┐
│ ████████████████████████████████████                                         │
│ [red]Banka[/red] 50%  [orange1]Garanti[/orange1] 27%  [yellow3]Google[/yellow3] 23% │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## --export-pdf

Analiz geçmişini PDF rapor olarak `reports/` klasörüne dışa aktarır.

### Açıklama

- `logs/analysis_history.jsonl` verilerini okur
- Özet istatistikler, risk çubukları ve son 10 analiz tablosu içerir
- Dosya adı: `reports/report_YYYYMMDD_HHMM.pdf`

### Örnek

```bash
phishlens --export-pdf
```

### Örnek Çıktı

```
Rapor başarıyla oluşturuldu: C:\...\phishlens-tr\reports\report_20260317_2100.pdf
```

---

## -f, --file

`.eml` dosyasından analiz yapar (SPF/DKIM/DMARC dahil).

### Örnek

```bash
phishlens -f süpheli.eml
```

---

## -o, --output

Raporu belirtilen dosyaya kaydeder.

### Örnek

```bash
phishlens -o rapor.txt
```

---

## Diğer Seçenekler

| Seçenek | Açıklama |
|---------|----------|
| `--no-api` | VirusTotal/AbuseIPDB çağrılarını atla |
| `--llm` | %50–%70 risk bandında AI açıklaması |
| `--no-history` | Analiz geçmişini history.db'ye kaydetme |
| `--no-log` | Log dosyasına kaydetme |
| `--no-prompt` | Rapor kaydı sorusu sorma |
