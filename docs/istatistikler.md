# İstatistikler

## Terminal İstatistikleri

`phishlens --stats` komutu ile analiz geçmişi özetlenir:

- **Toplam Analiz Sayısı**
- **Tespit Edilen Oltalama (Malicious)**
- **Güvenli (Safe)**
- **Başarı Oranı (%)**
- **En Çok Eşleşen Tehdit Kaynağı**
- **En Çok Taklit Edilen 3 Kurum**

## PDF Rapor

```bash
phishlens --export-pdf
```

Rapor `reports/report_YYYYMMDD_HHMM.pdf` dosyasına kaydedilir.

## Veri Kaynağı

İstatistikler `logs/analysis_history.jsonl` dosyasından okunur. Her analiz sonucu bu dosyaya JSON Lines formatında eklenir.
