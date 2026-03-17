# PhishLens-TR Wiki

PhishLens-TR projesinin detaylı dokümantasyonuna hoş geldiniz.

## İçindekiler

- [Kurulum](Kurulum) — Adım adım kurulum rehberi
- [Yapılandırma](Yapilandirma) — API anahtarları ve .env ayarları
- [Özellikler](Ozellikler) — Analiz türleri, tehdit beslemeleri, raporlama
- [CLI Referansı](CLI-Referansi) — Tüm komut satırı seçenekleri
- [Sorun Giderme](Sorun-Giderme) — Sık karşılaşılan hatalar ve çözümler

## Hızlı Başlangıç

```bash
pip install -r requirements.txt
python main.py --stats      # İstatistikleri görüntüle
python main.py --export-pdf # PDF rapor oluştur
```

## Kısa Özet

PhishLens-TR, şüpheli SMS ve e-posta metinlerinde oltalama (phishing) tespiti yapan bir araçtır. Kural tabanlı analiz, URL heuristikleri, tehdit beslemeleri (OpenPhish, PhishTank) ve opsiyonel AI destekli açıklamalarla risk skoru üretir.
