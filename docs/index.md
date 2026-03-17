# PhishLens-TR

**Türkiye odaklı, kural tabanlı phishing tespit aracı.**

PhishLens-TR, şüpheli SMS ve e-posta metinlerinde oltalama (phishing) tespiti yapan eğitim amaçlı bir siber güvenlik platformudur. Kural tabanlı analiz, URL heuristikleri, tehdit beslemeleri (OpenPhish, PhishTank) ve opsiyonel AI destekli açıklamalarla risk skoru üretir.

## Vizyon

- **Eğitim ve farkındalık:** Kullanıcıları phishing tehditlerine karşı bilinçlendirmek
- **Türkiye odaklı:** Banka, kargo, e-devlet temalı phishing kuralları
- **Modüler mimari:** Kural setleri, API entegrasyonları ve raporlama bileşenleri

## Hızlı Başlangıç (Quick Start)

```bash
# Paketi kur
pip install -e .

# İstatistikleri görüntüle
phishlens --stats

# PDF rapor oluştur
phishlens --export-pdf

# İnteraktif analiz
phishlens
```

## Özellikler

- 🔍 Canlı tehdit beslemeleri (OpenPhish, PhishTank)
- 📊 PDF raporlama
- 🎨 Rich terminal çıktıları
- 🔗 Heuristik URL analizi
- 🇹🇷 Türkiye odaklı kurallar
