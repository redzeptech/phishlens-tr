# CLI Referansı

## Ana Komutlar

```bash
python main.py              # İnteraktif mod
python main.py --stats      # İstatistik raporu
python main.py --export-pdf # PDF rapor oluştur
```

## Tüm Seçenekler

| Seçenek | Kısa | Açıklama |
|---------|------|----------|
| `--output` | `-o` | Rapor dosya adı |
| `--no-prompt` | — | Rapor kaydı sorusu sorma |
| `--no-api` | — | VirusTotal/AbuseIPDB atla |
| `--llm` | — | AI açıklaması (%50–%70 risk) |
| `--no-history` | — | history.db'ye kaydetme |
| `--no-log` | — | Log dosyasına kaydetme |
| `--file` | `-f` | .eml dosyasından analiz |
| `--stats` | — | İstatistik raporu göster |
| `--export-pdf` | — | PDF rapor oluştur |

## Örnekler

```bash
# Raporu belirli dosyaya kaydet
python main.py -o rapor.txt

# API olmadan analiz
python main.py --no-api

# E-posta dosyasından analiz
python main.py -f süpheli.eml

# Rapor sorusunu atla
python main.py --no-prompt
```

## phishlens.py ile Doğrudan

```bash
python -m phishlens --stats
python -m phishlens --export-pdf
```
