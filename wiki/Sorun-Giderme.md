# Sorun Giderme

## Sık Karşılaşılan Hatalar

### "ModuleNotFoundError: No module named 'fpdf2'"

```bash
pip install -r requirements.txt
```

### "ModuleNotFoundError: No module named 'src'"

Proje kök dizininden çalıştırın:

```bash
cd phishlens-tr
python main.py
```

### Türkçe karakterler bozuk görünüyor

- **Terminal:** `chcp 65001` (Windows) veya UTF-8 locale ayarlayın
- **PDF:** Arial veya DejaVu fontu otomatik kullanılır

### API anahtarı hatası

Anahtar yoksa `--no-api` kullanın:

```bash
python main.py --no-api
```

### "FileNotFoundError: logs/analysis_history.jsonl"

İlk analiz çalıştırıldığında otomatik oluşur. `main.py` başlangıçta `logs/` klasörünü oluşturur.

### PDF oluşturuldu ama görüntülenmiyor

- `reports/` klasörünü kontrol edin
- Dosya yolu: `reports/report_YYYYMMDD_HHMM.pdf`

## Destek

Sorun devam ederse [GitHub Issues](https://github.com/your-org/phishlens-tr/issues) üzerinden bildirin.
