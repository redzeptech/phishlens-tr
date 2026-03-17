# Rich Konsol Çıktısına Geçiş Rehberi

PhishLens TR ana çıktı mekanizması `src/utils/console.py` modülü ile Rich kütüphanesine hazırlanmıştır.

## Mevcut Yapı

- **requirements.txt:** `rich>=13.0.0` eklendi
- **src/utils/console.py:** Rich tabanlı çıktı fonksiyonları

## Kullanılabilir Fonksiyonlar

| Fonksiyon | Açıklama |
|-----------|----------|
| `print_risk_result(risk, score, details)` | Analiz sonucu Panel |
| `print_success(message)` | Yeşil başarı mesajı |
| `print_error(message)` | Kırmızı hata mesajı |
| `print_warning(message)` | Sarı uyarı mesajı |
| `print_info(message)` | Mavi bilgi mesajı |
| `print_header(title, subtitle)` | Başlık Panel |
| `print_table(headers, rows, title)` | Tablo |
| `print_markdown(text)` | Markdown metin |
| `print_plain(*args)` | Genel Rich print |

## phishlens.py Geçiş Eşlemesi

| Mevcut | Rich Alternatifi |
|--------|------------------|
| `print("PhishLens TR - Mesaj Risk Analizi")` | `print_header("Mesaj Risk Analizi", "Bir SMS/e-posta metnini girin")` |
| `print("Risk:", result["risk"])` | `print_risk_result(result["risk"], result["score"], {...})` |
| `print(f"\nHata: {e}")` | `print_error(str(e))` |
| `print(f"Rapor kaydedildi: {path}")` | `print_success(f"Rapor kaydedildi: {path}")` |

## Örnek Geçiş

```python
# Önce
from phishlens import analyze_message, format_report
# ...
print("\nSonuç")
print("Risk:", result["risk"])
print("Skor:", result["score"])

# Sonra
from src.utils.console import print_risk_result, print_success, print_error
# ...
details = {}
if result.get("email_auth", {}).get("details"):
    details["E-posta auth"] = "; ".join(result["email_auth"]["details"])
print_risk_result(result["risk"], result["score"], details)
```

## Fallback

Rich yüklü değilse fonksiyonlar standart `print()` kullanır.
