# API Referansı

## Ana Fonksiyonlar

### analyze_message

```python
from phishlens import analyze_message

result = analyze_message(
    text="Şüpheli mesaj metni",
    use_api=True,
    use_llm=False,
)
# result: {"risk": "YÜKSEK", "score": 12, "hits": {...}}
```

### analyze_eml_file

```python
from phishlens import analyze_eml_file

result = analyze_eml_file("süpheli.eml")
# result: analyze_message çıktısı + eml_metadata, email_auth
```

### format_report

```python
from phishlens import format_report

report_text = format_report(text, result)
```

## Scanner Sınıfı

```python
from phishlens.scanner import Scanner

scanner = Scanner(use_api=True, use_llm=False)
result = scanner.scan("Metin içeriği")
```
