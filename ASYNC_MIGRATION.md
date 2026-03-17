# PhishLens TR - Async/Await Geçiş Planı

Bu belge, projenin asenkron yapıya geçişinde dikkate alınacak noktaları özetler.

## Mevcut Durum

- Tüm işlemler senkron (bloklayıcı)
- `input()`, `Path.write_text()` gibi I/O işlemleri ana thread'i bloke ediyor

## Async Geçişe Uygun Fonksiyonlar

| Fonksiyon | Öncelik | Gerekçe |
|-----------|---------|---------|
| `save_report()` | Yüksek | Dosya yazma I/O; `aiofiles` veya `asyncio.to_thread()` ile non-blocking yapılabilir |
| `analyze_message()` | Orta | CPU-bound; `asyncio.to_thread()` ile event loop bloklanmadan çalıştırılabilir |
| `extract_urls()` | Düşük | Hafif; analiz içinde çağrılıyor |

## Gelecek Özellikler İçin Async Fırsatları

1. **URL doğrulama (DNS/HTTP)**  
   - `aiohttp` veya `httpx` ile async HTTP istekleri  
   - Birden fazla URL paralel kontrol edilebilir (`asyncio.gather`)

2. **Toplu mesaj analizi**  
   - `asyncio.gather()` ile birden fazla mesaj eşzamanlı analiz edilebilir

3. **Etkileşimli giriş**  
   - `aioconsole` veya async event loop ile `input()` bloklaması azaltılabilir

## Örnek Async Yapı (Referans)

```python
# save_report için async alternatif (aiofiles gerekir)
async def save_report_async(report_text: str, output_path: str | None) -> Path:
    import aiofiles
    path = Path(output_path) if output_path else Path(default_report_filename())
    async with aiofiles.open(path, "w", encoding="utf-8") as f:
        await f.write(report_text)
    return path

# analyze_message için thread pool (CPU-bound)
async def analyze_message_async(text: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, analyze_message, text)
```

## Bağımlılık Notu

Async geçiş için opsiyonel paketler:
- `aiofiles` – async dosya I/O
- `aiohttp` veya `httpx` – async HTTP (URL doğrulama eklenirse)
