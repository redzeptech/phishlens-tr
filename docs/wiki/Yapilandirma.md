# Yapılandırma

## .env Dosyası

`.env.example` dosyasını `.env` olarak kopyalayın:

```bash
cp .env.example .env
```

## API Anahtarları

| Servis | Değişken | Açıklama |
|--------|----------|----------|
| VirusTotal | `VIRUSTOTAL_API_KEY` | URL/IP taraması |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP kötüye kullanım kontrolü |
| OpenAI | `OPENAI_API_KEY` | LLM analizi (--llm) |

### Anahtar Alma

- **VirusTotal:** [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
- **AbuseIPDB:** [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api)
- **OpenAI:** [platform.openai.com/api-keys](https://platform.openai.com/api-keys)

## API Olmadan Çalıştırma

Anahtar yoksa `--no-api` ile API çağrıları atlanır:

```bash
python main.py --no-api
```

## Dinamik Badge (Shields.io)

`assets/stats.json` dosyası haftalık güncellenir. Base URL: `https://raw.githubusercontent.com/OWNER/REPO/main/assets/stats.json`

| Badge | query | label |
|-------|-------|-------|
| Captured Phish | `$.malicious` | Captured Phish |
| Total Scans | `$.total` | Total Scans |
| Security Score | `$.security_score` | Security Score |

Örnek: `https://img.shields.io/badge/dynamic/json?url=RAW_URL&label=Captured%20Phish&query=%24.malicious&color=dc3545`

## Ollama Kullanımı

Yerel LLM için Ollama kullanılabilir:

```bash
ollama run llama2
python main.py --llm
```

`llm_provider` ortam değişkeni ile sağlayıcı seçilebilir: `openai`, `ollama`, `auto`.
