"""
PhishLens TR - LLM tabanlı phishing analizi.

Kural tabanlı sistem %50-%70 risk verdiğinde OpenAI veya yerel (Ollama)
model ile doğal dil açıklaması üretir.
"""

import os
from typing import Any

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


def _get_llm_keys() -> dict[str, str | None]:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    return {
        "openai": os.getenv("OPENAI_API_KEY"),
        "ollama_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
    }


def _compute_risk_percent(score: int, max_score: int = 25) -> float:
    return min(100.0, (score / max_score) * 100)


def is_in_llm_trigger_zone(
    score: int,
    min_percent: float = 50,
    max_percent: float = 70,
    max_score: int = 25,
) -> bool:
    """Skor %50-%70 bandındaysa LLM çağrılmalı mı?"""
    percent = _compute_risk_percent(score, max_score)
    return min_percent <= percent <= max_percent


PHISHING_SYSTEM_PROMPT = (
    "Sen bir siber güvenlik uzmanısın. Verilen metni oltalama (phishing) saldırısı "
    "açısından analiz et.\n\nGörevin:\n1. Bu metin bir oltalama saldırısı mı? Evet veya "
    "Hayır ile başla.\n2. Kısa ve anlaşılır Türkçe bir açıklama yaz.\n3. Şüpheli unsurları "
    "(acil baskı, link, banka/kargo taklidi vb.) belirt.\n4. Kullanıcıya ne yapması "
    "gerektiğini özetle.\n\nYanıtı doğal dilde, eğitim amaçlı ve net yaz. Maksimum 150 kelime."
)

PHISHING_USER_PROMPT = """Aşağıdaki metni analiz et. Bu metin bir oltalama saldırısı mı?

---
METİN:
{text}
---

Kural tabanlı sistem bu metne {score} risk skoru vermiştir (yaklaşık %{percent:.0f})."""


def analyze_with_openai(text: str, score: int, api_key: str | None = None) -> dict[str, Any]:
    """OpenAI API ile phishing analizi yapar."""
    result = {"success": False, "explanation": "", "is_phishing": None, "error": None}
    if not OPENAI_AVAILABLE:
        result["error"] = "openai kütüphanesi yüklü değil (pip install openai)"
        return result
    key = api_key or _get_llm_keys()["openai"]
    if not key:
        result["error"] = "OPENAI_API_KEY .env dosyasında tanımlı değil"
        return result
    percent = _compute_risk_percent(score)
    user_prompt = PHISHING_USER_PROMPT.format(text=text, score=score, percent=percent)
    try:
        client = OpenAI(api_key=key)
        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": PHISHING_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=500,
            temperature=0.3,
        )
        content = response.choices[0].message.content or ""
        result["success"] = True
        result["explanation"] = content.strip()
        content_lower = content.lower()
        if "evet" in content_lower[:50] or "phishing" in content_lower[:100]:
            result["is_phishing"] = True
        elif "hayır" in content_lower[:50]:
            result["is_phishing"] = False
    except Exception as e:
        result["error"] = f"OpenAI hatası: {e}"
    return result


def analyze_with_ollama(text: str, score: int, base_url: str | None = None) -> dict[str, Any]:
    """Ollama (yerel model) ile phishing analizi yapar."""
    result = {"success": False, "explanation": "", "is_phishing": None, "error": None}
    if not REQUESTS_AVAILABLE:
        result["error"] = "requests kütüphanesi yüklü değil"
        return result
    url = base_url or _get_llm_keys()["ollama_url"]
    model = os.getenv("OLLAMA_MODEL", "llama3.2")
    percent = _compute_risk_percent(score)
    user_prompt = PHISHING_USER_PROMPT.format(text=text, score=score, percent=percent)
    full_prompt = f"{PHISHING_SYSTEM_PROMPT}\n\n{user_prompt}"
    try:
        resp = requests.post(
            f"{url.rstrip('/')}/api/generate",
            json={
                "model": model,
                "prompt": full_prompt,
                "stream": False,
                "options": {"temperature": 0.3, "num_predict": 500},
            },
            timeout=60,
        )
        if resp.status_code == 200:
            data = resp.json()
            content = data.get("response", "").strip()
            result["success"] = True
            result["explanation"] = content
            content_lower = content.lower()
            if "evet" in content_lower[:80] or "phishing" in content_lower[:150]:
                result["is_phishing"] = True
            elif "hayır" in content_lower[:80]:
                result["is_phishing"] = False
        else:
            result["error"] = f"Ollama hatası: {resp.status_code}"
    except requests.RequestException as e:
        result["error"] = f"Ollama bağlantı hatası: {e}"
    return result


def get_llm_analysis(
    text: str,
    score: int,
    provider: str = "auto",
) -> dict[str, Any]:
    """LLM ile phishing analizi. provider: 'openai', 'ollama' veya 'auto'."""
    keys = _get_llm_keys()
    if provider == "openai" or (provider == "auto" and keys["openai"]):
        return analyze_with_openai(text, score, keys["openai"])
    if provider == "ollama" or (provider == "auto" and not keys["openai"]):
        return analyze_with_ollama(text, score, keys["ollama_url"])
    result = analyze_with_openai(text, score, keys["openai"])
    if not result["success"] and result.get("error", "").find("tanımlı değil") >= 0:
        result = analyze_with_ollama(text, score, keys["ollama_url"])
    return result
