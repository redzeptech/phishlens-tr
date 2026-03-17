"""
PhishLens TR - Phishing tespit kuralları.

Türkiye'deki banka ve kargo temalı oltalama SMS/E-posta örneklerine
yönelik kural setleri ve regex tabanlı kontroller.

Not: Ana veri phishlens/data/keywords.json'da, motor phishlens/engine/ altındadır.
Bu modül geriye dönük uyumluluk için re-export sağlar.
"""

import re
from urllib.parse import urlparse

# phishlens/data'dan yükle (geriye dönük uyumluluk)
try:
    from phishlens.data import load_keywords
    _kw = load_keywords()
    SUSPICIOUS_WORDS = _kw.get("suspicious_words", [])
    SUSPICIOUS_TLDS = _kw.get("suspicious_tlds", [])
    OFFICIAL_TERMS = _kw.get("official_terms", [])
    KNOWN_LEGITIMATE_DOMAINS = _kw.get("known_legitimate_domains", [])
    REGEX_RULES = [
        (r["pattern"], r["score"], r["description"])
        for r in _kw.get("regex_rules", [])
    ]
except ImportError:
    # phishlens yoksa fallback (standalone çalışma)
    SUSPICIOUS_WORDS = [
        "acil", "hemen", "son uyarı", "hesabınız kapatılacak",
        "kimlik doğrulama", "ödeme", "borç", "icra", "güncelle",
        "teslim edilemedi", "paket", "kargonuz", "şifreniz", "doğrulayın",
        "ceza", "bloke", "askıya alındı", "işleminiz", "onaylayın"
    ]
    SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".online", ".site", ".icu", ".info"]
    OFFICIAL_TERMS = ["ptt", "banka", "edevlet", "e-devlet", "vergi", "kargo", "icra"]
    KNOWN_LEGITIMATE_DOMAINS = [
        "garanti.com.tr", "yapikredi.com.tr", "isbank.com.tr",
        "akbank.com", "ziraatbank.com.tr", "qnb.com.tr",
        "denizbank.com", "teb.com.tr", "halkbank.com.tr",
        "ptt.gov.tr", "ptten.com", "mngkargo.com.tr",
        "aras.com.tr", "yurticikargo.com.tr", "hepsiburada.com",
        "trendyol.com", "n11.com", "gittigidiyor.com",
        "turkcell.com.tr", "turktelekom.com.tr", "vodafone.com.tr",
        "google.com", "google.com.tr", "microsoft.com",
        "edevlet.gov.tr", "gib.gov.tr", "tcmb.gov.tr",
    ]
    REGEX_RULES = [
        (r"\b(kartı(nız|nı)|kartınız)\s*(bloke|askıya|askıya alındı)\b", 3, "Banka kartı bloke/askıya alındı ifadesi"),
        (r"\b(iban|hesap)\s*(doğrulama|güncelleme|güncelle)\b", 3, "IBAN/hesap doğrulama talebi"),
        (r"\b(otp|doğrulama kodu|şifre|sms kodu)\s*(girin|gönderin|giriniz)\b", 3, "OTP/doğrulama kodu giriş talebi"),
        (r"\b(kargo|gönderi)\s*(takip|yola çıktı|teslimat|numara)\b", 3, "Kargo takip / teslimat mesajı"),
        (r"\b(son\s*)?(24\s*saat|48\s*saat|gün\s*içinde)\b", 3, "Acil süre baskısı"),
    ]


def levenshtein_distance(s1: str, s2: str) -> int:
    """İki string arasındaki Levenshtein (düzenleme) mesafesini hesaplar."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr.append(min(
                prev[j + 1] + 1,
                curr[j] + 1,
                prev[j] + cost
            ))
        prev = curr
    return prev[-1]


def extract_urls(text: str) -> list[str]:
    """Metinden HTTP/HTTPS ve www ile başlayan URL'leri çıkarır."""
    return re.findall(r"(https?://\S+|www\.\S+)", text, re.IGNORECASE)


def extract_domain(url: str) -> str | None:
    """URL'den domain (host) çıkarır."""
    try:
        url_lower = url.lower().strip()
        if not url_lower.startswith(("http://", "https://", "www.")):
            url_lower = "https://" + url_lower
        parsed = urlparse(url_lower)
        netloc = parsed.netloc or parsed.path
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc if netloc else None
    except Exception:
        return None


def check_domain_similarity(
    domain: str,
    known_domains: list[str] | None = None,
    max_distance: int = 2,
    min_length: int = 6,
) -> list[tuple[str, int, float]]:
    """Domain'i bilinen meşru domainlerle Levenshtein mesafesine göre karşılaştırır."""
    if known_domains is None:
        known_domains = KNOWN_LEGITIMATE_DOMAINS

    domain = domain.lower().strip()
    if len(domain) < min_length:
        return []

    matches = []
    for known in known_domains:
        known = known.lower()
        dist = levenshtein_distance(domain, known)
        if 0 < dist <= max_distance:
            max_len = max(len(domain), len(known))
            similarity = 1 - (dist / max_len)
            matches.append((known, dist, similarity))

    return sorted(matches, key=lambda x: x[1])


def apply_regex_rules(text: str) -> tuple[int, list[tuple[str, str]]]:
    """Metne regex tabanlı phishing kurallarını uygular."""
    text_lower = text.lower()
    total_score = 0
    hits = []

    for pattern, score, description in REGEX_RULES:
        for match in re.finditer(pattern, text_lower, re.IGNORECASE):
            total_score += score
            hits.append((description, match.group(0)))

    return total_score, hits
