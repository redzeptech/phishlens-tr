"""
PhishLens TR - Duygu ve Risk Skoru.

Türkçe oltalama metinlerinde sık kullanılan anahtar kelimelerin yoğunluğu
ve büyük harf kullanım oranına dayalı risk analizi.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


EMOTION_RISK_KEYWORDS: dict[str, list[str]] = {
    "aciliyet": [
        "acil", "hemen", "derhal", "son dakika", "son uyarı",
        "süre doluyor", "süresi dolmak", "kapatılacak", "askıya alınacak",
    ],
    "eylem_talebi": [
        "giriş yap", "giriş yapın", "tıklayın", "tıklayınız",
        "doğrulayın", "onaylayın", "güncelleyin", "güncelle",
        "şifrenizi girin", "otp girin", "kod girin",
    ],
    "ödül_hediye": [
        "hediye", "ödül", "kazandınız", "kazandın", "çekiliş",
        "kampanya", "indirim", "bedava", "ücretsiz", "bonus",
    ],
    "tebrik": [
        "tebrikler", "tebrik ederiz", "kutluyoruz", "seçildiniz",
        "ödüle layık", "şanslısınız",
    ],
    "tehdit": [
        "hesabınız kapatılacak", "bloke", "askıya alındı",
        "borç", "icra", "ceza", "dava",
    ],
    "doğrulama": [
        "kimlik doğrulama", "hesap doğrulama", "kart doğrulama",
        "telefon doğrulama", "e-posta doğrulama",
    ],
}

ALL_EMOTION_KEYWORDS: list[str] = [
    kw for keywords in EMOTION_RISK_KEYWORDS.values() for kw in keywords
]


@dataclass
class EmotionRiskResult:
    """Duygu ve Risk Skoru analiz sonucu."""

    score: float
    keyword_count: int
    keyword_density: float
    uppercase_ratio: float
    keywords_found: list[str] = field(default_factory=list)
    category_hits: dict[str, list[str]] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "keyword_count": self.keyword_count,
            "keyword_density": round(self.keyword_density, 4),
            "uppercase_ratio": round(self.uppercase_ratio, 4),
            "keywords_found": self.keywords_found,
            "category_hits": self.category_hits,
            "details": self.details,
        }


def _count_words(text: str) -> int:
    if not text or not text.strip():
        return 0
    return len(re.findall(r"\S+", text))


def _get_uppercase_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c.isupper()) / len(letters)


def _find_keywords(text: str) -> tuple[list[str], dict[str, list[str]]]:
    text_lower = text.lower()
    all_found: list[str] = []
    by_category: dict[str, list[str]] = {}
    for category, keywords in EMOTION_RISK_KEYWORDS.items():
        found_in_cat: list[str] = []
        for kw in keywords:
            pattern = r"\b" + re.escape(kw) + r"\b"
            if re.search(pattern, text_lower, re.IGNORECASE):
                found_in_cat.append(kw)
                if kw not in all_found:
                    all_found.append(kw)
        if found_in_cat:
            by_category[category] = found_in_cat
    return all_found, by_category


def compute_emotion_risk_score(text: str) -> EmotionRiskResult:
    """Duygu ve Risk Skoru üretir."""
    word_count = _count_words(text)
    uppercase_ratio = _get_uppercase_ratio(text)
    keywords_found, category_hits = _find_keywords(text)
    keyword_count = len(keywords_found)

    if word_count > 0:
        text_lower = text.lower()
        total_keyword_occurrences = sum(
            len(re.findall(r"\b" + re.escape(kw) + r"\b", text_lower))
            for kw in keywords_found
        )
        keyword_density = total_keyword_occurrences / word_count
    else:
        keyword_density = 0.0

    keyword_score = min(50, keyword_count * 5 + min(30, keyword_density * 50))
    if uppercase_ratio >= 0.5:
        caps_score = 50
    elif uppercase_ratio >= 0.3:
        caps_score = 30 + (uppercase_ratio - 0.3) * 100
    elif uppercase_ratio >= 0.15:
        caps_score = 10 + (uppercase_ratio - 0.15) * 133
    elif uppercase_ratio >= 0.05:
        caps_score = uppercase_ratio * 200
    else:
        caps_score = 0

    total_score = min(100.0, keyword_score + caps_score)

    return EmotionRiskResult(
        score=total_score,
        keyword_count=keyword_count,
        keyword_density=keyword_density,
        uppercase_ratio=uppercase_ratio,
        keywords_found=keywords_found,
        category_hits=category_hits,
        details={
            "keyword_score_component": round(keyword_score, 2),
            "uppercase_score_component": round(caps_score, 2),
            "word_count": word_count,
        },
    )
