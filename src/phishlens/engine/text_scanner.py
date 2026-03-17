"""
PhishLens TR - Metin ve NLP analizi.

Şüpheli kelimeler, regex kuralları, Duygu ve Risk Skoru.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from phishlens.data import load_keywords


def _get_keywords() -> dict[str, Any]:
    return load_keywords()


def apply_regex_rules(text: str) -> tuple[int, list[tuple[str, str]]]:
    kw = _get_keywords()
    rules = kw.get("regex_rules", [])
    text_lower = text.lower()
    total_score = 0
    hits = []
    for rule in rules:
        pattern = rule.get("pattern", "")
        score = rule.get("score", 0)
        description = rule.get("description", "")
        for match in re.finditer(pattern, text_lower, re.IGNORECASE):
            total_score += score
            hits.append((description, match.group(0)))
    return total_score, hits


@dataclass
class EmotionRiskResult:
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


def compute_emotion_risk_score(text: str) -> EmotionRiskResult:
    kw = _get_keywords()
    emotion_keywords = kw.get("emotion_risk_keywords", {})
    word_count = _count_words(text)
    uppercase_ratio = _get_uppercase_ratio(text)

    text_lower = text.lower()
    all_found: list[str] = []
    by_category: dict[str, list[str]] = {}
    for category, keywords in emotion_keywords.items():
        found_in_cat: list[str] = []
        for kw_item in keywords:
            pattern = r"\b" + re.escape(kw_item) + r"\b"
            if re.search(pattern, text_lower, re.IGNORECASE):
                found_in_cat.append(kw_item)
                if kw_item not in all_found:
                    all_found.append(kw_item)
        if found_in_cat:
            by_category[category] = found_in_cat

    keyword_count = len(all_found)
    if word_count > 0:
        total_occurrences = sum(
            len(re.findall(r"\b" + re.escape(k) + r"\b", text_lower))
            for k in all_found
        )
        keyword_density = total_occurrences / word_count
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
        keywords_found=all_found,
        category_hits=by_category,
        details={
            "keyword_score_component": round(keyword_score, 2),
            "uppercase_score_component": round(caps_score, 2),
            "word_count": word_count,
        },
    )


def analyze_text(text: str) -> tuple[int, dict[str, Any]]:
    kw = _get_keywords()
    suspicious_words = kw.get("suspicious_words", [])
    official_terms = kw.get("official_terms", [])

    t = text.lower()
    score = 0
    hits: dict[str, Any] = {
        "words": [], "official": [], "regex": [], "emotion_risk": {},
    }

    for w in suspicious_words:
        if w in t:
            score += 2
            hits["words"].append(w)
    for term in official_terms:
        if term in t:
            score += 2
            hits["official"].append(term)

    regex_score, regex_hits = apply_regex_rules(text)
    score += regex_score
    hits["regex"] = regex_hits

    emotion_result = compute_emotion_risk_score(text)
    hits["emotion_risk"] = emotion_result.to_dict()
    if emotion_result.score >= 70:
        score += 3
    elif emotion_result.score >= 50:
        score += 2
    elif emotion_result.score >= 30:
        score += 1

    return score, hits
