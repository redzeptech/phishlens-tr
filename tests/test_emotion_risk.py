"""Duygu ve Risk Skoru testleri."""

import pytest

from phishlens.emotion_risk import (
    compute_emotion_risk_score,
    EMOTION_RISK_KEYWORDS,
    ALL_EMOTION_KEYWORDS,
)


class TestEmotionRiskKeywords:
    """Anahtar kelime sözlüğü testleri."""

    def test_keywords_exist(self):
        assert "acil" in ALL_EMOTION_KEYWORDS
        assert "hemen" in ALL_EMOTION_KEYWORDS
        assert "giriş yap" in ALL_EMOTION_KEYWORDS
        assert "hediye" in ALL_EMOTION_KEYWORDS
        assert "ödül" in ALL_EMOTION_KEYWORDS
        assert "tebrikler" in ALL_EMOTION_KEYWORDS

    def test_categories(self):
        assert "aciliyet" in EMOTION_RISK_KEYWORDS
        assert "ödül_hediye" in EMOTION_RISK_KEYWORDS
        assert "tebrik" in EMOTION_RISK_KEYWORDS


class TestComputeEmotionRiskScore:
    """compute_emotion_risk_score fonksiyonu testleri."""

    def test_high_risk_phishing_text(self):
        text = "ACİL! Hemen giriş yap, hediye kazandınız! TEBRİKLER!"
        result = compute_emotion_risk_score(text)
        assert result.score >= 50
        assert len(result.keywords_found) >= 3
        assert result.uppercase_ratio > 0.1

    def test_low_risk_normal_text(self):
        text = "Merhaba, yarın saat 14'te buluşalım mı?"
        result = compute_emotion_risk_score(text)
        assert result.score < 20
        assert len(result.keywords_found) == 0

    def test_keyword_density(self):
        text = "acil acil acil hemen hemen hediye hediye"
        result = compute_emotion_risk_score(text)
        assert result.keyword_count >= 2
        assert result.keyword_density > 0

    def test_uppercase_only(self):
        text = "BU BİR TEST MESAJIDIR"
        result = compute_emotion_risk_score(text)
        assert result.uppercase_ratio == 1.0
        assert result.score >= 40  # Sadece büyük harf bile skor artırır

    def test_empty_text(self):
        result = compute_emotion_risk_score("")
        assert result.score == 0
        assert result.keyword_count == 0
        assert result.uppercase_ratio == 0.0

    def test_to_dict(self):
        result = compute_emotion_risk_score("acil hemen")
        d = result.to_dict()
        assert "score" in d
        assert "keyword_count" in d
        assert "keyword_density" in d
        assert "uppercase_ratio" in d
        assert "keywords_found" in d
