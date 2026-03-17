"""Analiz mantığı testleri - pozitif ve negatif senaryolar."""

import pytest

from phishlens import analyze_message, format_report

from .conftest import PHISHING_SAMPLES, SAFE_SAMPLES


class TestPositiveScenarios:
    """Gerçek phishing senaryoları - YÜKSEK veya ORTA risk beklenir."""

    @pytest.mark.parametrize(
        "key,message",
        [
            ("banka_kart_bloke", PHISHING_SAMPLES["banka_kart_bloke"]),
            ("iban_dogrulama", PHISHING_SAMPLES["iban_dogrulama"]),
            ("otp_talebi", PHISHING_SAMPLES["otp_talebi"]),
            ("kargo_takip", PHISHING_SAMPLES["kargo_takip"]),
            ("acil_sure_baskisi", PHISHING_SAMPLES["acil_sure_baskisi"]),
            ("typosquatting", PHISHING_SAMPLES["typosquatting"]),
            ("coklu_tehdit", PHISHING_SAMPLES["coklu_tehdit"]),
        ],
    )
    def test_phishing_detected_as_high_or_medium(self, key, message):
        result = analyze_message(message, use_api=False)
        assert result["risk"] in ("YÜKSEK", "ORTA"), (
            f"{key}: Beklenen YÜKSEK/ORTA, alınan {result['risk']} (skor: {result['score']})"
        )
        assert result["score"] >= 5

    def test_banka_kart_bloke_hits(self):
        msg = PHISHING_SAMPLES["banka_kart_bloke"]
        result = analyze_message(msg, use_api=False)
        assert "bloke" in result["hits"]["words"] or len(result["hits"]["regex"]) > 0
        assert len(result["hits"]["urls"]) > 0
        assert ".xyz" in str(result["hits"]["tlds"]) or "xyz" in str(result["hits"]["urls"])

    def test_typosquatting_detected(self):
        msg = PHISHING_SAMPLES["typosquatting"]
        result = analyze_message(msg, use_api=False)
        assert len(result["hits"]["domain_similarity"]) > 0
        assert result["score"] >= 9

    def test_coklu_tehdit_high_score(self):
        msg = PHISHING_SAMPLES["coklu_tehdit"]
        result = analyze_message(msg, use_api=False)
        assert result["risk"] == "YÜKSEK"
        assert result["score"] >= 9


class TestNegativeScenarios:
    """Güvenli mesaj senaryoları - DÜŞÜK risk beklenir."""

    @pytest.mark.parametrize(
        "key,message",
        [
            ("normal_mesaj", SAFE_SAMPLES["normal_mesaj"]),
            ("bilgilendirme", SAFE_SAMPLES["bilgilendirme"]),
            ("mevcut_url", SAFE_SAMPLES["mevcut_url"]),
            ("sadece_rakam", SAFE_SAMPLES["sadece_rakam"]),
            ("mevcut_domain", SAFE_SAMPLES["mevcut_domain"]),
        ],
    )
    def test_safe_message_low_risk(self, key, message):
        if not message:
            pytest.skip("Boş mesaj")
        result = analyze_message(message, use_api=False)
        assert result["risk"] == "DÜŞÜK", (
            f"{key}: Beklenen DÜŞÜK, alınan {result['risk']} (skor: {result['score']})"
        )
        assert result["score"] < 5

    def test_empty_message(self):
        result = analyze_message("", use_api=False)
        assert result["risk"] == "DÜŞÜK"
        assert result["score"] == 0


class TestRiskThresholds:
    """Risk eşik değerleri testleri."""

    def test_score_9_plus_high(self):
        msg = (
            "ACİL! Kartınız bloke. IBAN doğrulama. OTP girin. "
            "https://fake.xyz/link"
        )
        result = analyze_message(msg, use_api=False)
        assert result["risk"] == "YÜKSEK"
        assert result["score"] >= 9

    def test_score_5_to_8_medium(self):
        msg = "Kartınız bloke. https://example.com"
        result = analyze_message(msg, use_api=False)
        assert result["risk"] in ("ORTA", "YÜKSEK")

    def test_score_below_5_low(self):
        result = analyze_message("Sadece merhaba", use_api=False)
        assert result["risk"] == "DÜŞÜK"
        assert result["score"] < 5


class TestAnalyzeMessageStructure:
    """analyze_message çıktı yapısı testleri."""

    def test_returns_required_keys(self):
        result = analyze_message("test", use_api=False)
        assert "risk" in result
        assert "score" in result
        assert "hits" in result

    def test_hits_structure(self):
        result = analyze_message("test", use_api=False)
        hits = result["hits"]
        assert "words" in hits
        assert "official" in hits
        assert "tlds" in hits
        assert "urls" in hits
        assert "regex" in hits
        assert "domain_similarity" in hits
        assert "api_results" in hits
        assert "url_heuristics" in hits
        assert "emotion_risk" in hits

    def test_risk_values_valid(self):
        result = analyze_message("acil bloke https://x.xyz", use_api=False)
        assert result["risk"] in ("YÜKSEK", "ORTA", "DÜŞÜK")


class TestFormatReport:
    """format_report çıktı testleri."""

    def test_report_contains_risk_and_score(self):
        result = analyze_message("test mesaj", use_api=False)
        report = format_report("test mesaj", result)
        assert "Risk:" in report
        assert "Skor:" in report
        assert result["risk"] in report
        assert str(result["score"]) in report

    def test_report_contains_original_text(self):
        text = "Örnek phishing mesajı"
        result = analyze_message(text, use_api=False)
        report = format_report(text, result)
        assert text in report
