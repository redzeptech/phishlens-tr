"""Scanner sınıfı birim testleri."""

import pytest

from phishlens.scanner import Scanner


class TestScannerAnalyzeContent:
    """analyze_content metodu testleri."""

    def test_suspicious_words(self):
        scanner = Scanner(use_api=False)
        score, hits = scanner.analyze_content("Acil! Hesabınız kapatılacak.")
        assert score >= 4
        assert "acil" in hits["words"] or "kapatılacak" in hits["words"]

    def test_official_terms(self):
        scanner = Scanner(use_api=False)
        score, hits = scanner.analyze_content("PTT kargo bilgisi banka hesabı")
        assert score >= 4
        assert "ptt" in hits["official"] or "banka" in hits["official"]

    def test_regex_rules(self):
        scanner = Scanner(use_api=False)
        score, hits = scanner.analyze_content("Kartınız bloke edildi. IBAN doğrulama gerekli.")
        assert score >= 3
        assert len(hits["regex"]) > 0

    def test_safe_content(self):
        scanner = Scanner(use_api=False)
        score, hits = scanner.analyze_content("Merhaba, nasılsın?")
        assert score == 0
        assert not hits["words"] and not hits["official"] and not hits["regex"]


class TestScannerAnalyzeUrl:
    """analyze_url metodu testleri."""

    def test_suspicious_tld(self):
        scanner = Scanner(use_api=False)
        score, hits = scanner.analyze_url(["https://fake.xyz/link"])
        assert score >= 2
        assert ".xyz" in str(hits["tlds"]) or hits["tlds"]

    def test_domain_similarity(self):
        scanner = Scanner(use_api=False)
        score, hits = scanner.analyze_url(["https://go0gle.com/verify"])
        assert len(hits["domain_similarity"]) > 0

    def test_empty_urls(self):
        scanner = Scanner(use_api=False)
        score, hits = scanner.analyze_url([])
        assert score == 0
        assert not hits["urls"]


class TestScannerScan:
    """scan metodu entegrasyon testleri."""

    def test_scan_returns_full_structure(self):
        scanner = Scanner(use_api=False)
        result = scanner.scan("Acil! Kartınız bloke. https://fake.xyz")
        assert "risk" in result
        assert "score" in result
        assert "hits" in result
        assert result["risk"] in ("YÜKSEK", "ORTA", "DÜŞÜK")

    def test_scan_combines_content_and_url(self):
        scanner = Scanner(use_api=False)
        result = scanner.scan("Kartınız bloke. https://garanti-dogrulama.xyz")
        assert result["score"] >= 5
        assert result["hits"]["words"] or result["hits"]["regex"]
        assert result["hits"]["urls"]
