"""URL Heuristic Engine testleri."""

import pytest

from phishlens.url_heuristics import (
    analyze_url_heuristics,
    analyze_urls_heuristics,
    _has_homograph_attack,
    _check_at_symbol,
    _check_subdomain_count,
    _check_url_length,
    _check_random_chars,
)


class TestHomograph:
    """Homograph (karakter değişimi) tespiti."""

    def test_g00gle(self):
        found, detail = _has_homograph_attack("go0gle.com")
        assert found
        assert "google" in detail.lower() or "homograph" in detail.lower()

    def test_goog1e(self):
        found, _ = _has_homograph_attack("goog1e.com")
        assert found

    def test_micr0soft(self):
        found, _ = _has_homograph_attack("micr0soft.com")
        assert found

    def test_legitimate_no_homograph(self):
        found, _ = _has_homograph_attack("google.com")
        assert not found


class TestAtSymbol:
    """@ sembolü kontrolü."""

    def test_at_in_url(self):
        found, detail = _check_at_symbol("https://real.com@fake.xyz/path")
        assert found
        assert "@" in detail

    def test_no_at(self):
        found, _ = _check_at_symbol("https://example.com/path")
        assert not found


class TestSubdomain:
    """Subdomain sayısı kontrolü."""

    def test_many_subdomains(self):
        found, count, _ = _check_subdomain_count("a.b.c.d.e.fake.com")
        assert found
        assert count >= 3

    def test_few_subdomains(self):
        found, _, _ = _check_subdomain_count("www.example.com")
        assert not found


class TestUrlLength:
    """URL uzunluğu kontrolü."""

    def test_long_url(self):
        long_url = "https://example.com/" + "a" * 80
        found, detail = _check_url_length(long_url)
        assert found
        assert "80" in detail or "uzun" in detail.lower()

    def test_short_url(self):
        found, _ = _check_url_length("https://example.com")
        assert not found


class TestRandomChars:
    """Anlamsız karakter dizisi kontrolü."""

    def test_high_digit_ratio(self):
        found, _ = _check_random_chars("a8x3k9m2q1w5.com")
        assert found

    def test_normal_domain(self):
        found, _ = _check_random_chars("google.com")
        assert not found


class TestAnalyzeUrlHeuristics:
    """analyze_url_heuristics entegrasyon testleri."""

    def test_phishing_url_multiple_hits(self):
        report = analyze_url_heuristics("https://go0gle.com@fake.xyz/very/long/path/" + "x" * 50)
        assert report.total_score >= 4
        assert len(report.findings) >= 1

    def test_safe_url(self):
        report = analyze_url_heuristics("https://www.google.com")
        assert report.total_score == 0 or len(report.findings) == 0


class TestAnalyzeUrlsHeuristics:
    """analyze_urls_heuristics toplu analiz testleri."""

    def test_returns_score_and_hits(self):
        score, hits = analyze_urls_heuristics(["https://g00gle.com", "https://fake.xyz"])
        assert score >= 0
        assert "homograph" in hits or "suspicious_tld" in hits
