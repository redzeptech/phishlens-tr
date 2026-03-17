"""rules modülü birim testleri."""

from phishlens.rules import (
    levenshtein_distance,
    extract_domain,
    check_domain_similarity,
    apply_regex_rules,
)


class TestLevenshteinDistance:
    """levenshtein_distance fonksiyonu testleri."""

    def test_identical_strings(self):
        assert levenshtein_distance("google.com", "google.com") == 0

    def test_single_char_diff(self):
        assert levenshtein_distance("google.com", "go0gle.com") == 1

    def test_empty_string(self):
        assert levenshtein_distance("test", "") == 4
        assert levenshtein_distance("", "test") == 4

    def test_symmetry(self):
        assert levenshtein_distance("abc", "abd") == levenshtein_distance("abd", "abc")

    def test_two_char_diff(self):
        assert levenshtein_distance("garanti.com.tr", "garanii.com.tr") == 1


class TestExtractDomain:
    """extract_domain fonksiyonu testleri."""

    def test_https_url(self):
        assert extract_domain("https://example.com/path") == "example.com"

    def test_www_stripped(self):
        assert extract_domain("https://www.example.com/path") == "example.com"

    def test_http_url(self):
        assert extract_domain("http://sub.domain.org") == "sub.domain.org"

    def test_www_only(self):
        assert extract_domain("www.example.com") == "example.com"

    def test_domain_with_path(self):
        assert extract_domain("https://api.example.com/v1/users") == "api.example.com"


class TestCheckDomainSimilarity:
    """check_domain_similarity fonksiyonu testleri."""

    def test_typosquatting_go0gle(self):
        result = check_domain_similarity("go0gle.com", max_distance=2)
        assert len(result) > 0
        assert any("google.com" in str(m) for m in result)

    def test_typosquatting_garanii(self):
        result = check_domain_similarity("garanii.com.tr", max_distance=2)
        assert len(result) > 0
        assert any("garanti" in str(m) for m in result)

    def test_legitimate_no_match(self):
        result = check_domain_similarity("google.com", max_distance=2)
        assert len(result) == 0

    def test_short_domain_skipped(self):
        result = check_domain_similarity("ab.com", min_length=6)
        assert len(result) == 0


class TestApplyRegexRules:
    """apply_regex_rules fonksiyonu testleri."""

    def test_kart_bloke(self):
        score, hits = apply_regex_rules("Kartınız bloke edildi!")
        assert score >= 3
        assert any("bloke" in str(h) for h in hits)

    def test_iban_dogrulama(self):
        score, hits = apply_regex_rules("IBAN doğrulama gerekiyor")
        assert score >= 3

    def test_otp_girin(self):
        score, hits = apply_regex_rules("OTP girin lütfen")
        assert score >= 3

    def test_kargo_takip(self):
        score, hits = apply_regex_rules("Kargo takip numarası: 123")
        assert score >= 3

    def test_24_saat(self):
        score, hits = apply_regex_rules("Son 24 saat içinde işlem yapın")
        assert score >= 3

    def test_safe_message_no_regex(self):
        score, hits = apply_regex_rules("Merhaba, nasılsın?")
        assert score == 0
        assert len(hits) == 0
