"""ThreatFeedManager testleri."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from phishlens.engine.threat_feeds import (
    ThreatFeedManager,
    is_url_malicious,
    OPENPHISH_FEED_URL,
    FEED_CACHE_FILENAME,
)


class TestThreatFeedManager:
    """ThreatFeedManager sınıfı testleri."""

    def test_fetch_openphish_mock(self):
        """fetch_openphish mock ile test (stream=True destekli)."""
        feed_data = b"https://phish1.example.com\nhttps://phish2.example.com\n"
        mock_response = MagicMock()
        mock_response.headers = {"Content-Length": str(len(feed_data))}
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_content = lambda chunk_size: [feed_data]

        with patch("phishlens.engine.threat_feeds.requests") as mock_requests:
            mock_requests.get.return_value = mock_response
            with tempfile.TemporaryDirectory() as tmp:
                manager = ThreatFeedManager(cache_dir=tmp)
                urls = manager.fetch_openphish(force_refresh=True)
                assert len(urls) == 2
                assert "https://phish1.example.com" in urls
                assert "https://phish2.example.com" in urls

    def test_feed_cache_json_created(self):
        """feed_cache.json dosyası oluşturulur."""
        feed_data = b"https://evil.com"
        mock_response = MagicMock()
        mock_response.headers = {"Content-Length": str(len(feed_data))}
        mock_response.raise_for_status = MagicMock()
        mock_response.iter_content = lambda chunk_size: [feed_data]

        with patch("phishlens.engine.threat_feeds.requests") as mock_requests:
            mock_requests.get.return_value = mock_response
            with tempfile.TemporaryDirectory() as tmp:
                manager = ThreatFeedManager(cache_dir=tmp, cache_file="feed_cache.json")
                manager.update_feeds(force=True)
                cache_path = Path(tmp) / "feed_cache.json"
                assert cache_path.exists()
                data = json.loads(cache_path.read_text(encoding="utf-8"))
                assert "cached_at" in data
                assert "urls" in data

    def test_cache_valid_skips_network(self):
        """1 saat içindeyse internete çıkmaz, yerel dosyayı okur."""
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "feed_cache.json"
            cache_path.write_text(
                json.dumps({
                    "cached_at": 9999999999,  # Gelecekte (geçerli)
                    "urls": ["https://cached.com"],
                }),
                encoding="utf-8",
            )
            manager = ThreatFeedManager(cache_dir=tmp, cache_max_age=3600)
            with patch("phishlens.engine.threat_feeds.requests") as mock_requests:
                manager.update_feeds(force=False)
                mock_requests.get.assert_not_called()
            assert "https://cached.com" in manager._urls

    def test_is_url_malicious(self):
        """is_url_malicious hızlı kontrol."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = ThreatFeedManager(cache_dir=tmp)
            manager._urls = {"https://known-phish.com"}
            assert manager.is_url_malicious("https://known-phish.com") is True
            assert manager.is_url_malicious("https://safe.com") is False

    def test_is_url_malicious_function(self):
        """Modül seviyesi is_url_malicious fonksiyonu."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = ThreatFeedManager(cache_dir=tmp)
            manager._urls = {"https://bad.com"}
            assert is_url_malicious("https://bad.com", manager=manager) is True
            assert is_url_malicious("https://good.com", manager=manager) is False

    def test_check_phishtank_no_key(self):
        """PhishTank API anahtarı yoksa hata döner."""
        import phishlens.engine.threat_feeds as tf
        with patch.object(tf, "_get_phishtank_api_key", return_value=None):
            manager = ThreatFeedManager()
            result = manager.check_phishtank("https://example.com")
            assert result["success"] is False
            assert "PHISHTANK" in (result.get("error") or "")

    def test_check_phishtank_success_mock(self):
        """PhishTank API başarılı yanıt mock."""
        import phishlens.engine.threat_feeds as tf
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": {
                "in_database": True,
                "valid": True,
                "phish_detail_page": "https://phishtank.com/phish_detail.php?phish_id=123",
            }
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(tf, "_get_phishtank_api_key", return_value="test-key"):
            with patch("phishlens.engine.threat_feeds.requests") as mock_requests:
                mock_requests.post.return_value = mock_response
                manager = ThreatFeedManager()
                result = manager.check_phishtank("https://phish.example.com")
                assert result["success"] is True
                assert result["is_phish"] is True
                assert "phishtank.com" in (result.get("phish_detail_page") or "")
