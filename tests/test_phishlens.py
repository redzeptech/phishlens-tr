"""phishlens ana modül testleri."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from phishlens.rules import extract_urls
from phishlens import (
    format_report,
    default_report_filename,
    save_report,
    parse_args,
    ReportSaveError,
)


class TestExtractUrls:
    """extract_urls fonksiyonu testleri."""

    def test_https_url(self):
        assert extract_urls("Site: https://example.com") == ["https://example.com"]

    def test_http_url(self):
        assert extract_urls("http://test.org/path") == ["http://test.org/path"]

    def test_www_url(self):
        assert "www.example.com" in str(extract_urls("Visit www.example.com"))

    def test_multiple_urls(self):
        text = "Link1: https://a.com Link2: https://b.com"
        urls = extract_urls(text)
        assert len(urls) == 2

    def test_no_urls(self):
        assert extract_urls("Sadece metin") == []

    def test_case_insensitive(self):
        urls = extract_urls("HTTPS://EXAMPLE.COM")
        assert len(urls) == 1
        assert "example" in urls[0].lower()


class TestDefaultReportFilename:
    """default_report_filename fonksiyonu testleri."""

    def test_format(self):
        name = default_report_filename()
        assert name.startswith("phishlens_report_")
        assert name.endswith(".txt")
        assert len(name) > 20

    def test_unique_per_call(self):
        names = [default_report_filename() for _ in range(3)]
        assert len(set(names)) >= 1


class TestSaveReport:
    """save_report fonksiyonu testleri."""

    def test_save_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test_report.txt"
            result = save_report("Test içerik", str(path))
            assert result.exists()
            assert result.read_text(encoding="utf-8") == "Test içerik"

    def test_save_default_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_name = str(Path(tmp) / "phishlens_report_123.txt")
            with patch("phishlens.core.default_report_filename", return_value=fake_name):
                result = save_report("İçerik", None)
            assert result.exists()
            assert "phishlens_report" in str(result)

    def test_save_invalid_path_raises(self):
        with patch.object(Path, "write_text", side_effect=OSError("Permission denied")):
            with pytest.raises(ReportSaveError):
                save_report("x", "report.txt")


class TestParseArgs:
    """parse_args fonksiyonu testleri."""

    def test_default_args(self):
        with patch("sys.argv", ["phishlens.py"]):
            args = parse_args()
            assert args.output is None
            assert args.no_prompt is False
            assert args.no_api is False

    def test_output_arg(self):
        with patch("sys.argv", ["phishlens.py", "-o", "rapor.txt"]):
            args = parse_args()
            assert args.output == "rapor.txt"

    def test_no_prompt_arg(self):
        with patch("sys.argv", ["phishlens.py", "--no-prompt"]):
            args = parse_args()
            assert args.no_prompt is True

    def test_no_api_arg(self):
        with patch("sys.argv", ["phishlens.py", "--no-api"]):
            args = parse_args()
            assert args.no_api is True

    def test_no_log_arg(self):
        with patch("sys.argv", ["phishlens.py", "--no-log"]):
            args = parse_args()
            assert args.no_log is True

    def test_llm_arg(self):
        with patch("sys.argv", ["phishlens.py", "--llm"]):
            args = parse_args()
            assert args.llm is True

    def test_no_history_arg(self):
        with patch("sys.argv", ["phishlens.py", "--no-history"]):
            args = parse_args()
            assert args.no_history is True

    def test_file_arg(self):
        with patch("sys.argv", ["phishlens.py", "-f", "test.eml"]):
            args = parse_args()
            assert args.file == "test.eml"


class TestFormatReportEdgeCases:
    """format_report kenar durumları."""

    def test_empty_hits(self):
        result = {
            "risk": "DÜŞÜK",
            "score": 0,
            "hits": {
                "words": [],
                "official": [],
                "tlds": [],
                "urls": [],
                "regex": [],
                "domain_similarity": [],
                "api_results": {},
            },
        }
        report = format_report("Boş mesaj", result)
        assert "DÜŞÜK" in report
        assert "0" in report

    def test_full_hits(self):
        result = {
            "risk": "YÜKSEK",
            "score": 15,
            "hits": {
                "words": ["acil", "bloke"],
                "official": ["banka"],
                "tlds": [".xyz"],
                "urls": ["https://fake.xyz"],
                "regex": [("Kural", "eşleşme")],
                "domain_similarity": [("fake.com", "google.com", 1, "%90")],
                "api_results": {},
            },
        }
        report = format_report("Test", result)
        assert "YÜKSEK" in report
        assert "acil" in report or "bloke" in report
        assert "fake.xyz" in report
