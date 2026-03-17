"""Tarih bazlı dosya log testleri."""

import tempfile
from pathlib import Path

from phishlens.utils.file_log import write_log_entry, get_today_log_path


class TestFileLog:
    """file_log modülü testleri."""

    def test_write_log_entry(self):
        """Log dosyasına yazma."""
        with tempfile.TemporaryDirectory() as tmp:
            path = write_log_entry("Test rapor içeriği", log_dir=tmp)
            assert path.exists()
            content = path.read_text(encoding="utf-8")
            assert "Test rapor içeriği" in content
            assert "phishlens_" in path.name
            assert path.suffix == ".log"

    def test_append_multiple(self):
        """Birden fazla kayıt append edilir."""
        with tempfile.TemporaryDirectory() as tmp:
            write_log_entry("Birinci", log_dir=tmp)
            write_log_entry("İkinci", log_dir=tmp)
            path = get_today_log_path(log_dir=tmp)
            content = path.read_text(encoding="utf-8")
            assert "Birinci" in content
            assert "İkinci" in content
