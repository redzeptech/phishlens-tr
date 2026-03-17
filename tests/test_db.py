"""db modülü testleri."""

import tempfile
from pathlib import Path

import pytest

from phishlens.db import (
    init_db,
    save_analysis,
    get_recent_analyses,
    get_analysis_by_id,
    get_stats,
)


@pytest.fixture
def temp_db(monkeypatch):
    """Geçici veritabanı ile test."""
    with tempfile.TemporaryDirectory() as tmp:
        test_path = Path(tmp) / "history.db"
        monkeypatch.setenv("PHISHLENS_DB_PATH", str(test_path))
        monkeypatch.setattr("phishlens.db.DB_PATH", test_path)
        init_db()
        yield test_path


def test_save_and_retrieve(temp_db):
    result = {
        "risk": "ORTA",
        "score": 6,
        "hits": {"words": ["acil"], "urls": ["https://x.com"]},
    }
    rid = save_analysis("Test mesaj içeriği", result)
    assert rid > 0

    recent = get_recent_analyses(limit=5)
    assert len(recent) >= 1
    assert recent[0]["risk"] == "ORTA"
    assert recent[0]["score"] == 6
    assert "Test mesaj" in recent[0]["text"]


def test_get_by_id(temp_db):
    result = {"risk": "YÜKSEK", "score": 12, "hits": {}}
    rid = save_analysis("Phishing test", result)
    row = get_analysis_by_id(rid)
    assert row is not None
    assert row["risk"] == "YÜKSEK"
    assert row["text"] == "Phishing test"


def test_get_stats(temp_db):
    save_analysis("A", {"risk": "DÜŞÜK", "score": 0, "hits": {}})
    save_analysis("B", {"risk": "ORTA", "score": 6, "hits": {}})
    stats = get_stats()
    assert stats["total"] >= 2
    assert "DÜŞÜK" in stats["by_risk"] or "ORTA" in stats["by_risk"]
