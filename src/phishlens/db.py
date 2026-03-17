"""
PhishLens TR - SQLite veritabanı modülü.

Analiz geçmişini history.db dosyasına kaydeder.
"""

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

# Proje kökü (src/phishlens/db.py -> parents[2] = project root)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Veritabanı dosyası - proje kökünde (PHISHLENS_DB_PATH env ile override)
DB_PATH = Path(
    os.getenv("PHISHLENS_DB_PATH", "")
) if os.getenv("PHISHLENS_DB_PATH") else _PROJECT_ROOT / "history.db"


def get_connection() -> sqlite3.Connection:
    """Veritabanı bağlantısı döner."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Veritabanı tablolarını oluşturur."""
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                text TEXT NOT NULL,
                risk TEXT NOT NULL,
                score INTEGER NOT NULL,
                hits_json TEXT,
                llm_explanation TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_analyses_created_at
            ON analyses(created_at)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_analyses_risk
            ON analyses(risk)
        """)
        conn.commit()
    finally:
        conn.close()


def save_analysis(text: str, result: dict) -> int:
    """Analiz sonucunu veritabanına kaydeder."""
    init_db()
    created_at = datetime.now().isoformat()
    risk = result.get("risk", "DÜŞÜK")
    score = result.get("score", 0)
    hits = result.get("hits", {})
    hits_json = json.dumps(hits, ensure_ascii=False) if hits else None

    llm = result.get("llm_analysis")
    llm_explanation = None
    if llm and llm.get("success") and llm.get("explanation"):
        llm_explanation = llm["explanation"]

    conn = get_connection()
    try:
        cur = conn.execute(
            """
            INSERT INTO analyses (created_at, text, risk, score, hits_json, llm_explanation)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (created_at, text, risk, score, hits_json, llm_explanation),
        )
        conn.commit()
        return cur.lastrowid or 0
    finally:
        conn.close()


def get_recent_analyses(limit: int = 50) -> list[dict[str, Any]]:
    """Son analizleri tarihe göre azalan sırada döner."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute(
            """
            SELECT id, created_at, text, risk, score, hits_json, llm_explanation
            FROM analyses
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_analysis_by_id(analysis_id: int) -> dict[str, Any] | None:
    """ID ile tek bir analiz kaydı döner."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute(
            (
                "SELECT id, created_at, text, risk, score, hits_json, llm_explanation "
                "FROM analyses WHERE id = ?"
            ),
            (analysis_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_stats() -> dict[str, Any]:
    """Özet istatistikler döner."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT COUNT(*) FROM analyses")
        total = cur.fetchone()[0]

        cur = conn.execute(
            "SELECT risk, COUNT(*) FROM analyses GROUP BY risk"
        )
        by_risk = {row[0]: row[1] for row in cur.fetchall()}

        return {"total": total, "by_risk": by_risk}
    finally:
        conn.close()
