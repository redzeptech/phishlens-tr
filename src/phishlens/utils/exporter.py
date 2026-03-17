"""
PhishLens TR - PDF rapor dışa aktarma.

logs/analysis_history.jsonl verilerini okuyup PhishLens-TR Güvenlik Raporu
oluşturur ve reports/ klasörüne kaydeder.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from fpdf import FPDF

# Proje kökü (src/phishlens/utils/exporter.py -> parents[3])
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_HISTORY_PATH = _PROJECT_ROOT / "logs" / "analysis_history.jsonl"
REPORTS_DIR = _PROJECT_ROOT / "reports"


def _find_unicode_font() -> str | None:
    candidates = []
    if sys.platform == "win32":
        drive = Path(__file__).resolve().drive or "C:"
        candidates = [
            Path(f"{drive}/Windows/Fonts/arial.ttf"),
            Path(f"{drive}/Windows/Fonts/arialuni.ttf"),
        ]
    else:
        candidates = [
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            Path("/usr/share/fonts/TTF/DejaVuSans.ttf"),
            Path.home() / ".fonts/DejaVuSans.ttf",
        ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None


def _load_entries(history_path: Path) -> list[dict[str, Any]]:
    entries = []
    if not history_path.exists():
        return entries
    with open(history_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def _compute_stats(entries: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(entries)
    malicious = sum(1 for e in entries if e.get("risk_level") in ("YÜKSEK", "ORTA"))
    safe = total - malicious
    threat_rate = (malicious / total * 100) if total > 0 else 0.0
    security_score = (safe / total * 100) if total > 0 else 100.0
    return {
        "total": total,
        "malicious": malicious,
        "safe": safe,
        "threat_rate": threat_rate,
        "security_score": security_score,
    }


class PhishLensPDF(FPDF):
    def __init__(self, font_path: str | None = None) -> None:
        super().__init__()
        self._font_path = font_path
        self._use_unicode = False

    def setup_font(self) -> None:
        if self._font_path:
            try:
                self.add_font("UnicodeFont", "", self._font_path)
                self.set_font("UnicodeFont", "", 10)
                self._use_unicode = True
            except Exception:
                self.set_font("Helvetica", "", 10)
        else:
            self.set_font("Helvetica", "", 10)

    def header(self) -> None:
        pass

    def footer(self) -> None:
        self.set_y(-18)
        self.set_font("Helvetica", "", 8)
        if self._use_unicode:
            try:
                self.set_font("UnicodeFont", "", 8)
            except Exception:
                pass
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, "Bu rapor PhishLens-TR tarafından otomatik oluşturulmuştur.", align="C")
        self.ln(4)
        self.set_text_color(0, 0, 0)
        self.cell(0, 6, f"Sayfa {self.page_no()}", align="C")


def export_stats_to_pdf(
    history_path: Path | None = None,
    output_path: Path | None = None,
) -> Path:
    path = history_path or DEFAULT_HISTORY_PATH
    entries = _load_entries(path)
    stats = _compute_stats(entries)

    font_path = _find_unicode_font()
    pdf = PhishLensPDF(font_path=font_path)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()
    pdf.setup_font()

    pdf.set_fill_color(41, 98, 255)
    pdf.rect(0, 0, 210, 35, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font_size(24)
    pdf.set_y(8)
    pdf.cell(0, 12, "PhishLens-TR", ln=True, align="C")
    pdf.set_font_size(10)
    pdf.cell(0, 6, datetime.now().strftime("%d.%m.%Y %H:%M"), ln=True, align="C")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(12)

    pdf.set_font_size(14)
    pdf.cell(0, 8, "Özet", ln=True)
    pdf.set_font_size(10)
    pdf.ln(4)

    col_w, row_h = 60, 9
    summary_rows = [
        ("Toplam Tarama", str(stats["total"])),
        ("Tespit Edilen Tehdit", str(stats["malicious"])),
        ("Güvenlik Skoru", f"%{stats['security_score']:.0f}"),
    ]
    for row in summary_rows:
        pdf.cell(col_w, row_h, row[0], border=0)
        pdf.cell(col_w, row_h, row[1], border=0, align="R")
        pdf.ln()
    pdf.ln(8)

    if stats["total"] > 0:
        pdf.set_font_size(12)
        pdf.cell(0, 6, "Durum Özeti", ln=True)
        pdf.set_font_size(10)
        pdf.ln(4)
        bar_width, bar_height = 150, 10
        threat_ratio = stats["malicious"] / stats["total"]
        safe_ratio = stats["safe"] / stats["total"]
        pdf.cell(0, 5, "Tehdit", ln=True)
        fill_w = bar_width * threat_ratio
        pdf.set_fill_color(220, 53, 69)
        pdf.rect(pdf.get_x(), pdf.get_y(), fill_w, bar_height, "F")
        pdf.set_fill_color(240, 240, 240)
        pdf.rect(pdf.get_x() + fill_w, pdf.get_y(), bar_width - fill_w, bar_height, "F")
        pdf.ln(bar_height + 2)
        pdf.cell(0, 5, f"{stats['threat_rate']:.1f}%", ln=True)
        pdf.ln(6)
        pdf.cell(0, 5, "Güvenli", ln=True)
        fill_w = bar_width * safe_ratio
        pdf.set_fill_color(40, 167, 69)
        pdf.rect(pdf.get_x(), pdf.get_y(), fill_w, bar_height, "F")
        pdf.set_fill_color(240, 240, 240)
        pdf.rect(pdf.get_x() + fill_w, pdf.get_y(), bar_width - fill_w, bar_height, "F")
        pdf.ln(bar_height + 2)
        pdf.cell(0, 5, f"{stats['security_score']:.1f}%", ln=True)
        pdf.ln(10)

    pdf.set_font_size(14)
    pdf.cell(0, 8, "Son 10 Analiz Sonucu", ln=True)
    pdf.set_font_size(10)
    pdf.ln(4)

    last_10 = entries[-10:] if len(entries) >= 10 else entries
    last_10 = list(reversed(last_10))
    col_url, col_score, col_status, row_h = 90, 25, 35, 7

    pdf.cell(col_url, row_h, "URL", border=1, fill=True)
    pdf.cell(col_score, row_h, "Skor", border=1, fill=True)
    pdf.cell(col_status, row_h, "Durum", border=1, fill=True)
    pdf.ln()

    for e in last_10:
        urls = e.get("urls", []) or []
        url_str = urls[0][:60] + "..." if urls and len(urls[0]) > 60 else (urls[0] if urls else "-")
        score = e.get("risk_score", 0)
        status = e.get("risk_level", "DÜŞÜK")
        pdf.cell(col_url, row_h, url_str, border=1)
        pdf.cell(col_score, row_h, str(score), border=1)
        pdf.cell(col_status, row_h, status, border=1)
        pdf.ln()

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if output_path is None:
        output_path = REPORTS_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    else:
        output_path = Path(output_path)

    pdf.output(str(output_path))
    return output_path
