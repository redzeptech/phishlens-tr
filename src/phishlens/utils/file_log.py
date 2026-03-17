"""
PhishLens TR - Tarih bazlı dosya loglama.

Analiz raporlarını logs/phishlens_YYYY-MM-DD.log dosyasına yazar.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

# Proje kökü (src/phishlens/utils/file_log.py -> parents[3])
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_LOG_DIR = _PROJECT_ROOT / "logs"
LOG_PREFIX = "phishlens"
LOG_SUFFIX = ".log"


def _log_path_for_date(date: datetime | None = None) -> Path:
    if date is None:
        date = datetime.now()
    date_str = date.strftime("%Y-%m-%d")
    return DEFAULT_LOG_DIR / f"{LOG_PREFIX}_{date_str}{LOG_SUFFIX}"


def write_log_entry(
    content: str,
    *,
    log_dir: Path | str | None = None,
    timestamp: bool = True,
) -> Path:
    base = Path(log_dir) if log_dir else DEFAULT_LOG_DIR
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"{LOG_PREFIX}_{datetime.now().strftime('%Y-%m-%d')}{LOG_SUFFIX}"

    lines = []
    if timestamp:
        lines.append(f"\n{'='*60}")
        lines.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]")
        lines.append("="*60)
    lines.append(content.strip())
    lines.append("")

    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def get_today_log_path(log_dir: Path | str | None = None) -> Path:
    base = Path(log_dir) if log_dir else DEFAULT_LOG_DIR
    return base / f"{LOG_PREFIX}_{datetime.now().strftime('%Y-%m-%d')}{LOG_SUFFIX}"
