"""
PhishLens TR - Loglama sistemi.

Python logging ile hem dosyaya (logs/phishlens_YYYY-MM-DD.log)
hem de terminale (RichHandler ile renkli) yazar.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

try:
    from rich.logging import RichHandler
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Proje kökü (src/phishlens/utils/logger.py -> parents[3])
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_LOG_DIR = _PROJECT_ROOT / "logs"
LOG_PREFIX = "phishlens"
LOG_SUFFIX = ".log"
FILE_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _get_today_log_path() -> Path:
    DEFAULT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    return DEFAULT_LOG_DIR / f"{LOG_PREFIX}_{date_str}{LOG_SUFFIX}"


def get_logger(
    name: str = "phishlens",
    level: int = logging.INFO,
    log_to_file: bool = True,
    log_to_console: bool = True,
) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)

    if log_to_file:
        file_path = _get_today_log_path()
        file_handler = logging.FileHandler(file_path, encoding="utf-8", mode="a")
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(FILE_FORMAT, datefmt=DATE_FORMAT))
        logger.addHandler(file_handler)

    if log_to_console and RICH_AVAILABLE:
        rich_handler = RichHandler(
            show_time=True,
            show_level=True,
            show_path=False,
            rich_tracebacks=True,
        )
        rich_handler.setLevel(level)
        rich_handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
        logger.addHandler(rich_handler)
    elif log_to_console:
        import sys
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setLevel(level)
        stream_handler.setFormatter(logging.Formatter(FILE_FORMAT, datefmt=DATE_FORMAT))
        logger.addHandler(stream_handler)

    return logger
