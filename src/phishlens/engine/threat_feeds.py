"""
PhishLens TR - Tehdit besleme yönetimi.

OpenPhish feed, PhishTank API ve cache mekanizması.
"""

from __future__ import annotations

import json
import time
from os import getenv
from pathlib import Path
from typing import Any

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from rich.progress import (
        Progress, BarColumn, TextColumn, DownloadColumn,
        TaskProgressColumn, SpinnerColumn,
    )
    RICH_PROGRESS_AVAILABLE = True
except ImportError:
    RICH_PROGRESS_AVAILABLE = False

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
PHISHTANK_CHECK_URL = "https://checkurl.phishtank.com/checkurl/"
# Proje kökü (src/phishlens/engine/threat_feeds.py -> parents[3])
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CACHE_DIR = _PROJECT_ROOT / ".cache"
FEED_CACHE_FILENAME = "feed_cache.json"
CACHE_MAX_AGE_SECONDS = 3600


def _get_phishtank_api_key() -> str | None:
    return getenv("PHISHTANK_API_KEY") or getenv("PHISHTANK_APP_KEY")


class ThreatFeedManager:
    def __init__(
        self,
        cache_dir: Path | str | None = None,
        cache_file: str = FEED_CACHE_FILENAME,
        cache_max_age: int = CACHE_MAX_AGE_SECONDS,
    ) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
        self.cache_file = cache_file
        self.cache_max_age = cache_max_age
        self._cache_path = self.cache_dir / cache_file
        self._urls: set[str] = set()
        self.openphish_url = OPENPHISH_FEED_URL

    def _is_cache_valid(self) -> bool:
        if not self._cache_path.exists():
            return False
        try:
            data = json.loads(self._cache_path.read_text(encoding="utf-8"))
            cached_at = data.get("cached_at", 0)
            return time.time() - cached_at <= self.cache_max_age
        except (json.JSONDecodeError, OSError):
            return False

    def _load_from_cache(self) -> bool:
        if not self._cache_path.exists():
            return False
        try:
            data = json.loads(self._cache_path.read_text(encoding="utf-8"))
            cached_at = data.get("cached_at", 0)
            if time.time() - cached_at > self.cache_max_age:
                return False
            self._urls = set(data.get("urls", []))
            return True
        except (json.JSONDecodeError, OSError):
            return False

    def _save_to_cache(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "cached_at": time.time(),
            "url_count": len(self._urls),
            "urls": sorted(self._urls),
        }
        self._cache_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def update_feeds(self, force: bool = False) -> set[str]:
        if not force and self._is_cache_valid():
            self._load_from_cache()
            return self._urls.copy()

        if not force and self._load_from_cache():
            return self._urls.copy()

        if not REQUESTS_AVAILABLE:
            if self._load_from_cache():
                return self._urls.copy()
            raise RuntimeError("requests kütüphanesi yüklü değil (pip install requests).")

        try:
            response = requests.get(
                self.openphish_url, stream=True, timeout=30,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            if self._load_from_cache():
                return self._urls.copy()
            raise RuntimeError(f"OpenPhish feed çekilemedi: {e}") from e

        total_bytes = int(response.headers.get("Content-Length", 0))
        chunk_size = 8192
        chunks: list[bytes] = []

        if RICH_PROGRESS_AVAILABLE and total_bytes > 0:
            with Progress(
                TextColumn("[bold blue]OpenPhish feed indiriliyor"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                DownloadColumn(),
            ) as progress:
                task = progress.add_task("", total=total_bytes)
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        chunks.append(chunk)
                        progress.update(task, advance=len(chunk))
        elif RICH_PROGRESS_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]OpenPhish feed indiriliyor..."),
            ) as progress:
                task = progress.add_task("", total=None)
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        chunks.append(chunk)
                        progress.advance(task)
        else:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    chunks.append(chunk)

        raw_text = b"".join(chunks).decode("utf-8", errors="replace")
        urls: set[str] = set()
        for line in raw_text.strip().splitlines():
            url = line.strip()
            if url and not url.startswith("#"):
                urls.add(url)

        self._urls = urls
        self._save_to_cache()
        return self._urls.copy()

    def fetch_openphish(self, force_refresh: bool = False) -> set[str]:
        return self.update_feeds(force=force_refresh)

    def is_url_malicious(self, url: str) -> bool:
        if not self._urls and not self._load_from_cache():
            self.update_feeds()
        return url.strip() in self._urls

    def contains(self, url: str) -> bool:
        return self.is_url_malicious(url)

    def check_phishtank(self, url: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "success": False, "is_phish": False, "phish_detail_page": None,
            "in_database": False, "error": None,
        }
        if not REQUESTS_AVAILABLE:
            result["error"] = "requests kütüphanesi yüklü değil"
            return result
        api_key = _get_phishtank_api_key()
        if not api_key:
            result["error"] = "PHISHTANK_API_KEY .env dosyasında tanımlı değil"
            return result
        try:
            resp = requests.post(
                PHISHTANK_CHECK_URL,
                data={"url": url, "format": "json", "app_key": api_key},
                headers={"User-Agent": "PhishLens-TR/1.0"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            result["error"] = str(e)
            return result
        except (json.JSONDecodeError, KeyError) as e:
            result["error"] = f"Yanıt ayrıştırma hatası: {e}"
            return result

        results = data.get("results", data)
        result["success"] = True
        result["in_database"] = results.get("in_database", results.get("in_the_database", False))
        result["is_phish"] = results.get("valid", results.get("is_phish", False))
        result["phish_detail_page"] = results.get("phish_detail_page")
        return result

    @property
    def url_count(self) -> int:
        return len(self._urls)


_default_manager: ThreatFeedManager | None = None


def is_url_malicious(url: str, manager: ThreatFeedManager | None = None) -> bool:
    global _default_manager
    if manager is None:
        if _default_manager is None:
            _default_manager = ThreatFeedManager()
        manager = _default_manager
    return manager.is_url_malicious(url)
