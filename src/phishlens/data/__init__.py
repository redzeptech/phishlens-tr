"""PhishLens TR - Veri yapılandırması."""

from pathlib import Path
import json
from typing import Any

_KEYWORDS_PATH = Path(__file__).parent / "keywords.json"


def load_keywords() -> dict[str, Any]:
    """keywords.json dosyasını yükler."""
    with open(_KEYWORDS_PATH, encoding="utf-8") as f:
        return json.load(f)
