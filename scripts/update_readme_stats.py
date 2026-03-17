"""
PhishLens-TR - README İstatistik Güncelleyici

logs/analysis_history.jsonl dosyasından son 7 günlük istatistikleri hesaplar
ve README.md içindeki PHISHLENS_WEEKLY_STATS etiketleri arasına yazar.

GitHub Actions ile haftalık çalıştırılabilir.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

# Proje kök dizini (script scripts/ içinde)
ROOT = Path(__file__).parent.parent
HISTORY_PATH = ROOT / "logs" / "analysis_history.jsonl"
README_PATH = ROOT / "README.md"
STATS_JSON_PATH = ROOT / "assets" / "stats.json"

START_MARKER = "<!-- PHISHLENS_WEEKLY_STATS_START -->"
END_MARKER = "<!-- PHISHLENS_WEEKLY_STATS_END -->"


def _parse_timestamp(ts: str) -> datetime | None:
    """ISO format timestamp'i datetime'a çevirir (yerel saat varsayılır)."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None) if dt.tzinfo else dt
    except (ValueError, TypeError):
        return None


def compute_weekly_stats(history_path: Path, days: int = 7) -> dict:
    """Son N günlük istatistikleri hesaplar."""
    cutoff = datetime.now() - timedelta(days=days)
    total = 0
    malicious = 0
    safe = 0
    brand_counts: dict[str, int] = {}

    if not history_path.exists():
        return {
            "total": 0,
            "malicious": 0,
            "safe": 0,
            "rate": 0.0,
            "security_score": 100.0,
            "top_brands": [],
            "period_days": days,
        }

    with open(history_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = _parse_timestamp(entry.get("timestamp", ""))
            if ts and ts < cutoff:
                continue

            total += 1
            risk_level = entry.get("risk_level", "DÜŞÜK")
            if risk_level in ("YÜKSEK", "ORTA"):
                malicious += 1
            else:
                safe += 1

            for brand in entry.get("brand", []) or []:
                if isinstance(brand, str) and brand.strip():
                    brand_counts[brand] = brand_counts.get(brand, 0) + 1

    threat_rate = (malicious / total * 100) if total > 0 else 0.0
    security_score = (safe / total * 100) if total > 0 else 100.0
    top_brands = sorted(brand_counts.items(), key=lambda x: -x[1])[:3]

    return {
        "total": total,
        "malicious": malicious,
        "safe": safe,
        "rate": threat_rate,
        "security_score": security_score,
        "top_brands": top_brands,
        "period_days": days,
    }


def format_stats_markdown(stats: dict) -> str:
    """İstatistikleri Markdown tablo/liste formatında döner."""
    if stats["total"] == 0:
        return (
            f"\n**Son {stats['period_days']} gün:** Henüz analiz kaydı yok.\n"
        )

    lines = [
        f"\n### 📊 Haftalık Özet (Son {stats['period_days']} Gün)\n",
        "| Metrik | Değer |",
        "|--------|-------|",
        f"| Toplam Tarama | {stats['total']} |",
        f"| Yakalanan Tehdit | {stats['malicious']} |",
        f"| Güvenli | {stats['safe']} |",
        f"| Tehdit Oranı | %{stats['rate']:.1f} |",
        f"| Güvenlik Skoru | %{stats['security_score']:.1f} |",
        "",
    ]

    if stats["top_brands"]:
        lines.append("**En Çok Taklit Edilen Kurumlar:**")
        for brand, count in stats["top_brands"]:
            lines.append(f"- {brand}: {count}")
        lines.append("")

    return "\n".join(lines)


def save_stats_json(stats: dict, output_path: Path) -> None:
    """İstatistikleri Shields.io uyumlu JSON dosyasına kaydeder."""
    payload = {
        "total": stats["total"],
        "malicious": stats["malicious"],
        "safe": stats["safe"],
        "threat_rate": round(stats["rate"], 1),
        "security_score": round(stats["security_score"], 1),
        "period_days": stats["period_days"],
        "last_updated": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def update_readme(readme_path: Path, new_content: str) -> bool:
    """README.md içindeki etiketler arasını günceller."""
    if not readme_path.exists():
        return False

    text = readme_path.read_text(encoding="utf-8")

    if START_MARKER not in text or END_MARKER not in text:
        return False

    start_idx = text.index(START_MARKER) + len(START_MARKER)
    end_idx = text.index(END_MARKER)

    before = text[:start_idx]
    after = text[end_idx:]

    updated = before + new_content + "\n" + after
    readme_path.write_text(updated, encoding="utf-8")
    return True


def main() -> None:
    """Ana akış: istatistik hesapla, README ve stats.json güncelle."""
    stats = compute_weekly_stats(HISTORY_PATH, days=7)
    markdown = format_stats_markdown(stats)

    save_stats_json(stats, STATS_JSON_PATH)
    print(f"İstatistikler kaydedildi: {STATS_JSON_PATH}")

    if update_readme(README_PATH, markdown):
        print("README.md güncellendi.")
    else:
        print("README.md güncellenemedi (etiketler bulunamadı veya dosya yok).")

    print(f"Son 7 gün: {stats['total']} tarama, {stats['malicious']} tehdit")


if __name__ == "__main__":
    main()
