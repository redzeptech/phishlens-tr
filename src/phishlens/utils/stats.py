"""
PhishLens TR - Analiz istatistikleri.

logs/analysis_history.jsonl dosyasını okuyarak özet istatistikler hesaplar.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

RULE_LABELS: dict[str, str] = {
    "words": "Şüpheli Kelimeler",
    "official": "Resmi Terim",
    "tlds": "Şüpheli TLD",
    "regex": "Regex",
    "domain_similarity": "Domain Benzerliği",
    "url_heuristics": "URL Heuristics",
    "email_auth": "E-posta Kimlik Doğrulama",
}

# Proje kökü (src/phishlens/utils/stats.py -> parents[3])
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_HISTORY_PATH = _PROJECT_ROOT / "logs" / "analysis_history.jsonl"


def _rules_that_fired(detected_rules: dict[str, Any]) -> list[str]:
    fired: list[str] = []
    for rule_key, values in detected_rules.items():
        if not values:
            continue
        if isinstance(values, list) and len(values) > 0:
            fired.append(rule_key)
        elif isinstance(values, dict):
            for sub_key, sub_val in values.items():
                if sub_val and isinstance(sub_val, list) and len(sub_val) > 0:
                    fired.append(f"{rule_key}.{sub_key}")
    return fired


def _compute_stats(history_path: Path) -> dict[str, Any]:
    total = malicious = safe = 0
    rule_counts: dict[str, int] = {}
    brand_counts: dict[str, int] = {}

    if not history_path.exists():
        return {
            "total": 0, "malicious": 0, "safe": 0, "success_rate": 0.0,
            "top_rule": None, "rule_counts": {}, "brand_counts": {},
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
            total += 1
            risk_level = entry.get("risk_level", "DÜŞÜK")
            if risk_level in ("YÜKSEK", "ORTA"):
                malicious += 1
            else:
                safe += 1
            detected = entry.get("detected_rules", {})
            for rule_key in _rules_that_fired(detected):
                rule_counts[rule_key] = rule_counts.get(rule_key, 0) + 1
            for brand in entry.get("brand", []) or []:
                if isinstance(brand, str) and brand.strip():
                    brand_counts[brand] = brand_counts.get(brand, 0) + 1

    success_rate = (malicious / total * 100) if total > 0 else 0.0
    top_rule = None
    if rule_counts:
        top_key = max(rule_counts, key=rule_counts.get)
        label = RULE_LABELS.get(top_key)
        if not label and top_key.startswith("url_heuristics."):
            sub = top_key.split(".", 1)[1]
            heur_map = {
                "homograph": "Homograph", "at_symbol": "URL @ Sembolü",
                "subdomain_count": "Subdomain", "suspicious_tld": "Şüpheli TLD",
                "url_length": "Uzun URL", "random_chars": "Rastgele Karakter",
            }
            label = heur_map.get(sub, sub)
        top_rule = (label or top_key, rule_counts[top_key])

    return {
        "total": total, "malicious": malicious, "safe": safe,
        "success_rate": success_rate, "top_rule": top_rule,
        "rule_counts": rule_counts, "brand_counts": brand_counts,
    }


def show_statistics(history_path: Path | None = None) -> None:
    path = history_path or DEFAULT_HISTORY_PATH
    stats = _compute_stats(path)
    console = Console()

    table = Table(title="PhishLens TR - Analiz İstatistikleri", show_header=True, header_style="bold cyan")
    table.add_column("Metrik", style="cyan")
    table.add_column("Değer", justify="right", style="green")
    table.add_row("Toplam Analiz Sayısı", str(stats["total"]))
    table.add_row("Tespit Edilen Oltalama (Malicious)", str(stats["malicious"]))
    table.add_row("Güvenli (Safe)", str(stats["safe"]))
    table.add_row("Başarı Oranı (%)", f"{stats['success_rate']:.1f}%")
    top = stats["top_rule"]
    table.add_row("En Çok Eşleşen Tehdit Kaynağı", f"{top[0]} ({top[1]} eşleşme)" if top else "-")
    console.print(table)

    if stats["total"] > 0:
        console.print()
        with Progress(
            TextColumn("[bold blue]Risk Oranı"),
            BarColumn(bar_width=40, complete_style="red", finished_style="red"),
            TextColumn(" "),
            TaskProgressColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("", total=100)
            progress.update(task, completed=stats["success_rate"])

    brand_counts = stats.get("brand_counts", {})
    if brand_counts:
        top_brands = sorted(brand_counts.items(), key=lambda x: -x[1])[:3]
        total_brand_hits = sum(c for _, c in top_brands)
        if total_brand_hits > 0:
            console.print()
            pie_colors = ["red", "orange1", "yellow3"]
            bar_width = 36
            block_char = "\u2588"
            pie_bar = Text()
            legend_parts: list[str] = []
            for i, (brand, count) in enumerate(top_brands):
                pct = (count / total_brand_hits) * 100
                block_count = max(1, round((count / total_brand_hits) * bar_width))
                color = pie_colors[i % len(pie_colors)]
                pie_bar.append(block_char * block_count, style=color)
                legend_parts.append(f"[{color}]{brand}[/{color}] {pct:.0f}%")
            panel_content = Text()
            panel_content.append(pie_bar)
            panel_content.append("\n\n")
            panel_content.append("  ".join(legend_parts))
            console.print(Panel(panel_content, title="[bold]En Çok Taklit Edilen 3 Kurum[/bold]", border_style="cyan"))
