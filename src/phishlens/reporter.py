"""
PhishLens TR - Analiz sonuç raporlama modülü.

Rich Table ve Panel ile terminale formatlı analiz çıktısı.
"""

from __future__ import annotations

from typing import Any, Literal

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

DurumTuru = Literal["güvenli", "şüpheli", "tehlikeli", "guvenli", "supheli"]
DURUM_STYLE = {
    "güvenli": "bold green", "guvenli": "bold green",
    "şüpheli": "bold yellow", "supheli": "bold yellow",
    "tehlikeli": "bold red",
}
DURUM_LABEL = {
    "güvenli": "Güvenli", "guvenli": "Güvenli",
    "şüpheli": "Şüpheli", "supheli": "Şüpheli",
    "tehlikeli": "Tehlikeli",
}

_console: Console | None = None


def _get_console() -> Console | None:
    global _console
    if RICH_AVAILABLE and _console is None:
        _console = Console()
    return _console


def _risk_to_durum(risk_puani: int) -> str:
    if risk_puani >= 70:
        return "Tehlikeli"
    if risk_puani >= 30:
        return "Şüpheli"
    return "Güvenli"


def _risk_to_style(risk_puani: int) -> str:
    if risk_puani >= 70:
        return DURUM_STYLE["tehlikeli"]
    if risk_puani >= 30:
        return DURUM_STYLE["şüpheli"]
    return DURUM_STYLE["güvenli"]


def print_analysis_report(
    rows: list[dict[str, Any]],
    overall_risk: str,
    overall_score: int,
    *,
    title: str = "PhishLens TR - Analiz Raporu",
) -> None:
    c = _get_console()
    if not c:
        for r in rows:
            print(f"{r.get('kriter', '')} | {r.get('durum', '')} | {r.get('detay', '')} | {r.get('risk_puani', 0)}")
        print(f"\nGenel Sonuç: {overall_risk} ({overall_score})")
        return

    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("Kriter", style="cyan", no_wrap=False)
    table.add_column("Durum", style="bold", min_width=10)
    table.add_column("Detay", no_wrap=False, max_width=50)
    table.add_column("Risk Puanı", justify="right", style="dim")

    for row in rows:
        kriter = str(row.get("kriter", ""))
        durum_raw = str(row.get("durum", "güvenli")).lower()
        detay = str(row.get("detay", ""))
        risk_puani = int(row.get("risk_puani", 0))
        if durum_raw in DURUM_STYLE:
            durum_style = DURUM_STYLE[durum_raw]
            durum_text = DURUM_LABEL.get(durum_raw, durum_raw.capitalize())
        else:
            durum_style = _risk_to_style(risk_puani)
            durum_text = _risk_to_durum(risk_puani)
        table.add_row(
            kriter,
            f"[{durum_style}]{durum_text}[/]",
            detay[:80] + "..." if len(detay) > 80 else detay,
            str(min(100, max(0, risk_puani))),
        )

    c.print(table)
    c.print()
    risk_upper = overall_risk.upper()
    panel_colors = {"YÜKSEK": "red", "ORTA": "yellow", "DÜŞÜK": "green"}
    panel_color = panel_colors.get(risk_upper, "white")
    c.print(
        Panel(
            f"[bold]{risk_upper}[/bold]\nSkor: {overall_score}",
            title="[bold]Risk Paneli[/bold]",
            border_style=panel_color,
        )
    )


def scan_result_to_report_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    hits = result.get("hits", {})
    rows: list[dict[str, Any]] = []

    if hits.get("urls"):
        rows.append({
            "kriter": "URL Tespiti",
            "durum": "şüpheli" if hits["urls"] else "güvenli",
            "detay": ", ".join(hits["urls"][:3]) + ("..." if len(hits["urls"]) > 3 else "") or "URL yok",
            "risk_puani": min(100, len(hits["urls"]) * 15),
        })

    domain_sim = hits.get("domain_similarity", [])
    if domain_sim:
        det = "; ".join(f"{d} ~ {k}" for d, k, _, _ in domain_sim[:2])
        rows.append({
            "kriter": "URL Benzerliği",
            "durum": "tehlikeli",
            "detay": det,
            "risk_puani": 85,
        })
    else:
        rows.append({
            "kriter": "URL Benzerliği",
            "durum": "güvenli",
            "detay": "Bilinen domain taklidi yok",
            "risk_puani": 0,
        })

    words = hits.get("words", [])
    official = hits.get("official", [])
    regex = hits.get("regex", [])
    combined = list(set(words + official + [h[1] for h in regex[:5]]))
    if combined:
        rows.append({
            "kriter": "Türkçe Kelime Analizi",
            "durum": "şüpheli" if len(combined) < 5 else "tehlikeli",
            "detay": ", ".join(str(x) for x in combined[:5]),
            "risk_puani": min(100, len(combined) * 12),
        })
    else:
        rows.append({
            "kriter": "Türkçe Kelime Analizi",
            "durum": "güvenli",
            "detay": "Şüpheli ifade yok",
            "risk_puani": 0,
        })

    emotion = hits.get("emotion_risk", {})
    if emotion:
        escore = emotion.get("score", 0)
        rows.append({
            "kriter": "Duygu ve Risk Skoru",
            "durum": "tehlikeli" if escore >= 70 else ("şüpheli" if escore >= 30 else "güvenli"),
            "detay": f"Skor: {escore} | Anahtar kelime: {emotion.get('keyword_count', 0)}",
            "risk_puani": int(escore),
        })

    email_auth = result.get("email_auth", {})
    if email_auth and email_auth.get("details"):
        rows.append({
            "kriter": "E-posta Kimlik Doğrulama",
            "durum": "şüpheli",
            "detay": "; ".join(email_auth["details"]),
            "risk_puani": email_auth.get("score_added", 0) * 10,
        })

    return rows
