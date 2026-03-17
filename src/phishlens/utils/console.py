"""
PhishLens TR - Rich tabanlı konsol çıktı modülü.

Panel, Table, Markdown ve renkli çıktı desteği.
"""

from __future__ import annotations

from typing import Any

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.markdown import Markdown
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

_console: Console | None = None


def _get_console() -> Console | None:
    global _console
    if RICH_AVAILABLE and _console is None:
        _console = Console()
    return _console


def print_risk_result(risk: str, score: int, details: dict[str, Any] | None = None) -> None:
    c = _get_console()
    if not c:
        return
    risk_colors = {"YÜKSEK": "red", "YUKSEK": "red", "ORTA": "yellow", "DÜŞÜK": "green", "DUSUK": "green"}
    color = risk_colors.get(risk.upper(), "white")
    content = Text()
    content.append("Risk: ", style="bold")
    content.append(risk, style=f"bold {color}")
    content.append(f"\nSkor: {score}", style="dim")
    if details:
        for k, v in details.items():
            if v:
                content.append(f"\n{k}: ", style="bold")
                content.append(str(v), style="dim")
    c.print(Panel(content, title="[bold]PhishLens TR - Analiz Sonucu[/bold]", border_style=color))


def print_success(message: str) -> None:
    c = _get_console()
    if c:
        c.print(f"[green][OK][/green] {message}")
    else:
        print(message)


def print_error(message: str) -> None:
    c = _get_console()
    if c:
        c.print(f"[red][HATA][/red] {message}")
    else:
        print(message)


def print_warning(message: str) -> None:
    c = _get_console()
    if c:
        c.print(f"[yellow][!][/yellow] {message}")
    else:
        print(message)


def print_info(message: str) -> None:
    c = _get_console()
    if c:
        c.print(f"[blue][i][/blue] {message}")
    else:
        print(message)


def print_header(title: str, subtitle: str = "") -> None:
    c = _get_console()
    if c:
        c.print(Panel(title, title="[bold]PhishLens TR[/bold]", subtitle=subtitle or None, style="cyan"))
    else:
        print(title)
        if subtitle:
            print(subtitle)


def print_table(headers: list[str], rows: list[list[str]], title: str = "") -> None:
    c = _get_console()
    if not c:
        return
    table = Table(title=title or None)
    for h in headers:
        table.add_column(h, style="cyan")
    for row in rows:
        table.add_row(*row)
    c.print(table)


def print_markdown(text: str) -> None:
    c = _get_console()
    if c:
        c.print(Markdown(text))
    else:
        print(text)


def print_plain(*args: Any, **kwargs: Any) -> None:
    c = _get_console()
    if c:
        c.print(*args, **kwargs)
    else:
        print(*args, **kwargs)
