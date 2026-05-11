from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

theme = Theme(
    {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "dim",
        "heading": "bold cyan",
    }
)

console = Console(theme=theme, stderr=False)
err_console = Console(theme=theme, stderr=True)
