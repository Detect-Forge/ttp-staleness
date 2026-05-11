from rich.console import Console

from detect_forge.console import console, err_console, theme


def test_theme_has_required_severity_styles() -> None:
    for name in ("critical", "high", "medium", "low", "info", "heading"):
        assert name in theme.styles


def test_console_writes_to_stdout() -> None:
    assert isinstance(console, Console)
    assert console.stderr is False


def test_err_console_writes_to_stderr() -> None:
    assert isinstance(err_console, Console)
    assert err_console.stderr is True
