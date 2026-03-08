"""Custom TUI widgets."""
from textual.widgets import Static


class SeverityBadge(Static):
    """Colored severity badge."""

    def __init__(self, severity: str, **kwargs):
        colors = {
            "CRITICAL": ("white", "#ff0033"),
            "HIGH": ("white", "#ff6600"),
            "MEDIUM": ("black", "#ffcc00"),
            "LOW": ("white", "#00802a"),
        }
        fg, bg = colors.get(severity, ("white", "gray"))
        super().__init__(f" {severity} ", **kwargs)
        self.styles.background = bg
        self.styles.color = fg
