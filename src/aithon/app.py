"""Textual TUI application."""
from pathlib import Path
from textual.app import App
from textual.binding import Binding

from aithon.config import ScanConfig
from aithon.core.scanner import Scanner
from aithon.ui.theme import CRT_CSS
from aithon.ui.screens import SplashScreen, ScanScreen, ReportScreen


class AithonApp(App):
    """Aithon Security Scanner TUI."""

    CSS = CRT_CSS
    TITLE = "AITHON"
    SUB_TITLE = "AI Agent Security Scanner"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
    ]

    SCREENS = {
        "splash": SplashScreen,
        "scan": ScanScreen,
        "report": ReportScreen,
    }

    def __init__(self, target_path: Path, agent_type: str = "auto"):
        super().__init__()
        self.config = ScanConfig(target=target_path, agent_type=agent_type)
        self.scanner = Scanner(self.config)

    def on_mount(self) -> None:
        self.push_screen("splash")
