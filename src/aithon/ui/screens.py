"""TUI screens."""
from textual.screen import Screen
from textual.app import ComposeResult
from textual.widgets import Static, DataTable, Footer, RichLog, Button, ProgressBar
from textual.containers import Horizontal, Vertical
from textual.binding import Binding
import asyncio

from aithon.ui.ascii_art import TITLE, BOOT_SEQUENCE
from aithon.config import Severity


class SplashScreen(Screen):
    """Boot sequence splash screen."""

    BINDINGS = [Binding("enter", "start", "Start Scan")]

    def compose(self) -> ComposeResult:
        yield Static(TITLE, id="splash-logo")
        yield RichLog(id="boot-log", highlight=True)
        yield Static("[blink]Press ENTER to begin scan[/blink]", id="splash-prompt")

    async def on_mount(self) -> None:
        log = self.query_one("#boot-log", RichLog)
        for line in BOOT_SEQUENCE:
            log.write(f"[green]> {line}[/green]")
            await asyncio.sleep(0.15)

    def action_start(self) -> None:
        self.app.push_screen("scan")


class ScanScreen(Screen):
    """Main scan screen with live progress."""

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "report", "Full Report"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("[bold green]AITHON SCAN[/bold green]", id="header")
        yield Horizontal(
            Vertical(
                RichLog(id="scan-log", highlight=True),
                id="log-container",
            ),
            Vertical(
                DataTable(id="findings-table"),
                id="table-container",
            ),
        )
        yield ProgressBar(id="progress", total=100, show_eta=True)
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("SEV", "ID", "Title", "File")
        table.cursor_type = "row"
        self.run_worker(self._run_scan())

    async def _run_scan(self) -> None:
        log = self.query_one("#scan-log", RichLog)
        table = self.query_one("#findings-table", DataTable)
        progress = self.query_one("#progress", ProgressBar)

        scanner = self.app.scanner
        modules = scanner.module_names
        step = 100 / max(len(modules), 1)

        for _i, module_name in enumerate(modules):
            log.write(f"[green]▶ Scanning: {module_name}...[/green]")

            try:
                findings = scanner.run_module(module_name)
                for f in findings:
                    if f.severity >= scanner.config.severity_threshold:
                        sev_style = {
                            Severity.CRITICAL: "[bold red]✖ CRIT[/bold red]",
                            Severity.HIGH: "[red]◆ HIGH[/red]",
                            Severity.MEDIUM: "[yellow]▲ MED[/yellow]",
                            Severity.LOW: "[dim]● LOW[/dim]",
                        }.get(f.severity, "?")

                        table.add_row(
                            sev_style,
                            f.id,
                            f.title[:50],
                            (f.file_path or "—")[-40:],
                        )
                        scanner.findings.append(f)

                count = len(findings)
                if count:
                    log.write(f"[yellow]  └─ {count} issue(s) found[/yellow]")
                else:
                    log.write("[dim green]  └─ Clean[/dim green]")
            except Exception as e:
                log.write(f"[red]  └─ ERROR: {e}[/red]")

            progress.advance(step)
            await asyncio.sleep(0.1)

        total = len(scanner.findings)
        if total:
            log.write(f"\n[bold red]SCAN COMPLETE: {total} issue(s) found[/bold red]")
        else:
            log.write("\n[bold green]SCAN COMPLETE: No issues found. Stay vigilant.[/bold green]")

        progress.update(total=100, progress=100)

    def action_report(self) -> None:
        self.app.push_screen("report")


class ReportScreen(Screen):
    """Detailed findings report."""

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("escape", "back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("[bold green]AITHON REPORT[/bold green]", id="header")
        yield RichLog(id="report-log", highlight=True)
        yield Horizontal(
            Button("Save JSON", id="save-json"),
            Button("Save Markdown", id="save-md"),
            Button("Back", id="back"),
        )
        yield Footer()

    async def on_mount(self) -> None:
        log = self.query_one("#report-log", RichLog)
        findings = self.app.scanner.findings

        if not findings:
            log.write("[bold green]No findings to report.[/bold green]")
            return

        for f in findings:
            sev_color = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "dim green",
            }.get(f.severity, "white")

            log.write(
                f"[{sev_color}]{f.severity_emoji} [{f.severity_label}] "
                f"{f.id}: {f.title}[/{sev_color}]"
            )
            log.write(f"  {f.description}")
            if f.file_path:
                log.write(f"  [dim]File: {f.file_path}[/dim]")
            if f.evidence:
                log.write(f"  [dim]Evidence: {f.evidence}[/dim]")
            log.write(f"  [green]Fix: {f.remediation}[/green]")
            log.write("")

    def action_back(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "save-json":
            from aithon.core.report import save_report
            from pathlib import Path
            save_report(
                self.app.scanner.findings, self.app.scanner.config, Path("aithon-report.json")
            )
            self.notify("Saved: aithon-report.json")
        elif event.button.id == "save-md":
            from aithon.core.report import save_report
            from pathlib import Path
            save_report(
                self.app.scanner.findings, self.app.scanner.config, Path("aithon-report.md")
            )
            self.notify("Saved: aithon-report.md")
