"""CLI entry point."""
import click
from pathlib import Path


@click.group()
@click.version_option()
def main():
    """Aithon — AI Agent Security Scanner.

    The eagle that finds what agents try to hide.
    """
    pass


@main.command()
@click.argument("target", type=click.Path(exists=True), default=".")
@click.option(
    "--agent", "-a",
    type=click.Choice(["openclaw", "auto"]),
    default="auto",
    help="Agent type to scan for",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output report file (json/md)")
@click.option(
    "--severity", "-s",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="low",
    help="Minimum severity to report",
)
@click.option("--no-tui", is_flag=True, help="Run headless (no TUI)")
def scan(target: str, agent: str, output: str | None, severity: str, no_tui: bool):
    """Scan an AI agent workspace for security issues."""
    target_path = Path(target).resolve()

    if no_tui:
        from aithon.core.scanner import Scanner
        from aithon.config import ScanConfig

        config = ScanConfig(
            target=target_path,
            agent_type=agent,
            min_severity=severity,
        )
        scanner = Scanner(config)
        findings = scanner.run()

        from aithon.core.report import print_terminal_report
        print_terminal_report(findings, config)

        if output:
            from aithon.core.report import save_report
            save_report(findings, config, Path(output))
    else:
        from aithon.app import AithonApp
        app = AithonApp(target_path=target_path, agent_type=agent)
        app.run()


@main.command()
def agents():
    """List supported agent types and their detection patterns."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="Supported Agent Types", style="green")
    table.add_column("Agent", style="bold cyan")
    table.add_column("Detection", style="white")
    table.add_column("Status", style="yellow")

    table.add_row("OpenClaw", "~/.openclaw/ or models.json", "✓ Full support")
    table.add_row("Cline", "~/.cline/ or cline.json", "◌ Planned v0.2")
    table.add_row("Aider", "~/.aider/ or .aider.conf.yml", "◌ Planned v0.2")
    table.add_row("Generic", "Any workspace with .env files", "◌ Planned v0.3")

    console.print(table)
