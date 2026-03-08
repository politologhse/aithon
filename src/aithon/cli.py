"""CLI entry point."""
from __future__ import annotations
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


@main.command(name="fix-plan")
@click.argument("target", type=click.Path(exists=True), default=".")
@click.option(
    "--agent", "-a",
    type=click.Choice(["openclaw", "auto"]),
    default="auto",
    help="Agent type to scan for",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Save script to file")
@click.option(
    "--severity", "-s",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="low",
    help="Minimum severity to include in plan",
)
def fix_plan(target: str, agent: str, output: str | None, severity: str):
    """Generate a remediation script from scan findings.

    Scans the target, then outputs a bash script with fixes.
    Review the script before running it.
    """
    from rich.console import Console
    from aithon.core.scanner import Scanner
    from aithon.core.fix_plan import generate_fix_plan
    from aithon.config import ScanConfig

    console = Console()
    target_path = Path(target).resolve()

    config = ScanConfig(
        target=target_path,
        agent_type=agent,
        min_severity=severity,
    )
    scanner = Scanner(config)
    findings = scanner.run()

    if not findings:
        console.print("[bold green]No findings — no fix plan needed.[/bold green]")
        return

    script = generate_fix_plan(findings, target_path)

    if output:
        out_path = Path(output)
        out_path.write_text(script)
        out_path.chmod(0o755)
        console.print(f"[bold green]Fix plan saved to: {out_path}[/bold green]")
        console.print(f"[dim]Review it, then run: bash {out_path}[/dim]")
    else:
        console.print(script)


@main.command()
@click.argument("target", type=click.Path(exists=True), default=".")
@click.option(
    "--agent", "-a",
    type=click.Choice(["openclaw", "auto"]),
    default="auto",
    help="Agent type to scan for",
)
@click.option(
    "--interval", "-i",
    type=int,
    default=3600,
    help="Scan interval in seconds (default: 3600)",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="low",
    help="Minimum severity to report",
)
@click.option(
    "--telegram-token", "-t",
    envvar="AITHON_TELEGRAM_TOKEN",
    default=None,
    help="Telegram bot token (or env AITHON_TELEGRAM_TOKEN)",
)
@click.option(
    "--telegram-chat-id", "-c",
    envvar="AITHON_TELEGRAM_CHAT_ID",
    default=None,
    help="Telegram chat ID (or env AITHON_TELEGRAM_CHAT_ID)",
)
@click.option(
    "--alert-severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="high",
    help="Minimum severity for Telegram alerts (default: high)",
)
def watch(
    target: str,
    agent: str,
    interval: int,
    severity: str,
    telegram_token: str | None,
    telegram_chat_id: str | None,
    alert_severity: str,
):
    """Watch mode — continuous monitoring with Telegram alerts.

    Runs periodic scans and reports new findings.
    Only alerts on findings that weren't present in the previous scan.
    """
    from aithon.config import ScanConfig, Severity
    from aithon.core.watcher import Watcher

    target_path = Path(target).resolve()

    config = ScanConfig(
        target=target_path,
        agent_type=agent,
        min_severity=severity,
    )

    watcher = Watcher(
        config=config,
        interval=interval,
        telegram_token=telegram_token,
        telegram_chat_id=telegram_chat_id,
        alert_severity=Severity.from_str(alert_severity),
    )
    watcher.run_loop()


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
    table.add_row("Cline", "~/.cline/ or cline.json", "◌ Planned")
    table.add_row("Aider", "~/.aider/ or .aider.conf.yml", "◌ Planned")
    table.add_row("Generic", "Any workspace with .env files", "◌ Planned")

    console.print(table)
