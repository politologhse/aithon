"""Report generation."""
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from aithon.core.finding import Finding
from aithon.config import ScanConfig, Severity


def print_terminal_report(findings: list[Finding], config: ScanConfig) -> None:
    console = Console()

    if not findings:
        console.print(Panel(
            "[bold green]No security issues found.[/bold green]\n"
            "Target appears clean. Stay vigilant.",
            title="[bold]AITHON SCAN COMPLETE[/bold]",
            border_style="green",
        ))
        return

    by_severity: dict[str, int] = {}
    for f in findings:
        label = f.severity_label
        by_severity[label] = by_severity.get(label, 0) + 1

    summary = " | ".join(f"{k}: {v}" for k, v in sorted(by_severity.items()))
    console.print(Panel(
        f"[bold]{len(findings)}[/bold] issues found — {summary}",
        title="[bold red]AITHON SCAN RESULTS[/bold red]",
        border_style="red",
    ))

    table = Table(show_header=True, header_style="bold")
    table.add_column("SEV", width=4, justify="center")
    table.add_column("ID", width=8)
    table.add_column("Title", min_width=30)
    table.add_column("File", max_width=40)
    table.add_column("Module", width=12)

    severity_colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "dim",
    }

    for f in findings:
        color = severity_colors.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity_emoji}[/{color}]",
            f.id,
            f.title,
            f.file_path or "—",
            f.module,
        )

    console.print(table)

    critical = [f for f in findings if f.severity >= Severity.HIGH]
    for f in critical:
        console.print(Panel(
            f"[bold]{f.description}[/bold]\n\n"
            f"Evidence: {f.evidence or 'N/A'}\n"
            f"Fix: {f.remediation}",
            title=f"[bold red]{f.id}: {f.title}[/bold red]",
            border_style="red",
        ))


def save_report(findings: list[Finding], config: ScanConfig, path: Path) -> None:
    if path.suffix == ".json":
        data = {
            "scanner": "aithon",
            "version": "0.1.0",
            "target": str(config.target),
            "findings_count": len(findings),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity_label,
                    "module": f.module,
                    "description": f.description,
                    "file": f.file_path,
                    "line": f.line_number,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in findings
            ],
        }
        path.write_text(json.dumps(data, indent=2))
    else:
        lines = [
            "# Aithon Security Scan Report\n",
            f"**Target:** `{config.target}`\n",
            f"**Findings:** {len(findings)}\n",
            "\n---\n",
        ]
        for f in findings:
            lines.append(f"\n## {f.severity_emoji} [{f.severity_label}] {f.id}: {f.title}\n")
            lines.append(f"\n{f.description}\n")
            if f.file_path:
                lines.append(f"\n**File:** `{f.file_path}`")
            if f.line_number:
                lines.append(f" (line {f.line_number})")
            lines.append(f"\n\n**Fix:** {f.remediation}\n")

        path.write_text("\n".join(lines))
