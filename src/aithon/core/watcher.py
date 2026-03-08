"""Watch mode — continuous monitoring with diff detection and Telegram alerts."""
from __future__ import annotations

import hashlib
import json
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

from aithon.config import ScanConfig, Severity
from aithon.core.finding import Finding
from aithon.core.scanner import Scanner


class Watcher:
    """Runs periodic scans and alerts on new findings."""

    def __init__(
        self,
        config: ScanConfig,
        interval: int = 3600,
        state_file: Path | None = None,
        telegram_token: str | None = None,
        telegram_chat_id: str | None = None,
        alert_severity: Severity = Severity.HIGH,
    ):
        self.config = config
        self.interval = interval
        self.state_file = state_file or (config.target / ".aithon-state.json")
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.alert_severity = alert_severity
        self._previous_hashes: set[str] = set()
        self._load_state()

    def _finding_hash(self, f: Finding) -> str:
        """Stable hash for a finding — same issue = same hash."""
        key = f"{f.module}:{f.title}:{f.file_path}:{f.evidence}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _load_state(self) -> None:
        if self.state_file.is_file():
            try:
                data = json.loads(self.state_file.read_text())
                self._previous_hashes = set(data.get("finding_hashes", []))
            except (json.JSONDecodeError, OSError):
                self._previous_hashes = set()

    def _save_state(self, findings: list[Finding]) -> None:
        hashes = [self._finding_hash(f) for f in findings]
        data = {
            "finding_hashes": hashes,
            "last_scan": datetime.now().isoformat(),
            "findings_count": len(findings),
        }
        try:
            self.state_file.write_text(json.dumps(data, indent=2))
        except OSError:
            pass

    def _diff_findings(self, findings: list[Finding]) -> tuple[list[Finding], list[str]]:
        """Return (new_findings, resolved_hashes)."""
        current_hashes = {self._finding_hash(f): f for f in findings}
        new = [
            f for h, f in current_hashes.items()
            if h not in self._previous_hashes
        ]
        resolved = [
            h for h in self._previous_hashes
            if h not in current_hashes
        ]
        return new, resolved

    def _send_telegram(self, message: str) -> bool:
        if not self.telegram_token or not self.telegram_chat_id:
            return False

        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = json.dumps({
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": "HTML",
        }).encode()

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def _format_alert(
        self,
        new_findings: list[Finding],
        resolved_count: int,
        total: int,
    ) -> str:
        lines = ["🦅 <b>AITHON SECURITY ALERT</b>\n"]
        lines.append(f"Target: <code>{self.config.target}</code>")
        lines.append(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"Total issues: {total}\n")

        if new_findings:
            lines.append(f"🚨 <b>{len(new_findings)} NEW issue(s):</b>\n")
            for f in new_findings[:10]:
                sev = {
                    Severity.CRITICAL: "🔴",
                    Severity.HIGH: "🟠",
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "⚪",
                }.get(f.severity, "⚪")
                lines.append(f"{sev} [{f.severity_label}] {f.id}: {f.title}")
                if f.file_path:
                    short_path = f.file_path.split("/")[-1]
                    lines.append(f"   📁 {short_path}")
            if len(new_findings) > 10:
                lines.append(f"\n... and {len(new_findings) - 10} more")

        if resolved_count:
            lines.append(f"\n✅ {resolved_count} issue(s) resolved")

        return "\n".join(lines)

    def scan_once(self) -> tuple[list[Finding], list[Finding], int]:
        """Run one scan, return (all_findings, new_findings, resolved_count)."""
        scanner = Scanner(self.config)
        findings = scanner.run()

        new_findings, resolved_hashes = self._diff_findings(findings)
        resolved_count = len(resolved_hashes)

        # Update state
        self._previous_hashes = {self._finding_hash(f) for f in findings}
        self._save_state(findings)

        return findings, new_findings, resolved_count

    def run_loop(self) -> None:
        """Main watch loop — runs until interrupted."""
        from rich.console import Console
        console = Console()

        console.print("[bold green]🦅 AITHON WATCH MODE[/bold green]")
        console.print(f"Target: {self.config.target}")
        console.print(f"Interval: {self.interval}s")
        if self.telegram_token:
            console.print("[green]Telegram alerts: enabled[/green]")
        else:
            console.print("[dim]Telegram alerts: disabled[/dim]")
        console.print()

        scan_num = 0
        while True:
            scan_num += 1
            now = datetime.now().strftime("%H:%M:%S")
            console.print(f"[dim]\\[{now}][/dim] Scan #{scan_num}...")

            try:
                findings, new_findings, resolved_count = self.scan_once()
            except Exception as e:
                console.print(f"[red]  Scan error: {e}[/red]")
                time.sleep(self.interval)
                continue

            # Print summary
            if new_findings:
                console.print(
                    f"[bold red]  🚨 {len(new_findings)} NEW issue(s) "
                    f"(total: {len(findings)})[/bold red]"
                )
                for f in new_findings:
                    console.print(f"    [red]{f.severity_emoji} {f.id}: {f.title}[/red]")
            else:
                console.print(
                    f"[green]  ✓ No new issues (total: {len(findings)})[/green]"
                )

            if resolved_count:
                console.print(f"[green]  ✅ {resolved_count} resolved[/green]")

            # Send Telegram alert if there are new findings above threshold
            alertable = [f for f in new_findings if f.severity >= self.alert_severity]
            if alertable and self.telegram_token:
                msg = self._format_alert(alertable, resolved_count, len(findings))
                sent = self._send_telegram(msg)
                if sent:
                    console.print("  [dim]📨 Telegram alert sent[/dim]")
                else:
                    console.print("  [red]📨 Telegram send failed[/red]")

            # Wait
            try:
                time.sleep(self.interval)
            except KeyboardInterrupt:
                console.print("\n[bold green]Watch stopped.[/bold green]")
                break
