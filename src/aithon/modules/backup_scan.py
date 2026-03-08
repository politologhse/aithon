"""Backup file scanning module."""
import re
from aithon.modules.base import BaseModule
from aithon.core.finding import Finding
from aithon.config import Severity
from aithon.utils.patterns import SECRET_PATTERNS


class BackupScanModule(BaseModule):

    @property
    def name(self) -> str:
        return "backup_scan"

    @property
    def description(self) -> str:
        return "Scans backup files and archives for leaked secrets"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        backup_paths = self.agent.get_backup_paths(self.config.target)
        hits: dict[str, list[str]] = {}

        for backup_dir in backup_paths:
            if not backup_dir.is_dir():
                continue

            for file_path in backup_dir.rglob("*"):
                if not file_path.is_file():
                    continue
                if file_path.stat().st_size > 10 * 1024 * 1024:
                    continue

                try:
                    file_content = file_path.read_text(errors="ignore")
                except (PermissionError, OSError):
                    continue

                for pattern_name, pattern in SECRET_PATTERNS.items():
                    if re.search(pattern, file_content):
                        hits.setdefault(pattern_name, []).append(str(file_path))
                        break

        for pattern_name, files in hits.items():
            findings.append(Finding(
                id=f"BAK-{len(findings) + 1:03d}",
                title=f"Secret in backups: {pattern_name} ({len(files)} files)",
                severity=Severity.HIGH,
                module=self.name,
                description=(
                    f"{pattern_name} found in {len(files)} backup file(s). "
                    "Backups often retain secrets removed from production configs."
                ),
                file_path=files[0],
                evidence=f"{len(files)} backup files contain this secret type",
                remediation=(
                    "Clean backup files of secrets. Use `ocback` snapshots "
                    "that exclude sensitive env vars, or encrypt backups."
                ),
            ))

        return findings
