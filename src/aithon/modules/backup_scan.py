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

        for backup_dir in backup_paths:
            if not backup_dir.is_dir():
                continue

            for file_path in backup_dir.rglob("*"):
                if not file_path.is_file():
                    continue
                if file_path.stat().st_size > 10 * 1024 * 1024:
                    continue

                try:
                    content = file_path.read_text(errors="ignore")
                except (PermissionError, OSError):
                    continue

                for pattern_name, pattern in SECRET_PATTERNS.items():
                    if re.search(pattern, content):
                        findings.append(Finding(
                            id=f"BAK-{len(findings) + 1:03d}",
                            title=f"Secret in backup: {pattern_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=(
                                f"Backup file contains {pattern_name}. "
                                "Backups often retain secrets that were removed from "
                                "production configs, creating a false sense of security."
                            ),
                            file_path=str(file_path),
                            evidence=f"Found in: {file_path.relative_to(backup_dir)}",
                            remediation=(
                                "Clean backup files of secrets. Use `ocback` snapshots "
                                "that exclude sensitive env vars, or encrypt backups."
                            ),
                        ))
                        break

        return findings
