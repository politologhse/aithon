"""File permission audit module."""
import stat
from aithon.modules.base import BaseModule
from aithon.core.finding import Finding
from aithon.config import Severity


class PermissionsModule(BaseModule):

    @property
    def name(self) -> str:
        return "permissions"

    @property
    def description(self) -> str:
        return "Checks file permissions on sensitive config and key files"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        sensitive_files = self.agent.get_sensitive_files(self.config.target)

        for file_path in sensitive_files:
            if not file_path.exists():
                continue
            try:
                st = file_path.stat()
            except (PermissionError, OSError):
                continue

            mode = st.st_mode

            if mode & stat.S_IROTH:
                findings.append(Finding(
                    id=f"PERM-{len(findings) + 1:03d}",
                    title=f"World-readable sensitive file: {file_path.name}",
                    severity=Severity.HIGH,
                    module=self.name,
                    description=(
                        f"File {file_path} is readable by all users (mode: {oct(mode)[-3:]}). "
                        "Sensitive configuration files should only be readable by the owner."
                    ),
                    file_path=str(file_path),
                    evidence=f"Permissions: {oct(mode)[-3:]}",
                    remediation=f"Run: chmod 600 {file_path}",
                ))

            if mode & stat.S_IWOTH:
                findings.append(Finding(
                    id=f"PERM-{len(findings) + 1:03d}",
                    title=f"World-writable sensitive file: {file_path.name}",
                    severity=Severity.CRITICAL,
                    module=self.name,
                    description=(
                        f"File {file_path} is writable by all users. "
                        "An attacker could modify agent configuration or inject malicious prompts."
                    ),
                    file_path=str(file_path),
                    evidence=f"Permissions: {oct(mode)[-3:]}",
                    remediation=f"Run: chmod 600 {file_path}",
                ))

        return findings
