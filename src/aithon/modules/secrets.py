"""Secret / API key leak detection module."""
import re
from aithon.modules.base import BaseModule
from aithon.core.finding import Finding
from aithon.config import Severity
from aithon.utils.patterns import SECRET_PATTERNS


class SecretsModule(BaseModule):

    @property
    def name(self) -> str:
        return "secrets"

    @property
    def description(self) -> str:
        return "Detects leaked API keys, tokens, and secrets in files"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        seen_secrets: set[str] = set()
        scan_paths = self.agent.get_secret_scan_paths(self.config.target)

        for file_path in scan_paths:
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text(errors="ignore")
            except (PermissionError, OSError):
                continue

            for pattern_name, pattern in SECRET_PATTERNS.items():
                for match in re.finditer(pattern, content):
                    secret = match.group(0)
                    if len(secret) > 12:
                        redacted = secret[:4] + "****" + secret[-4:]
                    else:
                        redacted = "****"

                    line_num = content[:match.start()].count("\n") + 1

                    # Deduplicate by actual secret value
                    if secret in seen_secrets:
                        continue
                    seen_secrets.add(secret)

                    findings.append(Finding(
                        id=f"SEC-{len(findings) + 1:03d}",
                        title=f"{pattern_name} found in {file_path.name}",
                        severity=Severity.CRITICAL,
                        module=self.name,
                        description=(
                            f"A {pattern_name} was found exposed in a file. "
                            "This key could be extracted by malicious actors or "
                            "accidentally committed to version control."
                        ),
                        file_path=str(file_path),
                        line_number=line_num,
                        evidence=redacted,
                        remediation=(
                            f"Move this {pattern_name} to a systemd environment variable "
                            "or a secrets manager. Remove from the file and rotate the key."
                        ),
                    ))

        return findings
