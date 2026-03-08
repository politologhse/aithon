"""Prompt injection surface analysis."""
from aithon.modules.base import BaseModule
from aithon.core.finding import Finding
from aithon.config import Severity


class InjectionModule(BaseModule):

    @property
    def name(self) -> str:
        return "injection"

    @property
    def description(self) -> str:
        return "Identifies prompt injection attack surfaces in agent workspace"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        workspace_files = self.agent.get_workspace_files(self.config.target)

        for ws_file in workspace_files:
            if not ws_file.is_file():
                continue
            try:
                content = ws_file.read_text(errors="ignore")
            except (PermissionError, OSError):
                continue

            mode = ws_file.stat().st_mode
            if mode & 0o002:
                findings.append(Finding(
                    id=f"INJ-{len(findings) + 1:03d}",
                    title=f"World-writable agent instruction file: {ws_file.name}",
                    severity=Severity.CRITICAL,
                    module=self.name,
                    description=(
                        f"File {ws_file.name} is world-writable. Any user on this system "
                        "can modify the agent's instructions, enabling prompt injection. "
                        "An attacker could make the agent exfiltrate data, modify files, "
                        "or execute arbitrary commands."
                    ),
                    file_path=str(ws_file),
                    evidence=f"Permissions: {oct(mode)[-3:]}",
                    remediation=f"chmod 600 {ws_file}",
                ))

            suspicious_patterns = [
                ("ignore previous instructions", "Instruction override attempt"),
                ("disregard all prior", "Instruction override attempt"),
                ("you are now", "Role hijacking attempt"),
                ("system: ", "Fake system prompt injection"),
                ("ADMIN OVERRIDE", "Privilege escalation attempt"),
            ]

            for pattern, label in suspicious_patterns:
                if pattern.lower() in content.lower():
                    line_num = None
                    for i, line in enumerate(content.splitlines(), 1):
                        if pattern.lower() in line.lower():
                            line_num = i
                            break

                    findings.append(Finding(
                        id=f"INJ-{len(findings) + 1:03d}",
                        title=f"{label} in {ws_file.name}",
                        severity=Severity.CRITICAL,
                        module=self.name,
                        description=(
                            "Suspicious content detected in agent workspace file. "
                            f"Pattern: '{pattern}' — this could be a prompt injection "
                            "planted by a previous agent interaction or malicious file."
                        ),
                        file_path=str(ws_file),
                        line_number=line_num,
                        evidence=f"Pattern: {pattern}",
                        remediation=(
                            "Review the file content manually. Remove any injected "
                            "instructions. Consider restricting file write access."
                        ),
                    ))

        return findings
