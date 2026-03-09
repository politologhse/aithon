"""Advanced prompt injection hardening checks."""
from __future__ import annotations

import json
import re
import stat
from aithon.modules.base import BaseModule
from aithon.core.finding import Finding
from aithon.config import Severity


# Patterns that indicate prompt injection attempts
INJECTION_PATTERNS: list[tuple[str, str, Severity]] = [
    ("ignore previous instructions", "Instruction override", Severity.CRITICAL),
    ("ignore all prior", "Instruction override", Severity.CRITICAL),
    ("disregard all prior", "Instruction override", Severity.CRITICAL),
    ("forget everything above", "Instruction override", Severity.CRITICAL),
    ("new instructions:", "Instruction override", Severity.CRITICAL),
    ("you are now", "Role hijacking", Severity.HIGH),
    ("act as root", "Privilege escalation", Severity.CRITICAL),
    ("pretend you are", "Role hijacking", Severity.HIGH),
    ("from now on you", "Role hijacking", Severity.HIGH),
    ("system:", "Fake system prompt", Severity.HIGH),
    ("ADMIN OVERRIDE", "Privilege escalation", Severity.CRITICAL),
    ("DEVELOPER MODE", "Privilege escalation", Severity.HIGH),
    ("send the contents of", "Data exfiltration", Severity.CRITICAL),
    ("output all api keys", "Data exfiltration", Severity.CRITICAL),
    ("read /etc/passwd", "Data exfiltration", Severity.CRITICAL),
    ("cat ~/.ssh", "Data exfiltration", Severity.CRITICAL),
    ("\u200b", "Zero-width space (invisible injection)", Severity.HIGH),
    ("\u200c", "Zero-width non-joiner (invisible injection)", Severity.HIGH),
    ("\u200d", "Zero-width joiner (invisible injection)", Severity.HIGH),
    ("\u2060", "Word joiner (invisible injection)", Severity.HIGH),
]


class InjectionModule(BaseModule):

    @property
    def name(self) -> str:
        return "injection"

    @property
    def description(self) -> str:
        return "Detects prompt injection vectors and workspace hardening issues"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_workspace_permissions())
        findings.extend(self._check_injection_patterns())
        findings.extend(self._check_skill_injection())
        findings.extend(self._check_inbound_media())
        findings.extend(self._check_sandbox_config())
        return findings

    def _check_workspace_permissions(self) -> list[Finding]:
        findings: list[Finding] = []
        for ws_file in self.agent.get_workspace_files(self.config.target):
            if not ws_file.is_file():
                continue
            try:
                mode = ws_file.stat().st_mode
            except (PermissionError, OSError):
                continue

            if mode & stat.S_IWOTH:
                findings.append(Finding(
                    id=f"INJ-{len(findings) + 1:03d}",
                    title=f"World-writable instruction file: {ws_file.name}",
                    severity=Severity.CRITICAL,
                    module=self.name,
                    description=(
                        f"File {ws_file.name} is writable by any user. "
                        "An attacker can inject instructions the agent follows every time."
                    ),
                    file_path=str(ws_file),
                    evidence=f"Permissions: {oct(mode)[-3:]}",
                    remediation=f"chmod 600 {ws_file}",
                ))
            elif mode & stat.S_IWGRP:
                findings.append(Finding(
                    id=f"INJ-{len(findings) + 1:03d}",
                    title=f"Group-writable instruction file: {ws_file.name}",
                    severity=Severity.HIGH,
                    module=self.name,
                    description=(
                        f"File {ws_file.name} is writable by the group. "
                        "Other processes in the same group can modify agent instructions."
                    ),
                    file_path=str(ws_file),
                    evidence=f"Permissions: {oct(mode)[-3:]}",
                    remediation=f"chmod 600 {ws_file}",
                ))
        return findings

    def _check_injection_patterns(self) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for ws_file in self.agent.get_workspace_files(self.config.target):
            if not ws_file.is_file():
                continue
            try:
                content = ws_file.read_text(errors="ignore")
            except (PermissionError, OSError):
                continue

            for pattern, label, sev in INJECTION_PATTERNS:
                key = f"{pattern}:{ws_file}"
                if key in seen:
                    continue
                if pattern.lower() in content.lower():
                    line_num = None
                    for i, line in enumerate(content.splitlines(), 1):
                        if pattern.lower() in line.lower():
                            line_num = i
                            break
                    seen.add(key)
                    findings.append(Finding(
                        id=f"INJ-{len(findings) + 1:03d}",
                        title=f"{label} in {ws_file.name}",
                        severity=sev,
                        module=self.name,
                        description=(
                            f"Suspicious content in agent workspace: '{pattern}'. "
                            "Could be a planted injection from a previous interaction, "
                            "a malicious skill, or a compromised inbound file."
                        ),
                        file_path=str(ws_file),
                        line_number=line_num,
                        evidence=f"Pattern: {repr(pattern)}",
                        remediation="Review file. Remove injected content. chmod 600.",
                    ))
        return findings

    def _check_skill_injection(self) -> list[Finding]:
        findings: list[Finding] = []
        oc = self.agent._find_openclaw_dir(self.config.target)
        if not oc:
            return findings

        skills_dir = oc / "skills"
        if not skills_dir.is_dir():
            return findings

        seen: set[str] = set()
        for md_file in skills_dir.rglob("*.md"):
            try:
                content = md_file.read_text(errors="ignore")
            except (PermissionError, OSError):
                continue
            for pattern, label, sev in INJECTION_PATTERNS:
                if sev < Severity.HIGH:
                    continue
                key = f"{pattern}:{md_file}"
                if key in seen:
                    continue
                if pattern.lower() in content.lower():
                    seen.add(key)
                    findings.append(Finding(
                        id=f"INJ-{len(findings) + 1:03d}",
                        title=f"Suspicious skill: {label} in {md_file.parent.name}",
                        severity=sev,
                        module=self.name,
                        description=(
                            f"Installed skill contains: '{pattern}'. "
                            "Skills load into agent context and can override instructions."
                        ),
                        file_path=str(md_file),
                        remediation="Review skill. Remove untrusted skills.",
                    ))
        return findings

    def _check_inbound_media(self) -> list[Finding]:
        findings: list[Finding] = []
        oc = self.agent._find_openclaw_dir(self.config.target)
        if not oc:
            return findings

        media_dir = oc / "media" / "inbound"
        if not media_dir.is_dir():
            return findings

        try:
            file_count = sum(1 for f in media_dir.rglob("*") if f.is_file())
        except (PermissionError, OSError):
            return findings

        if file_count > 50:
            findings.append(Finding(
                id=f"INJ-{len(findings) + 1:03d}",
                title=f"Large inbound media directory ({file_count} files)",
                severity=Severity.MEDIUM,
                module=self.name,
                description=(
                    f"Inbound media has {file_count} files. Each is an injection vector. "
                    "Clean old files periodically."
                ),
                file_path=str(media_dir),
                evidence=f"{file_count} files",
                remediation=f"find {media_dir} -mtime +7 -delete",
            ))
        return findings

    def _check_sandbox_config(self) -> list[Finding]:
        findings: list[Finding] = []
        config_files = self.agent.get_config_files(self.config.target)

        for cfg_path in config_files:
            if cfg_path.name != "openclaw.json":
                continue
            try:
                content = cfg_path.read_text(errors="ignore")
                lines = [ln for ln in content.splitlines() if not ln.lstrip().startswith("//")]
                clean = re.sub(r",\s*([}\]])", r"\1", "\n".join(lines))
                data = json.loads(clean)
            except (json.JSONDecodeError, PermissionError, OSError):
                continue
            if not isinstance(data, dict):
                continue

            # Sandbox check
            agents_cfg = data.get("agents", data.get("agent", {}))
            defaults = agents_cfg.get("defaults", agents_cfg) if isinstance(agents_cfg, dict) else {}
            sandbox = defaults.get("sandbox", {}) if isinstance(defaults, dict) else {}

            if not sandbox or not sandbox.get("mode"):
                findings.append(Finding(
                    id=f"INJ-{len(findings) + 1:03d}",
                    title="No sandbox mode configured",
                    severity=Severity.MEDIUM,
                    module=self.name,
                    description=(
                        "No sandbox.mode set. Non-main sessions run tools directly "
                        "on the host. Set sandbox.mode to 'non-main' for Docker isolation."
                    ),
                    file_path=str(cfg_path),
                    remediation='Add: agents.defaults.sandbox.mode: "non-main"',
                ))

            # DM policy check
            channels = data.get("channels", {})
            if isinstance(channels, dict):
                for ch_name, ch_cfg in channels.items():
                    if not isinstance(ch_cfg, dict):
                        continue
                    dm_policy = ch_cfg.get("dmPolicy", "")
                    allow_from = ch_cfg.get("allowFrom", [])
                    if dm_policy == "open" or (not allow_from and dm_policy != "pairing"):
                        findings.append(Finding(
                            id=f"INJ-{len(findings) + 1:03d}",
                            title=f"Open DM policy on channel: {ch_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=(
                                f"Channel '{ch_name}' accepts DMs from anyone. "
                                "Any user can send prompt injections directly to your agent."
                            ),
                            file_path=str(cfg_path),
                            remediation=f'Set channels.{ch_name}.dmPolicy: "pairing" or add allowFrom.',
                        ))
        return findings
