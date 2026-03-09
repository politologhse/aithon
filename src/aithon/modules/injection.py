"""Advanced prompt injection hardening checks — v2 (reduced false positives)."""
from __future__ import annotations

import json
import re
import stat
from aithon.modules.base import BaseModule
from aithon.core.finding import Finding
from aithon.config import Severity


# Patterns for workspace files (agent reads these every time)
# Format: (regex_pattern, label, severity)
# Using regex for precision — no more naive substring matching
WORKSPACE_PATTERNS: list[tuple[str, str, Severity]] = [
    # Direct instruction overrides — high confidence
    (r"(?i)^[\s>*-]*ignore\s+(all\s+)?previous\s+instructions", "Instruction override", Severity.CRITICAL),
    (r"(?i)^[\s>*-]*disregard\s+(all\s+)?prior", "Instruction override", Severity.CRITICAL),
    (r"(?i)^[\s>*-]*forget\s+everything\s+above", "Instruction override", Severity.CRITICAL),
    (r"(?i)^[\s>*-]*new\s+instructions\s*:", "Instruction override", Severity.CRITICAL),
    # Privilege escalation
    (r"(?i)\bact\s+as\s+root\b", "Privilege escalation", Severity.CRITICAL),
    (r"(?i)\bADMIN\s+OVERRIDE\b", "Privilege escalation", Severity.CRITICAL),
    # Data exfiltration commands (not in code blocks)
    (r"(?i)(?<!`)\bcat\s+~/\.ssh\b(?!`)", "Data exfiltration via SSH keys", Severity.CRITICAL),
    (r"(?i)(?<!`)\bread\s+/etc/passwd\b(?!`)", "Data exfiltration", Severity.CRITICAL),
    (r"(?i)\boutput\s+all\s+api\s+keys\b", "Data exfiltration", Severity.CRITICAL),
    (r"(?i)\bsend\s+the\s+contents\s+of\b", "Data exfiltration", Severity.HIGH),
    # Invisible unicode characters
    ("\u200b", "Zero-width space (invisible injection)", Severity.HIGH),
    ("\u200c", "Zero-width non-joiner (invisible injection)", Severity.HIGH),
    ("\u200d", "Zero-width joiner (invisible injection)", Severity.HIGH),
    ("\u2060", "Word joiner (invisible injection)", Severity.HIGH),
]

# Patterns for skills — only high-confidence dangerous patterns
# "system:" is intentionally NOT here — too many false positives in skill docs
SKILL_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"(?i)^[\s>*-]*ignore\s+(all\s+)?previous\s+instructions", "Instruction override", Severity.CRITICAL),
    (r"(?i)^[\s>*-]*disregard\s+(all\s+)?prior", "Instruction override", Severity.CRITICAL),
    (r"(?i)(?<!`)\bcat\s+~/\.ssh\b(?!`)", "Data exfiltration via SSH keys", Severity.CRITICAL),
    (r"(?i)(?<!`)\bread\s+/etc/passwd\b(?!`)", "Data exfiltration", Severity.CRITICAL),
    (r"(?i)\boutput\s+all\s+api\s+keys\b", "Data exfiltration", Severity.CRITICAL),
    (r"(?i)\bADMIN\s+OVERRIDE\b", "Privilege escalation", Severity.CRITICAL),
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

    def _match_pattern(self, content: str, pattern: str) -> tuple[bool, int | None]:
        """Match pattern against content. Return (matched, line_number)."""
        # Unicode chars — simple substring match
        if len(pattern) == 1 and ord(pattern) > 127:
            if pattern in content:
                for i, line in enumerate(content.splitlines(), 1):
                    if pattern in line:
                        return True, i
                return True, None
            return False, None

        # Regex patterns — match per line for line number
        for i, line in enumerate(content.splitlines(), 1):
            if re.search(pattern, line):
                return True, i
        return False, None

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

            for pattern, label, sev in WORKSPACE_PATTERNS:
                key = f"{label}:{ws_file}"
                if key in seen:
                    continue
                matched, line_num = self._match_pattern(content, pattern)
                if matched:
                    seen.add(key)
                    findings.append(Finding(
                        id=f"INJ-{len(findings) + 1:03d}",
                        title=f"{label} in {ws_file.name}",
                        severity=sev,
                        module=self.name,
                        description=(
                            "Suspicious content in agent workspace file. "
                            "Could be a planted injection from a previous interaction, "
                            "a malicious skill, or a compromised inbound file."
                        ),
                        file_path=str(ws_file),
                        line_number=line_num,
                        evidence=f"Pattern: {label}",
                        remediation="Review file. Remove injected content. chmod 600.",
                    ))
        return findings

    def _check_skill_injection(self) -> list[Finding]:
        """Check installed skills — collapse by skill, only critical patterns."""
        findings: list[Finding] = []
        oc = self.agent._find_openclaw_dir(self.config.target)
        if not oc:
            return findings

        skills_dir = oc / "skills"
        if not skills_dir.is_dir():
            return findings

        # Collect hits per skill: skill_name -> [(label, severity, file, line)]
        skill_hits: dict[str, list[tuple[str, Severity, str, int | None]]] = {}

        for md_file in skills_dir.rglob("*.md"):
            try:
                content = md_file.read_text(errors="ignore")
            except (PermissionError, OSError):
                continue

            # Determine skill name from path
            # e.g. skills/temp_skills/skills/psyb0t/mediaproc/references/setup.md
            # -> "psyb0t/mediaproc"
            rel = md_file.relative_to(skills_dir)
            parts = rel.parts
            if len(parts) >= 4 and parts[0] == "temp_skills" and parts[1] == "skills":
                skill_name = f"{parts[2]}/{parts[3]}"
            elif len(parts) >= 2:
                skill_name = parts[0]
            else:
                skill_name = md_file.stem

            for pattern, label, sev in SKILL_PATTERNS:
                matched, line_num = self._match_pattern(content, pattern)
                if matched:
                    hits = skill_hits.setdefault(skill_name, [])
                    # Deduplicate same label in same skill
                    if not any(h[0] == label for h in hits):
                        hits.append((label, sev, str(md_file), line_num))

        # Emit one finding per skill (not per file per pattern)
        for skill_name, hits in skill_hits.items():
            max_sev = max(h[1] for h in hits)
            labels = list(dict.fromkeys(h[0] for h in hits))  # unique, ordered
            example_file = hits[0][2]

            findings.append(Finding(
                id=f"INJ-{len(findings) + 1:03d}",
                title=f"Suspicious skill: {skill_name} ({', '.join(labels)})",
                severity=max_sev,
                module=self.name,
                description=(
                    f"Skill '{skill_name}' contains {len(hits)} suspicious pattern(s): "
                    f"{', '.join(labels)}. "
                    "Review this skill carefully — it may contain prompt injection "
                    "or data exfiltration attempts."
                ),
                file_path=example_file,
                evidence=f"{len(hits)} pattern(s) in skill",
                remediation=f"Review and consider removing: rm -rf skills/.../{skill_name}",
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
                                "Any user can send prompt injections to your agent."
                            ),
                            file_path=str(cfg_path),
                            remediation=f'Set channels.{ch_name}.dmPolicy: "pairing" or add allowFrom.',
                        ))
        return findings
