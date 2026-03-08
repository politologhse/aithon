"""Agent configuration security audit."""
import json
from pathlib import Path
from aithon.modules.base import BaseModule
from aithon.core.finding import Finding
from aithon.config import Severity


class ConfigAuditModule(BaseModule):

    @property
    def name(self) -> str:
        return "config_audit"

    @property
    def description(self) -> str:
        return "Audits agent configuration for insecure settings"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        config_files = self.agent.get_config_files(self.config.target)

        for cfg_path in config_files:
            if not cfg_path.is_file():
                continue
            try:
                content = cfg_path.read_text(errors="ignore")
            except (PermissionError, OSError):
                continue

            try:
                data = json.loads(content)
                findings.extend(self._audit_json_config(cfg_path, data))
            except json.JSONDecodeError:
                findings.extend(self._audit_text_config(cfg_path, content))

        return findings

    def _audit_json_config(self, path: Path, data: dict) -> list[Finding]:
        findings: list[Finding] = []

        def walk(obj: object, key_path: str = "") -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    current = f"{key_path}.{k}" if key_path else k
                    if isinstance(v, str) and any(
                        kw in k.lower()
                        for kw in ["key", "token", "secret", "password", "api_key"]
                    ):
                        if len(v) > 8 and v not in ("", "null", "none", "YOUR_KEY_HERE"):
                            findings.append(Finding(
                                id=f"CFG-{len(findings) + 1:03d}",
                                title=f"Hardcoded credential in config: {k}",
                                severity=Severity.HIGH,
                                module=self.name,
                                description=(
                                    f"Config key '{current}' contains what appears to be "
                                    "a hardcoded credential. Should use env vars instead."
                                ),
                                file_path=str(path),
                                evidence=f"{k}: {v[:4]}****",
                                remediation=(
                                    "Move to environment variable via systemd override: "
                                    f'Environment="{k.upper()}=value"'
                                ),
                            ))
                    walk(v, current)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    walk(item, f"{key_path}[{i}]")

        walk(data)

        providers = data.get("providers", data.get("models", {}).get("providers", {}))
        if isinstance(providers, dict):
            for prov_name, prov in providers.items():
                if isinstance(prov, dict):
                    if prov.get("allowAllTools", False) or prov.get("allow_all", False):
                        findings.append(Finding(
                            id=f"CFG-{len(findings) + 1:03d}",
                            title=f"Overly permissive provider: {prov_name}",
                            severity=Severity.MEDIUM,
                            module=self.name,
                            description=(
                                f"Provider '{prov_name}' has unrestricted tool access. "
                                "This allows the LLM to execute any tool without limitations."
                            ),
                            file_path=str(path),
                            remediation="Restrict tool access to only required tools.",
                        ))

        return findings

    def _audit_text_config(self, path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        if "sudo" in content or "chmod 777" in content:
            findings.append(Finding(
                id=f"CFG-{len(findings) + 1:03d}",
                title=f"Dangerous commands in {path.name}",
                severity=Severity.MEDIUM,
                module=self.name,
                description="File contains sudo or chmod 777 commands that could be abused.",
                file_path=str(path),
                remediation="Avoid sudo and overly permissive chmod in agent configs.",
            ))
        return findings
