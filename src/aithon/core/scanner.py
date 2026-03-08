"""Main scan orchestrator."""
from aithon.config import ScanConfig, Severity
from aithon.core.finding import Finding
from aithon.modules.base import BaseModule
from aithon.agents.base import BaseAgentProfile


class Scanner:
    """Orchestrates security scan across all modules."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: list[Finding] = []
        self.agent_profile = self._detect_agent()
        self._modules = self._load_modules()

    def _detect_agent(self) -> BaseAgentProfile:
        if self.config.agent_type != "auto":
            return self._get_agent_profile(self.config.agent_type)

        from aithon.agents.openclaw import OpenClawProfile

        profiles = [OpenClawProfile()]
        for profile in profiles:
            if profile.detect(self.config.target):
                return profile

        return OpenClawProfile()

    def _get_agent_profile(self, agent_type: str) -> BaseAgentProfile:
        from aithon.agents.openclaw import OpenClawProfile
        agents = {
            "openclaw": OpenClawProfile,
        }
        cls = agents.get(agent_type, OpenClawProfile)
        return cls()

    def _load_modules(self) -> list[BaseModule]:
        from aithon.modules.secrets import SecretsModule
        from aithon.modules.permissions import PermissionsModule
        from aithon.modules.config_audit import ConfigAuditModule
        from aithon.modules.backup_scan import BackupScanModule
        from aithon.modules.env_leak import EnvLeakModule
        from aithon.modules.injection import InjectionModule
        from aithon.modules.network import NetworkModule

        available = {
            "secrets": SecretsModule,
            "permissions": PermissionsModule,
            "config_audit": ConfigAuditModule,
            "backup_scan": BackupScanModule,
            "env_leak": EnvLeakModule,
            "injection": InjectionModule,
            "network": NetworkModule,
        }

        modules = []
        for name in self.config.modules:
            if name in available:
                modules.append(available[name](self.config, self.agent_profile))
        return modules

    def run(self) -> list[Finding]:
        self.findings = []
        for module in self._modules:
            try:
                module_findings = module.scan()
                self.findings.extend(module_findings)
            except Exception as e:
                self.findings.append(Finding(
                    id="ERR-000",
                    title=f"Module {module.name} failed",
                    severity=Severity.LOW,
                    module=module.name,
                    description=f"Module crashed: {e}",
                    remediation="Check module logs",
                ))

        threshold = self.config.severity_threshold
        self.findings = [f for f in self.findings if f.severity >= threshold]
        self.findings.sort(key=lambda f: f.severity, reverse=True)
        return self.findings

    def run_module(self, module_name: str) -> list[Finding]:
        for module in self._modules:
            if module.name == module_name:
                return module.scan()
        return []

    @property
    def module_names(self) -> list[str]:
        return [m.name for m in self._modules]
