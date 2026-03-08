"""Scanner configuration."""
from dataclasses import dataclass, field
from pathlib import Path
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls[s.upper()]


@dataclass
class ScanConfig:
    target: Path
    agent_type: str = "auto"
    min_severity: str = "low"
    modules: list[str] = field(default_factory=lambda: [
        "secrets", "permissions", "config_audit", "backup_scan", "env_leak",
        "injection", "network",
    ])

    @property
    def severity_threshold(self) -> Severity:
        return Severity.from_str(self.min_severity)
