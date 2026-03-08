"""Security finding data model."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from aithon.config import Severity


@dataclass
class Finding:
    """A single security finding."""
    id: str
    title: str
    severity: Severity
    module: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    evidence: str | None = None
    remediation: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def severity_label(self) -> str:
        return self.severity.name

    @property
    def severity_emoji(self) -> str:
        return {
            Severity.LOW: "●",
            Severity.MEDIUM: "▲",
            Severity.HIGH: "◆",
            Severity.CRITICAL: "✖",
        }[self.severity]
