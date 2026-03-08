"""Abstract base module for scan modules."""
from abc import ABC, abstractmethod
from aithon.core.finding import Finding
from aithon.config import ScanConfig
from aithon.agents.base import BaseAgentProfile


class BaseModule(ABC):
    def __init__(self, config: ScanConfig, agent: BaseAgentProfile):
        self.config = config
        self.agent = agent

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        ...

    @abstractmethod
    def scan(self) -> list[Finding]:
        ...
