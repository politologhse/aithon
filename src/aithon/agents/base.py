"""Abstract agent profile."""
from abc import ABC, abstractmethod
from pathlib import Path


class BaseAgentProfile(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def detect(self, target: Path) -> bool:
        ...

    @abstractmethod
    def get_secret_scan_paths(self, target: Path) -> list[Path]:
        ...

    @abstractmethod
    def get_sensitive_files(self, target: Path) -> list[Path]:
        ...

    @abstractmethod
    def get_config_files(self, target: Path) -> list[Path]:
        ...

    @abstractmethod
    def get_backup_paths(self, target: Path) -> list[Path]:
        ...

    @abstractmethod
    def get_workspace_files(self, target: Path) -> list[Path]:
        ...

    @abstractmethod
    def get_known_ports(self) -> dict[int, str]:
        ...
