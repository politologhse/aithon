"""OpenClaw agent profile."""
from __future__ import annotations
from pathlib import Path
from aithon.agents.base import BaseAgentProfile


class OpenClawProfile(BaseAgentProfile):

    @property
    def name(self) -> str:
        return "openclaw"

    def detect(self, target: Path) -> bool:
        indicators = [
            target / ".openclaw",
            target / "models.json",
            Path.home() / ".openclaw",
            Path("/root/.openclaw"),
        ]
        def _safe_exists(p: Path) -> bool:
            try:
                return p.exists()
            except (PermissionError, OSError):
                return False

        return any(_safe_exists(p) for p in indicators)

    def get_secret_scan_paths(self, target: Path) -> list[Path]:
        paths: list[Path] = []
        openclaw_dir = self._find_openclaw_dir(target)

        if openclaw_dir:
            paths.extend(openclaw_dir.rglob("*.json"))

        paths.extend(target.glob("models.json"))
        paths.extend(target.glob("auth-profiles.json"))

        systemd_override = Path("/etc/systemd/system/openclaw.service.d/override.conf")
        if systemd_override.exists():
            paths.append(systemd_override)

        for hist in [Path.home() / ".bash_history", Path.home() / ".zsh_history"]:
            if hist.exists():
                paths.append(hist)

        return paths

    def get_sensitive_files(self, target: Path) -> list[Path]:
        files: list[Path] = []
        openclaw_dir = self._find_openclaw_dir(target)

        if openclaw_dir:
            files.extend([
                openclaw_dir / "auth-profiles.json",
                openclaw_dir / "models.json",
                openclaw_dir / "config.json",
            ])

        files.extend([
            target / "auth-profiles.json",
            target / ".env",
        ])

        return [f for f in files if f.exists()]

    def get_config_files(self, target: Path) -> list[Path]:
        files: list[Path] = []
        openclaw_dir = self._find_openclaw_dir(target)

        if openclaw_dir:
            files.extend(openclaw_dir.rglob("*.json"))

        files.extend(target.glob("*.json"))
        files.extend(target.glob("*.yaml"))
        files.extend(target.glob("*.yml"))

        return [f for f in files if f.is_file()]

    def get_backup_paths(self, target: Path) -> list[Path]:
        dirs: list[Path] = []
        openclaw_dir = self._find_openclaw_dir(target)

        if openclaw_dir:
            backup_dir = openclaw_dir / "backup"
            if backup_dir.is_dir():
                dirs.append(backup_dir)

        for d in [Path("/root/.openclaw/backup"), Path.home() / ".openclaw/backup"]:
            try:
                if d.is_dir() and d not in dirs:
                    dirs.append(d)
            except (PermissionError, OSError):
                continue

        return dirs

    def get_workspace_files(self, target: Path) -> list[Path]:
        workspace_names = [
            "SOUL.md", "AGENTS.md", "USER.md", "TOOLS.md",
            "STATE.md", "PLAN.md", "README.md",
        ]
        files: list[Path] = []
        for ws_name in workspace_names:
            f = target / ws_name
            if f.exists():
                files.append(f)

        openclaw_dir = self._find_openclaw_dir(target)
        if openclaw_dir:
            workspace = openclaw_dir / "workspace"
            if workspace.is_dir():
                files.extend(workspace.glob("*.md"))

        return files

    def get_known_ports(self) -> dict[int, str]:
        return {
            3000: "OpenClaw Web UI",
            3001: "OpenClaw API",
            8080: "OpenClaw Proxy",
            8921: "Admin Panel (nginx)",
        }

    def _find_openclaw_dir(self, target: Path) -> Path | None:
        candidates = [
            target / ".openclaw",
            Path.home() / ".openclaw",
            Path("/root/.openclaw"),
        ]
        for c in candidates:
            try:
                if c.is_dir():
                    return c
            except (PermissionError, OSError):
                continue
        return None
