"""OpenClaw agent profile — aligned with openclaw/openclaw upstream (March 2026)."""
from __future__ import annotations
from pathlib import Path
from aithon.agents.base import BaseAgentProfile


def _safe_exists(p: Path) -> bool:
    try:
        return p.exists()
    except (PermissionError, OSError):
        return False


def _safe_is_dir(p: Path) -> bool:
    try:
        return p.is_dir()
    except (PermissionError, OSError):
        return False


class OpenClawProfile(BaseAgentProfile):

    @property
    def name(self) -> str:
        return "openclaw"

    # ── detection ────────────────────────────────────────────────

    def detect(self, target: Path) -> bool:
        indicators = [
            target / ".openclaw",
            target / "openclaw.json",
            target / "models.json",
            Path.home() / ".openclaw",
            Path("/root/.openclaw"),
        ]
        return any(_safe_exists(p) for p in indicators)

    # ── helpers ──────────────────────────────────────────────────

    def _find_openclaw_dir(self, target: Path) -> Path | None:
        candidates = [
            target / ".openclaw",
            target,  # target itself might be ~/.openclaw
            Path.home() / ".openclaw",
            Path("/root/.openclaw"),
        ]
        for c in candidates:
            if _safe_is_dir(c) and (
                _safe_exists(c / "openclaw.json")
                or _safe_exists(c / "models.json")
                or _safe_is_dir(c / "workspace")
                or _safe_is_dir(c / "credentials")
                or _safe_is_dir(c / "agents-workspaces")
            ):
                return c
        # Fallback: first dir that exists
        for c in candidates:
            if _safe_is_dir(c):
                return c
        return None

    def _find_agent_dirs(self, openclaw_dir: Path) -> list[Path]:
        """Find per-agent workspace dirs (new structure: agents-workspaces/<id>/agent/)."""
        agent_dirs: list[Path] = []
        aw = openclaw_dir / "agents-workspaces"
        if _safe_is_dir(aw):
            for child in aw.iterdir():
                agent_subdir = child / "agent"
                if _safe_is_dir(agent_subdir):
                    agent_dirs.append(agent_subdir)
                elif _safe_is_dir(child):
                    agent_dirs.append(child)
        return agent_dirs

    # ── scan paths ───────────────────────────────────────────────

    def get_secret_scan_paths(self, target: Path) -> list[Path]:
        paths: list[Path] = []
        oc = self._find_openclaw_dir(target)
        if not oc:
            return paths

        # Main config files
        for name in ["openclaw.json", "models.json", "auth-profiles.json"]:
            f = oc / name
            if _safe_exists(f):
                paths.append(f)

        # credentials/ directory (new structure — plain text key files)
        creds_dir = oc / "credentials"
        if _safe_is_dir(creds_dir):
            for f in creds_dir.iterdir():
                if f.is_file():
                    paths.append(f)

        # Per-agent auth-profiles.json (new per-agent structure)
        for agent_dir in self._find_agent_dirs(oc):
            ap = agent_dir / "auth-profiles.json"
            if _safe_exists(ap):
                paths.append(ap)
            # Also scan agent-level config files
            for f in agent_dir.glob("*.json"):
                if f not in paths:
                    paths.append(f)

        # Snapshots (contain historical copies of configs)
        snapshots = oc / "snapshots"
        if _safe_is_dir(snapshots):
            for snap_dir in snapshots.iterdir():
                if _safe_is_dir(snap_dir):
                    for name in ["auth-profiles.json", "models.json", "openclaw.json"]:
                        f = snap_dir / name
                        if _safe_exists(f):
                            paths.append(f)

        # Skills with embedded configs
        skills_dir = oc / "skills"
        if _safe_is_dir(skills_dir):
            for f in skills_dir.rglob("*.json"):
                paths.append(f)

        # .env files at openclaw root
        for f in oc.glob("*.env"):
            paths.append(f)
        for f in oc.glob(".env*"):
            paths.append(f)

        # systemd overrides
        for svc in ["openclaw.service.d", "openclaw-gateway.service.d"]:
            override = Path(f"/etc/systemd/system/{svc}/override.conf")
            if _safe_exists(override):
                paths.append(override)

        # Shell history (may contain pasted keys)
        for hist in [Path.home() / ".bash_history", Path.home() / ".zsh_history"]:
            if _safe_exists(hist):
                paths.append(hist)

        return paths

    def get_sensitive_files(self, target: Path) -> list[Path]:
        """Files that must have restricted permissions (chmod 600/700)."""
        files: list[Path] = []
        oc = self._find_openclaw_dir(target)
        if not oc:
            return files

        # Core config files
        for name in [
            "openclaw.json", "models.json", "auth-profiles.json",
        ]:
            f = oc / name
            if _safe_exists(f):
                files.append(f)

        # credentials/ directory files
        creds_dir = oc / "credentials"
        if _safe_is_dir(creds_dir):
            for f in creds_dir.iterdir():
                if f.is_file():
                    files.append(f)

        # Per-agent auth profiles
        for agent_dir in self._find_agent_dirs(oc):
            ap = agent_dir / "auth-profiles.json"
            if _safe_exists(ap):
                files.append(ap)

        # .env files
        for f in oc.glob("*.env"):
            files.append(f)
        env_file = oc / ".env"
        if _safe_exists(env_file) and env_file not in files:
            files.append(env_file)

        # Workspace .env
        ws_env = oc / "workspace" / ".env"
        if _safe_exists(ws_env):
            files.append(ws_env)

        return files

    def get_config_files(self, target: Path) -> list[Path]:
        files: list[Path] = []
        oc = self._find_openclaw_dir(target)
        if not oc:
            return files

        # Main configs
        for name in ["openclaw.json", "models.json"]:
            f = oc / name
            if _safe_exists(f):
                files.append(f)

        # Per-agent configs
        for agent_dir in self._find_agent_dirs(oc):
            for f in agent_dir.glob("*.json"):
                files.append(f)

        return files

    def get_backup_paths(self, target: Path) -> list[Path]:
        dirs: list[Path] = []
        oc = self._find_openclaw_dir(target)

        if oc:
            for subdir in ["backup", "snapshots"]:
                d = oc / subdir
                if _safe_is_dir(d):
                    dirs.append(d)

        for base in [Path("/root/.openclaw"), Path.home() / ".openclaw"]:
            for subdir in ["backup", "snapshots"]:
                d = base / subdir
                try:
                    if _safe_is_dir(d) and d not in dirs:
                        dirs.append(d)
                except (PermissionError, OSError):
                    continue

        return dirs

    def get_workspace_files(self, target: Path) -> list[Path]:
        workspace_names = [
            "SOUL.md", "AGENTS.md", "USER.md", "TOOLS.md",
            "STATE.md", "PLAN.md", "README.md", "HEARTBEAT.md",
            "BOOTSTRAP.md",
        ]
        files: list[Path] = []
        oc = self._find_openclaw_dir(target)

        # Check workspace/ subdirectory
        if oc:
            workspace = oc / "workspace"
            if _safe_is_dir(workspace):
                for ws_name in workspace_names:
                    f = workspace / ws_name
                    if _safe_exists(f):
                        files.append(f)
                # Also grab any other .md files
                for f in workspace.glob("*.md"):
                    if f not in files:
                        files.append(f)
                # Agent subdirectories
                agents_dir = workspace / "agents"
                if _safe_is_dir(agents_dir):
                    for f in agents_dir.rglob("*.md"):
                        files.append(f)

        # Check target directory directly (legacy layout)
        for ws_name in workspace_names:
            f = target / ws_name
            if _safe_exists(f) and f not in files:
                files.append(f)

        # Per-agent workspace files
        if oc:
            for agent_dir in self._find_agent_dirs(oc):
                ws = agent_dir / "workspace"
                if _safe_is_dir(ws):
                    for f in ws.glob("*.md"):
                        if f not in files:
                            files.append(f)

        return files

    def get_known_ports(self) -> dict[int, str]:
        return {
            18789: "OpenClaw Gateway",
            3000: "OpenClaw Studio / Web UI",
            8921: "Admin Panel (nginx)",
        }
