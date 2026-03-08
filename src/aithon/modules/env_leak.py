"""Environment variable exposure detection."""
from aithon.modules.base import BaseModule
from aithon.core.finding import Finding
from aithon.config import Severity


class EnvLeakModule(BaseModule):

    @property
    def name(self) -> str:
        return "env_leak"

    @property
    def description(self) -> str:
        return "Checks for environment variable exposure via .env files and process leaks"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        target = self.config.target

        skip_dirs = {"snapshots", "backup", "temp_skills", ".git", "node_modules"}
        env_files_raw = (
            list(target.rglob(".env"))
            + list(target.rglob(".env.*"))
            + list(target.rglob("*.env"))
        )
        env_files = [
            f for f in env_files_raw
            if not any(skip in f.parts for skip in skip_dirs)
        ]

        for env_file in env_files:
            if not env_file.is_file():
                continue
            try:
                content = env_file.read_text(errors="ignore")
            except (PermissionError, OSError):
                continue

            gitignore = target / ".gitignore"
            env_in_gitignore = False
            if gitignore.is_file():
                gi_content = gitignore.read_text(errors="ignore")
                if ".env" in gi_content:
                    env_in_gitignore = True

            if not env_in_gitignore:
                findings.append(Finding(
                    id=f"ENV-{len(findings) + 1:03d}",
                    title=".env file not in .gitignore",
                    severity=Severity.HIGH,
                    module=self.name,
                    description=(
                        f"File {env_file.name} exists but .gitignore doesn't exclude .env files. "
                        "This risks committing secrets to version control."
                    ),
                    file_path=str(env_file),
                    remediation="Add '.env*' to .gitignore immediately.",
                ))

            sensitive_keys = [
                "API_KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY",
                "DATABASE_URL", "DB_PASSWORD", "AWS_SECRET",
            ]
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key = line.split("=", 1)[0].strip()
                    value = line.split("=", 1)[1].strip().strip("'\"")
                    if any(sk in key.upper() for sk in sensitive_keys) and value:
                        mode = env_file.stat().st_mode
                        if mode & 0o044:
                            findings.append(Finding(
                                id=f"ENV-{len(findings) + 1:03d}",
                                title="Sensitive .env file too permissive",
                                severity=Severity.HIGH,
                                module=self.name,
                                description=(
                                    f"File {env_file} contains sensitive variable '{key}' "
                                    f"but has permissive permissions ({oct(mode)[-3:]})."
                                ),
                                file_path=str(env_file),
                                evidence=f"{key}=****",
                                remediation=f"chmod 600 {env_file}",
                            ))
                            break

        return findings
