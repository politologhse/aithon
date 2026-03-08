"""File system helpers."""
from pathlib import Path


def safe_read(path: Path, max_size: int = 5 * 1024 * 1024) -> str | None:
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > max_size:
            return None
        return path.read_text(errors="ignore")
    except (PermissionError, OSError):
        return None


def find_files(root: Path, patterns: list[str], max_depth: int = 5) -> list[Path]:
    files: list[Path] = []
    for pattern in patterns:
        for f in root.rglob(pattern):
            try:
                rel = f.relative_to(root)
                if len(rel.parts) <= max_depth:
                    files.append(f)
            except ValueError:
                continue
    return files
