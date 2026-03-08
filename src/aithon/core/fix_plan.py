"""Fix plan generator — outputs a reviewable bash script for remediation."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from aithon.core.finding import Finding


def generate_fix_plan(findings: list[Finding], target: Path) -> str:
    """Generate a bash remediation script from findings."""
    lines = [
        "#!/usr/bin/env bash",
        f"# Aithon Fix Plan — generated {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"# Target: {target}",
        f"# Findings: {len(findings)}",
        "#",
        "# REVIEW THIS SCRIPT BEFORE RUNNING.",
        "# Lines starting with '# ACTION:' describe what each command does.",
        "# Remove or comment out any lines you don't want to execute.",
        "#",
        'set -euo pipefail',
        "",
    ]

    section_num = 0

    # Group: permission fixes
    perm_findings = [f for f in findings if f.module == "permissions"]
    if perm_findings:
        section_num += 1
        lines.append(f"# === Section {section_num}: File Permission Fixes ===")
        lines.append("")
        for f in perm_findings:
            if f.file_path:
                lines.append(f"# ACTION: Fix permissions on {Path(f.file_path).name}")
                lines.append(f"# Severity: {f.severity_label} | {f.title}")
                lines.append(f"chmod 600 '{f.file_path}'")
                lines.append("")

    # Group: env file permissions
    env_perm_findings = [
        f for f in findings
        if f.module == "env_leak" and "permissive" in f.title.lower()
    ]
    if env_perm_findings:
        section_num += 1
        lines.append(f"# === Section {section_num}: Environment File Permissions ===")
        lines.append("")
        for f in env_perm_findings:
            if f.file_path:
                lines.append(f"# ACTION: Lock down {Path(f.file_path).name}")
                lines.append(f"chmod 600 '{f.file_path}'")
                lines.append("")

    # Group: secrets in files (advisory — can't auto-fix safely)
    secret_findings = [f for f in findings if f.module == "secrets"]
    if secret_findings:
        section_num += 1
        lines.append(f"# === Section {section_num}: Exposed Secrets (MANUAL REVIEW REQUIRED) ===")
        lines.append("#")
        lines.append("# These findings require manual action:")
        lines.append("# 1. Move secrets to systemd env vars or a secrets manager")
        lines.append("# 2. Rotate all exposed keys")
        lines.append("# 3. Remove secrets from files")
        lines.append("")
        for f in secret_findings:
            lines.append(f"# [{f.severity_label}] {f.id}: {f.title}")
            if f.file_path:
                lines.append(f"#   File: {f.file_path}")
            if f.evidence:
                lines.append(f"#   Evidence: {f.evidence}")
            lines.append(f"#   Fix: {f.remediation}")
            lines.append("")

        # Generate systemd override template if OpenClaw secrets found
        openclaw_secrets = [
            f for f in secret_findings
            if "auth-profiles" in (f.file_path or "") or "models.json" in (f.file_path or "")
        ]
        if openclaw_secrets:
            lines.append("# Suggested: create systemd override for OpenClaw secrets")
            lines.append("# Uncomment and edit the following:")
            lines.append("#")
            lines.append("# mkdir -p /etc/systemd/system/openclaw.service.d")
            lines.append("# cat > /etc/systemd/system/openclaw.service.d/secrets.conf << 'EOF'")
            lines.append("# [Service]")
            lines.append('# Environment="OPENAI_API_KEY=your-key-here"')
            lines.append('# Environment="ANTHROPIC_API_KEY=your-key-here"')
            lines.append('# Environment="OPENROUTER_API_KEY=your-key-here"')
            lines.append("# EOF")
            lines.append("# systemctl daemon-reload")
            lines.append("# systemctl restart openclaw")
            lines.append("")

    # Group: backup secrets
    backup_findings = [f for f in findings if f.module == "backup_scan"]
    if backup_findings:
        section_num += 1
        lines.append(f"# === Section {section_num}: Backup Cleanup ===")
        lines.append("#")
        lines.append("# Backups contain exposed secrets. Options:")
        lines.append("# a) Delete old backups that predate your security fix")
        lines.append("# b) Re-run ocback to create clean snapshots")
        lines.append("")
        for f in backup_findings:
            lines.append(f"# {f.title}")
            if f.file_path:
                lines.append(f"#   Example: {f.file_path}")
            lines.append("")
        lines.append("# Uncomment to clean old backups (DESTRUCTIVE — review first):")
        lines.append("# find /root/.openclaw/backup -name '*.json' -exec "
                      "grep -l 'sk-' {} \\; | head -20")
        lines.append("# rm -rf /root/.openclaw/backup/old-*  # adjust pattern as needed")
        lines.append("")

    # Group: network exposure
    net_findings = [f for f in findings if f.module == "network"]
    if net_findings:
        section_num += 1
        lines.append(f"# === Section {section_num}: Network Exposure Fixes ===")
        lines.append("")
        for f in net_findings:
            lines.append(f"# ACTION: {f.title}")
            lines.append(f"# {f.description}")
            if "8921" in (f.evidence or ""):
                lines.append("# Fix nginx to bind to localhost:")
                lines.append(
                    "# sed -i 's/0.0.0.0:8921/127.0.0.1:8921/' "
                    "/etc/nginx/sites-enabled/*"
                )
                lines.append("# nginx -t && systemctl reload nginx")
            lines.append("")

    # Group: injection risks
    inj_findings = [f for f in findings if f.module == "injection"]
    if inj_findings:
        section_num += 1
        lines.append(f"# === Section {section_num}: Prompt Injection Risks ===")
        lines.append("")
        for f in inj_findings:
            lines.append(f"# [{f.severity_label}] {f.title}")
            if f.file_path:
                lines.append(f"#   File: {f.file_path}")
                lines.append(f"#   Review: less '{f.file_path}'")
            lines.append(f"#   {f.remediation}")
            lines.append("")

    # Summary
    lines.append("# === Summary ===")
    auto_fixable = len(perm_findings) + len(env_perm_findings)
    manual = len(findings) - auto_fixable
    lines.append(f"# Auto-fixable (chmod): {auto_fixable}")
    lines.append(f"# Manual review required: {manual}")
    lines.append(f"# Total findings: {len(findings)}")
    lines.append("")
    lines.append('echo "Aithon fix plan complete. Re-run: aithon scan --no-tui"')

    return "\n".join(lines)
