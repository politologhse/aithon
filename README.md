# 🦅 AITHON

**AI Agent Security Scanner**

*The eagle that gnaws at what agents try to hide.*

```
╔═══════════════════════════════════════════════╗
║     █████╗ ██╗████████╗██╗  ██╗ ██████╗ ███╗ ║
║    ██╔══██╗██║╚══██╔══╝██║  ██║██╔═══██╗████╗║
║    ███████║██║   ██║   ███████║██║   ██║██╔██║
║    ██╔══██║██║   ██║   ██╔══██║██║   ██║██║╚█║
║    ██║  ██║██║   ██║   ██║  ██║╚██████╔╝██║ ╚║
║    ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝ ║
╚═══════════════════════════════════════════════╝
```

Aithon (Αἴθων) — named after the eagle that eternally gnawed Prometheus' liver — is an open-source security scanner built specifically for AI coding agents.

## What it does

Scans AI agent workspaces for security vulnerabilities:

- **Secret Detection** — Finds leaked API keys, tokens, and credentials in configs, backups, and workspace files
- **Permission Audit** — Checks file permissions on sensitive configuration files
- **Config Analysis** — Audits agent settings for insecure configurations
- **Backup Scanning** — Finds secrets that leaked into backup archives
- **Injection Detection** — Identifies prompt injection attack surfaces in workspace files
- **Network Exposure** — Detects agent endpoints listening on public interfaces

## Supported Agents

| Agent | Status |
|-------|--------|
| OpenClaw | ✅ Full support |
| Cline | 🔜 v0.2 |
| Aider | 🔜 v0.2 |
| Generic | 🔜 v0.3 |

## Install

```bash
pip install aithon
```

Or from source:

```bash
git clone https://github.com/politologhse/aithon.git
cd aithon
pip install -e .
```

## Usage

### TUI Mode (retro CRT terminal interface)

```bash
aithon scan /path/to/agent/workspace
```

### Headless Mode

```bash
aithon scan /path/to/workspace --no-tui
aithon scan /path/to/workspace --no-tui --severity high
aithon scan /path/to/workspace --no-tui -o report.json
aithon scan /path/to/workspace --no-tui -o report.md
```

### List Supported Agents

```bash
aithon agents
```

## Example Output

```
╭──── AITHON SCAN RESULTS ────╮
│ 7 issues found               │
│ CRITICAL: 3 | HIGH: 2 | MED: 2 │
╰──────────────────────────────╯

 SEV   ID       Title                          File                  Module
 ✖     SEC-001  OpenAI API Key in models.json  .openclaw/models.json secrets
 ✖     INJ-001  World-writable AGENTS.md       ./AGENTS.md           injection
 ✖     SEC-002  Anthropic Key in auth-profiles auth-profiles.json    secrets
 ◆     PERM-001 World-readable auth-profiles   auth-profiles.json    permissions
 ◆     BAK-001  Secret in backup: OpenRouter   backup/old-config.json backup_scan
 ▲     CFG-001  Hardcoded credential: api_key  .openclaw/models.json config_audit
 ▲     CFG-002  Overly permissive: anthropic   .openclaw/models.json config_audit
```

## Development

```bash
git clone https://github.com/politologhse/aithon.git
cd aithon
pip install -e ".[dev]"
pytest -v
ruff check src/ tests/
```

## Adding New Agent Profiles

Create a new file in `src/aithon/agents/` implementing `BaseAgentProfile`:

```python
from aithon.agents.base import BaseAgentProfile

class MyAgentProfile(BaseAgentProfile):
    @property
    def name(self) -> str:
        return "my_agent"
    
    def detect(self, target):
        ...
```

Register it in `scanner.py`.

## License

MIT

## Name

> *Aithon (Αἴθων, "blazing") was the eagle sent by Zeus to gnaw on the liver of Prometheus every day as punishment for giving fire to humanity. Every night the liver grew back; every day the eagle returned.*

Like its namesake, Aithon relentlessly finds what grows back — the security holes that keep reappearing in AI agent configurations.
