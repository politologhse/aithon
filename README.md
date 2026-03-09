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
- **Watch Mode** — Continuous monitoring with Telegram alerts on new findings
- **Fix Plan** — Generates a reviewable remediation bash script

## Supported Agents

| Agent | Status |
|-------|--------|
| OpenClaw | ✅ Full support |
| Cline | 🔜 Planned |
| Aider | 🔜 Planned |
| Generic | 🔜 Planned |

## Install

```bash
pip install aithon-scan
```

Or from source:

```bash
git clone https://github.com/politologhse/aithon.git
cd aithon
pip install -e .
```

## Usage

### One-shot scan

```bash
# TUI mode (retro CRT terminal interface)
aithon scan /path/to/agent/workspace

# Headless mode
aithon scan /path/to/workspace --no-tui
aithon scan /path/to/workspace --no-tui --severity high
aithon scan /path/to/workspace --no-tui -o report.json
```

### Watch mode (continuous monitoring)

```bash
# Scan every hour, alert via Telegram on HIGH+ findings
aithon watch /root/.openclaw \
  --interval 3600 \
  --telegram-token "YOUR_BOT_TOKEN" \
  --telegram-chat-id "YOUR_CHAT_ID"

# Or use environment variables
export AITHON_TELEGRAM_TOKEN="your-token"
export AITHON_TELEGRAM_CHAT_ID="your-chat-id"
aithon watch /root/.openclaw --interval 1800
```

Watch mode keeps a state file (`.aithon-state.json`) and only alerts on **new** findings — no spam on known issues.

### Fix plan (remediation script)

```bash
# Print remediation script to stdout
aithon fix-plan /root/.openclaw

# Save to file, review, then run
aithon fix-plan /root/.openclaw -o fix.sh
less fix.sh        # review it
bash fix.sh        # run it
```

The fix plan separates auto-fixable issues (chmod) from manual ones (key rotation, config changes) and generates commented bash with explanations.

### GitHub Action

Add to your workflow:

```yaml
- name: Aithon Security Scan
  uses: politologhse/aithon@main
  with:
    target: "."
    severity: "low"
    fail-on: "critical"     # fail CI on critical findings
    output: "report.json"   # upload as artifact
```

Inputs:

| Input | Default | Description |
|-------|---------|-------------|
| `target` | `.` | Path to scan |
| `agent` | `auto` | Agent type |
| `severity` | `low` | Min severity to report |
| `fail-on` | `critical` | Fail CI at this severity (`none` to never fail) |
| `output` | — | Report file path (json/md) |

### List supported agents

```bash
aithon agents
```

## Example Output

```
╭──── AITHON SCAN RESULTS ────╮
│ 17 issues found              │
│ CRITICAL: 11 | HIGH: 5 | LOW: 1 │
╰──────────────────────────────╯

 SEV   ID       Title                          File                  Module
 ✖     SEC-001  Telegram Bot Token in config   openclaw-modified.json secrets
 ✖     SEC-002  Private Key Block in device    device.json           secrets
 ◆     PERM-001 World-readable auth-profiles   auth-profiles.json    permissions
 ◆     NET-001  Admin Panel on 0.0.0.0:8921    —                     network
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
