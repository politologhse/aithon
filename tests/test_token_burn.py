"""Tests for token burn detection module."""
import json
from aithon.modules.token_burn import TokenBurnModule
from aithon.agents.openclaw import OpenClawProfile
from aithon.config import ScanConfig


def test_detects_expensive_primary(tmp_path):
    ws = tmp_path / "ws"
    oc = ws / ".openclaw"
    oc.mkdir(parents=True)
    (oc / "openclaw.json").write_text(json.dumps({
        "agents": {
            "defaults": {
                "model": {"primary": "anthropic/claude-opus-4-6"}
            }
        }
    }))
    config = ScanConfig(target=ws)
    module = TokenBurnModule(config, OpenClawProfile())
    findings = module.scan()
    assert any("Expensive model" in f.title for f in findings)


def test_detects_no_fallbacks(tmp_path):
    ws = tmp_path / "ws"
    oc = ws / ".openclaw"
    oc.mkdir(parents=True)
    (oc / "openclaw.json").write_text(json.dumps({
        "agents": {
            "defaults": {
                "model": {"primary": "anthropic/claude-haiku-4-5"}
            }
        }
    }))
    config = ScanConfig(target=ws)
    module = TokenBurnModule(config, OpenClawProfile())
    findings = module.scan()
    assert any("fallback" in f.title.lower() for f in findings)


def test_detects_no_context_overflow(tmp_path):
    ws = tmp_path / "ws"
    oc = ws / ".openclaw"
    oc.mkdir(parents=True)
    (oc / "openclaw.json").write_text(json.dumps({
        "agents": {"defaults": {"model": "anthropic/claude-haiku-4-5"}}
    }))
    config = ScanConfig(target=ws)
    module = TokenBurnModule(config, OpenClawProfile())
    findings = module.scan()
    assert any("context overflow" in f.title.lower() or "memory flush" in f.title.lower()
               for f in findings)


def test_cheap_primary_no_expensive_finding(tmp_path):
    ws = tmp_path / "ws"
    oc = ws / ".openclaw"
    oc.mkdir(parents=True)
    (oc / "openclaw.json").write_text(json.dumps({
        "agents": {
            "defaults": {
                "model": {
                    "primary": "anthropic/claude-haiku-4-5",
                    "fallbacks": ["openai/gpt-5-mini"],
                },
                "memoryFlush": {"enabled": True},
            }
        }
    }))
    config = ScanConfig(target=ws)
    module = TokenBurnModule(config, OpenClawProfile())
    findings = module.scan()
    assert not any("Expensive model" in f.title for f in findings)


def test_detects_expensive_cron(tmp_path):
    ws = tmp_path / "ws"
    oc = ws / ".openclaw"
    oc.mkdir(parents=True)
    (oc / "openclaw.json").write_text(json.dumps({
        "agents": {"defaults": {"model": "anthropic/claude-haiku-4-5"}},
        "crons": {
            "morning-briefing": {
                "model": "anthropic/claude-opus-4-6",
                "schedule": "0 8 * * *",
            }
        }
    }))
    config = ScanConfig(target=ws)
    module = TokenBurnModule(config, OpenClawProfile())
    findings = module.scan()
    assert any("cron" in f.title.lower() and "Expensive" in f.title for f in findings)
