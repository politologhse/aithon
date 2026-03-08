"""Tests for secrets detection module."""
from aithon.modules.secrets import SecretsModule
from aithon.agents.openclaw import OpenClawProfile
from aithon.config import ScanConfig


def test_detects_openai_key(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    module = SecretsModule(config, OpenClawProfile())
    findings = module.scan()
    titles = [f.title for f in findings]
    assert any("OpenAI API Key" in t for t in titles)


def test_detects_anthropic_key(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    module = SecretsModule(config, OpenClawProfile())
    findings = module.scan()
    titles = [f.title for f in findings]
    assert any("Anthropic API Key" in t for t in titles)


def test_redacts_evidence(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    module = SecretsModule(config, OpenClawProfile())
    findings = module.scan()
    for f in findings:
        if f.evidence and len(f.evidence) > 8:
            assert "****" in f.evidence


def test_clean_workspace_no_secrets(clean_workspace):
    config = ScanConfig(target=clean_workspace)
    module = SecretsModule(config, OpenClawProfile())
    findings = module.scan()
    critical = [f for f in findings if f.severity >= 4]
    assert len(critical) == 0
