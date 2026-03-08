"""Tests for config audit module."""
from aithon.modules.config_audit import ConfigAuditModule
from aithon.agents.openclaw import OpenClawProfile
from aithon.config import ScanConfig


def test_detects_hardcoded_key(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    module = ConfigAuditModule(config, OpenClawProfile())
    findings = module.scan()
    assert any("Hardcoded credential" in f.title for f in findings)


def test_detects_overly_permissive_provider(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    module = ConfigAuditModule(config, OpenClawProfile())
    findings = module.scan()
    assert any("Overly permissive" in f.title for f in findings)
