"""Tests for permission audit module."""
from aithon.modules.permissions import PermissionsModule
from aithon.agents.openclaw import OpenClawProfile
from aithon.config import ScanConfig


def test_detects_world_readable(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    module = PermissionsModule(config, OpenClawProfile())
    findings = module.scan()
    assert len(findings) > 0
    assert any("World-readable" in f.title for f in findings)


def test_clean_perms_no_findings(clean_workspace):
    config = ScanConfig(target=clean_workspace)
    module = PermissionsModule(config, OpenClawProfile())
    findings = module.scan()
    assert len(findings) == 0
