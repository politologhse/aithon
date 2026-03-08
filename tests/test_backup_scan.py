"""Tests for backup scanning module."""
from aithon.modules.backup_scan import BackupScanModule
from aithon.agents.openclaw import OpenClawProfile
from aithon.config import ScanConfig


def test_finds_secrets_in_backups(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    module = BackupScanModule(config, OpenClawProfile())
    findings = module.scan()
    assert len(findings) > 0
