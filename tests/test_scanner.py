"""Tests for main scanner orchestrator."""
from aithon.core.scanner import Scanner
from aithon.config import ScanConfig


def test_scanner_runs_all_modules(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    scanner = Scanner(config)
    findings = scanner.run()
    assert len(findings) > 0


def test_scanner_severity_filter(fake_workspace):
    config = ScanConfig(target=fake_workspace, min_severity="critical")
    scanner = Scanner(config)
    findings = scanner.run()
    for f in findings:
        assert f.severity >= 4


def test_scanner_detects_openclaw(fake_workspace):
    config = ScanConfig(target=fake_workspace, agent_type="auto")
    scanner = Scanner(config)
    assert scanner.agent_profile.name == "openclaw"
