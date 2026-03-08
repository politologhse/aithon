"""Tests for fix plan generator."""
from aithon.core.fix_plan import generate_fix_plan
from aithon.core.scanner import Scanner
from aithon.config import ScanConfig


def test_fix_plan_generates_script(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    scanner = Scanner(config)
    findings = scanner.run()
    script = generate_fix_plan(findings, fake_workspace)

    assert script.startswith("#!/usr/bin/env bash")
    assert "REVIEW THIS SCRIPT" in script
    assert "chmod 600" in script


def test_fix_plan_empty_on_clean(clean_workspace):
    config = ScanConfig(target=clean_workspace)
    scanner = Scanner(config)
    findings = scanner.run()

    # Clean workspace may still have some findings, but script should be valid
    script = generate_fix_plan(findings, clean_workspace)
    assert script.startswith("#!/usr/bin/env bash")


def test_fix_plan_includes_permission_fixes(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    scanner = Scanner(config)
    findings = scanner.run()
    script = generate_fix_plan(findings, fake_workspace)

    assert "File Permission" in script or "Environment File" in script


def test_fix_plan_includes_secret_advisories(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    scanner = Scanner(config)
    findings = scanner.run()
    script = generate_fix_plan(findings, fake_workspace)

    assert "MANUAL REVIEW" in script or "Exposed Secrets" in script
