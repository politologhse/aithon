"""Tests for watch mode."""
from pathlib import Path
from aithon.core.watcher import Watcher
from aithon.core.finding import Finding
from aithon.config import ScanConfig, Severity


def test_watcher_scan_once(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    watcher = Watcher(config=config, interval=1)
    findings, new_findings, resolved = watcher.scan_once()

    assert len(findings) > 0
    # First scan: most findings are new (some may share hash)
    assert len(new_findings) > 0
    assert resolved == 0


def test_watcher_detects_no_new_on_rescan(fake_workspace):
    config = ScanConfig(target=fake_workspace)
    watcher = Watcher(config=config, interval=1)

    # First scan
    watcher.scan_once()

    # Second scan — same workspace, no changes
    findings, new_findings, resolved = watcher.scan_once()
    assert len(new_findings) == 0
    assert resolved == 0


def test_watcher_finding_hash_stable():
    f1 = Finding(
        id="SEC-001", title="Test", severity=Severity.HIGH,
        module="secrets", description="desc", file_path="/a/b", evidence="sk-xxx",
    )
    f2 = Finding(
        id="SEC-999", title="Test", severity=Severity.LOW,
        module="secrets", description="other", file_path="/a/b", evidence="sk-xxx",
    )
    config = ScanConfig(target=Path("/tmp"))
    watcher = Watcher(config=config, interval=1)
    # Same module+title+file+evidence = same hash (id and severity don't matter)
    assert watcher._finding_hash(f1) == watcher._finding_hash(f2)


def test_watcher_state_persistence(fake_workspace, tmp_path):
    state_file = tmp_path / "state.json"
    config = ScanConfig(target=fake_workspace)

    watcher1 = Watcher(config=config, interval=1, state_file=state_file)
    watcher1.scan_once()
    assert state_file.exists()

    # New watcher loads state from file
    watcher2 = Watcher(config=config, interval=1, state_file=state_file)
    findings, new_findings, resolved = watcher2.scan_once()
    assert len(new_findings) == 0  # No new findings since state was loaded
