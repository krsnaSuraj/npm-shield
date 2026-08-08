"""Tests for npm_shield.persistence.PersistenceHunter.

The hunter reads persistence paths from the signature data and expands
`~` against $HOME, so tests monkeypatch HOME to hermetic temp dirs.
"""
import pytest

from npm_shield.persistence import PersistenceHunter


def test_hunt_no_persistence(monkeypatch, tmp_path):
    """A clean HOME has no critical persistence findings."""
    monkeypatch.setenv("HOME", str(tmp_path))
    findings = PersistenceHunter().hunt()
    assert not any(f.severity == "critical" for f in findings)


def test_hunt_with_persistence(monkeypatch, persistence_dir):
    """A HOME with ~/.config/gh-token-monitor/ is flagged critical."""
    monkeypatch.setenv("HOME", str(persistence_dir))
    findings = PersistenceHunter().hunt()
    assert any(f.severity == "critical" for f in findings)
    assert any(
        "gh-token-monitor" in ((f.message or "") + (f.file_path or ""))
        for f in findings
    )


def test_check_persistence_paths_direct(monkeypatch, persistence_dir):
    """The path check alone flags the artifact."""
    monkeypatch.setenv("HOME", str(persistence_dir))
    findings = PersistenceHunter().check_home()
    assert findings
    assert any("gh-token-monitor" in (f.file_path or "") for f in findings)


def test_check_processes_no_match(tmp_path):
    """No Shai-Hulud launcher process is running in the test environment."""
    findings = PersistenceHunter().check_processes()
    assert not any(f.severity == "critical" for f in findings)


def test_never_crashes(monkeypatch, tmp_path):
    """Weird HOME values must not raise; results are always lists."""
    for home in (str(tmp_path / "missing-home"), str(tmp_path / "a" / "b" / "c")):
        monkeypatch.setenv("HOME", home)
        hunter = PersistenceHunter()
        assert isinstance(hunter.hunt(), list)
        assert isinstance(hunter.check_processes(), list)
        assert isinstance(hunter.check_temp_dirs(), list)
        assert isinstance(hunter.check_ide_hooks(str(tmp_path)), list)
