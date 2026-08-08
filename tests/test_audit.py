"""Tests for npm_shield.audit.CredentialAudit.

The audit accepts a ``home`` override for hermetic tests. Token VALUES are
never written to disk and never asserted against real secrets — only that
the synthetic value is absent from every finding field.
"""
import subprocess

import pytest

from npm_shield.audit import CredentialAudit

FAKE_TOKEN = "npm_FAKE_TOKEN_9f3a7c"  # synthetic value, never a real credential


def _home_with_npmrc(tmp_path, content):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".npmrc").write_text(content)
    return home


def _audit(monkeypatch, home):
    # NPM_CONFIG_USERCONFIG would override home/.npmrc — keep it unset.
    monkeypatch.delenv("NPM_CONFIG_USERCONFIG", raising=False)
    return CredentialAudit(home=str(home))


def test_npmrc_token_redacted(monkeypatch, tmp_path):
    """A token in .npmrc is flagged and its VALUE never leaks into findings."""
    home = _home_with_npmrc(tmp_path, f"//registry.npmjs.org/:_authToken={FAKE_TOKEN}\n")
    finding = _audit(monkeypatch, home).check_npmrc()
    assert finding is not None
    assert finding.severity == "high"
    assert finding.category == "npmrc"
    for field in ("message", "detail", "fix", "file_path"):
        value = getattr(finding, field, None) or ""
        assert FAKE_TOKEN not in str(value)
    assert FAKE_TOKEN not in str(finding.to_dict())


def test_npmrc_plain_auth_token(monkeypatch, tmp_path):
    """A bare _authToken= line is also caught."""
    home = _home_with_npmrc(tmp_path, f"_authToken={FAKE_TOKEN}\n")
    finding = _audit(monkeypatch, home).check_npmrc()
    assert finding is not None
    assert finding.severity == "high"


def test_ignore_scripts_check_true(monkeypatch, tmp_path):
    """ignore-scripts=true blocks install scripts: no high/critical finding."""
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="true")

    monkeypatch.setattr("npm_shield.audit.subprocess.run", fake_run)
    finding = CredentialAudit(home=str(tmp_path)).check_ignore_scripts()
    assert finding is not None
    assert finding.severity not in ("high", "critical")


def test_ignore_scripts_check_false(monkeypatch, tmp_path):
    """ignore-scripts=false is a high-severity exposure."""
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="false")

    monkeypatch.setattr("npm_shield.audit.subprocess.run", fake_run)
    finding = CredentialAudit(home=str(tmp_path)).check_ignore_scripts()
    assert finding.severity == "high"


def test_no_credentials(monkeypatch, tmp_path):
    """A clean environment produces no high/critical findings."""
    import os

    for name in ("NPM_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    for name in list(os.environ):
        if name.startswith("AWS_"):
            monkeypatch.delenv(name, raising=False)

    home = tmp_path / "clean-home"
    home.mkdir()
    findings = _audit(monkeypatch, home).run_all()
    assert findings
    assert not any(f.severity in ("high", "critical") for f in findings)


def test_audit_never_crashes(monkeypatch, tmp_path):
    """Missing config files and garbage content must not raise."""
    monkeypatch.delenv("NPM_CONFIG_USERCONFIG", raising=False)
    audit = CredentialAudit(home=str(tmp_path / "missing-home"))
    assert audit.check_npmrc() is not None  # returns a finding, not a crash

    home = _home_with_npmrc(tmp_path, "\x00\x01 not a config\n")
    assert CredentialAudit(home=str(home)).check_npmrc() is not None
