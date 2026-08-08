"""Tests for npm_shield.reporter.Reporter."""
import json

import pytest

from npm_shield.engine import Finding, ScanResult
from npm_shield.reporter import Reporter, SEVERITY_ORDER, SEVERITY_STYLES


def _result(findings):
    return ScanResult(findings=findings, path="/tmp/fake-project")


def _finding(severity, rule_id="rule-1", message="test finding", **kw):
    return Finding(rule_id, severity, message, file_path="/tmp/fake-project/pkg.json", **kw)


def test_terminal_format():
    """Terminal report carries the npm-shield header."""
    out = Reporter().format_terminal(_result([]))
    assert "npm-shield" in out


def test_terminal_finding_details():
    """Findings appear with severity and message in terminal output."""
    out = Reporter().format_terminal(_result([_finding("critical", message="setup.mjs found")]))
    assert "CRITICAL" in out
    assert "setup.mjs found" in out


def test_json_format_valid():
    """JSON report parses and contains the findings array."""
    result = _result([_finding("critical")])
    data = json.loads(Reporter().format_json(result))
    assert data["tool"] == "npm-shield"
    assert data["findings"]
    assert data["findings"][0]["severity"] == "critical"
    assert data["summary"]["affected"] >= 1
    assert data["severity_counts"]["critical"] >= 1


def test_json_clean():
    """A clean result serializes with zero affected."""
    data = json.loads(Reporter().format_json(_result([])))
    assert data["findings"] == []
    assert data["summary"]["affected"] == 0


def test_hinglish_format():
    """lang='hi' reports use Hinglish status strings."""
    crit = _result([_finding("critical", message="setup.mjs found")])
    out = Reporter(lang="hi").format_terminal(crit, lang="hi")
    assert "AFFECTED MILA!" in out  # Hinglish for "AFFECTED FOUND!"

    clean = _result([])
    out_clean = Reporter(lang="hi").format_terminal(clean, lang="hi")
    assert "SAB SAF" in out_clean  # Hinglish for "CLEAN"


def test_hinglish_format_explicit_lang():
    """format_terminal(lang='hi') produces Hinglish regardless of constructor."""
    out = Reporter().format_terminal(_result([_finding("critical")]), lang="hi")
    assert "AFFECTED MILA!" in out


def test_severity_icons():
    """Every severity maps to its icon in terminal output."""
    result = _result(
        [
            _finding("critical"),
            _finding("high"),
            _finding("medium"),
            _finding("low"),
        ]
    )
    out = Reporter(colors=False).format_terminal(result)
    for sev in ("critical", "high", "medium", "low"):
        assert SEVERITY_STYLES[sev]["icon"] in out


def test_colors_flag():
    """colors=True emits ANSI codes; colors=False does not."""
    result = _result([_finding("critical")])
    assert "\x1b[" in Reporter(colors=True).format_terminal(result)
    assert "\x1b[" not in Reporter(colors=False).format_terminal(result)


def test_get_findings_duck_typing():
    """get_findings works on ScanResult, dicts and duck-typed objects."""
    result = _result([_finding("critical")])
    assert Reporter.get_findings(result) == result.findings
    assert Reporter.get_findings({"findings": result.findings}) == result.findings
    assert Reporter.get_findings(None) == []
    assert Reporter.get_findings(_finding("critical")) == []  # not a result
