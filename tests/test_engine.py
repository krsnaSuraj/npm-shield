"""Tests for npm_shield.engine (Scanner, ScanResult, Finding, risk scoring)."""
import json
from pathlib import Path

import pytest

from npm_shield.engine import Finding, ScanResult, Scanner, compute_risk_score


def test_scan_clean_project(scanner, clean_project):
    """A clean project yields zero findings and a risk score of zero."""
    result = scanner.scan(str(clean_project))
    assert result.findings == []
    assert result.risk_score == 0
    assert result.error is None


def test_scan_infected_project(scanner, infected_project):
    """An infected project yields at least one critical finding."""
    result = scanner.scan(str(infected_project))
    assert result.findings
    assert any(f.severity == "critical" for f in result.findings)
    assert result.risk_score > 0


def test_scan_lockfile_infected(scanner, tmp_path):
    """A lockfile pinning keyv@6.0.0 is caught even without package.json."""
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "app",
                "lockfileVersion": 3,
                "packages": {"node_modules/keyv": {"version": "6.0.0"}},
            }
        )
    )
    result = scanner.scan(str(tmp_path))
    keyv_findings = [f for f in result.findings if f.package == "keyv"]
    assert keyv_findings
    assert keyv_findings[0].severity == "critical"


def test_scan_infected_node_modules(scanner, infected_node_modules):
    """Installed node_modules with poisoned keyv + Math_Symbol.js are caught."""
    result = scanner.scan(str(infected_node_modules))
    assert result.findings
    assert any(f.severity == "critical" for f in result.findings)
    assert any(
        "Math_Symbol.js" in (f.file_path or "") for f in result.findings
    )


def test_compute_risk_score():
    """Critical findings dominate the risk score; clean findings sum to 0."""
    assert compute_risk_score([]) == 0
    critical = Finding("r1", "critical", "boom")
    high = Finding("r2", "high", "warn")
    score = compute_risk_score([critical, high])
    assert score == compute_risk_score([critical]) + compute_risk_score([high])
    assert score > compute_risk_score([high])
    # Unknown severities are ignored, not fatal.
    assert compute_risk_score([Finding("r3", "weird", "x")]) == 0


def test_compute_risk_score_critical_increases():
    """Adding a critical finding strictly increases the score."""
    base = compute_risk_score([Finding("a", "low", "meh")])
    bumped = compute_risk_score(
        [Finding("a", "low", "meh"), Finding("b", "critical", "boom")]
    )
    assert bumped > base


def test_scan_nonexistent_path(scanner):
    """Scanning a nonexistent path returns an errored result, no crash."""
    result = scanner.scan("/nonexistent/definitely-not-here")
    assert result.error is not None
    assert result.findings == []
    assert result.risk_score == 0


def test_scan_result_to_dict(scanner, infected_project):
    """ScanResult serializes to a JSON-friendly dict."""
    result = scanner.scan(str(infected_project))
    d = result.to_dict()
    assert isinstance(d["findings"], list)
    assert d["risk_score"] > 0
    json.dumps(d)  # must be serializable


def test_finding_accepts_hunter_kwargs():
    """Finding tolerates the hunter/audit keyword style (category/fix/message)."""
    f = Finding(
        severity="high",
        category="npmrc",
        file_path="/tmp/.npmrc",
        message="npm auth token configured",
        fix="Rotate the token now",
    )
    assert f.severity == "high"
    assert f.category == "npmrc"
    assert f.message == "npm auth token configured"
    assert f.description == "npm auth token configured"  # alias property
    assert f.file_path == "/tmp/.npmrc"
    assert f.fix == "Rotate the token now"


def test_scan_single_file(scanner, tmp_path):
    """Scanning a single file path works too."""
    f = tmp_path / "Math_Symbol.js"
    f.write_bytes(b"\x00" * 727680)
    result = scanner.scan(str(f))
    assert result.findings
