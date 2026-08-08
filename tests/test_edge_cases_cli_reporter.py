"""Edge-case tests for npm_shield.cli, npm_shield.reporter and npm_shield.watcher.

Covers defensive behaviors: argparse exits, malformed/odd findings, HTML/JSON
escaping, language fallbacks, watcher caching/change detection and callbacks.
"""
import json
import os
import time

import pytest

from npm_shield.cli import main
from npm_shield.engine import Finding, ScanResult
from npm_shield.reporter import Reporter
from npm_shield.watcher import Watcher


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _result(findings):
    return ScanResult(findings=findings, path="/tmp/fake-project")


def _finding(severity, message="test finding", **kw):
    return Finding("rule-1", severity, message, file_path="/tmp/fake-project/pkg.json", **kw)


# ---------------------------------------------------------------------------
# CLI edge cases
# ---------------------------------------------------------------------------
def test_no_command_prints_help(capsys):
    """No subcommand → help on stdout and exit 0."""
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "usage" in out.lower()
    assert "scan" in out.lower()


def test_unknown_command():
    """An unknown subcommand is an argparse error → SystemExit(2)."""
    with pytest.raises(SystemExit) as exc:
        main(["frobnicate"])
    assert exc.value.code == 2


def test_scan_with_lang_invalid(tmp_path):
    """--lang outside the (en, hi) choices is rejected by argparse → 2."""
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(tmp_path), "--lang", "xx"])
    assert exc.value.code == 2


def test_threads_zero_rejected(capsys, tmp_path):
    """--threads 0 is a usage error (exit 2) with a clear stderr message."""
    rc = main(["scan", str(tmp_path), "--threads", "0"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "threads" in err.lower()


def test_html_output_file(capsys, infected_project, tmp_path, monkeypatch):
    """--html writes npm-shield-report.html into the current dir and exits 1."""
    monkeypatch.chdir(tmp_path)
    rc = main(["scan", str(infected_project), "--html"])
    out = capsys.readouterr().out
    assert rc == 1
    report = tmp_path / "npm-shield-report.html"
    assert report.exists()
    assert "npm-shield" in report.read_text(encoding="utf-8")
    assert "HTML report" in out


def test_scan_single_lockfile_via_cli(capsys, tmp_path):
    """Scanning a single infected package-lock.json file works via the CLI."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "name": "infected-app",
                "version": "1.0.0",
                "lockfileVersion": 1,
                "requires": True,
                "dependencies": {"keyv": {"version": "6.0.0", "requires": {}}},
            }
        )
    )
    rc = main(["scan", str(lockfile), "--json"])
    out = capsys.readouterr().out
    assert rc == 1
    data = json.loads(out)
    assert data["findings"]
    assert data["findings"][0]["package"] == "keyv"


def test_system_command_runs(capsys):
    """`system` runs end-to-end without crashing (rc 0 clean or 1 affected)."""
    rc = main(["system"])
    capsys.readouterr()
    assert rc in (0, 1)


def test_version_short_flag(capsys):
    """--version prints the version and exits 0 via argparse."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "npm-shield" in out


# ---------------------------------------------------------------------------
# Reporter edge cases
# ---------------------------------------------------------------------------
def test_format_with_none_finding():
    """None entries in the findings list are filtered, formatting survives."""
    result = _result([None, _finding("critical", message="real one")])
    findings = Reporter.get_findings(result)
    assert len(findings) == 1
    assert all(f is not None for f in findings)
    out = Reporter().format_terminal(result)
    assert "real one" in out


def test_format_with_dict_finding():
    """Plain dict findings work with the terminal formatter."""
    result = _result([{"severity": "critical", "message": "dict finding"}])
    out = Reporter().format_terminal(result)
    assert "CRITICAL" in out
    assert "dict finding" in out


def test_format_with_unknown_severity():
    """An unknown severity is normalized to 'info' instead of crashing."""
    result = _result([Finding("rule-1", "purple", "weird severity")])
    out = Reporter().format_terminal(result)
    assert "weird severity" in out
    assert "INFO" in out


def test_format_json_weird_chars():
    """Emoji and control characters survive JSON serialization (round-trip)."""
    message = "emoji 🐛 and\nnewlines \t tab"
    result = _result([_finding("critical", message=message)])
    raw = Reporter().format_json(result)
    data = json.loads(raw)  # must parse cleanly
    assert data["findings"][0]["message"] == message


def test_html_escapes():
    """HTML output escapes raw <script> content from finding messages."""
    result = _result([_finding("critical", message="<script>alert(1)</script>")])
    html = Reporter().format_html(result)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_plain_no_ansi():
    """format_plain never emits ANSI codes even when colors=True."""
    result = _result([_finding("critical")])
    out = Reporter(colors=True).format_plain(result)
    assert "\x1b[" not in out


def test_hinglish_constructor_default():
    """Reporter(lang='hi') applies Hinglish when no lang kwarg is passed."""
    result = _result([_finding("critical")])
    out = Reporter(lang="hi").format_terminal(result)
    assert "MILA" in out


def test_finding_signature_stable():
    """Identical findings share a signature; different messages differ."""
    f1 = _finding("high", message="same message")
    f2 = _finding("high", message="same message")
    f3 = _finding("high", message="different message")
    assert Reporter.finding_signature(f1) == Reporter.finding_signature(f2)
    assert Reporter.finding_signature(f1) != Reporter.finding_signature(f3)


# ---------------------------------------------------------------------------
# Watcher edge cases
# ---------------------------------------------------------------------------
def test_watch_nonexistent_dir(capsys):
    """run_forever on a missing dir is an error (exit 2), no infinite loop."""
    rc = Watcher().run_forever("/nonexistent/npm-shield-nowhere")
    err = capsys.readouterr().err
    assert rc == 2
    assert "directory" in err.lower()


def test_watch_first_scan_reports(clean_project):
    """The first watch() always scans and returns a ScanResult."""
    watcher = Watcher(colors=False)
    assert watcher._first_report_done is False
    result = watcher.watch(str(clean_project))
    assert result is not None
    assert isinstance(result, ScanResult)
    # watch() itself does not mark the first report as done (run_forever does)
    assert watcher._first_report_done is False


def test_watch_no_rescan_when_unchanged(clean_project):
    """Unchanged project → the cached result object is returned as-is."""
    watcher = Watcher(colors=False)
    result1 = watcher.watch(str(clean_project))
    result2 = watcher.watch(str(clean_project))
    assert result1 is not None
    assert result2 is result1


def test_watch_rescan_on_change(clean_project):
    """Changing a watched file's mtime triggers a fresh scan (new object)."""
    watcher = Watcher(colors=False)
    result1 = watcher.watch(str(clean_project))
    pkg_json = clean_project / "package.json"
    t = time.time() + 10
    os.utime(pkg_json, (t, t))
    result2 = watcher.watch(str(clean_project))
    assert result2 is not None
    assert result2 is not result1


def test_watch_callback_called(clean_project):
    """The callback fires once with the result of the first scan."""
    watcher = Watcher(colors=False)
    calls = []
    result = watcher.watch(str(clean_project), callback=calls.append)
    assert len(calls) == 1
    assert calls[0] is result
