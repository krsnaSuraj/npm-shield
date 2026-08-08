"""Tests for npm_shield.cli (main entry point and exit codes)."""
import json

import pytest

from npm_shield.cli import main


def test_version_command(capsys):
    """`npm-shield version` prints 0.1.0 and exits 0."""
    rc = main(["version"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "0.1.0" in out


def test_scan_clean_exit_code(capsys, clean_project):
    """Scanning a clean project exits 0."""
    rc = main(["scan", str(clean_project)])
    capsys.readouterr()
    assert rc == 0


def test_scan_infected_exit_code(capsys, infected_project):
    """Scanning an infected project exits 1."""
    rc = main(["scan", str(infected_project)])
    capsys.readouterr()
    assert rc == 1


def test_json_output_valid(capsys, infected_project):
    """--json emits parseable JSON with findings."""
    rc = main(["scan", str(infected_project), "--json"])
    out = capsys.readouterr().out
    assert rc == 1
    data = json.loads(out)
    assert data["findings"]
    assert data["severity_counts"]["critical"] >= 1


def test_no_colors_flag(capsys, infected_project):
    """--no-colors strips ANSI escapes; default output is colored."""
    rc = main(["scan", str(infected_project)])
    colored = capsys.readouterr().out
    assert rc == 1
    assert "\x1b[" in colored  # ANSI color present by default

    rc = main(["scan", str(infected_project), "--no-colors"])
    plain = capsys.readouterr().out
    assert rc == 1
    assert "\x1b[" not in plain


def test_scan_nonexistent_path_exit_code(capsys):
    """A missing path is an error (exit 2), not a crash."""
    rc = main(["scan", "/nonexistent/definitely-not-here"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "path" in err.lower()


def test_hinglish_scan(capsys, infected_project):
    """--lang hi produces Hinglish output."""
    rc = main(["scan", str(infected_project), "--lang", "hi"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "AFFECTED MILA!" in out
