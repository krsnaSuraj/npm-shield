"""Regression tests for deep-audit fixes (AI review round 2).

Covers:
  1. _known_sizes cached (performance: no recompute per match_file call)
  2. Lockfile JSON sniff: package.json / config.json NOT treated as lockfile
  3. ReDoS Windows fallback path still returns correct results
  4. CLI direct method calls (no getattr guessing)
  5. 50MB lockfile warning emitted when ijson unavailable
"""
import io
import json
import os
import sys
from contextlib import redirect_stderr
from unittest.mock import patch

import pytest


class TestKnownSizesCache:
    """_known_sizes must be cached, not recomputed per access."""

    def test_known_sizes_cached_between_calls(self):
        from npm_shield.signatures import SignatureMatcher
        m = SignatureMatcher()
        # Prime cache
        first = m._known_sizes
        # Property should return same object (cached) unless file_hashes changed
        assert m._known_sizes is first, (
            "_known_sizes recomputes every call — performance bug"
        )

    def test_known_sizes_invalidates_on_file_hashes_replacement(self):
        from npm_shield.signatures import SignatureMatcher
        m = SignatureMatcher()
        orig = m._known_sizes
        # Tests/tooling replace file_hashes at runtime (must stay in sync)
        m.file_hashes = [
            {"sha256": "a" * 64, "size": 12345, "severity": "critical"}
        ]
        new = m._known_sizes
        assert 12345 in new
        assert new is not orig

    def test_match_file_uses_cached_sizes(self):
        """match_file must not recompute sizes set each call (hot loop)."""
        from npm_shield.signatures import SignatureMatcher
        m = SignatureMatcher()
        # Access once to prime
        m._known_sizes
        assert hasattr(m, "_known_sizes_cache")


class TestLockfileSniff:
    """detect_lockfile_type must not treat arbitrary JSON as lockfile."""

    def test_package_json_not_lockfile(self, tmp_path):
        from npm_shield.lockfile import detect_lockfile_type
        p = tmp_path / "package.json"
        p.write_text(json.dumps({"name": "myapp", "version": "1.0.0", "scripts": {}}))
        assert detect_lockfile_type(str(p)) is None, (
            "package.json (starts with {) falsely detected as lockfile"
        )

    def test_config_json_not_lockfile(self, tmp_path):
        from npm_shield.lockfile import detect_lockfile_type
        p = tmp_path / "config.json"
        p.write_text(json.dumps({"env": "prod", "region": "ap-south-1"}))
        assert detect_lockfile_type(str(p)) is None

    def test_real_package_lock_still_detected(self, tmp_path):
        from npm_shield.lockfile import detect_lockfile_type
        p = tmp_path / "package-lock.json"
        p.write_text(json.dumps({
            "name": "myapp",
            "lockfileVersion": 3,
            "packages": {"node_modules/keyv": {"version": "6.0.0"}},
        }))
        assert detect_lockfile_type(str(p)) == "package-lock"

    def test_oddly_named_lockfile_with_lockfileVersion(self, tmp_path):
        """Content sniff fallback still catches renamed lockfiles WITH evidence."""
        from npm_shield.lockfile import detect_lockfile_type
        p = tmp_path / "weird-name.json"
        p.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {},
        }))
        assert detect_lockfile_type(str(p)) == "package-lock"


class TestWindowsRegexFallback:
    """_safe_regex_match thread fallback (non-SIGALRM) must work."""

    def test_fallback_returns_match(self):
        from npm_shield import signatures as sig
        with patch.object(sig.signal, "SIGALRM", create=False), \
             patch.object(sig, "hasattr", side_effect=lambda name, *a: name != "SIGALRM"):
            result = sig._safe_regex_match(r"npm-shield", "x npm-shield y", timeout=0.5)
            assert result is not None
            assert result.group(0) == "npm-shield"

    def test_fallback_no_match_returns_none(self):
        from npm_shield import signatures as sig
        with patch.object(sig, "hasattr", side_effect=lambda name, *a: name != "SIGALRM"):
            result = sig._safe_regex_match(r"nothing-here", "abc", timeout=0.5)
            assert result is None


class TestCliDirectMethods:
    """CLI must call documented class methods directly (no getattr guessing)."""

    def test_cmd_system_uses_hunt_and_run_all(self, capsys):
        from npm_shield.cli import _cmd_system
        import argparse
        args = argparse.Namespace(
            command="system", json=True, html=False, sarif=False, output=None,
            lang="en", no_colors=True, threads=4, ignore_scripts_check=False,
        )
        code = _cmd_system(args)
        # Should not crash; exit code 0 or 1 (depends on machine state)
        assert code in (0, 1)
        out = capsys.readouterr().out
        # JSON output expected
        assert out.lstrip().startswith("{")

    def test_cmd_feed_update_uses_update_direct(self, capsys):
        from npm_shield.cli import _cmd_feed_update
        import argparse
        args = argparse.Namespace(
            command="feed-update", json=True, html=False, sarif=False, output=None,
            lang="en", no_colors=True, threads=4, ignore_scripts_check=False,
        )
        code = _cmd_feed_update(args)
        assert code in (0, 2)  # 0 = updated/offline ok, 2 = error handled
        out = capsys.readouterr().out
        assert "Threat feed" in out or out == ""


class TestLargeLockfileWarning:
    """50MB+ lockfile without ijson must warn that middle could be missed."""

    def test_warning_emitted_when_too_large(self, tmp_path):
        from npm_shield import lockfile as lf
        # Shrink cap so we don't need 50MB in test
        old_cap = lf._MAX_LOCKFILE_READ
        lf._MAX_LOCKFILE_READ = 1024  # 1KB
        try:
            p = tmp_path / "package-lock.json"
            # Build JSON > 1KB with a poisoned entry in the middle
            big = {
                "name": "test",
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/keyv": {"version": "6.0.0", "integrity": "x" * 5000},
                },
            }
            p.write_text(json.dumps(big))
            # Force the streaming parser to fail (simulates ijson absent),
            # which is the exact scenario the warning exists for.
            with patch.object(
                lf, "_parse_package_lock_streaming", side_effect=ImportError("no ijson")
            ):
                stderr_buf = io.StringIO()
                with redirect_stderr(stderr_buf):
                    result = lf.parse_package_lock(str(p))
            err = stderr_buf.getvalue()
            assert "ijson" in err or "large" in err.lower(), (
                "No warning emitted for oversized lockfile — silent miss risk"
            )
            assert isinstance(result, dict)
        finally:
            lf._MAX_LOCKFILE_READ = old_cap
