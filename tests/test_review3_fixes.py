"""Regression tests for AI review round 3 fixes.

Covers:
  1. Windows cache directory uses %LOCALAPPDATA% (not ~/.cache)
  2. HTML report error fallback includes escaped traceback for debugging
  3. Feed single-source failure still updates (multi-URL fallback works)
"""
import html
import io
import json
import sys
from unittest.mock import patch

import pytest


class TestWindowsCacheDir:
    """Cache dir must follow platform conventions (LOCALAPPDATA on Windows)."""

    def test_windows_uses_localappdata(self, monkeypatch):
        from npm_shield import feed as feed_mod
        monkeypatch.setattr(feed_mod.sys, "platform", "win32")
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
        monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
        d = feed_mod._default_cache_dir()
        assert str(d).startswith(r"C:\Users\test\AppData\Local")
        assert ".cache" not in str(d)

    def test_windows_without_localappdata_falls_back_home(self, monkeypatch):
        from npm_shield import feed as feed_mod
        monkeypatch.setattr(feed_mod.sys, "platform", "win32")
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
        d = feed_mod._default_cache_dir()
        # Falls back under home dir, never crashes
        assert "npm-shield" in str(d)

    def test_posix_uses_home_cache(self, monkeypatch):
        from npm_shield import feed as feed_mod
        monkeypatch.setattr(feed_mod.sys, "platform", "linux")
        d = feed_mod._default_cache_dir()
        assert str(d).endswith(".cache/npm-shield/feed_cache")


class TestHtmlErrorFallback:
    """format_html failure must expose a safe, escaped traceback."""

    def test_error_fallback_contains_traceback(self):
        from npm_shield.reporter import Reporter
        reporter = Reporter()

        class ExplodingResult:
            pass

        # Force _summary to raise — simulates unexpected mid-render error
        with patch.object(
            Reporter, "_summary", side_effect=RuntimeError("boom in report")
        ):
            out = reporter.format_html(ExplodingResult())
        assert "Error generating report" in out
        assert "boom in report" in out  # escaped traceback visible

    def test_error_fallback_html_is_safe(self):
        """Traceback text must be HTML-escaped (no raw angle brackets)."""
        from npm_shield.reporter import Reporter
        reporter = Reporter()

        class ExplodingResult:
            pass

        class SneakyError(RuntimeError):
            pass

        def raiser(result):
            raise SneakyError("<script>alert(1)</script>")

        with patch.object(Reporter, "_summary", side_effect=raiser):
            out = reporter.format_html(ExplodingResult())
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out


class TestFeedMultiSourceFallback:
    """One feed source failing must not stop the others."""

    def test_single_source_failure_still_updates(self, tmp_path, monkeypatch):
        from npm_shield import feed as feed_mod
        from npm_shield.feed import ThreatFeed

        monkeypatch.setenv("NPM_SHIELD_FEED_CACHE", str(tmp_path / "feed_cache"))
        calls = {"n": 0}

        def flaky_fetch(url, timeout=12):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("first source down")
            # second source returns a poisoned name@version pair
            return "keyv@6.0.0 and other packages compromised"

        monkeypatch.setattr(ThreatFeed, "_fetch", flaky_fetch)
        feed = ThreatFeed(offline_mode=False)
        assert feed.update() is True  # succeeded via fallback source
        assert calls["n"] >= 2

    def test_all_sources_down_returns_false(self, tmp_path, monkeypatch):
        from npm_shield.feed import ThreatFeed

        monkeypatch.setenv("NPM_SHIELD_FEED_CACHE", str(tmp_path / "feed_cache"))

        def down(url, timeout=12):
            raise OSError("all down")

        monkeypatch.setattr(ThreatFeed, "_fetch", down)
        feed = ThreatFeed(offline_mode=False)
        assert feed.update() is False
        assert feed.last_updated is None
