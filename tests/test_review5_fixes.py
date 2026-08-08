"""Regression tests for AI review round 5 — npm-shield fixes.

Covers:
  1. Nested lockfile dependencies parsed correctly (lodash/node_modules/keyv)
  2. Feed update: blog text mentioning benign packages does NOT flag them
  3. Evasion via file padding: content markers scanned even for >1MB files
"""
import io
import json
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import pytest


class TestNestedLockfileDeps:
    """package-lock v2/v3 nested dependencies must be resolved to leaf name."""

    def test_nested_dependency_detected(self):
        from npm_shield.lockfile import _parse_package_lock_flat
        doc = {
            "name": "test",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/lodash/node_modules/keyv": {"version": "6.0.0"},
            },
        }
        out = _parse_package_lock_flat(doc)
        assert out.get("keyv") == "6.0.0", (
            f"nested keyv not resolved to leaf name — got keys {list(out.keys())}"
        )

    def test_top_level_dependency_still_works(self):
        from npm_shield.lockfile import _parse_package_lock_flat
        doc = {
            "name": "test",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/keyv": {"version": "6.0.0"},
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }
        out = _parse_package_lock_flat(doc)
        assert out.get("keyv") == "6.0.0"
        assert out.get("lodash") == "4.17.21"

    def test_deeply_nested_dependency(self):
        from npm_shield.lockfile import _parse_package_lock_flat
        doc = {
            "name": "test",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/a/node_modules/b/node_modules/keyv": {"version": "6.0.0"},
            },
        }
        out = _parse_package_lock_flat(doc)
        assert out.get("keyv") == "6.0.0", f"deeply nested failed: {out}"

    def test_packages_to_out_nested(self):
        from npm_shield.lockfile import _packages_to_out
        doc = {
            "packages": {
                "node_modules/foo/node_modules/keyv": {"version": "6.0.0"},
                "node_modules/keyv": {"version": "5.6.0"},
            }
        }
        out = _packages_to_out(doc)
        # Nested keyv MUST be resolved to leaf name (not "foo/node_modules/keyv").
        # setdefault keeps the first-encountered entry — the point of this test
        # is that the nested dep is detected under the correct package name.
        assert "keyv" in out
        assert "node_modules" not in " ".join(out.keys())


class TestFeedFalsePositives:
    """Feed update must not flag benign packages mentioned in blog text."""

    def test_benign_packages_not_flagged(self, tmp_path, monkeypatch):
        from npm_shield import feed as feed_mod
        from npm_shield.feed import ThreatFeed

        monkeypatch.setenv("NPM_SHIELD_FEED_CACHE", str(tmp_path / "feed_cache"))

        blog_text = (
            "The malware targets projects using express@4.18.2 and developers "
            "using react@18.0.0 should be careful. Popular packages like lodash@4.17.21 "
            "and axios@1.6.0 are also widely used."
        )

        def fake_fetch(url, timeout=12):
            return blog_text

        monkeypatch.setattr(ThreatFeed, "_fetch", fake_fetch)
        feed = ThreatFeed(offline_mode=False)
        # All mentions are benign → nothing added to feed → update() returns
        # False (no cache written) and affected list stays local-only.
        feed.update()
        affected = feed.get_affected_packages()
        # Benign packages must NOT be in affected list
        for pkg in ("express", "react", "lodash", "axios"):
            assert pkg not in affected, (
                f"benign package {pkg} flagged as affected by feed scrape"
            )

    def test_verified_poisoned_still_detected(self, tmp_path, monkeypatch):
        """Real poisoned name@version pairs still make it into the feed."""
        from npm_shield import feed as feed_mod
        from npm_shield.feed import ThreatFeed

        monkeypatch.setenv("NPM_SHIELD_FEED_CACHE", str(tmp_path / "feed_cache"))

        blog_text = "keyv@6.0.0 and cacheable-request@13.0.20 are confirmed malicious."

        def fake_fetch(url, timeout=12):
            return blog_text

        monkeypatch.setattr(ThreatFeed, "_fetch", fake_fetch)
        feed = ThreatFeed(offline_mode=False)
        feed.update()
        affected = feed.get_affected_packages()
        assert "keyv" in affected


class TestPaddingEvasion:
    """Content markers must be found even in padded files >1MB."""

    def test_marker_found_in_padded_file(self, tmp_path):
        from npm_shield.signatures import SignatureMatcher
        m = SignatureMatcher()
        marker = "thebeautifulmarchoftime"
        # Build a padded file > MAX_MARKER_FILE_SIZE (1MB) with marker in middle
        p = tmp_path / "util.js"
        junk = b"\x00" * (1024 * 1024 + 500_000)  # 1.5MB padding
        content = junk + marker.encode() + junk
        p.write_bytes(content)
        assert p.stat().st_size > 1024 * 1024

        result = m.match_content_markers(str(p))
        assert result, "marker in padded file not detected (size evasion)"

    def test_marker_found_in_renamed_padded_file(self, tmp_path):
        """Renamed + padded dropper still caught by content marker scan."""
        from npm_shield.signatures import SignatureMatcher
        m = SignatureMatcher()
        # Actual token-relay marker from the verified IOC data
        marker = "IfYouBlockThisAPIKeyItWillCrashTheLiveProduction"
        p = tmp_path / "random-name.js"
        junk = b"A" * (1024 * 1024 + 100_000)
        p.write_bytes(junk + marker.encode())
        result = m.match_content_markers(str(p))
        assert result, "renamed+padded file evaded marker detection"

    def test_normal_file_marker_still_works(self, tmp_path):
        from npm_shield.signatures import SignatureMatcher
        m = SignatureMatcher()
        p = tmp_path / "loader.js"
        p.write_text("const x = 'thebeautifulmarchoftime';")
        result = m.match_content_markers(str(p))
        assert result
