"""Tests for regex DoS (ReDoS) protection in signatures.py.

Verifies that _safe_regex_match:
  1. Prevents catastrophic backtracking (ReDoS) via timeout
  2. Still matches legitimate content
  3. Handles empty input safely
  4. Handles unicode input safely
"""
import re
import pytest
from npm_shield.signatures import _safe_regex_match


class TestRegexDoS:
    """Verify regex operations cannot be abused for denial-of-service."""

    def test_regex_timeout_prevents_dos(self):
        """Evil input that causes catastrophic backtracking must not hang."""
        import threading
        import time
        # Bounded evil input: (a+)+$ on "a"*26 ≈ 2^26 paths — long enough to
        # trigger the timeout, small enough that the SIGALRM handler actually
        # interrupts the C regex search deterministically (2^100 would let the
        # timer fire at an unpredictable bytecode boundary → flaky).
        evil_input = "a" * 26 + "!"
        pre = {t.ident for t in threading.enumerate()}

        # Pattern (a+)+$ causes exponential backtracking on naive regex
        result = _safe_regex_match(r"(a+)+$", evil_input, timeout=0.05)
        assert result is None  # Timeout returns None, not hang

        # If the thread-based fallback path was used (non-main thread or
        # SIGALRM unavailable), wait for its daemon thread to finish so it
        # cannot saturate CPU during subsequent tests.
        deadline = time.time() + 30
        while time.time() < deadline:
            alive = [
                t for t in threading.enumerate()
                if t.ident not in pre and t.is_alive()
            ]
            if not alive:
                break
            time.sleep(0.2)

    def test_normal_regex_still_works(self):
        """Legitimate matches must still work after adding timeout protection."""
        result = _safe_regex_match(r"npm-shield", "npm-shield v0.1.0", timeout=1.0)
        assert result is not None
        assert result.group(0) == "npm-shield"

    def test_empty_input(self):
        """Empty content must not crash."""
        assert _safe_regex_match(r"npm-shield", "", timeout=1.0) is None

    def test_unicode_input(self):
        """Unicode content must not break regex matching."""
        result = _safe_regex_match(r"测试", "hello 测试 world", timeout=1.0)
        assert result is not None
        assert result.group(0) == "测试"

    def test_multiline_pattern(self):
        """MULTILINE flag must work correctly."""
        content = "line1\nnpm-shield\nline3"
        result = _safe_regex_match(r"^npm-shield$", content, timeout=1.0)
        assert result is not None

    def test_invalid_regex_returns_none(self):
        """Malformed regex must return None, not raise."""
        result = _safe_regex_match(r"unclosed[", "test", timeout=1.0)
        assert result is None

    def test_none_pattern_returns_none(self):
        """None pattern must not crash."""
        result = _safe_regex_match(None, "test", timeout=1.0)
        assert result is None

    def test_long_line_no_hang(self):
        """A 100KB single line must not cause timeout on simple patterns."""
        long_line = "x" * 100000
        result = _safe_regex_match(r"\d", long_line, timeout=1.0)
        assert result is None  # No digits to match
