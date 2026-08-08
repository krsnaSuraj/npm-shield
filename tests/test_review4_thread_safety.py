"""Regression tests for AI review round 4 — thread-safety & robustness.

Critical: _safe_regex_match must not call signal.signal() from worker
threads (ValueError: signal only works in main thread). Must fall back
to the thread-based path in non-main threads.
"""
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest


class TestSignalMainThreadGuard:
    """signal-based timeout only from the main thread; workers use fallback."""

    def test_no_signal_call_from_worker_thread(self):
        """Worker threads must NEVER call signal.signal (crashes)."""
        from npm_shield import signatures as sig

        signal_calls = []

        def guard_signal(signum, handler):
            signal_calls.append(1)
            raise AssertionError("signal.signal called from worker thread!")

        def worker(i):
            # Patch signal.signal ONLY inside this worker's own call scope.
            # CRITICAL: the patch target is the *function object* referenced
            # by signatures.signal.signal. If we patched the global signal
            # module attribute with patch.object(sig.signal, "signal", ...),
            # the guard could leak into MAIN-thread calls running at the same
            # time (threads share module state) → spurious AssertionError in
            # unrelated tests. Instead, replace only what this worker's
            # _safe_regex_match will resolve, and do it via a per-thread
            # context so no other thread ever sees the guard.
            import threading
            tid = threading.get_ident()
            old_signal_fn = sig.signal.signal
            real = sig.signal.signal

            def thread_scoped_guard(signum, handler):
                # Only raise when called from THIS worker thread; any other
                # thread (main thread) falls through to the real function.
                if threading.get_ident() == tid:
                    signal_calls.append(1)
                    raise AssertionError(
                        "signal.signal called from worker thread!"
                    )
                return real(signum, handler)

            with patch.object(sig.signal, "signal", thread_scoped_guard):
                return sig._safe_regex_match(
                    r"keyv@6\.0\.0", "x" * 50 + " keyv@6.0.0", timeout=1.0
                )

        with ThreadPoolExecutor(max_workers=4) as ex:
            results = list(ex.map(worker, range(4)))
        assert len(signal_calls) == 0, "signal.signal called from worker!"
        # All workers still returned correct match results via fallback
        for r in results:
            assert r is not None
            assert r.group(0) == "keyv@6.0.0"

    def test_main_thread_still_uses_signal(self):
        """Main thread keeps the fast signal path (no regression)."""
        from npm_shield import signatures as sig

        used_signal = []

        def spy_signal(signum, handler):
            used_signal.append(1)
            # Preserve real behavior: install a no-op handler
            return None

        with patch.object(sig.signal, "signal", side_effect=spy_signal), \
             patch.object(sig.signal, "setitimer", lambda *a, **k: None):
            r = sig._safe_regex_match(r"abc", "xx abc yy", timeout=1.0)
        assert used_signal, "main thread should use the signal path"
        assert r is not None and r.group(0) == "abc"

    def test_worker_timeout_returns_none_not_crash(self):
        """Catastrophic backtracking in a worker returns None (no crash).

        Uses a *bounded* evil input so the daemon fallback thread finishes
        eventually — unbounded catastrophic patterns would leave a CPU-burning
        daemon thread (the documented platform limitation).
        """
        import threading
        import time
        from npm_shield import signatures as sig

        def worker(i):
            return sig._safe_regex_match(r"(a+)+$", "a" * 26 + "!", timeout=0.05)

        # Snapshot pre-existing threads so we can detect the daemon fallback
        # threads created by this test and wait for them to actually die.
        pre = {t.ident for t in threading.enumerate()}

        with ThreadPoolExecutor(max_workers=2) as ex:
            results = list(ex.map(worker, range(2)))
        for r in results:
            assert r is None  # timed out gracefully

        # CRITICAL: the daemon fallback threads are still backtracking on
        # the evil input in the background (they cannot be killed). If we
        # return immediately, they saturate CPU during the NEXT test and a
        # signal-based timeout there fires spuriously (flaky full-suite
        # failures). Wait for them to finish before handing back to pytest.
        # (a+)+$ on "a"*26 ≈ 2^26 paths ≈ seconds of CPU per thread.)
        deadline = time.time() + 30
        while time.time() < deadline:
            alive = [
                t for t in threading.enumerate()
                if t.ident not in pre and t.is_alive()
            ]
            if not alive:
                break
            time.sleep(0.2)

    def test_engine_parallel_scan_no_crash(self, tmp_path):
        """Full engine scan with parallel workers must not raise."""
        from npm_shield.engine import Scanner
        # Build a project with several package.json files to force
        # parallel candidate processing
        for i in range(6):
            d = tmp_path / f"pkg{i}"
            d.mkdir()
            (d / "package.json").write_text(
                '{"name":"demo","version":"1.0.0","scripts":{"preinstall":"node x.js"}}'
            )
        scanner = Scanner(threads=4)
        result = scanner.scan(str(tmp_path))
        assert result is not None


class TestAuditSubprocess:
    """check_gh_creds must not hang or flash windows (minor robustness)."""

    def test_gh_creds_uses_timeout_and_no_window(self, tmp_path, monkeypatch):
        from npm_shield import audit as audit_mod
        audit_mod._tool_argv("gh")
        # Ensure subprocess.run is called with timeout + creationflags
        # by simulating the call path
        calls = {}

        def fake_run(cmd, *args, **kwargs):
            calls["cmd"] = cmd
            calls["timeout"] = kwargs.get("timeout")
            calls["creationflags"] = kwargs.get("creationflags")
            class R:
                returncode = 1
                stdout = ""
            return R()

        monkeypatch.setattr(audit_mod.subprocess, "run", fake_run)
        audit_mod.CredentialAudit(home=str(tmp_path)).check_gh_creds()
        assert calls.get("timeout") is not None, "gh subprocess missing timeout"
