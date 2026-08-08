"""Real-time watch mode for npm-shield.

Polls a project directory and rescans whenever dependency-relevant files
(``package.json``, lockfiles, ``node_modules``) change on disk. Simple
mtime-based polling — no external watchdog dependency required.

Typical usage::

    from npm_shield.watcher import Watcher
    Watcher().run_forever("./my-project", interval=5)
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set

from npm_shield.reporter import Reporter, VERSION, _msg as _watcher_msg

__all__ = ["Watcher"]

#: files/dirs whose mtime changes trigger a rescan
_WATCH_TARGETS = (
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "node_modules",
)


class Watcher:
    """Polls a project directory and rescans when dependency files change.

    The first poll always runs a scan; subsequent polls only rescan when
    a watched path's mtime changed since the previous poll.
    """

    def __init__(self, lang: str = "en", colors: bool = True) -> None:
        self.reporter = Reporter(lang=lang, colors=colors)
        self._last_snapshot: Optional[Dict[str, Optional[float]]] = None
        self._last_result: Any = None
        self._known_keys: Optional[Set[str]] = None
        self._first_report_done: bool = False

    # ------------------------------------------------------------------
    # Polling internals
    # ------------------------------------------------------------------
    def _snapshot(self, project_dir: str) -> Dict[str, Optional[float]]:
        """mtime map for every watched path (None when missing)."""
        snap: Dict[str, Optional[float]] = {}
        for name in _WATCH_TARGETS:
            path = os.path.join(project_dir, name)
            try:
                snap[path] = os.path.getmtime(path)
            except OSError:
                snap[path] = None
        return snap

    def _scan(self, project_dir: str) -> Any:
        """Run the engine scanner; return None (instead of raising) on failure."""
        try:
            from npm_shield.engine import Scanner

            return Scanner().scan(project_dir)
        except Exception:
            return None

    def _new_finding_keys(self, result: Any) -> Set[str]:
        keys = {Reporter.finding_signature(f) for f in Reporter.get_findings(result)}
        return keys - (self._known_keys or set())

    def _alert(self, count: int) -> None:
        msg = _watcher_msg("new_findings", self.reporter.lang)
        print(self.reporter.paint(f"⚠️ {msg} ({count} new)", "critical", bold=True))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def watch(
        self,
        project_dir: str,
        interval: int = 5,
        callback: Optional[Callable[[Any], None]] = None,
    ) -> Any:
        """Perform one poll cycle.

        Rescans only when a watched path changed since the last poll (or
        on the very first call). Returns the fresh ``ScanResult``, the
        previous result when nothing changed, or ``None`` when the engine
        is unavailable. ``interval`` is accepted for API compatibility;
        the sleep loop lives in :meth:`run_forever`.
        """
        project_dir = os.path.abspath(project_dir)
        snapshot = self._snapshot(project_dir)
        changed = snapshot != self._last_snapshot
        self._last_snapshot = snapshot

        if not changed and self._last_result is not None:
            return self._last_result

        result = self._scan(project_dir)
        self._last_result = result
        if result is not None and callback is not None:
            try:
                callback(result)
            except Exception:
                pass
        return result

    def run_forever(self, project_dir: str, interval: int = 5) -> int:
        """Blocking watch loop: rescan on change, alert on new findings.

        Prints a full report on the first successful scan and whenever
        new findings appear. Ctrl+C stops cleanly and returns 0.
        """
        project_dir = os.path.abspath(project_dir)
        # Guard against UnicodeEncodeError on non-UTF-8 locales (e.g.
        # Windows cp1252 pipes) when printing emoji report headers.
        try:
            reconfigure = getattr(sys.stdout, "reconfigure", None)
            if callable(reconfigure):
                reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        if not os.path.isdir(project_dir):
            print(f"error: not a directory: {project_dir}", file=sys.stderr)
            return 2
        try:
            interval = max(0.5, float(interval))
        except (TypeError, ValueError):
            interval = 5.0

        print(f"🛡️ npm-shield v{VERSION} — {_watcher_msg('watching', self.reporter.lang)}")
        print(f"Watching {project_dir} every {interval:g}s — Ctrl+C to stop")
        try:
            while True:
                result = self.watch(project_dir, interval=interval)
                if result is not None:
                    new_keys = self._new_finding_keys(result)
                    if new_keys:
                        self._alert(len(new_keys))
                    if not self._first_report_done or new_keys:
                        print()
                        print(self.reporter.format_terminal(result))
                        self._first_report_done = True
                    self._known_keys = {
                        Reporter.finding_signature(f) for f in Reporter.get_findings(result)
                    }
                time.sleep(interval)
        except KeyboardInterrupt:
            print()
            print(self.reporter.paint(f"⏹ {_watcher_msg('stopped', self.reporter.lang)}", "info"))
            return 0
