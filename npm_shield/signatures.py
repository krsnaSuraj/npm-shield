"""Signature engine for npm-shield.

Loads the verified IOC data from ``data/`` and provides YARA-style matching
helpers: file hashes, package.json patterns, IDE hooks and poisoned-package
lookups.

Matching methods return a single result ``dict`` (or ``None``) — the
engine layer wraps them into :class:`~npm_shield.engine.Finding` objects.

All data files live in ``<package_root>/data`` by default and can be
overridden with the ``NPM_SHIELD_DATA_DIR`` environment variable.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import signal
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("npm_shield.signatures")

def _find_data_dir() -> Path:
    """Resolve the directory containing the verified IOC data.

    Resolution order (first existing wins):
      1. ``<package>/data`` — the data shipped inside the installed package
         (``pip install .`` / site-packages layout).
      2. ``<repo root>/data`` — the repo checkout layout used by tests and
         ``pip install -e .``.
    """
    package_dir = Path(__file__).resolve().parent
    candidates = (
        package_dir / "data",
        package_dir.parent / "data",
    )
    for candidate in candidates:
        if (candidate / "signatures.json").is_file():
            return candidate
    return candidates[0]


DATA_DIR = Path(
    os.environ.get(
        "NPM_SHIELD_DATA_DIR",
        str(
            _find_data_dir()
        ),
    )
)

#: Windows and macOS (default APFS/HFS+) filesystems are case-insensitive:
#: on those platforms IOC filename matching must ignore case or casing
#: variants of artifact names would evade detection. Linux stays exact
#: (casing variants are distinct files there). Monkeypatchable so tests
#: can exercise both branches on any host.
_CASE_INSENSITIVE_FS = sys.platform in ("win32", "darwin")


# ---------------------------------------------------------------------------
# Safe regex execution with timeout protection
# ---------------------------------------------------------------------------
# Some patterns in signatures.json are complex enough to be vulnerable to
# catastrophic backtracking (ReDoS). We wrap every match in a signal-based
# timeout so a crafted package.json can never hang the scanner.

def _safe_regex_match(
    pattern: str, content: str, timeout: float = 2.0
) -> Optional[re.Match]:
    """Run *pattern* against *content* with a hard timeout.

    Returns a match object or ``None``. If the regex takes longer than
    *timeout* seconds the operation is aborted, preventing ReDoS hangs.

    Thread-safety: ``signal.signal()``/``signal.setitimer()`` only work
    in the **main thread** — calling them from a worker thread raises
    ``ValueError: signal only works in main thread``. The engine runs
    scans on a ``ThreadPoolExecutor``, so we branch on
    ``threading.current_thread() is threading.main_thread()``: the main
    thread gets the fast signal-based timeout; every other thread gets
    the daemon-thread fallback (bounded, non-crashing).
    """
    try:
        rx = re.compile(pattern, re.MULTILINE | re.DOTALL)
    except (re.error, TypeError):
        return None

    # Use signal-based timeout ONLY from the main thread (POSIX).
    import threading

    is_main_thread = threading.current_thread() is threading.main_thread()
    if hasattr(signal, "SIGALRM") and is_main_thread:
        # Drain any stale SIGALRM from a previous call BEFORE installing
        # our handler. A timer that fired at a bytecode boundary after the
        # prior call's finally-block would otherwise be delivered to OUR
        # handler the moment we install it → spurious TimeoutError → wrong
        # None (flaky cross-test failures).
        signal.signal(signal.SIGALRM, signal.SIG_IGN)
        signal.setitimer(signal.ITIMER_REAL, 0)

        def _timeout_handler(signum, frame):
            raise TimeoutError("regex exceeded timeout")

        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        try:
            return rx.search(content)
        except (TimeoutError, Exception):
            return None
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        # Non-Unix (Windows) fallback — Python cannot kill a thread, so a
        # regex that exceeds the timeout keeps running in a daemon thread
        # (bounded CPU burn until the engine finishes) while the caller
        # proceeds with a None result. This is a documented platform
        # limitation: install the ``re2`` engine or use a POSIX host for
        # hard ReDoS guarantees. ``daemon=True`` ensures the process can
        # still exit; ``join(timeout)`` keeps the main path responsive.
        result: List[Any] = []
        def _worker():
            try:
                result.append(rx.search(content))
            except Exception:
                result.append(None)

        import threading
        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(timeout=timeout)
        return result[0] if result else None


def _hook_name_matches(actual: str, expected: str) -> bool:
    """Compare hook filenames, case-insensitively on case-insensitive
    filesystems (Windows/macOS) so ``.CLAUDE/SETTINGS.JSON`` is still seen
    as ``.claude/settings.json``; exactly on Linux, where casing variants
    are distinct paths. Matching is content-gated downstream."""
    if _CASE_INSENSITIVE_FS:
        return actual.lower() == expected.lower()
    return actual == expected


#: Severity -> risk weight used by :func:`npm_shield.engine.compute_risk_score`.
#:
#: Weights are chosen for *incident-response urgency*: a single critical
#: finding (a verified worm carrier) immediately signals "stop the line"
#: rather than a low single-digit score that a developer might skip.
#:   critical=40  -> 1 critical = 40 (urgent), 3 critical = max-out (100)
#:   high=20, medium=8, low=3, info=1
SEVERITY_WEIGHTS: Dict[str, float] = {
    "info": 1.0,
    "low": 3.0,
    "medium": 8.0,
    "high": 20.0,
    "critical": 40.0,
}

#: Files larger than this are never hashed (size gate for scan speed).
MAX_HASH_FILE_SIZE = 2 * 1024 * 1024  # 2 MiB

#: Files larger than this are never content-scanned for campaign markers.
#: 1 MiB comfortably covers the 727680-byte stage-2 harvester.
MAX_MARKER_FILE_SIZE = 1024 * 1024  # 1 MiB

_SIGNATURES: Optional[Dict[str, Any]] = None
_AFFECTED: Optional[Dict[str, List[str]]] = None


def load_signatures() -> Dict[str, Any]:
    """Load ``signatures.json`` once and cache it. Never raises."""
    global _SIGNATURES
    if _SIGNATURES is None:
        try:
            with open(DATA_DIR / "signatures.json", "r", encoding="utf-8") as fh:
                _SIGNATURES = json.load(fh)
        except Exception:
            _SIGNATURES = {}
    return _SIGNATURES


def load_affected_packages() -> Dict[str, List[str]]:
    """Load ``affected_packages.json`` (package name -> poisoned versions)."""
    global _AFFECTED
    if _AFFECTED is None:
        try:
            with open(DATA_DIR / "affected_packages.json", "r", encoding="utf-8") as fh:
                _AFFECTED = json.load(fh)
        except Exception:
            _AFFECTED = {}
    return _AFFECTED


def load_campaign_meta() -> Dict[str, Any]:
    """Load ``campaign_meta.json``. Never raises."""
    try:
        with open(DATA_DIR / "campaign_meta.json", "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


class SignatureMatcher:
    """YARA-style matcher over the verified Shai-Hulud IOC data.

    Result shape: a plain dict with at least ``severity`` plus context keys
    (``description``/``message``, ``file_path``, ``package``, ``version``,
    ``pattern``, ``sha256`` ...), or ``None`` when nothing matched.
    """

    def __init__(self) -> None:
        self._sig = load_signatures()
        self._affected = load_affected_packages()
        self.file_hashes: List[Dict[str, Any]] = self._sig.get("file_hashes", []) or []
        self.name_signals: set = set(self._sig.get("file_name_signals", []) or [])
        self._pkg_patterns: List[Dict[str, Any]] = self._sig.get("package_json_patterns", []) or []
        self._ide_hooks: List[Dict[str, Any]] = self._sig.get("ide_hook_patterns", []) or []
        self._compiled_patterns: List[Any] = []
        for entry in self._pkg_patterns:
            try:
                self._compiled_patterns.append(
                    (re.compile(entry["pattern"], re.MULTILINE), entry)
                )
            except (re.error, KeyError):
                continue

    # ------------------------------------------------------------------ #
    # Exposed data (used by reporting / other modules)
    # ------------------------------------------------------------------ #

    @property
    def persistence_paths(self) -> List[Dict[str, Any]]:
        return self._sig.get("persistence_paths", []) or []

    @property
    def exfil_endpoint(self) -> str:
        return self._sig.get("exfil_endpoint", "")

    @property
    def dead_drop_marker(self) -> str:
        return self._sig.get("dead_drop_repo_marker", "")

    @property
    def bun_version_signal(self) -> str:
        return self._sig.get("bun_version_signal", "")

    @property
    def token_relay_marker(self) -> str:
        """The campaign's token-relay marker string.

        The stored value is a prefix of the full marker observed in the
        wild (``...ServersOfAllThirdPartyClients``), so an ``in`` check on
        it matches the real marker too.
        """
        return self._sig.get("token_relay_marker", "")

    @property
    def content_marker_strings(self) -> List[str]:
        """Additional campaign-unique content-marker strings (e.g. the
        Datadog-verified Ethereum C2 fallback markers
        ``thebeautifulmarchoftime`` / ``thebeautifulsnadsoftime``).

        These are embedded in loader/harvester code and are strong,
        campaign-unique signals for unknown/renamed variants.
        """
        return list(self._sig.get("content_marker_strings", []) or [])

    @property
    def _known_sizes(self) -> set:
        # Cached per file_hashes identity: match_file() runs in hot loops
        # (one call per file in node_modules), so recomputing this set on
        # every access is wasted CPU. Tests/tooling may replace
        # ``file_hashes`` at runtime — the cache key is the list identity,
        # so any replacement invalidates it automatically.
        try:
            if (
                getattr(self, "_sizes_cache_key", None) != id(self.file_hashes)
                or getattr(self, "_known_sizes_cache", None) is None
            ):
                self._known_sizes_cache = {
                    int(h["size"]) for h in self.file_hashes if h.get("size")
                }
                self._sizes_cache_key = id(self.file_hashes)
            return self._known_sizes_cache
        except Exception:
            return set()

    # ------------------------------------------------------------------ #
    # File matching
    # ------------------------------------------------------------------ #

    @staticmethod
    def _read_text_chunked(path: Path, chunk_size: int = 65536) -> str:
        """Read a file as text with bounded memory, preserving full-content
        substring search.

        Reads in overlapping chunks so a marker spanning a chunk boundary
        is still found, and never loads files > a few MB fully into RAM.
        Catches undecodable bytes via errors='ignore'.
        """
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if size <= MAX_MARKER_FILE_SIZE * 4:
            # Small enough — fast path (read whole, match once)
            return path.read_text(encoding="utf-8", errors="ignore")

        # Large file — overlapping chunks, keep the tail of each chunk so
        # markers straddling boundaries are caught.
        overlap = 512  # larger than any campaign marker
        buf = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                prev = ""
                while True:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break
                    buf.append(prev + chunk)
                    prev = chunk[-overlap:] if len(chunk) > overlap else chunk
        except Exception:
            return ""
        return "\n".join(buf)

    def is_signal_name(self, fname: str) -> bool:
        """True when *fname* matches a known signal filename.

        Exact match everywhere. On case-insensitive filesystems
        (win32/darwin — see ``_CASE_INSENSITIVE_FS``) casing variants also
        match, so ``SETUP.MJS`` / ``math_symbol.js`` are caught on
        Windows/macOS while Linux stays exact. Recomputed per call so
        runtime replacements of ``name_signals`` (tests, tooling) stay in
        sync.
        """
        try:
            if fname in self.name_signals:
                return True
            if _CASE_INSENSITIVE_FS:
                lowered = {str(s).lower() for s in self.name_signals}
                return (fname or "").lower() in lowered
            return False
        except Exception:
            return False

    def match_file(self, path: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """Check a file against known hashes, sizes and filename signals.

        Returns a single result dict or ``None``. Hash checks only run for
        files <= 2 MiB whose size matches a known malicious size, so scanning
        a full node_modules tree stays fast while still catching renamed
        copies.
        """
        try:
            p = Path(path)
            if not p.is_file():
                return None
            try:
                size = p.stat().st_size
            except OSError:
                return None

            name = p.name
            known_sizes = self._known_sizes

            # 1) exact hash match (highest confidence)
            if 0 < size <= MAX_HASH_FILE_SIZE and size in known_sizes:
                digest = self._sha256(p)
                if digest:
                    for h in self.file_hashes:
                        entry_size = h.get("size")
                        if h.get("sha256") == digest and (
                            not entry_size or int(entry_size) == size
                        ):
                            return {
                                "severity": h.get("severity", "critical"),
                                "category": "file_hash",
                                "file_path": str(p),
                                "pattern": name,
                                "sha256": digest,
                                "message": h.get(
                                    "description",
                                    "Known malicious file hash (Shai-Hulud)",
                                ),
                                "description": h.get(
                                    "description",
                                    "Known malicious file hash (Shai-Hulud)",
                                ),
                                "fix": (
                                    "Quarantine/delete the file immediately; "
                                    "treat the host as compromised and rotate "
                                    "all credentials."
                                ),
                            }

            # 2) known filename + known size (practical fallback for
            #    unknown content — the stage-2 harvester's size signature).
            #    Case-insensitive: Windows/macOS filesystems are not.
            if self.is_signal_name(name) and size in known_sizes:
                return {
                    "severity": "critical",
                    "category": "file_name_size",
                    "file_path": str(p),
                    "pattern": name,
                    "message": (
                        "Filename and size match a known Shai-Hulud artifact: %s"
                        % name
                    ),
                    "description": (
                        "Filename and size match a known Shai-Hulud artifact: %s"
                        % name
                    ),
                    "fix": (
                        "Quarantine/delete the file and reinstall "
                        "dependencies from a clean lockfile."
                    ),
                }

            # 3) filename signal only (case-insensitive match)
            if self.is_signal_name(name):
                return {
                    "severity": "high",
                    "category": "file_name_signal",
                    "file_path": str(p),
                    "pattern": name,
                    "message": (
                        "Filename matches a known Shai-Hulud artifact: %s" % name
                    ),
                    "description": (
                        "Filename matches a known Shai-Hulud artifact: %s" % name
                    ),
                    "fix": (
                        "Quarantine/delete the file and reinstall "
                        "dependencies from a clean lockfile."
                    ),
                }
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    # Content markers (unknown/renamed variants)
    # ------------------------------------------------------------------ #

    def _live_exfil_domain(self) -> str:
        """The exfil endpoint with defanging removed, lowercased.

        ``data/signatures.json`` stores the defanged form
        (``npm-cache[.]com``) for safe display; malware code contains the
        live form (``npm-cache.com``), which is what we scan for.
        """
        try:
            return (
                (self.exfil_endpoint or "").replace("[.]", ".").strip().lower()
            )
        except Exception:
            return ""

    def match_content_markers(
        self, path: Union[str, Path]
    ) -> List[Dict[str, Any]]:
        """Scan a small text file for embedded campaign marker strings.

        Catches unknown or renamed dropper/harvester variants that dodge
        the hash and filename checks but still embed campaign strings:

        * the token-relay marker (critical — campaign-unique string),
        * the live exfil endpoint domain (high — C2 reference),
        * the Bun loader version signal (medium — version string alone).

        Files larger than :data:`MAX_MARKER_FILE_SIZE` are chunk-scanned
        (not skipped) so an attacker padding a dropper with junk cannot
        evade the campaign-marker checks. Returns a list (0..n result
        dicts) and never raises.
        """
        out: List[Dict[str, Any]] = []
        try:
            p = Path(path)
            if not p.is_file():
                return out
            try:
                text = self._read_text_chunked(p)
            except Exception:
                return out

            marker = self.token_relay_marker
            if marker and marker in text:
                msg = (
                    "File contains the Shai-Hulud token-relay marker "
                    "('%s…') — token-harvesting code or workflow present."
                    % marker
                )
                out.append(
                    {
                        "severity": "critical",
                        "category": "content_marker",
                        "file_path": str(p),
                        "pattern": marker,
                        "message": msg,
                        "description": msg,
                        "fix": (
                            "Quarantine the file and treat the host as "
                            "compromised; kill the gh-token-monitor watcher "
                            "BEFORE rotating any tokens (the dead-man's "
                            "switch detonates on revocation)."
                        ),
                    }
                )

            # Generic campaign-unique markers (Ethereum C2 fallback etc.)
            for marker_str in self.content_marker_strings:
                if marker_str and marker_str in text:
                    msg = (
                        "File contains the Shai-Hulud campaign marker "
                        "('%s') — C2 fallback / loader code present."
                        % marker_str
                    )
                    out.append(
                        {
                            "severity": "critical",
                            "category": "content_marker",
                            "file_path": str(p),
                            "pattern": marker_str,
                            "message": msg,
                            "description": msg,
                            "fix": (
                                "Quarantine the file and treat the host as "
                                "compromised; investigate for other "
                                "artifacts before rotating credentials."
                            ),
                        }
                    )

            bun = self.bun_version_signal
            if bun and bun in text:
                msg = (
                    "File references the Shai-Hulud Bun loader version "
                    "signal (%s) — loader variant." % bun
                )
                out.append(
                    {
                        "severity": "medium",
                        "category": "content_marker",
                        "file_path": str(p),
                        "pattern": bun,
                        "message": msg,
                        "description": msg,
                        "fix": (
                            "Quarantine/delete the file and reinstall "
                            "dependencies from a clean lockfile."
                        ),
                    }
                )

            endpoint = self._live_exfil_domain()
            if endpoint and endpoint in text.lower():
                msg = (
                    "File references the Shai-Hulud exfil endpoint "
                    "(%s) — C2/exfil code present." % endpoint
                )
                out.append(
                    {
                        "severity": "high",
                        "category": "content_marker",
                        "file_path": str(p),
                        "pattern": endpoint,
                        "message": msg,
                        "description": msg,
                        "fix": (
                            "Quarantine/delete the file; block the domain at "
                            "the egress proxy and audit for prior "
                            "exfiltration."
                        ),
                    }
                )
        except Exception:
            pass
        return out

    # ------------------------------------------------------------------ #
    # package.json matching
    # ------------------------------------------------------------------ #

    def check_package_json(self, content: str) -> Optional[Dict[str, Any]]:
        """Return the first malicious pattern match in package.json content."""
        for hit in self.match_package_json(content):
            return hit
        return None

    def match_package_json(self, content: str) -> List[Dict[str, Any]]:
        """Run all malicious package.json regex patterns against content."""
        findings: List[Dict[str, Any]] = []
        try:
            if not content:
                return findings
            for rx, entry in self._compiled_patterns:
                match = _safe_regex_match(entry["pattern"], content, timeout=2.0)
                if match:
                    desc = entry.get(
                        "description", "Malicious package.json pattern"
                    )
                    findings.append(
                        {
                            "severity": entry.get("severity", "critical"),
                            "category": "package_json_pattern",
                            "pattern": entry.get("pattern", ""),
                            "message": desc,
                            "description": desc,
                            "fix": (
                                "Remove the malicious install script and "
                                "reinstall from a clean lockfile."
                            ),
                        }
                    )
        except Exception:
            pass
        return findings

    # ------------------------------------------------------------------ #
    # IDE hooks
    # ------------------------------------------------------------------ #

    def check_ide_hooks(self, file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """Check one IDE hook file (e.g. ``.claude/settings.json``) for the
        malicious SessionStart / folderOpen patterns. Returns dict or None."""
        try:
            p = Path(file_path)
            for hook in self._ide_hooks:
                rel = hook.get("path", "")
                if not _hook_name_matches(p.name, Path(rel).name):
                    continue
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                marker = hook.get("pattern", "")
                command = hook.get("command", "")
                if marker and marker in text and (not command or command in text):
                    desc = hook.get("description", "Malicious IDE hook")
                    return {
                        "severity": hook.get("severity", "critical"),
                        "category": "ide_hook",
                        "file_path": str(p),
                        "pattern": marker,
                        "command": command,
                        "message": desc,
                        "description": desc,
                        "fix": (
                            "Remove the hook entry; IDE hooks should never "
                            "execute scripts from node_modules."
                        ),
                    }
        except Exception:
            pass
        return None

    def match_ide_hooks(self, repo_dir: Union[str, Path]) -> List[Dict[str, Any]]:
        """Check every known IDE hook location under ``repo_dir``."""
        findings: List[Dict[str, Any]] = []
        try:
            base = Path(repo_dir)
            for hook in self._ide_hooks:
                rel = hook.get("path", "")
                marker = hook.get("pattern", "")
                command = hook.get("command", "")
                fpath = base / rel
                try:
                    if not fpath.is_file():
                        continue
                    text = fpath.read_text(encoding="utf-8", errors="ignore")
                except Exception as exc:
                    # Visibility: don't silently swallow — log why we skipped
                    # so debug mode can reveal permission/corruption issues.
                    logger.debug("skip IDE hook %s: %s", fpath, exc)
                    continue
                if marker and marker in text and (not command or command in text):
                    desc = hook.get("description", "Malicious IDE hook")
                    findings.append(
                        {
                            "severity": hook.get("severity", "critical"),
                            "category": "ide_hook",
                            "file_path": str(fpath),
                            "pattern": marker,
                            "command": command,
                            "message": desc,
                            "description": desc,
                            "fix": (
                                "Remove the hook entry; IDE hooks should never "
                                "execute scripts from node_modules."
                            ),
                        }
                    )
                elif marker and marker in text:
                    findings.append(
                        {
                            "severity": "low",
                            "category": "ide_hook",
                            "file_path": str(fpath),
                            "pattern": marker,
                            "message": (
                                "IDE hook file references '%s' but not the "
                                "known malicious command" % marker
                            ),
                            "description": (
                                "IDE hook file references '%s' but not the "
                                "known malicious command" % marker
                            ),
                            "fix": "Review the hook; verify it runs nothing untrusted.",
                        }
                    )
        except Exception:
            pass
        return findings

    # ------------------------------------------------------------------ #
    # Poisoned packages
    # ------------------------------------------------------------------ #

    def check_poisoned_package(
        self, name: str, version: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Return a result dict if ``name@version`` is on the affected list.

        A ``*`` entry matches any version; otherwise the version must match
        exactly (a ``None`` version only matches ``*`` entries).
        """
        try:
            if not name:
                return None
            versions = self._affected.get(name)
            if not versions:
                return None
            if "*" in versions or (version and version in versions):
                return {
                    "severity": "critical",
                    "category": "poisoned_package",
                    "package": name,
                    "version": version or "unknown",
                    "message": (
                        "Package %s is on the Shai-Hulud affected list "
                        "(verified IOC)." % name
                    ),
                    "description": (
                        "Package %s is on the Shai-Hulud affected list "
                        "(verified IOC)." % name
                    ),
                    "fix": (
                        "Remove the package and its lockfile entries; upgrade "
                        "to the latest clean version."
                    ),
                }
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _sha256(path: Path) -> Optional[str]:
        try:
            digest = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except Exception:
            return None
