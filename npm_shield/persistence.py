"""Persistence and runtime artifact hunter for npm-shield.

Scans the host for Shai-Hulud persistence artifacts: the gh-token-monitor
dead-man's switch (Linux/macOS/Windows), systemd user services, running
processes and bun download temp directories.

Every check is wrapped in try/except — this module never crashes and
returns an empty list when a platform check does not apply.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, List, Optional

from npm_shield.signatures import SignatureMatcher

_PROCESS_PATTERNS = (
    re.compile(r"gh-token-monitor", re.IGNORECASE),
    re.compile(r"setup\.mjs", re.IGNORECASE),
    re.compile(r"Math_Symbol", re.IGNORECASE),
    re.compile(r"bun.*runner", re.IGNORECASE),
)

# Legitimate processes that share IOC filenames — skip if the full
# command line contains a safe-path indicator (user project dir, etc.).
_LEGIT_SETUPMJS_INDICATORS = (
    re.compile(r"github\.com/"),
    re.compile(r"\.git/"),
    re.compile(r"/node_modules/"),
    re.compile(r"pnpm-dlx"),
    re.compile(r"tmp/.*/[A-Za-z]+/setup\.mjs"),
)

_PLATFORM_ALIASES = {
    "linux": ("linux", "all"),
    "darwin": ("macos", "darwin", "all"),
    "win32": ("windows", "win32", "all"),
}


# Paths that indicate a malicious systemd ExecStart (Shai-Hulud markers)
_EXECSTART_MALICIOUS = re.compile(
    r"(setup\.mjs|gh-token-monitor|Math_Symbol|bun.*runner)",
    re.IGNORECASE,
)


def _get_systemd_execstart(unit: str) -> str:
    """Return the ExecStart= line for a systemd unit, or empty string."""
    try:
        proc = subprocess.run(
            ["systemctl", "--user", "show", unit, "-p", "ExecStart"],
            capture_output=True,
            text=True,
            timeout=10,
            errors="replace",
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except Exception:
        return ""


def _mk_svc_finding(self, unit: str):
    """Build a systemd service finding with IR-appropriate fix guidance."""
    return self._mk(
        severity="high",
        category="systemd_service",
        message="Suspicious user service unit: %s" % unit,
        detail="Service unit matches Shai-Hulud persistence naming or ExecStart",
        fix=(
            "Disable/remove the unit FIRST "
            "(systemctl --user disable --now %s), "
            "then rotate tokens — the watcher detonates "
            "on revocation (dead-man's switch)." % unit
        ),
    )


class PersistenceHunter:
    """Hunts Shai-Hulud persistence and runtime artifacts on the host.

    ``home`` overrides the base directory used for persistence-path checks
    (defaults to the real $HOME) — useful for isolated testing and
    container scans.
    """

    def __init__(
        self,
        home: Optional[str] = None,
        matcher: Optional[SignatureMatcher] = None,
    ) -> None:
        self.home = Path(home) if home else Path.home()
        self.matcher = matcher or SignatureMatcher()
        self.platform = sys.platform

    def hunt(self) -> List[Any]:
        """Run all host-level checks and return every Finding."""
        findings: List[Any] = []
        findings.extend(self._check_persistence_paths())
        findings.extend(self._check_systemd_services())
        findings.extend(self.check_processes())
        findings.extend(self.check_temp_dirs())
        return findings

    # ------------------------------------------------------------------ #
    # Persistence paths from signatures.json
    # ------------------------------------------------------------------ #

    def _check_persistence_paths(self) -> List[Any]:
        """Check every configured persistence path under ``self.home``."""
        findings: List[Any] = []
        try:
            allowed = set(_PLATFORM_ALIASES.get(self.platform, ("all",)))
            for entry in self.matcher.persistence_paths or []:
                os_name = (entry.get("os") or "all").lower()
                if os_name not in allowed:
                    continue
                raw = entry.get("path", "")
                if not raw:
                    continue
                expanded = self._resolve(raw)
                if expanded.exists():
                    desc = entry.get(
                        "description", "Shai-Hulud persistence artifact present"
                    )
                    findings.append(
                        self._mk(
                            severity=entry.get("severity", "critical"),
                            category="persistence",
                            file_path=str(expanded),
                            message="%s (path: %s)" % (desc, expanded),
                            detail=(
                                "Shai-Hulud dead-man's switch persistence "
                                "artifact; value redacted"
                            ),
                            fix=(
                                "ORDER MATTERS: stop the gh-token-monitor "
                                "watcher FIRST (kill its process, remove this "
                                "dir and any LaunchAgent/systemd unit) — it "
                                "polls token validity every 60s and evals its "
                                "handler the moment the token is revoked. "
                                "THEN rotate all GitHub/npm tokens; rotating "
                                "first detonates the dead-man's switch. "
                                "Audit for exfiltration afterwards."
                            ),
                        )
                    )
        except Exception:
            pass
        return findings

    def check_home(self) -> List[Any]:
        """Alias for :meth:`_check_persistence_paths`."""
        return self._check_persistence_paths()

    def _resolve(self, raw: str) -> Path:
        """Resolve a '~'-prefixed entry path against ``self.home``.

        Exactly one leading ``~`` is replaced by ``self.home``; both ``/``
        and ``\\`` separators are accepted so entries like
        ``~/.config/...`` (POSIX) and ``~\\.config\\...`` (Windows) both
        resolve. Non-``~`` paths get environment-variable expansion
        (``$VAR`` on POSIX, ``%VAR%`` on Windows — handled by
        :func:`os.path.expandvars` per platform).
        """
        try:
            if raw.startswith("~"):
                rel = raw[1:].lstrip("/\\")
                return self.home / rel
            return Path(os.path.expandvars(raw))
        except Exception:
            return Path(raw)

    # ------------------------------------------------------------------ #
    # systemd user services (Linux)
    # ------------------------------------------------------------------ #

    def _check_systemd_services(self) -> List[Any]:
        findings: List[Any] = []
        if self.platform != "linux":
            return findings
        try:
            proc = subprocess.run(
                ["systemctl", "--user", "list-unit-files"],
                capture_output=True,
                text=True,
                timeout=15,
                errors="replace",
            )
            if proc.returncode != 0:
                return findings
            for line in proc.stdout.splitlines():
                lowered = line.lower()
                unit = line.split()[0] if line.split() else line.strip()
                if "gh-token" in lowered:
                    findings.append(_mk_svc_finding(self, unit))
                elif "node" in lowered and (
                    ".service" in lowered or ".timer" in lowered
                ):
                    # Verify the service actually executes a malicious script
                    # (not just a legitimate node backend service)
                    exec_start = _get_systemd_execstart(unit)
                    if _EXECSTART_MALICIOUS.match(exec_start):
                        findings.append(_mk_svc_finding(self, unit))
        except Exception:
            pass
        return findings

    # ------------------------------------------------------------------ #
    # Processes
    # ------------------------------------------------------------------ #

    def check_processes(self) -> List[Any]:
        """Scan running processes for Shai-Hulud launcher patterns."""
        findings: List[Any] = []
        seen: set = set()
        try:
            rows = self._running_processes()
            for cmd in rows:
                lowered = cmd.lower()
                # Skip legitimate processes that share IOC filenames
                # (e.g. user's own database-migrate/setup.mjs in a project dir)
                if any(ind.search(cmd) for ind in _LEGIT_SETUPMJS_INDICATORS):
                    continue
                for rx in _PROCESS_PATTERNS:
                    if rx.search(lowered) and cmd not in seen:
                        seen.add(cmd)
                        findings.append(
                            self._mk(
                                severity="critical",
                                category="process",
                                message=(
                                    "Running process matches Shai-Hulud "
                                    "pattern: %s" % _truncate(cmd, 200)
                                ),
                                detail="Process command line matched an IOC pattern",
                                fix=(
                                    "Kill the process immediately — BEFORE "
                                    "rotating any tokens: the watcher evals "
                                    "its handler when the token is revoked, "
                                    "so rotating first detonates the "
                                    "dead-man's switch. Then investigate "
                                    "how it was launched."
                                ),
                            )
                        )
                        break
        except Exception:
            pass
        return findings

    def _running_processes(self) -> List[str]:
        """Return command lines of running processes (psutil, else `ps aux`)."""
        rows: List[str] = []
        try:
            import psutil  # type: ignore

            for proc in psutil.process_iter(["cmdline", "name"]):
                try:
                    parts = proc.info.get("cmdline") or [
                        proc.info.get("name") or ""
                    ]
                    rows.append(" ".join(str(x) for x in parts))
                except psutil.AccessDenied:
                    # System/root-owned processes we can't inspect — skip
                    # (documented: never crash on permission boundaries).
                    continue
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
                except Exception:
                    continue
            if rows:
                return rows
        except Exception:
            pass
        try:
            # Windows has no `ps`; psutil (tried above) is the only path.
            if sys.platform == "win32":
                return rows
            proc = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=15,
                errors="replace",
            )
            if proc.returncode == 0:
                rows = [ln for ln in proc.stdout.splitlines()[1:] if ln.strip()]
        except Exception:
            pass
        return rows

    # ------------------------------------------------------------------ #
    # Temp dirs
    # ------------------------------------------------------------------ #

    def check_temp_dirs(self) -> List[Any]:
        """Look for 'bun-dl-*' directories in the platform temp locations.

        Covers POSIX (``$TMPDIR``, ``/tmp``), macOS (``$TMPDIR``) and
        Windows (``%TEMP%``/``%TMP%`` and AppData\\Local\\Temp via
        :func:`tempfile.gettempdir`), so the loader's staging dir is found
        regardless of which env vars a platform actually sets.
        """
        findings: List[Any] = []
        candidates = {
            tempfile.gettempdir(),
            "/tmp",
            os.environ.get("TMPDIR", ""),
            os.environ.get("TEMP", ""),
            os.environ.get("TMP", ""),
        }
        for raw in candidates:
            if not raw:
                continue
            try:
                base = Path(raw)
                if not base.is_dir():
                    continue
                for child in base.iterdir():
                    if child.is_dir() and child.name.startswith("bun-dl-"):
                        findings.append(
                            self._mk(
                                severity="medium",
                                category="temp_artifact",
                                file_path=str(child),
                                message=(
                                    "Bun download temp directory found: %s "
                                    "(loader artifact)" % child.name
                                ),
                                detail="bun-dl-* temp dir is a Shai-Hulud loader artifact",
                                fix=(
                                    "Remove the directory; if unexplained, "
                                    "treat the host as potentially infected."
                                ),
                            )
                        )
                        # The loader keeps the downloaded Bun runtime here —
                        # a filename carrying the campaign version signal is
                        # a much stronger indicator than the dir name alone.
                        bun_signal = self.matcher.bun_version_signal
                        if not bun_signal:
                            continue
                        try:
                            for grand in child.iterdir():
                                if bun_signal in grand.name:
                                    findings.append(
                                        self._mk(
                                            severity="high",
                                            category="bun_artifact",
                                            file_path=str(grand),
                                            message=(
                                                "Bun loader archive with the "
                                                "campaign version signal: %s"
                                                % grand.name
                                            ),
                                            detail=(
                                                "%s is the Shai-Hulud "
                                                "loader's pinned runtime"
                                                % bun_signal
                                            ),
                                            fix=(
                                                "Delete the archive and the "
                                                "bun-dl-* temp dir; treat "
                                                "the host as compromised."
                                            ),
                                        )
                                    )
                        except Exception:
                            continue
            except Exception:
                continue
        return findings

    # ------------------------------------------------------------------ #
    # IDE hooks
    # ------------------------------------------------------------------ #

    def check_ide_hooks(self, project_dir: str) -> List[Any]:
        """Delegate IDE-hook checks to the signature matcher."""
        try:
            return [self._mk(**h) for h in self.matcher.match_ide_hooks(project_dir)]
        except Exception:
            return []

    @staticmethod
    def _mk(**kwargs: Any) -> Any:
        # Lazy import avoids a circular dependency with engine.py.
        from npm_shield.engine import Finding  # noqa: PLC0415

        return Finding(**kwargs)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."
