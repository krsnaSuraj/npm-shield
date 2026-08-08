"""Detection orchestrator for npm-shield.

The :class:`Scanner` takes a scan target (a project directory or a lockfile),
runs every detection stage (lockfile version checks, node_modules walk,
package.json pattern checks, IDE hooks) and produces a :class:`ScanResult`
with findings, a weighted risk score, an optional error and a summary.

Security note: all ``os.walk`` calls use ``followlinks=False`` to prevent
symlink-traversal attacks (e.g. ``node_modules/evil -> ../../secrets``).
"""
from __future__ import annotations

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from npm_shield import lockfile as lockfile_mod
from npm_shield.signatures import SEVERITY_WEIGHTS, SignatureMatcher

MAX_WORKERS = min(32, (os.cpu_count() or 4) + 4)
MAX_RISK_SCORE = 100.0
logger = logging.getLogger("npm_shield")

_LOCKFILE_NAMES = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
)

_SKIP_DIRS = {".git", ".hg", ".svn"}

#: Script extensions content-scanned at the project root (renamed variants).
_SCRIPT_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx"}


class Finding:
    """A single detection result.

    Positional constructor: ``Finding(rule_id, severity, message)``.
    Accepts any keyword; ``description=`` is an alias for ``message=``;
    unknown keywords are absorbed as attributes so the hunter/audit
    keyword style (category/fix/detail/...) never breaks.
    """

    _FIELDS = (
        "rule_id",
        "severity",
        "message",
        "category",
        "package",
        "version",
        "file_path",
        "fix",
        "detail",
        "pattern",
        "sha256",
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.rule_id = ""
        self.severity = "info"  # info | low | medium | high | critical
        self.message = ""
        self.category = ""
        self.package = ""
        self.version = ""
        self.file_path = ""
        self.fix = ""
        self.detail = ""
        self.pattern = ""
        self.sha256 = ""

        positional = ("rule_id", "severity", "message")
        for i, val in enumerate(args):
            if i < len(positional):
                setattr(self, positional[i], val)

        if "description" in kwargs:
            kwargs.setdefault("message", kwargs.pop("description"))
        for key, val in kwargs.items():
            setattr(self, key, val)

    @property
    def description(self) -> str:
        """Alias for ``message`` (some consumers read ``description``)."""
        return self.message

    def to_dict(self) -> Dict[str, Any]:
        """JSON-friendly dict of every known field plus any extras."""
        out: Dict[str, Any] = {
            name: getattr(self, name, "") for name in self._FIELDS
        }
        for key in vars(self):
            if key not in self._FIELDS:
                out[key] = getattr(self, key)
        return out


@dataclass
class ScanResult:
    """Aggregate result of a scan.

    Accepts ``ScanResult(findings, risk_score)`` positionally and
    ``ScanResult(findings=..., path=..., risk_score=..., ...)`` by keyword.
    """

    findings: List[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    error: Optional[str] = None
    summary: Dict[str, Any] = field(default_factory=dict)
    path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """JSON-friendly dict of the whole result."""
        return {
            "path": self.path or self.summary.get("target", ""),
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "error": self.error,
            "summary": self.summary,
        }


def compute_risk_score(findings: List[Finding]) -> float:
    """Weighted risk score: critical=40, high=20, medium=8, low=3, info=1.

    One critical finding = 40 (urgent, stop-the-line). Capped at 100
    so 3 critical findings max out the scale. Unknown severities are
    ignored (weight 0).
    """
    total = 0.0
    for f in findings or []:
        total += SEVERITY_WEIGHTS.get(f.severity, 0.0)
    return round(min(total, MAX_RISK_SCORE), 1)


class Scanner:
    """Full detection orchestrator for a project directory or lockfile."""

    def __init__(
        self,
        target: Union[str, Path, None] = None,
        threads: Optional[int] = None,
        ignore_scripts_check: bool = False,
    ) -> None:
        self.target = Path(target) if target else Path.cwd()
        self.matcher = SignatureMatcher()
        self.ignore_scripts_check = bool(ignore_scripts_check)
        self._max_workers = threads if threads and threads > 0 else MAX_WORKERS

    # ------------------------------------------------------------------ #
    # Entry points
    # ------------------------------------------------------------------ #

    def scan(self, target: Union[str, Path, None] = None) -> ScanResult:
        """Scan a project dir, a lockfile, or a single artifact file."""
        t = Path(target) if target else self.target
        if not t.exists():
            return ScanResult(
                findings=[], risk_score=0.0,
                error="path does not exist: %s" % t,
                summary={"target": str(t)},
                path=str(t),
            )
        if t.is_dir():
            return self.scan_project(t)
        # Single file: lockfile or artifact?
        if lockfile_mod.detect_lockfile_type(t):
            return self.scan_lockfile(t)
        hit = self.matcher.match_file(t)
        findings = [self._to_finding(hit)] if hit else []
        risk = compute_risk_score(findings)
        summary = self._build_summary(
            findings, risk, "file", target=str(t), packages_checked=0
        )
        return ScanResult(findings=findings, risk_score=risk, summary=summary, path=str(t))

    def scan_project(self, project_dir: Union[str, Path]) -> ScanResult:
        """Full scan: lockfiles + node_modules + package.json files + IDE hooks."""
        findings: List[Finding] = []
        base = Path(project_dir)
        packages_checked = 0
        files_scanned = 0

        if not base.is_dir():
            return ScanResult(
                findings=[],
                risk_score=0.0,
                error="not a directory: %s" % base,
                summary={"target": str(base)},
                path=str(base),
            )

        # 1) Lockfiles in the project root
        for name in _LOCKFILE_NAMES:
            lf = base / name
            if lf.is_file():
                result = self.scan_lockfile(lf)
                findings.extend(result.findings)
                packages_checked += result.summary.get("packages_checked", 0)

        # 2) node_modules tree
        nm = base / "node_modules"
        if nm.is_dir():
            sub_findings, nm_pkgs, nm_files = self.scan_node_modules(nm)
            findings.extend(sub_findings)
            packages_checked += nm_pkgs
            files_scanned += nm_files

        # 3) package.json files outside node_modules
        for pkg_json in _walk_package_jsons(base):
            files_scanned += 1
            findings.extend(self._scan_package_json_file(pkg_json))

        # 4) suspicious artifact files outside node_modules (signal names)
        for artifact in _walk_signal_files(base, self.matcher):
            files_scanned += 1
            hit = self.matcher.match_file(artifact)
            if hit:
                findings.append(self._to_finding(hit))
            else:
                # Unknown/renamed variant: check embedded campaign strings.
                findings.extend(
                    f
                    for f in (
                        self._to_finding(h)
                        for h in self.matcher.match_content_markers(artifact)
                    )
                    if f
                )

        # 4b) root-level JS variants (renamed droppers/harvesters). A renamed
        # stage-2 payload often lands at the project root with an innocuous
        # name (e.g. util.js) — neither a signal name nor a workflow file.
        # Content-scan top-level script files so those variants are caught
        # without paying for a full-tree walk on large repos.
        for artifact in _walk_root_script_files(base):
            files_scanned += 1
            findings.extend(
                f
                for f in (
                    self._to_finding(h)
                    for h in self.matcher.match_content_markers(artifact)
                )
                if f
            )

        # 5) IDE hooks (.claude/settings.json, .vscode/tasks.json)
        for hit in self.matcher.match_ide_hooks(base):
            findings.append(self._to_finding(hit))

        # 6) GitHub Actions workflows with campaign content markers
        for wf in _walk_workflow_files(base):
            files_scanned += 1
            findings.extend(
                f
                for f in (
                    self._to_finding(h)
                    for h in self.matcher.match_content_markers(wf)
                )
                if f
            )

        # De-duplicate findings: the same file can legitimately trigger
        # multiple detection rules (e.g. both the token-relay content
        # marker and the exfil-endpoint marker in one file). Collapse by
        # (category, file_path, pattern) to avoid inflation while keeping
        # each distinct rule.
        seen: set = set()
        deduped: List[Finding] = []
        for f in findings:
            key = (f.category, f.file_path, f.pattern)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        findings = deduped

        risk = compute_risk_score(findings)
        summary = self._build_summary(
            findings,
            risk,
            "project",
            target=str(base),
            packages_checked=packages_checked,
            files_scanned=files_scanned,
            node_modules_present=nm.is_dir(),
        )
        return ScanResult(findings=findings, risk_score=risk, summary=summary, path=str(base))

    def scan_lockfile(self, path: Union[str, Path]) -> ScanResult:
        """Parse a lockfile and check every pinned package against the
        affected-packages list."""
        findings: List[Finding] = []
        p = Path(path)
        lf_type = lockfile_mod.detect_lockfile_type(p) or "unknown"
        packages: Dict[str, str] = lockfile_mod.parse_lockfile(p)

        for name, version in packages.items():
            hit = self.matcher.check_poisoned_package(name, version)
            if hit:
                hit["file_path"] = str(p)
                findings.append(self._to_finding(hit))

        risk = compute_risk_score(findings)
        summary = self._build_summary(
            findings,
            risk,
            "lockfile",
            target=str(p),
            lockfile_type=lf_type,
            packages_checked=len(packages),
        )
        return ScanResult(findings=findings, risk_score=risk, summary=summary, path=str(p))

    def scan_node_modules(
        self, node_modules_dir: Union[str, Path]
    ) -> Tuple[List[Finding], int, int]:
        """Walk a node_modules tree concurrently.

        Returns ``(findings, packages_checked, files_scanned)``. Checks every
        package.json for malicious install patterns and poisoned versions, and
        hash-checks every JS file (size-gated for speed).
        """
        findings: List[Finding] = []
        nm = Path(node_modules_dir)
        if not nm.is_dir():
            return findings, 0, 0

        candidates: List[Tuple[str, str]] = []
        try:
            for root, dirs, files in os.walk(str(nm), followlinks=False):
                dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
                if "package.json" in files:
                    candidates.append(("pkg", os.path.join(root, "package.json")))
                for fname in files:
                    low = fname.lower()
                    if (
                        low.endswith((".js", ".mjs", ".cjs"))
                        or self.matcher.is_signal_name(fname)
                    ):
                        candidates.append(("file", os.path.join(root, fname)))
        except Exception:
            pass

        if not candidates:
            return findings, 0, 0

        def _one(item: Tuple[str, str]) -> List[Finding]:
            kind, fpath = item
            if kind == "pkg":
                return self._scan_package_json_file(Path(fpath))
            hit = self.matcher.match_file(fpath)
            if hit:
                return [self._to_finding(hit)]
            # Unknown/renamed variant: embedded campaign strings (token
            # relay marker, Bun loader version, exfil endpoint).
            return [
                f
                for f in (
                    self._to_finding(h)
                    for h in self.matcher.match_content_markers(fpath)
                )
                if f
            ]

        with ThreadPoolExecutor(max_workers=self._max_workers) as ex:
            # Batch submission to prevent memory spike from thousands of
            # Future objects on massive monorepos — submit in chunks of
            # max_workers * 10, draining results between batches.
            batch_size = self._max_workers * 10
            for i in range(0, len(candidates), batch_size):
                batch = candidates[i : i + batch_size]
                futures = [ex.submit(_one, c) for c in batch]
                for fut in as_completed(futures):
                    try:
                        res = fut.result()
                    except Exception:
                        logger.debug("worker error: %s", exc_info=True)
                        continue
                    for f in res or []:
                        findings.append(f)

        packages_checked = sum(1 for kind, _ in candidates if kind == "pkg")
        files_scanned = sum(1 for kind, _ in candidates if kind == "file")
        return findings, packages_checked, files_scanned

    # ------------------------------------------------------------------ #
    # Scoring / summary
    # ------------------------------------------------------------------ #

    def compute_risk_score(self, findings: List[Finding]) -> float:
        """Instance-level wrapper around the module scoring function."""
        return compute_risk_score(findings)

    @staticmethod
    def _build_summary(
        findings: List[Finding],
        risk: float,
        scan_type: str,
        **extra: Any,
    ) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for f in findings or []:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary: Dict[str, Any] = {
            "scan_type": scan_type,
            "risk_score": risk,
            "total_findings": len(findings or []),
            "severity_counts": counts,
            "verdict": _verdict(risk, counts),
        }
        summary.update(extra)
        return summary

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _scan_package_json_file(self, pkg_json: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            content = pkg_json.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings

        for hit in self.matcher.match_package_json(content):
            hit["file_path"] = str(pkg_json)
            findings.append(self._to_finding(hit))

        try:
            doc = json.loads(content)
            name = doc.get("name")
            version = doc.get("version")
        except Exception:
            name, version = None, None

        if name:
            hit = self.matcher.check_poisoned_package(
                str(name), str(version) if version else None
            )
            if hit:
                hit["file_path"] = str(pkg_json)
                findings.append(self._to_finding(hit))

        # Resolve npm aliases in dependencies (e.g. "keyv": "npm:keyv@6.0.0")
        deps_hit = False
        for dep_key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = doc.get(dep_key) if isinstance(doc, dict) else None
            if not isinstance(deps, dict):
                continue
            for dep_name, dep_spec in deps.items():
                if not isinstance(dep_spec, str):
                    continue
                if dep_spec.startswith("npm:"):
                    spec = dep_spec[4:]  # strip "npm:"
                    at = spec.rfind("@")
                    if at > 0:
                        resolved_name = spec[:at]
                        resolved_ver = spec[at + 1:]
                        hit = self.matcher.check_poisoned_package(
                            resolved_name, resolved_ver
                        )
                        if hit and not deps_hit:
                            hit["file_path"] = str(pkg_json)
                            hit["detail"] = (
                                hit.get("detail", "")
                                + f" (via npm alias '{dep_name}: {dep_spec}')"
                            )
                            findings.append(self._to_finding(hit))
                            deps_hit = True

        return findings

    def _to_finding(self, hit: Optional[Dict[str, Any]]) -> Optional[Finding]:
        if hit is None:
            return None
        if isinstance(hit, Finding):
            return hit
        if isinstance(hit, dict):
            return Finding(
                rule_id=str(hit.get("rule_id", "") or ""),
                severity=str(hit.get("severity", "info") or "info"),
                message=str(
                    hit.get("message") or hit.get("description") or ""
                ),
                category=str(hit.get("category", "") or ""),
                package=str(hit.get("package", "") or ""),
                version=str(hit.get("version", "") or ""),
                file_path=str(hit.get("file_path", "") or ""),
                fix=str(hit.get("fix", "") or ""),
                detail=str(hit.get("detail", "") or ""),
                pattern=str(hit.get("pattern", "") or ""),
                sha256=str(hit.get("sha256", "") or ""),
            )
        return None


def _walk_package_jsons(base: Path) -> List[Path]:
    """All package.json files under ``base``, excluding node_modules/VCS dirs."""
    results: List[Path] = []
    try:
        for root, dirs, files in os.walk(str(base), followlinks=False):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and d != "node_modules"]
            if "package.json" in files:
                results.append(Path(root) / "package.json")
    except Exception:
        pass
    return results


def _walk_signal_files(base: Path, matcher: "SignatureMatcher") -> List[Path]:
    """Signal-named files under ``base``, excluding node_modules/VCS dirs.

    Delegates the name decision to ``matcher.is_signal_name`` so matching
    follows the same platform rules as ``match_file`` (case-insensitive on
    Windows/macOS filesystems, exact elsewhere).
    """
    results: List[Path] = []
    try:
        for root, dirs, files in os.walk(str(base), followlinks=False):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and d != "node_modules"]
            for fname in files:
                if matcher.is_signal_name(fname):
                    results.append(Path(root) / fname)
    except Exception:
        pass
    return results


def _walk_root_script_files(base: Path) -> List[Path]:
    """Top-level script files (``*.js``/``*.mjs``/``*.cjs``/``*.ts``)
    directly under ``base`` — the common landing spot for renamed
    droppers/harvesters.

    Only direct children are scanned (no recursive walk) so large repos
    stay fast; node_modules, VCS dirs and workflows are handled elsewhere.
    """
    results: List[Path] = []
    try:
        for child in base.iterdir():
            if not child.is_file():
                continue
            if child.suffix.lower() in _SCRIPT_SUFFIXES:
                results.append(child)
    except Exception:
        pass
    return results


def _walk_workflow_files(base: Path) -> List[Path]:
    """GitHub Actions workflow files (``.github/workflows/*.yml|yaml``)
    anywhere under ``base``.

    The worm's token-relay marker and pinned-Bun version strings appear in
    workflow files of its repos and planted packages, so these get a
    content-marker scan even though their names are not signals.
    """
    results: List[Path] = []
    try:
        for root, dirs, files in os.walk(str(base), followlinks=False):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            if os.path.basename(root).lower() != "workflows":
                continue
            if ".github" not in {p.lower() for p in Path(root).parts}:
                continue
            for fname in files:
                if fname.lower().endswith((".yml", ".yaml")):
                    results.append(Path(root) / fname)
    except Exception:
        pass
    return results


def _verdict(risk: float, counts: Dict[str, int]) -> str:
    if risk >= 50 or counts.get("critical", 0) > 0:
        return "COMPROMISED — immediate action required"
    if risk >= 20 or counts.get("high", 0) > 0:
        return "HIGH RISK — investigate immediately"
    if risk >= 5:
        return "ELEVATED RISK — review findings"
    if risk > 0:
        return "LOW RISK — minor hardening recommended"
    return "CLEAN — no Shai-Hulud indicators found"
