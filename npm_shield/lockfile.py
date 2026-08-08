"""Lockfile parsers for npm (v1/v2/v3), yarn (v1 classic) and pnpm.

Every parser returns an empty dict on failure — they never raise.
Output shape: ``{package_name: installed_version}``.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("npm_shield.lockfile")

#: name@version with optional scope, e.g. ``keyv@6.0.0`` / ``@babel/code-frame@^7.0.0``
_NAME_VERSION_RE = re.compile(r"^(@?[^\s]+)@([^@\s]+)$")

_PACKAGE_LOCK_NAMES = ("package-lock.json", "npm-shrinkwrap.json")

#: Hard cap on how much of a lockfile is read at once. Files larger than
#: this skip the JSON parse entirely and go straight to the streaming
#: regex fallback (reading only the tail), preventing memory exhaustion
#: from adversarial or absurdly large "lockfiles".
_MAX_LOCKFILE_READ = 50 * 1024 * 1024  # 50 MB


def _parse_package_lock_streaming(path: str) -> Dict[str, str]:
    """Streaming JSON parser for lockfiles > 50MB.

    Uses ``ijson`` (optional dependency) to parse the ``"packages"``
    table incrementally without loading the whole file into memory.
    This catches poisoned entries in the *middle* of large lockfiles
    that the head+tail regex fallback would miss.

    Falls back silently — raises ``Exception`` if ijson is unavailable
    or parsing fails, so the caller can degrade to head+tail regex.
    """
    import ijson  # optional dep — only imported when needed
    out: Dict[str, str] = {}
    with open(path, "rb") as fh:
        # Stream key-value pairs from the "packages" table incrementally.
        for key, entry in ijson.kvitems(fh, "packages"):
            if not isinstance(entry, dict) or "version" not in entry:
                continue
            name = key[len("node_modules/"):] if key.startswith("node_modules/") else key
            # Nested deps: "lodash/node_modules/keyv" → "keyv" (rsplit is a
            # no-op for top-level names).
            name = name.rsplit("/node_modules/", 1)[-1]
            version = str(entry["version"])
            if version.startswith("npm:"):
                aliased = _resolve_alias(version)
                if aliased:
                    out.setdefault(aliased[0], aliased[1] or "unknown")
            else:
                out.setdefault(name, version)
    return out


def detect_lockfile_type(path: str) -> Optional[str]:
    """Return 'package-lock' | 'yarn' | 'pnpm' | None (driven by filename,
    with a content sniff as fallback)."""
    try:
        name = Path(path).name.lower()
        if name in _PACKAGE_LOCK_NAMES:
            return "package-lock"
        if name == "yarn.lock":
            return "yarn"
        if name == "pnpm-lock.yaml":
            return "pnpm"
        # content-based fallback for oddly-named files. Only trust a JSON
        # blob as a lockfile when it carries lockfile evidence — requiring
        # "lockfileVersion"/"packages"/"dependencies" keys. Without this
        # gate, ANY file starting with "{" (package.json, config.json, …)
        # would be mis-detected as package-lock and produce false
        # positives/confusing scans.
        try:
            head = Path(path).read_text(encoding="utf-8", errors="ignore")[:4096]
        except Exception:
            head = ""
        stripped = head.lstrip()
        if not stripped:
            return None
        if stripped.startswith("{"):
            for evidence in ("lockfileVersion", '"packages"', '"dependencies"'):
                if evidence in head:
                    return "package-lock"
            return None
        if "yarn lockfile" in head:
            return "yarn"
        if "lockfileVersion:" in head:
            return "pnpm"
        return None
    except Exception:
        return None


def parse_lockfile(path: str) -> Dict[str, str]:
    """Dispatch on the detected lockfile type. Never raises."""
    try:
        lf_type = detect_lockfile_type(path)
        if lf_type == "package-lock":
            return parse_package_lock(path)
        if lf_type == "yarn":
            return parse_yarn_lock(path)
        if lf_type == "pnpm":
            return parse_pnpm_lock(path)
    except Exception:
        pass
    return {}


def parse_package_lock(path: str) -> Dict[str, str]:
    """Parse an npm package-lock.json — routes to v1/v3 logic by shape.

    Robust path: the raw file is JSON. If it's malformed (truncated,
    corrupted, 10MB+ with injected junk), we fall back to a streaming
    regex extractor that still recovers every ``name@version`` pair we
    can — so a single poisoned lockfile line is never silently missed.

    A hard 50 MB cap prevents memory exhaustion on absurdly large or
    adversarial files (a 2 GB "lockfile" would otherwise be read whole).

    For files exceeding the cap, we scan the **head and tail** (each up
    to the cap size) so poisoned entries at either end are still caught
    without reading the full file into memory.
    """
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError:
        return {}
    if size > _MAX_LOCKFILE_READ:
        # Too large for a single JSON parse — use ijson streaming parser
        # if available, otherwise fall back to head+tail regex extraction.
        try:
            return _parse_package_lock_streaming(path)
        except Exception:
            pass
        # Streaming parser unavailable or failed: head+tail can miss
        # poisoned entries injected in the middle of the file. Tell the
        # user explicitly — silent partial scans are how malware slips
        # through.
        print(
            "Warning: lockfile is too large for a full scan "
            f"({size // (1024 * 1024)} MB > {_MAX_LOCKFILE_READ // (1024 * 1024)} MB). "
            "Malware in the middle may be missed. Install ijson for full "
            "streaming coverage: pip install ijson",
            file=sys.stderr,
        )
        with p.open("r", encoding="utf-8", errors="ignore") as fh:
            head = fh.read(_MAX_LOCKFILE_READ // 2)
            fh.seek(0)
            fh.seek(max(0, size - _MAX_LOCKFILE_READ // 2))
            tail = fh.read(_MAX_LOCKFILE_READ // 2)
        combined = head + "\n" + tail
        return _packages_to_out(_extract_lock_packages_fallback(combined))
    text = p.read_text(encoding="utf-8", errors="ignore")
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Corrupted / truncated lockfile — extract what we still can.
        doc = _extract_lock_packages_fallback(text)
    if not isinstance(doc, dict):
        return {}
    packages = doc.get("packages")
    if isinstance(packages, dict):
        return _parse_package_lock_flat(doc)
    deps = doc.get("dependencies")
    if isinstance(deps, dict):
        return _parse_package_lock_nested(doc)
    return {}


def parse_package_lock_v1(path: str) -> Dict[str, str]:
    """Parse an npm v1 lockfile (nested ``dependencies`` tree)."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8", errors="ignore"))
        if isinstance(doc, dict) and isinstance(doc.get("dependencies"), dict):
            return _parse_package_lock_nested(doc)
    except Exception:
        pass
    return {}


def parse_package_lock_v3(path: str) -> Dict[str, str]:
    """Parse an npm v2/v3 lockfile (flat ``packages`` map)."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8", errors="ignore"))
        if isinstance(doc, dict) and isinstance(doc.get("packages"), dict):
            return _parse_package_lock_flat(doc)
    except Exception:
        pass
    return {}


def _parse_package_lock_nested(doc: dict) -> Dict[str, str]:
    out: Dict[str, str] = {}

    def walk(deps: dict) -> None:
        for name, entry in deps.items():
            if not isinstance(entry, dict):
                continue
            if "version" in entry:
                out.setdefault(name, str(entry["version"]))
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                walk(nested)

    walk(doc["dependencies"])
    return out


def _parse_package_lock_flat(doc: dict) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, entry in doc["packages"].items():
        if not key.startswith("node_modules/"):
            continue
        if not isinstance(entry, dict):
            continue
        # Handle npm alias entries: "version": "npm:real-package@6.0.0"
        # or "version": "npm:^6.0.0" or "version": "npm:real-package"
        # or "version": "npm:*" — resolve to real package name + version
        version_val = str(entry.get("version", "")) if "version" in entry else ""
        if version_val.startswith("npm:"):
            aliased = _resolve_alias(version_val)
            if aliased:
                out.setdefault(aliased[0], aliased[1] or "unknown")
            continue
        if "version" not in entry:
            continue
        name = key[len("node_modules/"):]
        # Nested deps: "lodash/node_modules/keyv" → "keyv". rsplit is safe
        # for top-level too ("keyv" has no "/node_modules/" → unchanged).
        name = name.rsplit("/node_modules/", 1)[-1]
        out.setdefault(name, str(entry["version"]))
    return out


def _resolve_alias(version: str) -> Optional[tuple]:
    """Resolve npm alias specifier to (package_name, version).

    Handles all npm alias forms:
    - ``"npm:keyv@6.0.0"`` → ``("keyv", "6.0.0")``
    - ``"npm:^6.0.0"`` → ``(None, "^6.0.0")`` (no name — bare version, skip)
    - ``"npm:keyv"`` → ``("keyv", None)`` (bare package, no version)
    - ``"npm:*"`` → ``(None, None)`` (wildcard, skip)
    - ``"npm:keyv@*`` → ``("keyv", "*")``

    Return ``None`` for cases that don't resolve to a checkable package
    (e.g. ``npm:^6.0.0`` with no name prefix, or ``npm:*``).
    """
    if not version.startswith("npm:"):
        return None
    spec = version[4:]  # strip "npm:"
    if not spec or spec == "*":
        return None
    # Version-only spec like "npm:^6.0.0" — starts with a version specifier
    if spec[0] in "^~>=<":
        return None  # version-only alias, no package name to check
    at = spec.rfind("@")
    if at > 0:
        name = spec[:at]
        ver = spec[at + 1:]
        # If the "name" part starts with a version specifier character (^~>=<), 
        # it's actually a version-only alias like "npm:^6.0.0"
        if name and name[0] in "^~>=<":
            return None  # version-only alias, no package name to check
        return (name, ver) if name else None
    # No '@' — bare package name without version (e.g. "npm:keyv")
    return (spec, None)


def _packages_to_out(doc: dict) -> Dict[str, str]:
    """Convert a {name: {"version": x}} dict (from fallback extraction)
    into {name: version}."""
    out: Dict[str, str] = {}
    packages = doc.get("packages") if isinstance(doc, dict) else None
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if not key.startswith("node_modules/"):
                continue
            if isinstance(entry, dict) and "version" in entry:
                name = key[len("node_modules/"):]
                # Nested deps: "lodash/node_modules/keyv" → "keyv" (rsplit
                # is a no-op for top-level "keyv").
                name = name.rsplit("/node_modules/", 1)[-1]
                version = str(entry["version"])
                if version.startswith("npm:"):
                    aliased = _resolve_alias(version)
                    if aliased:
                        out.setdefault(aliased[0], aliased[1] or "unknown")
                    continue
                out.setdefault(name, version)
    return out


def _extract_lock_packages_fallback(text: str) -> Dict[str, Dict[str, str]]:
    """Streaming regex extraction for malformed/truncated lockfiles.

    When JSON parsing fails (corruption, 10MB+ injected content), pull
    every ``node_modules/<pkg>`` → ``"version": "<ver>"`` pair from the
    raw text without loading the whole file into a JSON parse tree.

    Uses chunk-based matching: text is split on ``"node_modules/"``
    boundaries so nested objects before ``"version"`` don't cause
    premature ``}`` matches that drop entries — fixing the old
    ``[^}]*?`` regex limitation.

    Returns ``{"packages": {"node_modules/keyv": {"version": "6.0.0"}, ...}}``
    so it's compatible with _parse_package_lock_flat.
    """
    out: Dict[str, Dict[str, str]] = {}
    # Find each "node_modules/<name>" entry and track brace depth to
    # extract the entry-level "version" — skipping nested objects like
    # "dependencies": {"sub": {"version": "1.0.0"}} that would confuse a
    # naive first-match approach.
    chunk_re = re.compile(r'"node_modules/(@[A-Za-z0-9_\-\.\/]+|[A-Za-z0-9_\-\.]+)"\s*:\s*\{')
    ver_re = re.compile(r'"version"\s*:\s*"([^"]+)"')
    positions = list(chunk_re.finditer(text))
    for i, m in enumerate(positions):
        full_key = f"node_modules/{m.group(1)}"
        start = m.end()  # position after the opening brace
        # Chunk extends to the next node_modules entry (or end of text)
        end = positions[i + 1].start() if i + 1 < len(positions) else len(text)
        chunk = text[start:end]
        # Only match "version" at entry level (depth 0): braces from this
        # entry's opening "{" must be balanced before "version", so we don't
        # match a nested "dependencies": {"sub": {"version": "x"}}.
        for vm in ver_re.finditer(chunk):
            prefix = chunk[:vm.start()]
            if prefix.count("{") == prefix.count("}"):
                out[full_key] = {"version": vm.group(1)}
                break
    return {"packages": out}


def parse_yarn_lock(path: str) -> Dict[str, str]:
    """Parse a yarn v1 classic lockfile. Yarn berry lockfiles yield {}."""
    result: Dict[str, str] = {}
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
        if "__metadata:" in text[:2000]:
            return result  # yarn berry format — out of scope

        current_specs: List[str] = []
        resolved: Optional[str] = None
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.endswith(":") and "@" in stripped:
                _record_block(result, current_specs, resolved)
                current_specs = _extract_specs(stripped)
                resolved = None
                continue
            if current_specs and stripped.startswith("version "):
                resolved = stripped[len("version "):].strip().strip('"')
        _record_block(result, current_specs, resolved)
    except Exception:
        pass
    return result


def _extract_specs(header: str) -> List[str]:
    """Extract spec strings from a yarn header, quoted or not."""
    line = header.rstrip(":").strip()
    if line.startswith('"'):
        return re.findall(r'"([^"]+)"', line)
    return [s.strip() for s in line.split(",") if s.strip()]


def _record_block(
    result: Dict[str, str], specs: List[str], resolved: Optional[str]
) -> None:
    if not specs:
        return
    for spec in specs:
        m = _NAME_VERSION_RE.match(spec)
        if not m:
            continue
        name = m.group(1)
        ver = resolved or _clean_version(m.group(2))
        if ver:
            result.setdefault(name, ver)


def parse_pnpm_lock(path: str) -> Dict[str, str]:
    """Parse a pnpm-lock.yaml. Prefers PyYAML, falls back to a line parser."""
    try:
        yaml_mod = _import_yaml()
        if yaml_mod is not None:
            return _parse_pnpm_yaml(path, yaml_mod)
    except Exception:
        pass
    return _parse_pnpm_fallback(path)


def _import_yaml():
    try:
        import yaml  # type: ignore

        return yaml
    except Exception:
        return None


def _parse_pnpm_yaml(path: str, yaml_mod) -> Dict[str, str]:
    result: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            doc = yaml_mod.safe_load(fh)
        if not isinstance(doc, dict):
            return result
        # pnpm v9 uses "snapshots:" instead of "packages:" — parse both
        for section in ("packages", "snapshots"):
            packages = doc.get(section, {})
            if isinstance(packages, dict):
                for key in packages:
                    name, ver = _split_pnpm_key(key)
                    if name and ver:
                        result.setdefault(name, ver)
    except Exception:
        pass
    return result


def _parse_pnpm_fallback(path: str) -> Dict[str, str]:
    """Minimal line-based parser for pnpm-lock.yaml (no PyYAML needed)."""
    result: Dict[str, str] = {}
    try:
        in_packages = False
        for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            indent = len(line) - len(line.lstrip())
            if indent == 0 and stripped.endswith(":"):
                in_packages = stripped.rstrip(":").strip() in ("packages", "snapshots")
                continue
            if in_packages and indent == 2 and stripped.endswith(":"):
                name, ver = _split_pnpm_key(stripped.rstrip(":"))
                if name and ver:
                    result.setdefault(name, ver)
    except Exception as exc:
        # Visibility: log why we fell back empty — corrupted/undecodable
        # pnpm lockfiles otherwise look "clean" with zero explanation.
        logger.debug("pnpm fallback parse failed for %s: %s", path, exc)
    return result


def _split_pnpm_key(key: str):
    """Split a pnpm package key like '/keyv@6.0.0' -> ('keyv', '6.0.0').

    Scoped names are preserved by splitting on the LAST '@' that comes
    *before* any peer-dep annotation.

    pnpm v6/v9: strip peer dependency annotations, e.g.
    ``keyv@6.0.0(typescript@5.5.0)`` -> ``keyv@6.0.0`` -> ('keyv', '6.0.0').
    Also handles v9 format ``/keyv@6.0.0:`` (trailing colon).
    """
    key = key.lstrip("/")
    # Strip trailing colon (pnpm v9: '/keyv@6.0.0:')
    if key.endswith(":"):
        key = key[:-1]
    # Strip peer-dependency annotations BEFORE splitting on '@'
    # so the last '@' inside '(typescript@5)' isn't picked as the
    # name/version separator.
    if "(" in key:
        key = key[: key.index("(")]
    idx = key.rfind("@")
    if idx <= 0:
        return None, None
    name, ver = key[:idx], key[idx + 1:]
    if not name or not ver:
        return None, None
    return name, ver


def _clean_version(version: str) -> str:
    v = version.strip()
    for prefix in ("^", "~", "=", ">=", "<=", ">", "<"):
        if v.startswith(prefix):
            v = v[len(prefix):]
    return v
