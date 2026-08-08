"""Output formatters for npm-shield scan results.

Renders :class:`ScanResult` objects (produced by :mod:`npm_shield.engine`)
as colorful terminal output, JSON, a shareable HTML report, or plain text.

This module deliberately does NOT import the engine at module scope. It
introspects result / finding attributes defensively, so it keeps working
regardless of the exact attribute names the engine uses and can be
imported even before the engine modules exist on disk.

Languages:
    * ``en`` — English (default).
    * ``hi`` — Hinglish: key status messages in a Hindi-English mix,
      technical terms kept in English (e.g. ``AFFECTED MILA!``).
"""

from __future__ import annotations

import html as _html
import json
import re as _re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

__all__ = ["Reporter", "SEVERITY_STYLES", "SEVERITY_ORDER", "VERSION"]

VERSION = "0.1.0"

RESET = "\033[0m"
BOLD = "\033[1m"

#: severity -> (ANSI color code, icon)
SEVERITY_STYLES: Dict[str, Dict[str, str]] = {
    "critical": {"color": "\033[91m", "icon": "🔴"},
    "high": {"color": "\033[31m", "icon": "⚠️"},
    "medium": {"color": "\033[93m", "icon": "🟡"},
    "low": {"color": "\033[94m", "icon": "🔵"},
    "info": {"color": "\033[92m", "icon": "ℹ️"},
}

SEVERITY_ORDER: Tuple[str, ...] = ("critical", "high", "medium", "low", "info")

#: key -> (english, hinglish) — technical terms stay English
_MESSAGES: Dict[str, Tuple[str, str]] = {
    "affected_found": ("AFFECTED FOUND!", "AFFECTED MILA!"),
    "clean": ("CLEAN", "CLEAN — SAB SAF"),
    "no_issues": ("No issues found", "Koi issue nahi mila"),
    "no_threats": ("No threats detected", "Koi threat nahi mila"),
    "scan": ("Scan", "Scan"),
    "packages_checked": ("packages checked", "packages checked"),
    "safe": ("safe", "safe"),
    "affected": ("affected", "affected"),
    "findings": ("Findings", "Findings"),
    "fix_suggestions": ("Fix suggestions", "Fix suggestions (kya karein)"),
    "path": ("path", "path"),
    "fix": ("fix", "fix"),
    "status": ("Status", "Status"),
    "scan_complete": ("Scan complete", "Scan ho gaya"),
    "new_findings": ("NEW FINDINGS DETECTED", "NAYE FINDINGS MILE"),
    "watching": ("Watching", "Nazar rakh rahe hain"),
    "stopped": ("Watcher stopped", "Watcher ruk gaya"),
}


def _msg(key: str, lang: str) -> str:
    pair = _MESSAGES.get(key, (key, key))
    return pair[1] if lang == "hi" else pair[0]


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences (for width measurement)."""
    try:
        return _re.sub(r"\033\[[0-9;]*m", "", str(text))
    except Exception:
        return str(text)


def _char_width(ch: str) -> int:
    """Approximate terminal cell width of a character (0/1/2)."""
    try:
        if unicodedata.combining(ch):
            return 0  # zero-width combining / variation selectors
        ea = unicodedata.east_asian_width(ch)
        if ea in ("W", "F"):
            return 2
        if ea == "A":
            o = ord(ch)
            # box drawing / block elements render 1-wide in most fonts
            if 0x2500 <= o <= 0x259F:
                return 1
            # common emoji ranges render 2-wide
            if 0x2100 <= o <= 0x27BF or 0x1F000 <= o <= 0x1FAFF:
                return 2
        return 1
    except Exception:
        return 1


def _disp_width(text: str) -> int:
    """Display width of text, ignoring ANSI codes and honoring wide chars."""
    return sum(_char_width(ch) for ch in _strip_ansi(text))


def _box(lines: List[str], title: str = "") -> List[str]:
    """Wrap lines in a unicode box with an optional title in the top edge."""
    title = title or f"npm-shield v{VERSION}"
    widths = [_disp_width(ln) for ln in lines]
    widths.append(_disp_width(title))
    width = max(widths) if widths else 0
    dashes = max(0, width - _disp_width(title) - 1)
    top = f"┌─ {title} {'─' * dashes}┐"
    middle = []
    for ln in lines:
        pad = max(0, width - _disp_width(ln))
        middle.append(f"│ {ln}{' ' * pad} │")
    bottom = f"└{'─' * (width + 2)}┘"
    return [top, *middle, bottom]


def _paint(colors: bool, text: str, style: str, bold: bool = False) -> str:
    """Colorize *text* with a severity style (or raw ANSI) unless disabled."""
    if not colors:
        return text
    color = SEVERITY_STYLES.get(style, {}).get("color", "")
    if not color and isinstance(style, str) and style.startswith("\033"):
        color = style
    prefix = (BOLD if bold else "") + color
    return f"{prefix}{text}{RESET}"


class Reporter:
    """Formats scan results for terminal / JSON / HTML / plain output.

    All formatting is defensive: unexpected attribute names, missing
    fields or malformed findings never raise — they degrade gracefully.
    """

    def __init__(self, lang: str = "en", colors: bool = True) -> None:
        self.lang = lang if lang in ("en", "hi") else "en"
        self.colors = bool(colors)

    # ------------------------------------------------------------------
    # Public introspection helpers (engine-agnostic)
    # ------------------------------------------------------------------
    @staticmethod
    def _pick(obj: Any, names: Sequence[str], default: Any = None) -> Any:
        """First non-None, non-callable attribute/dict-key among *names*."""
        for name in names:
            val = None
            try:
                if isinstance(obj, dict):
                    val = obj.get(name)
                else:
                    val = getattr(obj, name, None)
            except Exception:
                val = None
            if val is not None and not callable(val):
                return val
        return default

    @staticmethod
    def get_findings(result: Any) -> List[Any]:
        """Return the list of findings from a scan result (never crashes)."""
        if result is None:
            return []
        findings = None
        for name in ("findings", "results", "issues", "detections"):
            try:
                if isinstance(result, dict):
                    findings = result.get(name)
                else:
                    findings = getattr(result, name, None)
            except Exception:
                findings = None
            if findings is not None:
                break
        if findings is None:
            return []
        if isinstance(findings, dict):
            findings = list(findings.values())
        try:
            return [f for f in findings if f is not None]
        except Exception:
            return []

    @staticmethod
    def finding_severity(finding: Any) -> str:
        """Normalized severity label (one of SEVERITY_ORDER keys)."""
        val = Reporter._pick(finding, ("severity", "level", "priority"), "info")
        sev = str(val or "info").strip().lower()
        return sev if sev in SEVERITY_STYLES else "info"

    @staticmethod
    def finding_signature(finding: Any) -> str:
        """Stable key for a finding (used for change detection across rescans)."""
        sev = Reporter.finding_severity(finding)
        msg = str(Reporter._pick(finding, ("message", "description", "detail", "title"), ""))
        path = str(Reporter._pick(finding, ("path", "file_path", "location"), ""))
        pkg = str(Reporter._pick(finding, ("package", "package_name", "name"), ""))
        return f"{sev}|{pkg}|{path}|{msg}"

    def paint(self, text: str, style: str, bold: bool = False) -> str:
        """Public color helper that respects the ``colors`` flag."""
        return _paint(self.colors, text, style, bold)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _resolve_lang(self, lang: Optional[str]) -> str:
        if lang is None:
            return self.lang
        return lang if lang in ("en", "hi") else self.lang

    def _finding_dict(self, finding: Any) -> Dict[str, Any]:
        sev = self.finding_severity(finding)
        return {
            "severity": sev,
            "message": str(
                self._pick(finding, ("message", "description", "detail", "title"), "Unknown finding")
            ),
            "path": str(self._pick(finding, ("path", "file_path", "location", "target"), "")),
            "package": str(self._pick(finding, ("package", "package_name", "name"), "")),
            "version": str(self._pick(finding, ("version",), "")),
            "kind": str(self._pick(finding, ("kind", "finding_type", "category", "type"), "")),
            "fix": str(
                self._pick(finding, ("fix", "suggestion", "remediation", "recommended_action"), "")
            ),
        }

    def _summary(self, result: Any) -> Dict[str, Any]:
        findings = self.get_findings(result)

        packages = self._pick(result, ("packages_checked", "total_packages", "packages_scanned", "checked"), None)
        try:
            packages = int(packages) if packages is not None else 0
        except (TypeError, ValueError):
            packages = 0

        target = self._pick(result, ("path", "scanned_path", "target", "root"), "")

        affected = self._pick(result, ("affected_count", "infected_count", "vulnerable_count"), None)
        try:
            affected = int(affected) if affected is not None else 0
        except (TypeError, ValueError):
            affected = 0
        affected = max(affected, len(findings))
        safe = max(0, packages - affected) if packages else 0

        duration = self._pick(result, ("duration", "elapsed", "elapsed_seconds", "scan_duration"), None)
        try:
            duration = float(duration)
        except (TypeError, ValueError):
            duration = None

        counts: Dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
        for finding in findings:
            counts[self.finding_severity(finding)] += 1

        return {
            "findings": findings,
            "packages_checked": packages,
            "affected": affected,
            "safe": safe,
            "target": str(target or ""),
            "duration": duration,
            "severity_counts": counts,
        }

    def _collect_fixes(self, findings: Sequence[Any]) -> List[str]:
        fixes: List[str] = []
        seen: Set[str] = set()
        for finding in findings:
            fx = self._finding_dict(finding).get("fix", "")
            if fx and fx not in seen:
                seen.add(fx)
                fixes.append(fx)
        return fixes

    # ------------------------------------------------------------------
    # Public formatters
    # ------------------------------------------------------------------
    def format_terminal(self, result: Any, lang: Optional[str] = None) -> str:
        """Beautiful terminal output: header box, summary, findings, fixes.

        ``lang`` defaults to the reporter's configured language.
        """
        return self._render(result, self._resolve_lang(lang), colors=self.colors)

    def format_plain(self, result: Any, lang: Optional[str] = None) -> str:
        """Plain text output, same structure, no ANSI colors."""
        return self._render(result, self._resolve_lang(lang), colors=False)

    def format_json(self, result: Any) -> str:
        """Full machine-readable JSON dump of the scan result."""
        try:
            summary = self._summary(result)
            payload = {
                "tool": "npm-shield",
                "version": VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "target": summary["target"] or None,
                "summary": {
                    "packages_checked": summary["packages_checked"],
                    "safe": summary["safe"],
                    "affected": summary["affected"],
                    "duration_seconds": summary["duration"],
                },
                "severity_counts": summary["severity_counts"],
                "findings": [self._finding_dict(f) for f in summary["findings"]],
            }
            return json.dumps(payload, indent=2, ensure_ascii=False)
        except Exception:
            return json.dumps(
                {
                    "tool": "npm-shield",
                    "version": VERSION,
                    "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "error": "failed to serialize scan result",
                },
                indent=2,
            )

    def format_sarif(self, result: Any) -> str:
        """Output SARIF 2.1.0 for GitHub Code Scanning / VS Code."""
        import os
        from datetime import datetime, timezone

        findings = self.get_findings(result)
        tool_name = "npm-shield"
        version = VERSION
        base_path = os.getcwd()

        sarif_results: List[Dict[str, Any]] = []
        for finding in findings:
            d = self._finding_dict(finding)
            sev = d["severity"]
            sarif_severity = {
                "critical": 10,
                "high": 8,
                "medium": 5,
                "low": 2,
                "info": 1,
            }.get(sev, 1)

            location: Dict[str, Any] = {}
            if d["path"]:
                location = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": d["path"]},
                        "region": {"startLine": 1},
                    }
                }
            elif d["package"]:
                location = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"node_modules/{d['package']}"},
                    }
                }

            sarif_results.append({
                "ruleId": d["kind"] or "npm-shield-default",
                "level": "error" if sarif_severity >= 8 else "warning" if sarif_severity >= 3 else "note",
                "message": {"text": d["message"]},
                "locations": [location] if location else [],
                "properties": {
                    "sev": sev,
                    "package": d.get("package", ""),
                    "version": d.get("version", ""),
                },
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": version,
                    }
                },
                "results": sarif_results,
                "columnKind": "utf16CodeUnit",
            }],
            "generated": datetime.now(timezone.utc).isoformat(),
        }
        return json.dumps(sarif_doc, indent=2, ensure_ascii=False)

    def format_html(self, result: Any, lang: Optional[str] = None) -> str:
        """Minimal self-contained HTML report for sharing."""
        lang = self._resolve_lang(lang)
        esc = _html.escape
        try:
            summary = self._summary(result)
            affected = summary["affected"] > 0
            status = _msg("affected_found" if affected else "clean", lang)
            target = esc(summary["target"] or ".")
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if summary["packages_checked"] > 0:
                scan_info = (
                    f"{_msg('scan', lang)}: {summary['packages_checked']} "
                    f"{_msg('packages_checked', lang)}"
                )
            else:
                scan_info = f"{_msg('scan', lang)}: {target}"
            badge_color = "#b42318" if affected else "#067647"

            rows: List[str] = []
            for idx, finding in enumerate(summary["findings"], 1):
                d = self._finding_dict(finding)
                sev = d["severity"]
                target_cell = esc(d["package"] or d["path"] or "—")
                detail = esc(d["message"])
                if d["path"] and d["path"] != (d["package"] or ""):
                    detail += f"<br><code>{esc(d['path'])}</code>"
                fix = esc(d["fix"]) or "—"
                rows.append(
                    f'<tr class="{sev}-row">'
                    f"<td>{idx}</td>"
                    f'<td><span class="sev-{sev}">{esc(sev.upper())}</span></td>'
                    f"<td><code>{target_cell}</code></td>"
                    f"<td>{detail}</td>"
                    f"<td>{fix}</td>"
                    f"</tr>"
                )
            if rows:
                findings_section = (
                    f"<h2>{esc(_msg('findings', lang))}</h2>"
                    "<table><thead><tr>"
                    "<th>#</th><th>Severity</th><th>Target</th><th>Details</th><th>Fix</th>"
                    "</tr></thead><tbody>"
                    + "".join(rows)
                    + "</tbody></table>"
                )
            else:
                findings_section = (
                    f"<h2>{esc(_msg('findings', lang))}</h2>"
                    f"<p>✅ {esc(_msg('no_threats', lang))}</p>"
                )

            fixes = self._collect_fixes(summary["findings"])
            fixes_section = ""
            if fixes:
                items = "".join(f"<li>{esc(fx)}</li>" for fx in fixes)
                fixes_section = f"<h2>{esc(_msg('fix_suggestions', lang))}</h2><ul>{items}</ul>"

            counts = summary["severity_counts"]
            counts_line = " · ".join(
                f"{SEVERITY_STYLES[sev]['icon']} {counts[sev]} {sev.upper()}"
                for sev in SEVERITY_ORDER
                if counts[sev] > 0
            ) or "—"

            return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>npm-shield v{VERSION} — Scan Report</title>
<style>
body {{ font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1f2328; line-height: 1.5; }}
h1 {{ font-size: 1.6rem; }}
.summary {{ background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }}
.badge {{ display: inline-block; padding: .15em .6em; border-radius: 4px; color: #fff; font-size: .85rem; font-weight: 600; background: {badge_color}; }}
table {{ width: 100%; border-collapse: collapse; margin-top: .5rem; }}
th, td {{ text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; font-size: .92rem; }}
th {{ background: #f6f8fa; }}
code {{ background: #f0f1f3; padding: .1em .35em; border-radius: 4px; font-size: .88em; }}
.sev-critical {{ color: #b42318; font-weight: 600; }}
.sev-high {{ color: #d92d20; font-weight: 600; }}
.sev-medium {{ color: #b54708; font-weight: 600; }}
.sev-low {{ color: #175cd3; font-weight: 600; }}
.sev-info {{ color: #067647; font-weight: 600; }}
.critical-row {{ background: #fef3f2; }}
.high-row {{ background: #fff5ec; }}
.medium-row {{ background: #fffaeb; }}
footer {{ margin-top: 2rem; color: #667085; font-size: .8rem; }}
</style>
</head>
<body>
<h1>🛡️ npm-shield <span class="badge">v{VERSION}</span></h1>
<div class="summary">
<p><strong>{esc(status)}</strong> — {scan_info}</p>
<p>✅ {summary['safe']} {esc(_msg('safe', lang))} &nbsp; ⚠️ {summary['affected']} {esc(_msg('affected', lang))}</p>
<p>{counts_line}</p>
<p>target: {target} · generated: {now}</p>
</div>
{findings_section}
{fixes_section}
<footer>Generated by npm-shield v{VERSION} · Shai-Hulud worm (Chaindrop) detection</footer>
</body>
</html>
"""
        except Exception:
            # Expose the failure for debugging — HTML-escaped so a
            # malicious path/name in the traceback can never inject
            # markup (XSS-safe), and we never leak values, only code
            # locations and error text.
            import traceback

            tb = _html.escape(traceback.format_exc())
            return (
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
                f"<title>npm-shield v{VERSION}</title></head><body>"
                f"<h1>🛡️ npm-shield v{VERSION}</h1><p>Error generating report.</p>"
                f"<pre>{tb}</pre></body></html>"
            )

    # ------------------------------------------------------------------
    # Shared rendering core (terminal + plain)
    # ------------------------------------------------------------------
    def _render(self, result: Any, lang: str, colors: bool) -> str:
        summary = self._summary(result)
        lines: List[str] = []

        if summary["packages_checked"] > 0:
            scan_line = (
                f"{_msg('scan', lang)}: {summary['packages_checked']} {_msg('packages_checked', lang)}"
            )
            if summary["duration"] is not None:
                scan_line += f" ({summary['duration']:.2f}s)"
        else:
            scan_line = f"{_msg('scan', lang)}: {summary['target'] or 'system'}"

        safe_part = _paint(colors, f"✅ {summary['safe']} {_msg('safe', lang)}", "info")
        aff_part = _paint(colors, f"⚠️ {summary['affected']} {_msg('affected', lang)}", "critical")
        lines.extend(_box([scan_line, f"{safe_part}  {aff_part}"]))

        if summary["affected"] > 0:
            lines.append("")
            lines.append(_paint(colors, f"⚠️ {_msg('affected_found', lang)}", "critical", bold=True))
            counts_line = "  ".join(
                f"{SEVERITY_STYLES[sev]['icon']} {summary['severity_counts'][sev]} {sev.upper()}"
                for sev in SEVERITY_ORDER
                if summary["severity_counts"][sev] > 0
            )
            if counts_line:
                lines.append("")
                lines.append(counts_line)
            lines.append("")
            lines.append(_paint(colors, f"━━ {_msg('findings', lang)} ━━", "info", bold=True))
            for idx, finding in enumerate(summary["findings"], 1):
                d = self._finding_dict(finding)
                sev = d["severity"]
                target = d["path"] or d["package"] or "?"
                head = _paint(colors, f"{SEVERITY_STYLES[sev]['icon']} {sev.upper()}", sev, bold=True)
                lines.append(f"{idx:>3}. {head}  {target} — {d['message']}")
                if d["path"] and d["package"] and d["path"] != d["package"]:
                    lines.append(f"      {_msg('path', lang)}: {_paint(colors, d['path'], 'low')}")
                if d["version"] and not d["package"]:
                    lines.append(f"      version: {d['version']}")
                if d["kind"]:
                    lines.append(f"      type: {d['kind']}")
            fixes = self._collect_fixes(summary["findings"])
            if fixes:
                lines.append("")
                lines.append(_paint(colors, f"━━ {_msg('fix_suggestions', lang)} ━━", "info", bold=True))
                for fx in fixes:
                    lines.append(f"  • {fx}")
        else:
            lines.append("")
            lines.append(_paint(colors, f"✅ {_msg('clean', lang)}", "info", bold=True))
            lines.append(f"   {_msg('no_issues', lang)}")

        return "\n".join(lines)
