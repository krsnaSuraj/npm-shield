"""npm-shield command line interface.

Usage::

    npm-shield scan [PATH] [options]     scan a project dir or lockfile
    npm-shield system [options]          system persistence + process scan
    npm-shield feed-update               update the threat feed
    npm-shield version                   print version
    python -m npm_shield scan ./project  same via module invocation

Exit codes:
    0 = clean (no findings)
    1 = affected (findings detected)
    2 = error (bad usage, missing path, engine unavailable, ...
)
"""
from __future__ import annotations

import logging

logger = logging.getLogger("npm_shield")

import argparse
import importlib
import os
import sys
from typing import Any, List, Optional, Sequence

try:
    from npm_shield import __version__ as VERSION  # type: ignore
except Exception:  # pragma: no cover - __init__ may be missing during dev
    VERSION = "0.1.0"

PROG = "npm-shield"


def _add_common_flags(parser: argparse.ArgumentParser) -> None:
    """Flags shared by every subcommand (usable before or after it)."""
    parser.add_argument("--json", action="store_true", help="output machine-readable JSON")
    parser.add_argument(
        "--html",
        action="store_true",
        help="write an HTML report to ./npm-shield-report.html (use --output to override)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="output file path for --html report (default: ./npm-shield-report.html)",
    )
    parser.add_argument(
        "--lang",
        choices=("en", "hi"),
        default="en",
        help="output language: en (English, default) or hi (Hinglish)",
    )
    parser.add_argument(
        "--no-colors",
        action="store_true",
        help="plain output without ANSI colors",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=4,
        metavar="N",
        help="number of worker threads (default: 4)",
    )
    parser.add_argument(
        "--ignore-scripts-check",
        action="store_true",
        help="skip the npm ignore-scripts safety check",
    )
    parser.add_argument(
        "--sarif",
        action="store_true",
        help="output SARIF format for GitHub Code Scanning (implies --json)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            f"npm-shield v{VERSION} — detects the Shai-Hulud npm worm (Chaindrop) "
            "in projects, lockfiles and systems."
        ),
        epilog="Exit codes: 0 = clean, 1 = affected, 2 = error",
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {VERSION}")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_scan = sub.add_parser(
        "scan",
        help="scan a project directory or lockfile (default: current directory)",
    )
    p_scan.add_argument(
        "path",
        nargs="?",
        default=".",
        help="project directory or lockfile to scan (default: .)",
    )
    _add_common_flags(p_scan)

    p_sys = sub.add_parser(
        "system",
        help="full system persistence + process scan (no path needed)",
    )
    _add_common_flags(p_sys)

    p_feed = sub.add_parser("feed-update", help="update the threat feed")
    _add_common_flags(p_feed)

    p_ver = sub.add_parser("version", help="print the npm-shield version")
    _add_common_flags(p_ver)

    _add_common_flags(parser)
    return parser


# ----------------------------------------------------------------------
# Command implementations
# ----------------------------------------------------------------------
def _build_scanner(scanner_cls: Any, args: argparse.Namespace) -> Any:
    """Instantiate the engine Scanner, tolerating engines without extras."""
    kwargs: dict = {}
    threads = getattr(args, "threads", 4)
    if threads not in (None, 1):
        kwargs["threads"] = threads
    if getattr(args, "ignore_scripts_check", False):
        kwargs["ignore_scripts_check"] = True
    try:
        return scanner_cls(**kwargs)
    except TypeError:
        # engine does not accept these kwargs — fall back to defaults
        return scanner_cls()


def _emit(result: Any, args: argparse.Namespace) -> int:
    """Render the result per output flags; returns the process exit code."""
    from npm_shield.reporter import Reporter

    lang = getattr(args, "lang", "en")
    colors = not getattr(args, "no_colors", False)
    # Windows: keep ANSI codes only for a real console — redirected
    # output (files/pipes) would otherwise be polluted with raw ESC
    # bytes. POSIX keeps colored-by-default behavior (see --no-colors).
    if sys.platform == "win32":
        try:
            colors = colors and bool(sys.stdout.isatty())
        except Exception:
            colors = False
    reporter = Reporter(lang=lang, colors=colors)

    if getattr(args, "sarif", False):
        print(reporter.format_sarif(result))
    elif getattr(args, "json", False):
        print(reporter.format_json(result))
    elif getattr(args, "html", False):
        out_path = getattr(args, "output", None) or os.path.join(
            os.getcwd(), "npm-shield-report.html"
        )
        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(reporter.format_html(result, lang=lang))
        except OSError as exc:
            print(f"error: could not write HTML report: {exc}", file=sys.stderr)
            return 2
        print(f"HTML report written to {out_path}")
    else:
        print(reporter.format_terminal(result, lang=lang))

    return 1 if Reporter.get_findings(result) else 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """``scan`` — scan a project directory or lockfile."""
    try:
        from npm_shield.engine import Scanner  # lazy: engine may not exist yet
    except Exception as exc:
        print(f"error: scanning engine unavailable: {exc}", file=sys.stderr)
        print("hint: is npm_shield.engine installed/importable?", file=sys.stderr)
        return 2

    threads = getattr(args, "threads", 4)
    if threads is not None and threads < 1:
        print("error: --threads must be >= 1", file=sys.stderr)
        return 2

    path = os.path.abspath(os.path.expanduser(getattr(args, "path", ".") or "."))
    if not os.path.exists(path):
        print(f"error: path not found: {path}", file=sys.stderr)
        return 2

    scanner = _build_scanner(Scanner, args)
    result = scanner.scan(path)
    return _emit(result, args)


def _cmd_system(args: argparse.Namespace) -> int:
    """``system`` — persistence, credential-audit and process checks."""
    from npm_shield.reporter import Reporter

    findings: List[Any] = []

    # Each engine module is optional: if missing or broken, warn and
    # continue. Methods are the *documented* entry points — no getattr
    # guessing loops (an anti-pattern that fails silently when a class
    # changes its method names).
    modules = (
        ("npm_shield.persistence", "PersistenceHunter", "hunt"),
        ("npm_shield.audit", "CredentialAudit", "run_all"),
    )
    for mod_name, cls_name, method_name in modules:
        try:
            module = importlib.import_module(mod_name)
            cls = getattr(module, cls_name)
            obj = cls()
            method = getattr(obj, method_name, None)
            if not callable(method):
                print(
                    f"warning: {cls_name}.{method_name} not callable; continuing",
                    file=sys.stderr,
                )
                continue
            res = method()
        except Exception as exc:
            print(f"warning: {mod_name} unavailable ({exc}); continuing", file=sys.stderr)
            continue
        if isinstance(res, (list, tuple)):
            findings.extend(res)
        elif res is not None:
            findings.append(res)

    class _SystemResult:
        """Duck-typed ScanResult for system-wide scans."""

        def __init__(self, findings_list: List[Any]) -> None:
            self.findings = findings_list
            self.packages_checked = 0
            self.path = "system"

    return _emit(_SystemResult(findings), args)


def _cmd_feed_update(args: argparse.Namespace) -> int:  # noqa: ARG001
    """``feed-update`` — refresh the threat feed."""
    try:
        from npm_shield.feed import ThreatFeed
    except Exception as exc:
        print(f"error: threat feed unavailable: {exc}", file=sys.stderr)
        return 2

    feed = ThreatFeed()
    try:
        updated = feed.update()
    except TypeError:
        updated = None
    except Exception as exc:
        print(f"error: feed update failed: {exc}", file=sys.stderr)
        return 2

    extra = ""
    if isinstance(updated, dict):
        count = updated.get("packages") or updated.get("count") or updated.get("total")
        if count is not None:
            extra = f" ({count} packages)"
    print(f"Threat feed updated{extra}")
    return 0


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def _safe_stdout() -> None:
    """Make stdout resilient to non-UTF-8 locales (e.g. Windows cp1252
    pipes) so emoji/box-drawing output never crashes with a
    UnicodeEncodeError. No-op when stdout cannot be reconfigured."""
    try:
        reconfigure = getattr(sys.stdout, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _enable_vt() -> None:
    """Enable ANSI VT processing on Windows 10+ consoles so colors render.

    No-op on POSIX and on legacy Windows terminals (which then need
    ``--no-colors``). Never raises.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(
                handle, mode.value | 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            )
    except Exception:
        pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point. Returns exit code (0 clean / 1 affected / 2 error)."""
    _safe_stdout()
    _enable_vt()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    try:
        if args.command == "version":
            print(f"{PROG} {VERSION}")
            return 0
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "system":
            return _cmd_system(args)
        if args.command == "feed-update":
            return _cmd_feed_update(args)
        parser.error(f"unknown command: {args.command}")
        return 2  # unreachable
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 2
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - defensive CLI, never traceback
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
