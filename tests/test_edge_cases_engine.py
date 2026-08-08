"""Edge-case tests for the detection engine (engine.py) and signature
matcher (signatures.py).

These tests probe robustness: empty trees, unicode names, symlink loops,
unreadable files, corrupt data, oversized files, odd Finding/ScanResult
shapes and boundary inputs. They use the *real* Scanner/SignatureMatcher
classes against throwaway trees under pytest's tmp_path — the real
data/ directory is never modified.
"""
import json
import os
import time
from pathlib import Path

import pytest

import npm_shield.signatures as sig_mod
from npm_shield.engine import Finding, ScanResult, Scanner
from npm_shield.signatures import SignatureMatcher

# ---------------------------------------------------------------------------
# Scanner / scan_project edge cases
# ---------------------------------------------------------------------------


def test_scan_empty_directory(tmp_path, scanner):
    """A completely empty directory scans cleanly with no findings/error."""
    result = scanner.scan(tmp_path)
    assert isinstance(result, ScanResult)
    assert result.findings == []
    assert result.risk_score == 0.0
    assert result.error is None


def test_scan_directory_with_only_irrelevant_files(tmp_path, scanner):
    """READMEs, text files and benign JS produce zero findings."""
    (tmp_path / "README.md").write_text("# readme")
    (tmp_path / "notes.txt").write_text("nothing suspicious here")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.js").write_text("console.log('hello');")
    result = scanner.scan(tmp_path)
    assert result.findings == []
    assert result.risk_score == 0.0
    assert result.error is None


def test_scan_unicode_filenames(tmp_path, scanner):
    """Unicode filenames and unicode package.json content must not crash."""
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "café-app",
                "version": "1.0.0",
                "description": "café ☕ test — шай-хулуд",
            }
        )
    )
    nm = tmp_path / "node_modules"
    nm.mkdir()
    (nm / "café-☕.js").write_text("const x = '☕'; // unicode")
    result = scanner.scan(tmp_path)
    assert isinstance(result, ScanResult)
    assert result.error is None
    assert isinstance(result.findings, list)


def test_scan_symlink_loop(tmp_path, scanner):
    """A node_modules symlink cycle must not hang or crash the scan."""
    nm = tmp_path / "node_modules"
    nm.mkdir()
    loop_target = tmp_path / "loop_target"
    loop_target.mkdir()
    try:
        os.symlink(loop_target, nm / "keyv", target_is_directory=True)
        os.symlink(nm, loop_target / "back", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not supported on this platform/filesystem")

    result = scanner.scan(tmp_path)
    assert isinstance(result, ScanResult)
    assert isinstance(result.findings, list)
    assert result.error is None


def test_scan_permission_denied(tmp_path, scanner, monkeypatch):
    """An unreadable package.json is skipped; the scan still completes and
    detects everything else."""
    keyv_pkg = tmp_path / "node_modules" / "keyv" / "package.json"
    keyv_pkg.parent.mkdir(parents=True)
    keyv_pkg.write_text(json.dumps({"name": "keyv", "version": "6.0.0"}))
    # Known Loader-B stub: 11017 bytes matches the setup.mjs size signature.
    (tmp_path / "setup.mjs").write_bytes(b"\x00" * 11017)

    real_read_text = Path.read_text

    def denying_read_text(self, *args, **kwargs):
        if str(self).endswith("node_modules/keyv/package.json"):
            raise PermissionError("permission denied")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denying_read_text)

    result = scanner.scan(tmp_path)
    assert isinstance(result, ScanResult)
    assert result.error is None
    # The unreadable keyv package.json contributed nothing…
    assert not any(f.package == "keyv" for f in result.findings)
    # …but the rest of the scan still ran and caught the setup.mjs stub.
    assert any(f.category == "file_name_size" for f in result.findings)


def test_scan_nested_node_modules(tmp_path, scanner):
    """Poisoned packages buried in nested node_modules are still caught."""
    pkg = tmp_path / "node_modules" / "a" / "node_modules" / "keyv"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(
        json.dumps({"name": "keyv", "version": "6.0.0"})
    )
    result = scanner.scan(tmp_path)
    hits = [
        f
        for f in result.findings
        if f.category == "poisoned_package" and f.package == "keyv"
    ]
    assert hits
    assert result.summary.get("packages_checked", 0) >= 1


def test_scan_large_file_skipped(tmp_path, matcher, monkeypatch):
    """Files over MAX_HASH_FILE_SIZE are never hashed (perf gate).

    The name-signal match may still fire, but _sha256 must not be invoked
    for the oversized file.
    """
    big = tmp_path / "Math_Symbol.js"
    big.write_bytes(b"\x00" * (3 * 1024 * 1024))  # 3 MiB > 2 MiB gate

    hashed_paths = []
    real_sha256 = sig_mod.SignatureMatcher._sha256

    def guarded_sha256(path):
        hashed_paths.append(Path(path))
        if Path(path).name == "Math_Symbol.js":
            raise AssertionError("oversized file was hashed — size gate broken")
        return real_sha256(path)

    monkeypatch.setattr(
        sig_mod.SignatureMatcher, "_sha256", staticmethod(guarded_sha256)
    )

    hit = matcher.match_file(big)
    assert hit is not None
    assert hit["category"] == "file_name_signal"
    assert not any(p.name == "Math_Symbol.js" for p in hashed_paths)


def test_scan_huge_node_modules_performance(tmp_path, scanner):
    """~200 tiny package.json files scan quickly and count correctly."""
    nm = tmp_path / "node_modules"
    nm.mkdir()
    for i in range(200):
        d = nm / ("pkg_%03d" % i)
        d.mkdir()
        (d / "package.json").write_text(
            json.dumps(
                {
                    "name": "pkg_%03d" % i,
                    "version": "1.0.0",
                    "scripts": {"test": "echo ok"},
                }
            )
        )

    start = time.monotonic()
    result = scanner.scan(tmp_path)
    elapsed = time.monotonic() - start

    assert isinstance(result, ScanResult)
    assert result.error is None
    assert result.summary.get("packages_checked") == 200
    assert elapsed < 5.0, "scan of 200 packages took %.2fs" % elapsed


def test_scanner_threads_parameter(infected_project):
    """threads=1 works; threads=0/negative falls back to the default pool."""
    result_one = Scanner(threads=1).scan(infected_project)
    assert isinstance(result_one, ScanResult)
    assert result_one.findings

    result_zero = Scanner(threads=0).scan(infected_project)
    assert isinstance(result_zero, ScanResult)
    assert Scanner(threads=0)._max_workers > 0
    assert Scanner(threads=-3)._max_workers > 0


# ---------------------------------------------------------------------------
# Finding / ScanResult shapes
# ---------------------------------------------------------------------------


def test_finding_without_message():
    """Finding with only rule_id/severity defaults to an empty message."""
    f = Finding(rule_id="r", severity="critical")
    assert f.message == ""
    d = f.to_dict()
    assert d["rule_id"] == "r"
    assert d["severity"] == "critical"
    assert d["message"] == ""


def test_finding_description_alias():
    """description= kwarg is aliased onto message."""
    f = Finding(rule_id="r", description="hello world")
    assert f.message == "hello world"
    assert f.description == "hello world"
    assert f.to_dict()["message"] == "hello world"


def test_scan_result_repr_roundtrip():
    """ScanResult.to_dict() is JSON-serializable even with odd findings."""
    f = Finding(
        rule_id="r1",
        severity="high",
        category="x",
        message="weird ☃ payload",
        custom_attr="absorbed",
    )
    result = ScanResult(findings=[f], risk_score=7.5, path="/tmp/proj")
    payload = json.dumps(result.to_dict())
    assert '"rule_id": "r1"' in payload
    assert '"category": "x"' in payload
    assert "custom_attr" in payload


# ---------------------------------------------------------------------------
# SignatureMatcher robustness
# ---------------------------------------------------------------------------


def test_signature_matcher_corrupt_data(tmp_path, monkeypatch):
    """Corrupt/missing data files must not crash the matcher."""
    (tmp_path / "signatures.json").write_text("{this is not valid json")
    monkeypatch.setattr(sig_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(sig_mod, "_SIGNATURES", None)
    monkeypatch.setattr(sig_mod, "_AFFECTED", None)

    m = SignatureMatcher()
    assert m.file_hashes == []
    assert m.name_signals == set()
    assert sig_mod.load_signatures() == {}
    assert sig_mod.load_affected_packages() == {}
    assert m.check_poisoned_package("keyv", "6.0.0") is None
    assert m.match_file(tmp_path / "whatever.js") is None


def test_signatures_reload_after_data_change(tmp_path, monkeypatch):
    """load_signatures() caches — a data change on disk is not re-read
    until the cache is cleared (real data/ is left untouched)."""
    first = sig_mod.load_signatures()
    assert isinstance(first, dict)
    assert "file_hashes" in first

    # Simulate the data changing on disk in a throwaway dir.
    (tmp_path / "signatures.json").write_text(
        json.dumps({"file_hashes": [{"fake": True}]})
    )
    monkeypatch.setattr(sig_mod, "DATA_DIR", tmp_path)

    second = sig_mod.load_signatures()
    assert second is first  # cached object returned, no re-read
    assert "file_hashes" in second
    assert second.get("file_hashes") != [{"fake": True}]


def test_match_file_directory_input(tmp_path, matcher):
    """match_file on a directory or a missing path returns None, no crash."""
    assert matcher.match_file(tmp_path) is None
    assert matcher.match_file(tmp_path / "does_not_exist") is None


def test_match_file_relative_and_absolute(tmp_path, matcher, monkeypatch):
    """Relative and absolute paths to the same file match identically."""
    stub = tmp_path / "setup.mjs"
    stub.write_bytes(b"\x00" * 11017)  # known name+size signature (Loader B)
    monkeypatch.chdir(tmp_path)

    rel = matcher.match_file("setup.mjs")
    abs_ = matcher.match_file(str(stub))
    assert rel is not None
    assert abs_ is not None
    rel.pop("file_path")
    abs_.pop("file_path")
    assert rel == abs_


def test_poisoned_package_version_none(matcher):
    """A None version only matches '*' entries; keyv has none, so None."""
    assert matcher.check_poisoned_package("keyv", None) is None
    assert matcher.check_poisoned_package("keyv", "7.0.0") is None
    assert matcher.check_poisoned_package("", "6.0.0") is None


def test_poisoned_package_scoped(matcher):
    """Scoped packages on the affected list are detected by exact version."""
    hit = matcher.check_poisoned_package("@or-sdk/auth", "0.38.1")
    assert hit is not None
    assert hit["severity"] == "critical"
    assert hit["package"] == "@or-sdk/auth"
    assert hit["version"] == "0.38.1"


def test_ide_hooks_missing_command(tmp_path, matcher):
    """folderOpen marker without the known malicious command → LOW finding,
    not critical."""
    vscode = tmp_path / ".vscode"
    vscode.mkdir()
    (vscode / "tasks.json").write_text(
        json.dumps(
            {
                "version": "2.0.0",
                "tasks": [
                    {
                        "label": "build",
                        "command": "npm run build",
                        "runOptions": {"runOn": "folderOpen"},
                    }
                ],
            }
        )
    )

    hits = matcher.match_ide_hooks(tmp_path)
    assert len(hits) == 1
    assert hits[0]["severity"] == "low"
    assert "folderOpen" in hits[0]["pattern"]

    # check_ide_hooks only reports the exact critical match — the LOW
    # "marker present, wrong command" fallback lives in match_ide_hooks.
    assert matcher.check_ide_hooks(vscode / "tasks.json") is None


def test_package_json_binary_content(matcher):
    """Garbage/binary-ish content never crashes the pattern matcher."""
    assert matcher.match_package_json("\x00\x01\x02") == []
    assert matcher.match_package_json("") == []
    assert matcher.match_package_json(None) == []


def test_risk_score_urgency_weighting():
    """A single CRITICAL finding scores 40 (urgent), 3 critical maxes at 100."""
    from npm_shield.engine import compute_risk_score, Finding
    assert compute_risk_score([Finding("x", "critical", "1")]) == 40.0
    assert compute_risk_score([Finding("x", "critical", "1")] * 3) == 100.0
    assert compute_risk_score([Finding("x", "high", "1")]) == 20.0
    assert compute_risk_score([]) == 0.0


def test_findings_deduped_by_category_and_path(tmp_path):
    """Same file triggering multiple detection rules (different patterns)
    is reported once per (category, file_path, pattern) — no duplicates."""
    from npm_shield.engine import Scanner
    from npm_shield.signatures import SignatureMatcher
    m = SignatureMatcher()
    marker = m.token_relay_marker or "IfYouBlockThisAPIKeyItWillCrashTheLiveProduction"
    # util.js is a known signal-name file → file_name_signal will fire,
    # AND we embed the content marker → content_marker will also fire.
    # Both on the SAME file but DIFFERENT (category, pattern) → both kept.
    f = tmp_path / "util.js"
    f.write_text(f"{marker}\n")
    s = Scanner()
    r = s.scan_project(str(tmp_path))
    keys = [(f.category, f.file_path, f.pattern) for f in r.findings]
    assert len(keys) == len(set(keys)), f"duplicate findings: {keys}"
    # content marker should still be caught
    marker_hits = [f for f in r.findings if f.category == "content_marker"]
    assert len(marker_hits) >= 1, "content marker not detected"


def test_size_cap_skips_json_parse_for_large_file(tmp_path):
    """Files > 50MB skip JSON parse entirely — no memory blowup."""
    from npm_shield.lockfile import parse_package_lock, _MAX_LOCKFILE_READ
    lf = tmp_path / "huge.json"
    # Write: valid JSON head + tail marker that the streaming regex can find
    lf.write_text('{"lockfileVersion":3,"packages":{')
    lf.write_text(lf.read_text() + '"node_modules/keyv":{"version":"6.0.0"}' + 'X' * (_MAX_LOCKFILE_READ + 100) + '}')
    pkgs = parse_package_lock(str(lf))
    # The tail slice should still recover keyv via regex fallback
    assert pkgs.get("keyv") == "6.0.0", f"tail recovery failed: {pkgs}"


def test_size_cap_head_tail_recovery(tmp_path):
    """Large lockfile (>50MB): poisoned packages at EITHER end are recovered."""
    from npm_shield.lockfile import parse_package_lock, _MAX_LOCKFILE_READ
    lf = tmp_path / "huge.json"
    junk = "X" * (_MAX_LOCKFILE_READ + 100)
    # keyv at start, flat-cache at end
    content = '{"lockfileVersion":3,"packages":{"node_modules/keyv":{"version":"6.0.0"}}' + junk + '"node_modules/flat-cache":{"version":"6.1.24"}}}'
    lf.write_text(content)
    pkgs = parse_package_lock(str(lf))
    assert pkgs.get("keyv") == "6.0.0", f"head keyv not recovered: {pkgs}"
    assert pkgs.get("flat-cache") == "6.1.24", f"tail flat-cache not recovered: {pkgs}"


def test_npm_alias_in_package_json_scan(tmp_path):
    """package.json with 'dep': 'npm:keyv@6.0.0' is flagged in project scan."""
    from npm_shield.engine import Scanner
    pj = tmp_path / "package.json"
    pj.write_text('{"name":"app","version":"1.0.0","dependencies":{"my-keyv":"npm:keyv@6.0.0"}}')
    s = Scanner()
    r = s.scan_project(str(tmp_path))
    alias_hits = [f for f in r.findings if "alias" in (f.detail or "")]
    assert len(alias_hits) >= 1, "npm alias in package.json not detected in project scan"
# ---------------------------------------------------------------------------
# AI Reviewer Fixes — regression tests for false-positive reduction
# ---------------------------------------------------------------------------


def test_setup_mjs_legit_path_not_flagged():
    """setup.mjs in a user project dir is NOT flagged as a process IOC."""
    from npm_shield.persistence import _LEGIT_SETUPMJS_INDICATORS

    safe_cmds = [
        "node /home/user/projects/myapp/scripts/setup.mjs --init",
        "node /tmp/dl/setup.mjs --install",
        "/usr/local/bin/node .pnpm/setup.mjs 2>&1",
    ]
    for cmd in safe_cmds:
        assert not any(ind.search(cmd) for ind in _LEGIT_SETUPMJS_INDICATORS), (
            f"false positive on legit setup.mjs path: {cmd}"
        )
        # setup.mjs filename still matches the IOC pattern
        from npm_shield.persistence import _PROCESS_PATTERNS
        assert any(rx.search(cmd.lower()) for rx in _PROCESS_PATTERNS), (
            f"setup.mjs pattern should still match: {cmd}"
        )


def test_malicious_setup_mjs_still_flagged():
    """setup.mjs from suspicious temp dirs / no safe indicators = flagged."""
    from npm_shield.persistence import _LEGIT_SETUPMJS_INDICATORS, _PROCESS_PATTERNS

    malicious_cmds = [
        "node /tmp/ab/setup.mjs",
        "node ./setup.mjs --silent",
        "/usr/bin/node setup.mjs --exec",
    ]
    for cmd in malicious_cmds:
        flagged = any(rx.search(cmd.lower()) for rx in _PROCESS_PATTERNS)
        safe = any(ind.search(cmd) for ind in _LEGIT_SETUPMJS_INDICATORS)
        assert flagged and not safe, (
            f"malicious setup.mjs should be flagged: {cmd}"
        )


def test_aws_config_env_vars_not_flagged():
    """AWS_REGION / AWS_PROFILE etc. are config — not secrets to report."""
    from npm_shield.audit import CredentialAudit, _AWS_CONFIG_ENV_NAMES

    # Simulate env vars
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ["AWS_DEFAULT_PROFILE"] = "default"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "AKIATEST123"

    ca = CredentialAudit()
    finding = ca.check_env_secrets()
    assert finding is not None
    names = finding.message
    # Should NOT list config vars
    assert "AWS_REGION" not in names
    assert "AWS_DEFAULT_PROFILE" not in names
    # SHOULD list the real secret
    assert "AWS_SECRET_ACCESS_KEY" in names

    # Clean up
    for v in ("AWS_REGION", "AWS_DEFAULT_PROFILE", "AWS_SECRET_ACCESS_KEY"):
        os.environ.pop(v, None)


def test_aws_config_blocklist_complete():
    """All common AWS config (non-secret) vars are in the blocklist."""
    from npm_shield.audit import _AWS_CONFIG_ENV_NAMES

    must_skip = {
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_PROFILE",
        "AWS_EXECUTION_ENV",
        "AWS_LAMBDA_LOG_GROUP_NAME",
    }
    assert must_skip <= _AWS_CONFIG_ENV_NAMES, (
        f"Missing config vars in blocklist: {must_skip - _AWS_CONFIG_ENV_NAMES}"
    )
    # Real secrets should NOT be in blocklist
    assert "AWS_SECRET_ACCESS_KEY" not in _AWS_CONFIG_ENV_NAMES
    assert "AWS_ACCESS_KEY_ID" not in _AWS_CONFIG_ENV_NAMES
    assert "AWS_SESSION_TOKEN" not in _AWS_CONFIG_ENV_NAMES


def test_systemd_node_service_execstart_verification():
    """node.service flagged only if ExecStart contains malicious paths."""
    from npm_shield.persistence import _EXECSTART_MALICIOUS, _get_systemd_execstart

    # Malicious ExecStart
    malicious = "/usr/bin/node /home/user/.node/gh-token-monitor/index.js"
    assert _EXECSTART_MALICIOUS.search(malicious), (
        "Should detect gh-token-monitor in ExecStart"
    )

    evil2 = "node /tmp/ab123/setup.mjs --run"
    assert _EXECSTART_MALICIOUS.search(evil2), (
        "Should detect setup.mjs in ExecStart"
    )

    # Legit ExecStart
    legit = "node /usr/src/app/server.js"
    assert not _EXECSTART_MALICIOUS.search(legit), (
        "Should NOT flag legit node service"
    )

    legit2 = "/usr/local/bin/node /home/user/myapp/dist/index.js"
    assert not _EXECSTART_MALICIOUS.search(legit2), (
        "Should NOT flag legit backend service"
    )
