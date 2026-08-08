

# --- Robustness regression tests (red-team findings) ---


def test_corrupted_large_lockfile_recovers_keyv(tmp_path):
    """A 10MB lockfile with injected junk still recovers keyv@6.0.0
    via the streaming regex fallback when JSON parse fails."""
    from npm_shield.lockfile import parse_package_lock
    lf = tmp_path / "corrupt.json"
    lf.write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/keyv":{"version":"6.0.0"}}'
        + "A" * 10_000_000
        + "}"
    )
    pkgs = parse_package_lock(str(lf))
    assert pkgs.get("keyv") == "6.0.0"


def test_alias_entries_handled(tmp_path):
    """npm alias entries (version: npm:*) don't break parsing."""
    from npm_shield.lockfile import parse_package_lock
    lf = tmp_path / "alias.json"
    lf.write_text(
        '{"lockfileVersion":3,"packages":{'
        '"node_modules/keyv-alias":{"version":"npm:*"},'
        '"node_modules/real-pkg":{"version":"1.0.0"}}}'
    )
    pkgs = parse_package_lock(str(lf))
    assert pkgs.get("real-pkg") == "1.0.0"
