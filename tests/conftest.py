"""Shared fixtures for the npm-shield test suite.

Fixtures build throwaway project trees under pytest's tmp_path so no real
filesystem state outside the test session is ever touched.
"""
import json
import os
import sys
from pathlib import Path

import pytest

# Make the repo root importable so `import npm_shield` works regardless of cwd.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Keep the threat-feed cache out of the repo's data/ dir (must be set before
# npm_shield.feed is first imported, since CACHE_DIR is bound at import time).
os.environ.setdefault(
    "NPM_SHIELD_FEED_CACHE", str(REPO_ROOT / "tests" / ".feed_cache")
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def clean_project(tmp_path):
    """A benign project: safe package.json + package-lock.json (v3, flat)."""
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "clean-app",
                "version": "1.0.0",
                "scripts": {"test": "echo ok"},
                "dependencies": {"lodash": "^4.17.21", "express": "^4.19.2"},
            }
        )
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "clean-app",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": True,
                "packages": {
                    "": {"name": "clean-app", "dependencies": {"lodash": "^4.17.21", "express": "^4.19.2"}},
                    "node_modules/lodash": {"version": "4.17.21"},
                    "node_modules/express": {"version": "4.19.2"},
                },
            }
        )
    )
    return tmp_path


@pytest.fixture
def infected_project(tmp_path):
    """A project matching Shai-Hulud IOCs: malicious preinstall hook,
    poisoned keyv@6.0.0 in the lockfile, and a setup.mjs stub at the root."""
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "infected-app",
                "version": "1.0.0",
                "scripts": {"preinstall": "node setup.mjs"},
            }
        )
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "infected-app",
                "version": "1.0.0",
                "lockfileVersion": 1,
                "requires": True,
                "dependencies": {"keyv": {"version": "6.0.0", "requires": {}}},
            }
        )
    )
    # Loader-B stub: 11017 bytes matches the known setup.mjs size signature.
    (tmp_path / "setup.mjs").write_bytes(b"\x00" * 11017)
    return tmp_path


@pytest.fixture
def infected_node_modules(tmp_path):
    """An installed node_modules tree containing a poisoned package."""
    keyv_dir = tmp_path / "node_modules" / "keyv"
    keyv_dir.mkdir(parents=True)
    (keyv_dir / "package.json").write_text(
        json.dumps({"name": "keyv", "version": "6.0.0"})
    )
    # Stage-2 harvester stub: 727680 bytes matches the known Math_Symbol.js size.
    (keyv_dir / "Math_Symbol.js").write_bytes(b"\x00" * 727680)
    return tmp_path


@pytest.fixture
def persistence_dir(tmp_path):
    """A fake $HOME containing the gh-token-monitor persistence artifact."""
    home = tmp_path / "home"
    state_dir = home / ".config" / "gh-token-monitor"
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text('{"watcher": "active"}')
    return home


@pytest.fixture
def matcher():
    """A SignatureMatcher loaded from the real data/ directory."""
    from npm_shield.signatures import SignatureMatcher

    return SignatureMatcher()


@pytest.fixture
def scanner():
    """A Scanner wired to the real data/ directory."""
    from npm_shield.engine import Scanner

    return Scanner()
