"""Live threat feed for npm-shield with a graceful offline fallback.

Attempts to refresh the affected-packages list from public advisories
(socket.dev, safedep). Network failure NEVER crashes: ``update()`` simply
returns False and the scanner keeps using the local verified IOC data.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

from npm_shield.signatures import (
    load_affected_packages,
    load_campaign_meta,
)

#: Feed cache lives in a user-writable location (the package data dir is
#: read-only once installed into site-packages). Override with
#: NPM_SHIELD_FEED_CACHE. The cache is created lazily on first update.
def _default_cache_dir() -> Path:
    """Platform-correct cache directory for the feed cache.

    Windows uses ``%LOCALAPPDATA%`` (native convention); POSIX uses
    ``~/.cache``. Falls back to ``~/AppData/Local`` when the env var is
    unset, and never raises.
    """
    try:
        if sys.platform == "win32":
            base = os.environ.get("LOCALAPPDATA") or str(
                Path.home() / "AppData" / "Local"
            )
            return Path(base) / "npm-shield" / "feed_cache"
        return Path.home() / ".cache" / "npm-shield" / "feed_cache"
    except Exception:
        return Path.home() / ".npm-shield" / "feed_cache"


CACHE_DIR = _default_cache_dir()
CACHE_FILE = CACHE_DIR / "affected_packages.cache.json"

#: Public sources describing the Shai-Hulud / Chaindrop campaign.
_FEED_SOURCES: tuple = (
    "https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain",
    "https://safedep.io/keyv-npm-supply-chain-compromise/",
)

#: name@version pairs as they appear in advisory text.
_PKG_VERSION_RE = re.compile(
    r"([@a-z0-9][a-z0-9._-]*(?:/[@a-z0-9][a-z0-9._-]*)?)@(\d[0-9a-zA-Z._-]*)"
)

#: Words that are clearly not npm package names.
_SKIP_NAMES = {
    "node", "npm", "bun", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8",
    "v9", "version", "lockfileversion", "src", "main", "module", "types",
    "author", "license", "status", "error", "data", "value", "type", "name",
    "code", "user", "host", "registry", "packages", "dependencies", "http",
    "https", "url", "sha", "integrity", "tarball", "resolved",
}

#: Popular benign packages frequently mentioned in security blog prose
#: ("developers using express@4.18.2 should be careful"). Without this
#: blocklist, blind name@version extraction from advisory text would flag
#: everyday packages as malicious — massive false positives. The local
#: verified IOC data (load_affected_packages) remains the authoritative
#: source; the network feed only ADDS to it, and never for these names.
_POPULAR_BENIGN = {
    "express", "react", "react-dom", "lodash", "axios", "vue", "next",
    "gatsby", "angular", "@angular/core", "@angular/common", "typescript",
    "webpack", "babel", "@babel/core", "eslint", "jest", "mocha", "chai",
    "node-fetch", "ws", "socket.io", "body-parser", "cors", "dotenv",
    "mongoose", "sequelize", "pg", "mysql2", "redis", "ioredis", "knex",
    "jsonwebtoken", "bcrypt", "bcryptjs", "uuid", "moment", "dayjs",
    "chalk", "commander", "yargs", "inquirer", "ora", "semver", "path",
    "fs-extra", "glob", "rimraf", "mkdirp", "minimist", "debug", "nanoid",
    "crypto-js", "zod", "yup", "joi", "helmet", "compression",
    "express-session", "passport", "passport-jwt", "swagger-ui-express",
    "tailwindcss", "sass", "postcss", "autoprefixer", "prettier",
    "husky", "lint-staged", "concurrently", "nodemon", "ts-node",
    "esbuild", "rollup", "vite", "vitest", "storybook", "cypress",
    "puppeteer", "playwright", "axios-retry", "form-data", "mime-types",
    "punycode", "querystring", "tough-cookie", "http-proxy", "http-proxy-middleware",
}


class ThreatFeed:
    """Merges local verified IOC data with a best-effort network cache."""

    def __init__(self, offline_mode: bool = False) -> None:
        self.offline_mode = offline_mode
        # Resolved at init time so tests can override the cache location
        # via NPM_SHIELD_FEED_CACHE before constructing the feed.
        self.cache_dir = Path(
            os.environ.get("NPM_SHIELD_FEED_CACHE", str(CACHE_DIR))
        )
        self.cache_file = self.cache_dir / CACHE_FILE.name
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self.local: Dict[str, List[str]] = load_affected_packages()

    @property
    def campaign_meta(self) -> Dict:
        """Campaign metadata from ``data/campaign_meta.json``."""
        return load_campaign_meta()

    def affected_packages(self) -> Dict[str, List[str]]:
        """The affected-package map (local verified data + feed cache)."""
        return self.get_affected_packages()

    def is_affected(self, name: str, version: Optional[str]) -> bool:
        """True if ``name@version`` is on the affected list."""
        try:
            versions = self.affected_packages().get(name)
            if not versions:
                return False
            return self.version_matches(version, versions)
        except Exception:
            return False

    @staticmethod
    def version_matches(version: Optional[str], versions: List[str]) -> bool:
        """True if ``version`` is in ``versions``; a '*' entry matches all."""
        try:
            if not versions:
                return False
            if "*" in versions:
                return True
            return version is not None and version in versions
        except Exception:
            return False

    def update(self) -> bool:
        """Fetch the latest affected packages; True if the cache was refreshed.

        Network failures return False gracefully and never raise.
        """
        if self.offline_mode:
            return False
        merged: Dict[str, set] = {}
        fetched = False
        for url in _FEED_SOURCES:
            try:
                text = self._fetch(url)
            except Exception:
                continue
            if not text:
                continue
            for name, ver in _PKG_VERSION_RE.findall(text):
                if _looks_like_package(name):
                    merged.setdefault(name, set()).add(ver)
            fetched = True
        if not fetched:
            return False
        payload = {
            "fetched_at": int(time.time()),
            "sources": list(_FEED_SOURCES),
            "packages": {k: sorted(v) for k, v in merged.items()},
        }
        try:
            self.cache_file.write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
        except Exception:
            pass
        return bool(merged)

    def get_affected_packages(self) -> Dict[str, List[str]]:
        """Local verified data merged with any cached feed data (union)."""
        merged: Dict[str, List[str]] = {
            name: list(vers) for name, vers in self.local.items()
        }
        cached = self._load_cache()
        for name, vers in cached.items():
            existing = set(merged.get(name, []))
            existing.update(vers)
            merged[name] = sorted(existing)
        return merged

    @property
    def last_updated(self) -> Optional[int]:
        """Unix timestamp of the last successful feed update, or None."""
        try:
            doc = json.loads(self.cache_file.read_text(encoding="utf-8"))
            ts = int(doc.get("fetched_at", 0))
            return ts or None
        except Exception:
            return None

    # ------------------------------------------------------------------ #

    def _load_cache(self) -> Dict[str, List[str]]:
        try:
            if not self.cache_file.is_file():
                return {}
            doc = json.loads(self.cache_file.read_text(encoding="utf-8"))
            pkgs = doc.get("packages", {})
            return {
                name: list(vers)
                for name, vers in pkgs.items()
                if isinstance(vers, list)
            }
        except Exception:
            return {}

    @staticmethod
    def _fetch(url: str, timeout: int = 12) -> str:
        req = urllib.request.Request(
            url, headers={"User-Agent": "npm-shield/0.1.0 (defensive scanner)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(1024 * 1024).decode("utf-8", errors="ignore")


def _looks_like_package(name: str) -> bool:
    """Heuristic filter: reject obvious non-package matches from blog HTML."""
    if len(name) < 2 or ":" in name or " " in name or "node_modules" in name:
        return False
    lowered = name.lower()
    if lowered in _SKIP_NAMES:
        return False
    # Popular benign packages mentioned in prose must never enter the
    # feed — they are not attack targets, just blog text context.
    if lowered in _POPULAR_BENIGN:
        return False
    return any(ch.isalpha() for ch in name)
