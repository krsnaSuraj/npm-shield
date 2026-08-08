"""npm-shield — detects the Shai-Hulud npm worm (Chaindrop) on developer
machines and projects.

A defensive tool. v0.1.0 ships verified IOC data for the Aug 4 2026 campaign
and scans lockfiles, node_modules trees, IDE hooks, host persistence,
processes and credential exposure.
"""
from __future__ import annotations

__version__ = "0.1.0"

from npm_shield.audit import CredentialAudit
from npm_shield.engine import Finding, Scanner, ScanResult, compute_risk_score
from npm_shield.feed import ThreatFeed
from npm_shield.lockfile import (
    detect_lockfile_type,
    parse_lockfile,
    parse_package_lock,
    parse_package_lock_v1,
    parse_package_lock_v3,
    parse_pnpm_lock,
    parse_yarn_lock,
)
from npm_shield.persistence import PersistenceHunter
from npm_shield.signatures import (
    DATA_DIR,
    SignatureMatcher,
    load_affected_packages,
    load_campaign_meta,
    load_signatures,
)

__all__ = [
    "__version__",
    "DATA_DIR",
    "CredentialAudit",
    "Finding",
    "PersistenceHunter",
    "Scanner",
    "ScanResult",
    "SignatureMatcher",
    "ThreatFeed",
    "compute_risk_score",
    "detect_lockfile_type",
    "load_affected_packages",
    "load_campaign_meta",
    "load_signatures",
    "parse_lockfile",
    "parse_package_lock",
    "parse_package_lock_v1",
    "parse_package_lock_v3",
    "parse_pnpm_lock",
    "parse_yarn_lock",
]
