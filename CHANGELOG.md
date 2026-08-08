# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0]

### Round 5 — Review Fixes
- Nested lockfile deps parsed correctly (top-level + nested).
- Feed: benign package blocklist stops false positives from blog text.
- Content markers now found in padded/renamed files (>1MB).
- Signal guard thread-scoped — fixes flaky suite race.
- 220 tests passing.

### Round 4 — Thread Safety
- Signal-based regex timeout only from main thread; workers use daemon fallback.
- Explicit psutil exception handling in process scan.
- Windows `CREATE_NO_WINDOW` for helper subprocesses.

### Round 3 — Cross-Platform & Robustness
- Windows cache dir (`%LOCALAPPDATA%`), POSIX unchanged.
- HTML error fallback (XSS-safe traceback).
- Feed multi-source resilience.
- Lockfile type detection hardened.
- Silent except spots now log with reason.
- CLI uses documented class methods directly.

### Round 2 — Performance & Robustness
- `_known_sizes` cached per `file_hashes` identity.
- 50MB+ lockfile fallback warning when ijson absent.
- ReDoS thread fallback documented as platform limitation.

### Round 1 — Initial Deep Audit
- Lockfile corrupted-JSON recovery.
- Content marker matching fix.
- Root-level JS detection.
- 220+ tests, packaging verified, live E2E scan.
