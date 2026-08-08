"""Credential exposure audit for npm-shield.

SECURITY: none of these checks ever prints or returns token *values* —
only presence, names and file paths. Values are always redacted as '***'.

``home`` overrides the base directory for checks (defaults to $HOME) so
the audit can run against an isolated/container home.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, List, Optional

#: Matches `_authToken=` / `_auth=` lines and registry-scoped token lines.
_NPMRC_TOKEN_RE = re.compile(
    r"(?:^|[\r\n])\s*[^#\r\n]*?(?:_authToken|_auth)\s*="
    r"|//registry\.npmjs\.org/:_authToken\s*="
)

_SECRET_ENV_NAMES = ("NPM_TOKEN", "GH_TOKEN", "GITHUB_TOKEN")

#: AWS_* env vars that are configuration (not actual secrets) — skip them.
_AWS_CONFIG_ENV_NAMES = frozenset({
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_PROFILE",
    "AWS_EXECUTION_ENV",
    "AWS_LAMBDA_LOG_GROUP_NAME",
    "AWS_LAMBDA_LOG_STREAM_NAME",
    "AWS_LAMBDA_FUNCTION_NAME",
    "AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
    "AWS_LAMBDA_FUNCTION_VERSION",
    "AWS_DEFAULT_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
})

_REDACTED = "***"


def _tool_argv(name: str) -> List[str]:
    """Resolve a CLI tool to an executable argv prefix, cross-platform.

    On Windows, npm and other Node.js tools ship as ``.cmd`` shims that
    ``CreateProcess`` cannot launch directly (``shell=False`` performs no
    PATHEXT lookup), so they are routed through ``cmd.exe``. POSIX tools
    run via the resolved absolute path. Unknown tools fall back to the
    bare name so the caller's exception handling applies.
    """
    exe = shutil.which(name)
    if not exe:
        return [name]
    if sys.platform == "win32" and exe.lower().endswith((".cmd", ".bat")):
        return ["cmd", "/d", "/c", exe]
    return [exe]


class CredentialAudit:
    """Audits developer credentials that Shai-Hulud targets for exfiltration.

    Every ``check_*`` returns a Finding (``info`` severity when the check is
    clean) and never raises. ``run_all`` runs the credential-exposure checks;
    ``check_ignore_scripts`` is a separate hardening check.
    """

    def __init__(self, home: Optional[str] = None) -> None:
        self.home = Path(home) if home else Path.home()

    def run_all(self) -> List[Any]:
        """Run the credential-exposure checks (npmrc, gh, env). Never raises."""
        out: List[Any] = []
        for fn in (
            self.check_npmrc,
            self.check_gh_creds,
            self.check_env_secrets,
        ):
            try:
                f = fn()
                if f is not None:
                    out.append(f)
            except Exception:
                pass
        return out

    # ------------------------------------------------------------------ #

    def check_npmrc(self) -> Optional[Any]:
        """Report presence of an npm auth token in .npmrc (never the value).

        Returns a ``high`` finding when a token is present, otherwise an
        ``info`` finding. The token value is never included in any field.
        """
        npmrc_path = Path(
            os.environ.get("NPM_CONFIG_USERCONFIG", str(self.home / ".npmrc"))
        )
        try:
            content = npmrc_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            content = ""
        if content and _NPMRC_TOKEN_RE.search(content):
            return self._mk(
                severity="high",
                category="npmrc",
                file_path=str(npmrc_path),
                message=(
                    "npm auth token configured in %s — Shai-Hulud harvests "
                    "npm tokens (value redacted as %s)." % (npmrc_path, _REDACTED)
                ),
                detail=(
                    "npm registry auth token present in %s; value redacted "
                    "as %s" % (npmrc_path, _REDACTED)
                ),
                fix=(
                    "Rotate the token now, then switch to `npm login` "
                    "(keystore-backed) or a secret manager."
                ),
            )
        return self._mk(
            severity="info",
            category="npmrc",
            file_path=str(npmrc_path),
            message="No npm auth token found in %s." % npmrc_path,
        )

    def check_gh_creds(self) -> Optional[Any]:
        """Check plaintext ~/.git-credentials and `gh auth status`.

        The gh check runs with HOME pointed at ``self.home`` so it never
        reflects an unrelated host account.
        """
        creds = self.home / ".git-credentials"
        if creds.is_file():
            return self._mk(
                severity="medium",
                category="gh_creds",
                file_path=str(creds),
                message=(
                    "Plaintext git credential file present at %s — Shai-Hulud "
                    "targets GitHub tokens (values redacted as %s)."
                    % (creds, _REDACTED)
                ),
                detail=(
                    "git credential file found at %s; values redacted as %s"
                    % (creds, _REDACTED)
                ),
                fix=(
                    "Remove the file and use `gh auth login` or a credential "
                    "helper instead."
                ),
            )
        try:
            env = dict(os.environ)
            env["HOME"] = str(self.home)
            kwargs: dict = {
                "capture_output": True,
                "text": True,
                "timeout": 10,
                "env": env,
                "errors": "replace",
            }
            if sys.platform == "win32":
                # Never flash a console window for the helper binary.
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            proc = subprocess.run(
                _tool_argv("gh") + ["auth", "status"],
                **kwargs,
            )
            authed = (
                proc.returncode == 0
                and "logged in" in (proc.stdout + proc.stderr).lower()
            )
        except Exception:
            authed = False
        if authed:
            return self._mk(
                severity="medium",
                category="gh_creds",
                message=(
                    "GitHub CLI is authenticated — verify the session is still "
                    "yours and rotate the token if unsure."
                ),
                detail=(
                    "`gh auth status` reports a logged-in session "
                    "(token value redacted)"
                ),
                fix="Run `gh auth refresh` to rotate the token.",
            )
        return self._mk(
            severity="info",
            category="gh_creds",
            message="No GitHub credentials detected.",
        )

    def check_ignore_scripts(self) -> Optional[Any]:
        """Check `npm config get ignore-scripts` (recommend true).

        ``true`` -> info finding (safe); ``false`` -> high finding; npm
        unavailable/error -> info finding. Never raises.
        """
        try:
            kwargs: dict = {
                "capture_output": True,
                "text": True,
                "timeout": 10,
                "errors": "replace",
            }
            if sys.platform == "win32":
                # Never flash a console window for the helper binary.
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            proc = subprocess.run(
                _tool_argv("npm") + ["config", "get", "ignore-scripts"],
                **kwargs,
            )
            value = (proc.stdout or "").strip().lower()
        except Exception:
            value = ""
        if value == "false":
            return self._mk(
                severity="high",
                category="ignore_scripts",
                message=(
                    "npm install scripts are ENABLED (ignore-scripts=false) — "
                    "the worm's preinstall hooks would execute on install."
                ),
                detail="npm config ignore-scripts=false",
                fix="Run: npm config set ignore-scripts true",
            )
        if value == "true":
            return self._mk(
                severity="info",
                category="ignore_scripts",
                message=(
                    "npm install scripts are blocked (ignore-scripts=true) — "
                    "Shai-Hulud preinstall hooks cannot fire."
                ),
            )
        return self._mk(
            severity="info",
            category="ignore_scripts",
            message=(
                "Could not determine ignore-scripts setting (npm "
                "unavailable?). npm v12+ blocks install scripts by default."
            ),
        )

    def check_env_secrets(self) -> Optional[Any]:
        """Report NAMES of secret env vars only — never values."""
        found: List[str] = []
        for name in _SECRET_ENV_NAMES:
            if name in os.environ:
                found.append(name)
        for name in os.environ:
            if name.startswith("AWS_") and name not in _AWS_CONFIG_ENV_NAMES:
                found.append(name)
        found = sorted(set(found))
        if found:
            return self._mk(
                severity="high",
                category="env_secrets",
                message=(
                    "Secret environment variables present (names only): %s — "
                    "Shai-Hulud exfiltrates these (values redacted as %s)."
                    % (", ".join(found), _REDACTED)
                ),
                detail=(
                    "Secret env var names: %s; values never exposed"
                    % ", ".join(found)
                ),
                fix=(
                    "Avoid ambient credentials; use short-lived tokens or a "
                    "secret manager."
                ),
            )
        return self._mk(
            severity="info",
            category="env_secrets",
            message=(
                "No NPM_TOKEN/GH_TOKEN/GITHUB_TOKEN/AWS_* env vars found."
            ),
        )

    # ------------------------------------------------------------------ #

    @staticmethod
    def _mk(**kwargs: Any) -> Any:
        # Lazy import avoids a circular dependency with engine.py.
        from npm_shield.engine import Finding  # noqa: PLC0415

        return Finding(**kwargs)
