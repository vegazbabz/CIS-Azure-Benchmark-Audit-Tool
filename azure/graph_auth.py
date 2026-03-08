"""azure/graph_auth.py — MSAL-based Microsoft Graph authentication.

Provides ``msal_rest()`` as a companion to ``az_rest()`` for Graph endpoints
that require scopes the az CLI app cannot obtain (e.g. ``Policy.Read.All``).

Auth modes (selected automatically from config):

  User (interactive):   PublicClientApplication + acquire_token_interactive()
                        Browser popup on first run; subsequent runs use the
                        token cache silently.
                        NOT device code flow (prohibited by CIS 5.2.3).

  Service principal:    ConfidentialClientApplication + acquire_token_for_client()
                        Configured via [graph_auth] in cis_audit.toml or env vars.

Configuration — cis_audit.toml [graph_auth] section or environment variables:

  client_id     /  CIS_GRAPH_CLIENT_ID     — app registration client ID (required)
  tenant_id     /  CIS_GRAPH_TENANT_ID     — AAD tenant ID (optional, auto-detected)
  client_secret /  CIS_GRAPH_CLIENT_SECRET — SP mode credential (optional;
                                             omit for interactive user auth)
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Delegated scope for user-mode interactive auth
_USER_SCOPES = ["https://graph.microsoft.com/Policy.Read.All"]

# App scope for SP mode — pulls all granted application permissions
_APP_SCOPES = ["https://graph.microsoft.com/.default"]

# Per-user token cache — avoids a browser popup on every run
_TOKEN_CACHE_PATH = Path.home() / ".cis_audit" / "msal_token_cache.json"


def is_configured() -> bool:
    """Return True if MSAL auth is configured (client_id present in config or env)."""
    from cis.config import GRAPH_AUTH

    return bool(GRAPH_AUTH.get("client_id") or os.environ.get("CIS_GRAPH_CLIENT_ID"))


def _get_tenant_id() -> str:
    """Return tenant ID from config/env or fall back to ``az account show``."""
    from cis.config import GRAPH_AUTH

    tid = GRAPH_AUTH.get("tenant_id") or os.environ.get("CIS_GRAPH_TENANT_ID")
    if tid:
        return tid

    import subprocess
    import sys

    az = "az.cmd" if sys.platform == "win32" else "az"
    try:
        result = subprocess.run(
            [az, "account", "show", "--query", "tenantId", "--output", "tsv"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    raise RuntimeError("Cannot determine tenant ID — set tenant_id in [graph_auth] or CIS_GRAPH_TENANT_ID env var")


def _load_cache() -> Any:
    """Load a serializable MSAL token cache from disk."""
    import msal

    cache = msal.SerializableTokenCache()
    if _TOKEN_CACHE_PATH.exists():
        try:
            cache.deserialize(_TOKEN_CACHE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass  # Corrupted cache — start fresh
    return cache


def _save_cache(cache: Any) -> None:
    """Persist a serializable MSAL token cache to disk if it has changed."""
    if not cache.has_state_changed:
        return
    try:
        _TOKEN_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _TOKEN_CACHE_PATH.write_text(cache.serialize(), encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to persist MSAL token cache: %s", exc)


def _acquire_token() -> str:
    """Acquire a Graph access token via MSAL, using the cache when available.

    Returns the raw access_token string.  Raises ``RuntimeError`` on failure.
    """
    import msal
    from cis.config import GRAPH_AUTH

    client_id = GRAPH_AUTH.get("client_id") or os.environ.get("CIS_GRAPH_CLIENT_ID")
    if not client_id:
        raise RuntimeError("MSAL not configured — set client_id in [graph_auth] or CIS_GRAPH_CLIENT_ID")

    client_secret = GRAPH_AUTH.get("client_secret") or os.environ.get("CIS_GRAPH_CLIENT_SECRET")
    tenant_id = _get_tenant_id()
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    cache = _load_cache()

    if client_secret:
        # ── Service principal mode (client credentials flow) ──────────────────
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=authority,
            client_credential=client_secret,
            token_cache=cache,
        )
        result = app.acquire_token_for_client(scopes=_APP_SCOPES)
    else:
        # ── User mode (interactive browser — authorization code with PKCE) ─────
        # Device code flow is intentionally NOT used (CIS 5.2.3).
        app = msal.PublicClientApplication(
            client_id,
            authority=authority,
            token_cache=cache,
        )
        # Attempt silent acquisition from cache first
        accounts = app.get_accounts()
        result = None
        if accounts:
            result = app.acquire_token_silent(scopes=_USER_SCOPES, account=accounts[0])
        if not result:
            logger.info("Opening browser for interactive sign-in (Policy.Read.All scope)...")
            result = app.acquire_token_interactive(scopes=_USER_SCOPES)

    _save_cache(cache)

    if not result or "access_token" not in result:
        error = (result or {}).get("error_description") or (result or {}).get("error") or "Unknown auth failure"
        raise RuntimeError(f"MSAL token acquisition failed: {error}")

    return str(result["access_token"])


def msal_rest(url: str, timeout: int = 30) -> tuple[int, Any]:
    """Call a Graph REST endpoint using an MSAL-acquired token.

    Interface mirrors ``az_rest()``::

        rc, data = msal_rest("https://graph.microsoft.com/v1.0/...")
        # rc == 0 → data is parsed JSON
        # rc != 0 → data is an error string

    Only call this after verifying ``is_configured()`` returns True.
    """
    try:
        token = _acquire_token()
    except RuntimeError as exc:
        return 1, str(exc)

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return 0, json.loads(body) if body.strip() else None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        logger.debug("MSAL Graph call HTTP %d for %s: %s", exc.code, url, body[:300])
        return 1, body
    except Exception as exc:
        return 1, str(exc)
