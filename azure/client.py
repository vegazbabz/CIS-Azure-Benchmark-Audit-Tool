"""az_client.py — Low-level Azure CLI subprocess layer.

Provides:
- az(args, sub, timeout)       — run any az command, returns (rc, parsed_json)
- az_rest(url, timeout)        — call az rest, returns (rc, parsed_json)
- graph_query(query, sub_ids)  — paginated Resource Graph query
- get_and_reset_rate_limit_retry_count() — throttle-signal for the orchestrator
- is_firewall_error(msg)       — detect firewall-blocked responses
- _friendly_error(msg)         — collapse multi-line errors to one line
- _run_cmd_with_retries(...)   — subprocess with exponential backoff
"""

from __future__ import annotations

import json
import logging
import random
import subprocess
import sys
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

# Tracks transient throttling retries across command calls so the orchestrator
# can adapt worker concurrency between subscription batches.
_rate_limit_retries = 0
_rate_limit_lock = threading.Lock()

# Registry of currently-running az subprocesses. Populated by _run_cmd_with_retries
# so that kill_running_procs() can terminate them all immediately on Ctrl+C,
# unblocking worker threads that are stuck in proc.communicate().
_running_procs: set[subprocess.Popen[str]] = set()
_running_procs_lock = threading.Lock()


def kill_running_procs() -> None:
    """Kill all az subprocesses currently tracked in _running_procs.

    Called on KeyboardInterrupt so that worker threads blocked in
    proc.communicate() unblock immediately instead of waiting for az to exit.
    """
    with _running_procs_lock:
        procs = list(_running_procs)
    for proc in procs:
        try:
            proc.kill()
        except Exception:
            pass


# On Windows, Python cannot find 'az' without the .cmd extension.
AZ = "az.cmd" if sys.platform == "win32" else "az"

# Timeout (seconds) for Resource Graph bulk queries — longer because the response
# payload can be large and pagination adds round-trips.
_GRAPH_TIMEOUT = 120


def _first_error_line(msg: str) -> str:
    """Return the first non-empty line of an error message."""
    if not msg:
        return ""
    for line in str(msg).splitlines():
        line = line.strip()
        if line:
            return line
    return str(msg).strip()


_AUTHZ_TOKENS = frozenset(
    [
        "forbiddenbyrbac",
        "not authorized",
        "authorizationfailed",
        "does not have authorization",
        "caller is not authorized",
        # Key Vault data-plane permission errors (list/get keys, secrets, certs)
        "does not have certificates list permission",
        "does not have secrets list permission",
        "does not have keys list permission",
        "does not have certificate get permission",
        "does not have secret get permission",
        "does not have key get permission",
        # Key Vault data-plane errors from newer SDK / tenants with many groups
        "requires key vault data plane permissions",
        # Microsoft Graph scope / consent errors — also in _GRAPH_SCOPE_TOKENS so
        # _friendly_error can return a Graph-specific message instead of the KV one.
        "required scopes are missing in the token",
        "authorization_requestdenied",
    ]
)

# Graph-specific access-denied tokens.  These are a strict subset of
# _AUTHZ_TOKENS so _run_cmd_with_retries still logs them at DEBUG, but
# _friendly_error checks this set FIRST to return a Graph-specific message
# instead of the Key Vault-specific _CLEAN_KV_AUTHZ_MSG.
_GRAPH_SCOPE_TOKENS = frozenset(
    [
        "required scopes are missing in the token",
        "authorization_requestdenied",
    ]
)

# Errors that indicate the requested feature is not supported on this account
# type (e.g. Azure Files on a blob-only or ADLS Gen2 storage account). These
# are expected during storage checks and should not surface as ERROR log lines.
_NOTAPPLICABLE_TOKENS = frozenset(
    [
        "featurenotsupportedforaccount",
    ]
)

# Firewall-block tokens must be checked BEFORE generic auth tokens because
# "ForbiddenByFirewall" contains "forbidden" which would otherwise match _AUTHZ_TOKENS.
_FIREWALL_TOKENS = frozenset(
    [
        "forbiddenbyFirewall",
        "public network access is disabled",
        "not allowed by its firewall rules",
        "caller's ip address",
        # Private endpoint / service endpoint blocks
        "connection is not an approved private link",
        "not an approved private link and caller was ignored",
    ]
)


def is_firewall_error(msg: str) -> bool:
    """Return True if the error message indicates a network firewall block."""
    lowered = str(msg).lower()
    return any(t.lower() in lowered for t in _FIREWALL_TOKENS)


def is_authz_error(msg: str) -> bool:
    """Return True if the error indicates a missing authorisation / permission."""
    lowered = str(msg).lower()
    return any(t in lowered for t in _AUTHZ_TOKENS)


def is_notapplicable_error(msg: str) -> bool:
    """Return True if the error indicates the feature is not supported on this account type."""
    lowered = str(msg).lower()
    return any(t in lowered for t in _NOTAPPLICABLE_TOKENS)


# Single source of truth for the KV data-plane permission error message.
# Also imported by cis/checkpoint.py to reclassify old raw CLI dumps on load.
_CLEAN_KV_AUTHZ_MSG = (
    "Audit incomplete — account lacks Key Vault data-plane permissions. "
    "Grant 'Key Vault Reader' data-plane role (or an access policy) to include this vault."
)


def _friendly_error(msg: str) -> str:
    """Return a short, human-readable version of an Azure CLI error string.

    Permission/auth errors are collapsed to a single tidy phrase so reports
    don't contain truncated multi-line CLI blobs.  All other errors are
    reduced to their first meaningful line.
    """
    if not msg:
        return "Unknown error"
    if is_firewall_error(msg):
        return "Firewall blocked — vault not reachable from this runner IP"
    if is_notapplicable_error(msg):
        return "Feature not supported for this account type"
    lowered = str(msg).lower()
    # Graph scope errors must be checked before the generic RBAC block so they
    # get a Graph-specific message rather than the Key Vault-specific one.
    if any(t in lowered for t in _GRAPH_SCOPE_TOKENS):
        return (
            "Graph API access denied — the signed-in account lacks the required "
            "permission. Assign 'Reports Reader', 'Security Reader', or 'Global Reader' "
            "in Entra ID (for user accounts), or grant the required Graph application "
            "permission (for service principals)."
        )
    if any(t in lowered for t in _AUTHZ_TOKENS):
        return _CLEAN_KV_AUTHZ_MSG
    first = _first_error_line(msg)
    return first[:160] if len(first) > 160 else first


def _run_cmd_with_retries(
    cmd: list[str],
    timeout: int = 25,
    max_retries: int = 3,
    base_backoff: float = 1.0,
) -> tuple[int, str, str]:
    """Run a subprocess command with retries and exponential backoff.

    Returns
    -------
    tuple[int, str, str]
        ``(returncode, stdout, stderr)``
    """
    global _rate_limit_retries
    for attempt in range(1, max_retries + 1):
        logger.debug("running command attempt %d: %s", attempt, cmd)
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            with _running_procs_lock:
                _running_procs.add(proc)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            finally:
                with _running_procs_lock:
                    _running_procs.discard(proc)
            r_returncode = proc.returncode
            stdout = stdout or ""
            stderr = stderr or ""
            if r_returncode != 0:
                low = stderr.lower() if isinstance(stderr, str) else ""
                transient_tokens = ("429", "too many requests", "rate limit", "throttl")
                is_transient = any(tok in low for tok in transient_tokens)
                if attempt < max_retries and is_transient:
                    with _rate_limit_lock:
                        _rate_limit_retries += 1
                    sleep_for = base_backoff * (2 ** (attempt - 1)) + random.random() * 0.5
                    logger.warning("transient error detected, sleeping %.1fs before retry", sleep_for)
                    time.sleep(sleep_for)
                    continue
                is_authz = any(tok in low for tok in _AUTHZ_TOKENS)
                is_notapplicable = any(tok in low for tok in _NOTAPPLICABLE_TOKENS)
                summary = _first_error_line(stderr)
                if is_authz:
                    logger.debug("command denied by permissions (rc=%d): %s", r_returncode, summary)
                elif is_notapplicable:
                    logger.debug("command not applicable for account type (rc=%d): %s", r_returncode, summary)
                elif summary.strip() in ("^C", ""):
                    # az subprocess killed by Ctrl+C (Windows forwards SIGINT to
                    # all console processes); not a real error — suppress the noise.
                    logger.debug("command interrupted (rc=%d)", r_returncode)
                else:
                    logger.error("command failed (rc=%d): %s", r_returncode, summary)
                return r_returncode, stdout, stderr
            logger.debug("command succeeded")
            return 0, stdout, stderr

        except subprocess.TimeoutExpired:
            with _running_procs_lock:
                _running_procs.discard(proc)
            proc.kill()
            proc.communicate()  # drain pipes to avoid ResourceWarning
            if attempt < max_retries:
                sleep_for = base_backoff * (2 ** (attempt - 1))
                time.sleep(sleep_for)
                continue
            return 1, "", f"Timed out ({timeout}s)"
        except FileNotFoundError:
            return 1, "", "az CLI not found"

    return 1, "", "No command attempts were made"


def az(args: list[str], sub: str | None = None, timeout: int = 25) -> tuple[int, Any]:
    """Execute an az CLI command and return (returncode, parsed_output)."""
    cmd = [AZ] + args + ["--output", "json"]
    if sub:
        cmd += ["--subscription", sub]
    logger.debug("az() invoking: %s", cmd)
    rc, stdout, stderr = _run_cmd_with_retries(cmd, timeout=timeout)
    if rc != 0:
        return rc, (stderr or "").strip()
    if not (stdout or "").strip():
        return 0, None
    try:
        return 0, json.loads(stdout)
    except json.JSONDecodeError:
        return 0, stdout.strip()


def get_and_reset_rate_limit_retry_count() -> int:
    """Return and reset the transient retry counter."""
    global _rate_limit_retries
    with _rate_limit_lock:
        count = _rate_limit_retries
        _rate_limit_retries = 0
        return count


def az_rest(url: str, timeout: int = 25) -> tuple[int, Any]:
    """Call an Azure REST or Microsoft Graph endpoint via ``az rest``.

    For Graph URLs (https://graph.microsoft.com/...) the ``--resource`` flag
    is added explicitly so the az CLI requests a Graph-scoped token rather
    than an ARM-scoped one.  Without this, Graph returns AccessDenied even
    when the signed-in user has the correct Entra ID directory roles.
    """
    cmd = [AZ, "rest", "--method", "get", "--url", url, "--output", "json"]
    if url.startswith("https://graph.microsoft.com/"):
        cmd += ["--resource", "https://graph.microsoft.com"]
    rc, stdout, stderr = _run_cmd_with_retries(cmd, timeout=timeout)
    if rc != 0:
        return rc, (stderr or "").strip()
    if not (stdout or "").strip():
        return 0, None
    try:
        return 0, json.loads(stdout)
    except json.JSONDecodeError:
        return 0, stdout.strip()


def az_rest_paged(url: str, timeout: int = 25) -> tuple[int, list[Any]]:
    """Call an OData-paged Graph endpoint and return all items as a flat list.

    Follows ``@odata.nextLink`` cursors until the last page.  Each page must
    return a JSON object with a ``value`` array (the standard OData envelope).

    Returns
    -------
    (0, [items...]) on success, or (non-zero, []) on the first HTTP/parse error.
    """
    items: list[Any] = []
    next_url: str | None = url
    while next_url:
        rc, data = az_rest(next_url, timeout=timeout)
        if rc != 0:
            return rc, []
        if not isinstance(data, dict):
            return 1, []
        items.extend(data.get("value", []))
        next_url = data.get("@odata.nextLink")
    return 0, items


def graph_query(query: str, sub_ids: list[str]) -> tuple[int, Any]:
    """Execute a Kusto query against Azure Resource Graph and return all results.

    Transparently follows ``skipToken`` cursors and batches subscription IDs
    in groups of 10 (Resource Graph limit).
    """
    all_data = []

    for batch in [sub_ids[i : i + 10] for i in range(0, len(sub_ids), 10)]:
        skip = None
        while True:
            cmd = (
                [AZ, "graph", "query", "-q", query.strip(), "--first", "1000", "--output", "json"]
                + ["--subscriptions"]
                + batch
                + (["--skip-token", skip] if skip else [])
            )
            rc, stdout, stderr = _run_cmd_with_retries(cmd, timeout=_GRAPH_TIMEOUT)
            if rc != 0:
                return 1, stderr.strip() if stderr else "Graph query failed"
            try:
                d = json.loads(stdout)
                all_data.extend(d.get("data", []))
                skip = d.get("skipToken")
                if not skip:
                    break
            except (json.JSONDecodeError, KeyError) as e:
                return 1, f"Parse error: {e}"

    return 0, all_data
