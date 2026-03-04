"""Azure CLI helper functions split out from the main audit script.
Provides:
- AZ constant
- _run_cmd_with_retries(cmd, timeout, max_retries, base_backoff)
- az(args, sub, timeout)
- az_rest(url, timeout)
- graph_query(query, sub_ids)

This module intentionally uses only the standard library so the main script
remains runnable without external dependencies.
"""

from __future__ import annotations

from typing import Any

import subprocess
import json
import time
import random
import sys
import logging
import re
import threading

# module-level logger; this will inherit the level set by the caller
logger = logging.getLogger(__name__)

# Tracks transient throttling retries across command calls so the orchestrator
# can adapt worker concurrency between subscription batches.
_rate_limit_retries = 0
_rate_limit_lock = threading.Lock()

# On Windows, Python cannot find 'az' without the .cmd extension.
AZ = "az.cmd" if sys.platform == "win32" else "az"


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
    ["forbidden", "not authorized", "authorizationfailed", "does not have authorization", "caller is not authorized"]
)


def _friendly_error(msg: str) -> str:
    """Return a short, human-readable version of an Azure CLI error string.

    Permission/auth errors are collapsed to a single tidy phrase so reports
    don't contain truncated multi-line CLI blobs.  All other errors are
    reduced to their first meaningful line.
    """
    if not msg:
        return "Unknown error"
    lowered = str(msg).lower()
    if any(t in lowered for t in _AUTHZ_TOKENS):
        return "Insufficient permissions (data-plane role required on this Key Vault)"
    first = _first_error_line(msg)
    return first[:160] if len(first) > 160 else first


def _run_cmd_with_retries(
    cmd: list[str],
    timeout: int = 25,
    max_retries: int = 3,
    base_backoff: float = 1.0,
) -> tuple[int, str, str]:
    """Run a subprocess command with retries and exponential backoff.

    This helper is the heart of our resilient CLI access. It calls
    ``subprocess.run`` and inspects the return code & stderr output for
    transient errors such as HTTP 429 (rate limiting) or generic timeouts.
    When a transient condition is detected we wait (exponentially increasing
    delay plus jitter) and retry up to ``max_retries`` times.  Fatal
    conditions (non-429 failures, TimeoutExpired on the last attempt, or
    missing ``az`` binary) are returned immediately.

    Returns
    -------
    tuple[int, str, str]
        ``(returncode, stdout, stderr)`` where stdout/stderr are empty strings
        if the subprocess raised an exception or produced no output.
    """
    for attempt in range(1, max_retries + 1):
        # each loop is a single CLI invocation; ``attempt`` is 1-based
        logger.debug("running command attempt %d: %s", attempt, cmd)
        try:
            # run the command, capturing both stdout/stderr as text
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            stdout = r.stdout or ""  # avoid None
            stderr = r.stderr or ""
            if r.returncode != 0:
                # look for known transient error indicators in stderr
                low = stderr.lower() if isinstance(stderr, str) else ""
                transient_tokens = ("429", "too many requests", "rate limit", "throttl")
                is_transient = any(tok in low for tok in transient_tokens)
                if attempt < max_retries and is_transient:
                    with _rate_limit_lock:
                        global _rate_limit_retries
                        _rate_limit_retries += 1
                    # exponential backoff with jitter before retrying
                    sleep_for = base_backoff * (2 ** (attempt - 1)) + random.random() * 0.5
                    logger.warning("transient error detected, sleeping %.1fs before retry", sleep_for)
                    time.sleep(sleep_for)
                    continue
                # either non-transient error or max attempts reached.
                # Permission denials (Forbidden/Unauthorized) are expected in
                # many read-only audit scenarios and should not spam console
                # output as runtime "errors".
                authz_tokens = (
                    "forbidden",
                    "forbiddenbyrbac",
                    "not authorized",
                    "authorizationfailed",
                    "does not have authorization",
                )
                is_authz = any(tok in low for tok in authz_tokens)
                summary = _first_error_line(stderr)
                if is_authz:
                    logger.debug("command denied by permissions (rc=%d): %s", r.returncode, summary)
                else:
                    logger.error("command failed (rc=%d): %s", r.returncode, summary)
                return r.returncode, stdout, stderr
            # success path
            logger.debug("command succeeded")
            return 0, stdout, stderr

        except subprocess.TimeoutExpired:
            if attempt < max_retries:
                sleep_for = base_backoff * (2 ** (attempt - 1))
                time.sleep(sleep_for)
                continue
            return 1, "", f"Timed out ({timeout}s)"
        except FileNotFoundError:
            return 1, "", "az CLI not found"

    return 1, "", "No command attempts were made"


def az(args: list[str], sub: str | None = None, timeout: int = 25) -> tuple[int, Any]:
    """Execute an az CLI command and return (returncode, parsed_output).

    Convenience wrapper around ``_run_cmd_with_retries`` that also handles
    JSON decoding of the stdout.  ``az`` by default emits JSON when
    ``--output json`` is specified, so this function ensures callers always
    receive parsed data structures rather than raw strings.
    """
    # build the base CLI command list; always request JSON output
    cmd = [AZ] + args + ["--output", "json"]
    if sub:
        # optional subscription scope
        cmd += ["--subscription", sub]

    logger.debug("az() invoking: %s", cmd)
    rc, stdout, stderr = _run_cmd_with_retries(cmd, timeout=timeout)
    if rc != 0:
        # propagate the error message to caller
        return rc, (stderr or "").strip()
    if not (stdout or "").strip():
        # some az commands legitimately return no body
        return 0, None
    try:
        # most callers expect parsed structures
        return 0, json.loads(stdout)
    except json.JSONDecodeError:
        # gracefully degrade to raw text if JSON is invalid
        return 0, stdout.strip()


def get_and_reset_rate_limit_retry_count() -> int:
    """Return and reset the transient retry counter.

    This exposes a lightweight signal to the orchestrator so it can adapt
    subscription-level concurrency when Azure starts throttling.
    """
    with _rate_limit_lock:
        global _rate_limit_retries
        count = _rate_limit_retries
        _rate_limit_retries = 0
        return count


def az_rest(url: str, timeout: int = 25) -> tuple[int, Any]:
    """Call an Azure REST or Microsoft Graph endpoint via ``az rest``.

    ``az rest`` is useful for APIs not yet exposed via the normal ``az``
    command hierarchy (for example Microsoft Graph or ARM preview APIs).  The
    return semantics mirror :func:`az`.
    """
    # unlike ``az`` this is a fixed command structure for REST calls
    cmd = [AZ, "rest", "--method", "get", "--url", url, "--output", "json"]
    rc, stdout, stderr = _run_cmd_with_retries(cmd, timeout=timeout)
    if rc != 0:
        return rc, (stderr or "").strip()
    if not (stdout or "").strip():
        return 0, None
    try:
        return 0, json.loads(stdout)
    except json.JSONDecodeError:
        return 0, stdout.strip()


def graph_query(query: str, sub_ids: list[str]) -> tuple[int, Any]:
    """Execute a Kusto query against Azure Resource Graph and return all results.

    Resource Graph enforces two limits:
    * at most 1000 rows per page, returned via a ``skipToken`` cursor
    * at most 10 subscription IDs per request

    This helper transparently follows the cursor until all records are
    retrieved, and loops over subscription batches when more than 10 IDs are
    provided.  Failures (CLI error, timeout, parse error) produce a nonzero
    return code and descriptive message.
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
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if r.returncode != 0:
                    return 1, r.stderr.strip()
                d = json.loads(r.stdout)
                all_data.extend(d.get("data", []))
                skip = d.get("skipToken")
                if not skip:
                    break
            except subprocess.TimeoutExpired:
                return 1, "Graph query timed out"
            except (json.JSONDecodeError, KeyError) as e:
                return 1, f"Parse error: {e}"

    return 0, all_data


# ---------------------------------------------------------------------------
# Permission/role helpers
# ---------------------------------------------------------------------------


def _upn_to_objectid(upn: str) -> str | None:
    """Convert a UPN to its Azure AD objectId.

    Useful when ``get_signed_in_user_id`` only manages to obtain a UPN.
    If the lookup fails (permissions, not found) ``None`` is returned.
    """
    rc, out = az(["ad", "user", "show", "--id", upn, "--query", "objectId", "-o", "tsv"])
    if rc == 0 and isinstance(out, str) and out:
        return out.strip()
    logger.debug("unable to resolve UPN to objectId: %s (rc=%d out=%r)", upn, rc, out)
    return None


def get_signed_in_user_id() -> str | None:
    """Return an Azure AD object ID for the signed-in user.

    This first attempts ``az ad signed-in-user show`` (recommended but requires
    Graph permissions).  If that fails we fall back to ``az account show`` to
    get the UPN and then try to look up the object ID via ``az ad user show``.
    The returned value is always an object ID when possible; only if both
    methods fail will a raw UPN be returned (and even then the caller may not
    be able to use it for role queries).

    ``None`` is returned if we cannot determine any identifier, which usually
    means the CLI is not authenticated.
    """
    rc, out = az(["ad", "signed-in-user", "show", "--query", "objectId", "-o", "tsv"])
    if rc == 0 and isinstance(out, str) and out:
        return out.strip()
    # try fallback to account show (UPN or service principal name)
    logger.debug("primary signed-in-user query failed (rc=%d), trying account show", rc)
    rc2, upn = az(["account", "show", "--query", "user.name", "-o", "tsv"])
    if rc2 == 0 and isinstance(upn, str) and upn:
        upn = upn.strip()
        obj = _upn_to_objectid(upn)
        if obj:
            return obj
        # return the UPN itself if we can't resolve the ID; role listing may
        # still work, but may miss inherited assignments (see docs).
        return upn
    logger.debug("fallback account show also failed: rc2=%d upn=%r", rc2, upn)
    return None


def list_role_names_for_user(
    user_id: str | None = None,
    subscription: str | None = None,
) -> tuple[int, Any]:
    """Return the names of roles assigned to the user (including inherited).

    When a GUID-like ``user_id`` is provided we first attempt the more
    specific query which mirrors the command you supplied in the issue:

      az role assignment list --assignee <user_id> --subscription <sub> \\
        --include-inherited --include-groups \\
        --query "[].roleDefinitionName"

    This ensures management-group scoped assignments (including group
    memberships) are discovered when the API returns them for the assignee.

    If that call fails (permission restrictions, UPN used instead of object
    id, or no GUID-like ID provided) we fall back to the reliable
    ``--all --include-inherited`` query which lists assignments visible to
    the signed-in CLI context.

    Returns a tuple of (return_code, roles_list) where roles_list contains
    role definition names (strings), or an error message on failure.
    """

    # Helper: simple GUID check
    def _looks_like_guid(s: str) -> bool:
        return bool(re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", str(s)))

    # 1) If we have any user_id at all, always scope with --assignee so we only
    #    get THIS user's roles.  --include-groups captures group-inherited
    #    assignments regardless of whether user_id is a GUID or UPN.
    if user_id:
        args = ["role", "assignment", "list", "--assignee", user_id, "--include-inherited", "--include-groups"]
        if subscription:
            args += ["--subscription", subscription]
        args += ["--query", "[].roleDefinitionName"]
        rc, out = az(args)
        if rc == 0:
            return 0, out or []
        logger.debug("assignee-scoped role query failed (rc=%d), falling back to --all: %r", rc, out)

    # 2) Last resort (no user_id or assignee query failed): list all assignments
    #    scoped to the subscription and filter by principalType so we at least
    #    narrow to user objects (still not user-specific, but better than nothing).
    args = [
        "role",
        "assignment",
        "list",
        "--all",
        "--include-inherited",
        "--query",
        "[?principalType=='User'].roleDefinitionName",
    ]
    if subscription:
        args += ["--subscription", subscription]
    rc, out = az(args)
    if rc != 0:
        return rc, out
    return 0, out or []


def check_user_permissions(sub_ids: list[str]) -> dict[str, Any]:
    """Run a preflight check on the signed-in user's permissions.

    This function checks whether the user has necessary roles to audit
    the provided subscriptions. It is advisory-only: checks that fail
    report warnings but do not block the audit from running.

    Returns a dict with keys:
      user_id: str or None (the resolved Azure AD object ID or UPN)
      roles: list of str (role names the user has)
      warnings: list of str (human-readable permission warnings)
      all_clear: bool (True if all critical roles are present)

    Returns all_clear=False if the user lacks Reader or a Security role.
    """
    warnings = []

    # Attempt to get the user's ID (for display purposes)
    user_id = get_signed_in_user_id()
    if not user_id:
        warnings.append("Could not determine user identity for permission checks")
        # Even if we can't get user_id, we can still list roles via --all fallback
        user_id = None

    # List the user's roles scoped to the subscriptions being audited.
    # Query per-subscription so we never pick up roles from unrelated subscriptions.
    all_roles: set[str] = set()
    role_sub_count: dict[str, int] = {}  # role name → number of subscriptions it appears in
    query_subs: list[str | None] = [*sub_ids] if sub_ids else [None]  # None → tenant-wide fallback
    total_subs = len(query_subs)
    last_error = None
    for sub in query_subs:
        rc, result = list_role_names_for_user(user_id, subscription=sub)
        if rc == 0 and isinstance(result, list):
            all_roles.update(result)
            for r in result:
                role_sub_count[r] = role_sub_count.get(r, 0) + 1
        elif rc != 0:
            last_error = result

    if not all_roles and last_error:
        warnings.append(f"Could not enumerate user roles: {last_error}")
        return {
            "user_id": user_id,
            "roles": [],
            "role_sub_count": {},
            "total_subs": total_subs,
            "warnings": warnings,
            "all_clear": False,
        }

    roles = sorted(all_roles)

    # Normalize role names to lowercase for comparison
    roles_lower = [r.lower() for r in roles]

    # Check for critical roles: Reader or higher (Contributor, Owner)
    has_reader = any(r in roles_lower for r in ["reader", "contributor", "owner", "user access administrator"])

    # Check for security-specific roles (Security Reader, Security Admin, etc.)
    has_security = any(r.startswith("security") for r in roles_lower)

    if not has_reader:
        warnings.append(
            "User does not have 'Reader' or higher role. " "Most audit checks require Reader access to subscriptions."
        )

    if not has_security:
        warnings.append(
            "User does not have a 'Security Reader' or 'Security Admin' role. "
            "Some security-specific checks (8.1, 8.2, etc.) may be skipped or show as ERROR."
        )

    return {
        "user_id": user_id,
        "roles": roles,
        "role_sub_count": role_sub_count,
        "total_subs": total_subs,
        "warnings": warnings,
        "all_clear": has_reader and has_security,
    }
