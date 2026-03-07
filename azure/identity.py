"""az_identity.py — Azure identity lookup and permission preflight helpers.

Provides:
- get_signed_in_user_id()          — resolve caller's Azure AD object ID
- list_role_names_for_user(...)     — list RBAC role names for a user
- check_user_permissions(sub_ids)  — preflight gate used by the audit CLI
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from azure.client import az

logger = logging.getLogger(__name__)


def _upn_to_objectid(upn: str) -> str | None:
    """Convert a UPN to its Azure AD objectId.

    Returns ``None`` if the lookup fails (permissions, not found).
    """
    rc, out = az(["ad", "user", "show", "--id", upn, "--query", "objectId"])
    if rc == 0 and isinstance(out, str) and out:
        return out.strip()
    logger.debug("unable to resolve UPN to objectId: %s (rc=%d out=%r)", upn, rc, out)
    return None


def get_signed_in_user_id() -> str | None:
    """Return an Azure AD object ID for the signed-in user.

    Falls back from ``az ad signed-in-user show`` → ``az account show`` →
    UPN-to-objectId resolution.  Returns ``None`` when unauthenticated.
    """
    rc, out = az(["ad", "signed-in-user", "show", "--query", "objectId"])
    if rc == 0 and isinstance(out, str) and out:
        return out.strip()
    logger.debug("primary signed-in-user query failed (rc=%d), trying account show", rc)
    rc2, upn = az(["account", "show", "--query", "user.name"])
    if rc2 == 0 and isinstance(upn, str) and upn:
        upn = upn.strip()
        obj = _upn_to_objectid(upn)
        if obj:
            return obj
        return upn
    logger.debug("fallback account show also failed: rc2=%d upn=%r", rc2, upn)
    return None


def list_role_names_for_user(
    user_id: str | None = None,
    subscription: str | None = None,
) -> tuple[int, Any]:
    """Return the names of roles assigned to the user (including inherited).

    Uses ``--assignee`` scoping when a user_id is provided; falls back to
    ``--all --include-inherited`` filtered to User principal type.
    """

    def _looks_like_guid(s: str) -> bool:
        return bool(
            re.match(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                str(s),
            )
        )

    if user_id:
        args = [
            "role",
            "assignment",
            "list",
            "--assignee",
            user_id,
            "--include-inherited",
            "--include-groups",
        ]
        if subscription:
            args += ["--subscription", subscription]
        args += ["--query", "[].roleDefinitionName"]
        rc, out = az(args)
        if rc == 0:
            return 0, out or []
        logger.debug("assignee-scoped role query failed (rc=%d), falling back to --all: %r", rc, out)

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

    Returns a dict with keys: user_id, roles, role_sub_count, total_subs,
    warnings, all_clear.
    """
    warnings: list[str] = []

    user_id = get_signed_in_user_id()
    if not user_id:
        warnings.append("Could not determine user identity for permission checks")
        user_id = None

    all_roles: set[str] = set()
    role_sub_count: dict[str, int] = {}
    query_subs: list[str | None] = [*sub_ids] if sub_ids else [None]
    total_subs = len(query_subs)
    last_error = None

    max_workers = min(8, max(1, total_subs))
    pool = ThreadPoolExecutor(max_workers=max_workers)
    try:
        futures = {pool.submit(list_role_names_for_user, user_id, sub): sub for sub in query_subs}
        for future in as_completed(futures):
            rc, result = future.result()
            if rc == 0 and isinstance(result, list):
                all_roles.update(result)
                for r in result:
                    role_sub_count[r] = role_sub_count.get(r, 0) + 1
            elif rc != 0:
                last_error = result
        pool.shutdown(wait=True)
    except KeyboardInterrupt:
        pool.shutdown(wait=False, cancel_futures=True)
        raise

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
    roles_lower = [r.lower() for r in roles]

    has_reader = any(r in roles_lower for r in ["reader", "contributor", "owner", "user access administrator"])
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
