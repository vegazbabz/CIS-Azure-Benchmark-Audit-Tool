"""az_identity.py — Azure identity lookup and permission preflight helpers.

Provides:
- get_signed_in_user_id()          — resolve caller's Azure AD object ID
- list_role_names_for_user(...)     — list RBAC role names for a user
- check_user_permissions(sub_ids)  — preflight gate used by the audit CLI
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from azure.client import az

_KEY_VAULT_DATA_PLANE_ROLE_PREFIXES = ("key vault",)
_STORAGE_DATA_PLANE_ROLE_PREFIXES = (
    "storage blob data",
    "storage file data",
    "storage queue data",
    "storage table data",
)
_STORAGE_DATA_PLANE_ROLES = frozenset({"storage account key operator service role"})

logger = logging.getLogger(__name__)


def _upn_to_objectid(upn: str) -> str | None:
    """Convert a UPN to its Azure AD object ID.

    Queries the full user object and checks both ``id`` (CLI ≥ 2.37) and
    the legacy ``objectId`` field so the function works across CLI versions.
    Returns ``None`` if the lookup fails (insufficient permissions, not found).
    """
    rc, out = az(["ad", "user", "show", "--id", upn])
    if rc == 0 and isinstance(out, dict):
        oid = out.get("id") or out.get("objectId")
        if oid and isinstance(oid, str):
            return str(oid.strip())
    logger.debug("unable to resolve UPN to objectId: %s (rc=%d out=%r)", upn, rc, out)
    return None


def get_signed_in_user_id() -> str | None:
    """Return an Azure AD object ID for the signed-in user.

    Checks both ``id`` (CLI ≥ 2.37) and the legacy ``objectId`` field so the
    function works across CLI versions.
    Falls back from ``az ad signed-in-user show`` → ``az account show`` →
    UPN-to-objectId resolution.  Returns ``None`` when unauthenticated.
    """
    rc, out = az(["ad", "signed-in-user", "show"])
    if rc == 0 and isinstance(out, dict):
        oid = out.get("id") or out.get("objectId")
        if oid and isinstance(oid, str):
            return str(oid.strip())
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
    scope: str | None = None,
) -> tuple[int, Any]:
    """Return the names of roles assigned to the user (including inherited).

    Uses ``--assignee`` scoping when a user_id is provided; falls back to
    ``--all --include-inherited`` filtered to User principal type.

    ``scope`` takes precedence over ``subscription`` when both are provided and
    is used to query a specific ARM scope (e.g. a management group).
    """

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
        if scope:
            args += ["--scope", scope]
        elif subscription:
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


def check_user_permissions(sub_ids: list[str], tenant_id: str | None = None) -> dict[str, Any]:
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
                # Deduplicate per subscription: the same role can appear multiple
                # times in a single result when it is assigned at several parent
                # scopes (e.g. once at the subscription level and again inherited
                # from a management group).  Count each role at most once per sub.
                for r in set(result):
                    role_sub_count[r] = role_sub_count.get(r, 0) + 1
            elif rc != 0:
                last_error = result
        pool.shutdown(wait=True)
    except KeyboardInterrupt:
        pool.shutdown(wait=False, cancel_futures=True)
        raise

    # Supplement with a tenant-root management-group scope query.
    # Per-subscription queries (even with --include-inherited) do not reliably
    # surface role assignments made at management-group scope via the ARM
    # subscription API.  Querying the root MG scope directly ensures those
    # assignments (e.g. Security Reader / Security Admin on Tenant Root Group)
    # are included in the permission summary.
    if user_id and sub_ids:
        tenant_id_raw: Any = tenant_id
        if not tenant_id_raw:
            _, tenant_id_raw = az(["account", "show", "--query", "tenantId"])
        if isinstance(tenant_id_raw, str) and tenant_id_raw.strip():
            mg_scope = f"/providers/Microsoft.Management/managementGroups/{tenant_id_raw.strip()}"
            rc_mg, result_mg = list_role_names_for_user(user_id, scope=mg_scope)
            if rc_mg == 0 and isinstance(result_mg, list):
                for r in set(result_mg):
                    if r not in all_roles:
                        # Role only visible at MG/tenant scope — it applies to
                        # all subscriptions beneath it.
                        role_sub_count[r] = total_subs
                all_roles.update(result_mg)

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
    has_key_vault_data_plane = any(r.startswith(_KEY_VAULT_DATA_PLANE_ROLE_PREFIXES) for r in roles_lower)
    has_storage_data_plane = any(
        r.startswith(_STORAGE_DATA_PLANE_ROLE_PREFIXES) or r in _STORAGE_DATA_PLANE_ROLES for r in roles_lower
    )

    if not has_reader:
        warnings.append(
            "User does not have 'Reader' or higher role. " "Most audit checks require Reader access to subscriptions."
        )

    if not has_security:
        warnings.append(
            "User does not have a 'Security Reader' or 'Security Admin' role. "
            "Some security-specific checks (8.1, 8.2, etc.) may be skipped or show as ERROR."
        )

    if not has_key_vault_data_plane or not has_storage_data_plane:
        missing = []
        if not has_key_vault_data_plane:
            missing.append("Key Vault data-plane")
        if not has_storage_data_plane:
            missing.append("Storage data-plane")
        warnings.append(
            "No recognized " + " or ".join(missing) + " role was found in enumerated role assignments. "
            "Control-plane Reader access is enough to run most checks, but Key Vault key/secret/certificate "
            "and storage service data-plane checks may report ERROR until the audit identity has matching data-plane "
            "RBAC roles or Key Vault access policies."
        )

    return {
        "user_id": user_id,
        "roles": roles,
        "role_sub_count": role_sub_count,
        "total_subs": total_subs,
        "warnings": warnings,
        "all_clear": has_reader and has_security,
    }
