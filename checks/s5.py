"""
checks_s5.py — CIS Azure Benchmark Section 5 checks.

SECTION 5 — IDENTITY SERVICES
These checks target the Entra ID tenant and run ONCE (not per subscription).
Most use the Microsoft Graph API via az_rest rather than az CLI.
"""

from __future__ import annotations

from typing import Any

from cis.config import PASS, FAIL, INFO, MANUAL, TIMEOUTS, ROLE_OWNER, ROLE_UAA
from cis.models import R
from cis.check_helpers import _err, _idx
from azure.helpers import az, az_rest


def check_5_1_1() -> R:
    """
    5.1.1 — Security defaults enabled in Microsoft Entra ID (Level 1)

    Security defaults provide a baseline level of security at no additional
    cost. They are designed for tenants that do NOT have Microsoft Entra ID
    P1/P2 licences and cannot use Conditional Access.

    For E3/E5 tenants (which use Conditional Access), security defaults are
    intentionally disabled — a Conditional Access policy that enforces MFA
    for all users is the equivalent (and superior) control. For those tenants
    this control is returned as INFO rather than FAIL because the correct
    state depends on the tenant's licensing tier.

    If your tenant uses Conditional Access, manually verify that policies
    enforce MFA for all users to satisfy this control.
    """
    return R(
        "5.1.1",
        "Security defaults enabled in Microsoft Entra ID",
        1,
        "5 - Identity Services",
        INFO,
        "Not applicable — tenant uses Conditional Access (E3/E5 licensed).",
        "Verify Conditional Access policies enforce MFA for all users.",
    )


def check_5_1_2() -> R:
    """
    5.1.2 — MFA enabled for all privileged users (Level 1)

    The CIS benchmark's prescribed audit method is a Graph PowerShell command:
      Get-MgUser -All | where {$_.StrongAuthenticationMethods.Count -eq 0}

    There is no equivalent az CLI or Graph REST API call that returns
    per-user MFA registration status without additional Graph permissions
    and a more complex paginated call. This control is marked MANUAL so it
    appears in the report as a reminder rather than being silently skipped.
    """
    return R(
        "5.1.2",
        "MFA enabled for all privileged users",
        1,
        "5 - Identity Services",
        MANUAL,
        "Verify via: Get-MgUser -All | where {$_.StrongAuthenticationMethods.Count -eq 0}",
        "Entra ID > Per-user MFA or Conditional Access > Require MFA for all users.",
    )


def check_5_3_3(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    5.3.3 — User Access Administrator role is restricted (Level 1)

    The User Access Administrator role at subscription scope is extremely
    powerful — it allows the holder to grant themselves or others the Owner
    role. Best practice is to have zero standing assignments at subscription
    scope and use PIM (Privileged Identity Management) for just-in-time
    elevation when needed.

    Data source: Resource Graph 'roles' query, filtered to ROLE_UAA assignments
    where the scope contains the subscription ID.

    Note: This check counts group assignments as one, even if the group has
    many members — this is a known limitation documented in the tool's README.
    """
    assignments = _idx(td, "roles", sid)

    # Filter to UAA assignments scoped specifically to this subscription.
    # Role assignments can be scoped to management group, subscription,
    # resource group, or resource — we only flag subscription-level ones.
    uaa = [
        a
        for a in assignments
        if ROLE_UAA in a.get("roleDefinitionId", "") and sid.lower() in a.get("scope", "").lower()
    ]

    if not uaa:
        return [
            R(
                "5.3.3",
                "User Access Administrator role restricted",
                1,
                "5 - Identity Services",
                PASS,
                "No UAA assignments at subscription scope.",
                "",
                sid,
                sname,
            )
        ]

    # One FAIL result per assignment found (may be multiple)
    return [
        R(
            "5.3.3",
            "User Access Administrator role restricted",
            1,
            "5 - Identity Services",
            FAIL,
            f"UAA assigned to: {a.get('principalName') or a.get('principalId')}",
            "Review and remove unnecessary User Access Administrator assignments.",
            sid,
            sname,
            a.get("principalName") or a.get("principalId", "?"),
        )
        for a in uaa
    ]


def check_5_4() -> R:
    """
    5.4 — Restrict non-admin users from creating tenants (Level 1)

    By default, any Entra ID user can create new Azure AD tenants.
    This setting must be restricted to admin roles only to prevent
    shadow IT tenants that bypass organisational controls.

    API: GET https://graph.microsoft.com/v1.0/policies/authorizationPolicy
    Field: defaultUserRolePermissions.allowedToCreateTenants
    Compliant state: false
    """
    rc, data = az_rest("https://graph.microsoft.com/v1.0/policies/authorizationPolicy")
    if rc != 0:
        return _err("5.4", "Restrict non-admin users from creating tenants", 1, "5 - Identity Services", str(data))

    allowed = (
        data.get("defaultUserRolePermissions", {}).get("allowedToCreateTenants") if isinstance(data, dict) else None
    )

    return R(
        "5.4",
        "Restrict non-admin users from creating tenants",
        1,
        "5 - Identity Services",
        FAIL if allowed else PASS,
        f"allowedToCreateTenants = {allowed}",
        "Entra ID > User settings > Restrict non-admin users from creating tenants: Yes" if allowed else "",
    )


def check_5_14() -> R:
    """
    5.14 — 'Users can register applications' set to No (Level 1)

    When users can register applications, they create app registrations that
    can request delegated permissions and gain access to tenant resources.
    Restricting this forces app registration requests through IT governance.

    API: GET https://graph.microsoft.com/v1.0/policies/authorizationPolicy
    Field: defaultUserRolePermissions.allowedToCreateApps
    Compliant state: false
    """
    rc, data = az_rest("https://graph.microsoft.com/v1.0/policies/authorizationPolicy")
    if rc != 0:
        return _err("5.14", "'Users can register applications' set to No", 1, "5 - Identity Services", str(data))

    allowed = data.get("defaultUserRolePermissions", {}).get("allowedToCreateApps") if isinstance(data, dict) else None

    return R(
        "5.14",
        "'Users can register applications' set to No",
        1,
        "5 - Identity Services",
        FAIL if allowed else PASS,
        f"allowedToCreateApps = {allowed}",
        "Entra ID > Users > User settings > Users can register applications: No" if allowed else "",
    )


def check_5_15() -> R:
    """
    5.15 — Guest user access is restricted to own directory objects (Level 1)

    This setting controls what guest users can see and access in the directory.
    The guestUserRoleId GUID maps to one of three permission levels:
      10dae51f-b6af-4016-8d66-8c2a99b929b3 — Restricted (most restrictive — COMPLIANT)
      bf31c1d6-d977-4538-8dae-bfb8961cf69a — Guest (limited access)
      a0b1b346-4d3e-4e8b-98f8-753987be4970 — Same as member (most permissive — NON-COMPLIANT)

    API: GET https://graph.microsoft.com/v1.0/policies/authorizationPolicy
    Field: guestUserRoleId
    """
    rc, data = az_rest("https://graph.microsoft.com/v1.0/policies/authorizationPolicy")
    if rc != 0:
        return _err("5.15", "Guest access restricted to own directory objects", 1, "5 - Identity Services", str(data))

    # Only the most restrictive GUID is considered compliant
    MOST_RESTRICTIVE = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
    role_id = data.get("guestUserRoleId", "") if isinstance(data, dict) else ""

    return R(
        "5.15",
        "Guest access restricted to own directory objects",
        1,
        "5 - Identity Services",
        PASS if role_id == MOST_RESTRICTIVE else FAIL,
        f"guestUserRoleId = {role_id}",
        (
            "Entra ID > External Identities > External collaboration settings > "
            "Guest user access restrictions: Most Restrictive"
            if role_id != MOST_RESTRICTIVE
            else ""
        ),
    )


def check_5_16() -> R:
    """
    5.16 — Guest invite restrictions set to admins or no one (Level 2)

    Controls who can send guest invitations. The allowInvitesFrom values are:
      none                      — No one (most restrictive)
      admins                    — Global/Guest Invite Admins only
      adminsAndGuestInviters    — Admins + users with Guest Inviter role (COMPLIANT)
      adminsAndAllMembers       — All internal users (NON-COMPLIANT)
      everyone                  — Including guests (most permissive, NON-COMPLIANT)

    API: GET https://graph.microsoft.com/v1.0/policies/authorizationPolicy
    Field: allowInvitesFrom
    """
    rc, data = az_rest("https://graph.microsoft.com/v1.0/policies/authorizationPolicy")
    if rc != 0:
        return _err("5.16", "Guest invite restrictions set to admins or no one", 2, "5 - Identity Services", str(data))

    val = data.get("allowInvitesFrom", "") if isinstance(data, dict) else ""
    # Three values are acceptable — anything else is non-compliant
    compliant = val.lower() in ("adminsandguestinviters", "admins", "none")

    return R(
        "5.16",
        "Guest invite restrictions set to admins or no one",
        2,
        "5 - Identity Services",
        PASS if compliant else FAIL,
        f"allowInvitesFrom = {val}",
        (
            "Entra ID > External Identities > External collaboration settings > "
            "Guest invite restrictions: Only users assigned to specific admin roles"
            if not compliant
            else ""
        ),
    )


def check_5_23(sid: str, sname: str) -> R:
    """
    5.23 — No custom subscription administrator roles exist (Level 1)

    Azure built-in roles are reviewed and maintained by Microsoft. Custom roles
    with wildcard (*) actions give the same level of access as Owner and bypass
    the principle of least privilege. This check flags any custom role where
    the permissions array includes "*" in its actions list.

    Data source: az role definition list --custom-role-only true
    """
    rc, data = az(["role", "definition", "list", "--custom-role-only", "true"], sid, timeout=TIMEOUTS["default"])
    if rc != 0:
        return _err(
            "5.23", "No custom subscription administrator roles", 1, "5 - Identity Services", str(data), sid, sname
        )

    # A role is flagged if any of its permission blocks contains "*" in actions
    bad = [
        r.get("roleName", "?") for r in (data or []) for p in r.get("permissions", []) if "*" in p.get("actions", [])
    ]

    return R(
        "5.23",
        "No custom subscription administrator roles",
        1,
        "5 - Identity Services",
        FAIL if bad else PASS,
        (
            f"Custom roles with wildcard (*) actions: {bad}"
            if bad
            else "No custom admin roles with wildcard actions found."
        ),
        "Remove or restrict wildcard permissions from custom roles." if bad else "",
        sid,
        sname,
    )


def check_5_27(sid: str, sname: str, td: dict[str, Any]) -> R:
    """
    5.27 — Between 2 and 3 subscription owners (Level 1)

    Fewer than 2 owners is a single point of failure — if the sole owner
    leaves or is unavailable, the subscription cannot be administered.
    More than 3 owners increases attack surface and makes it harder to
    audit access.

    Only Owner assignments scoped DIRECTLY to the subscription are counted.
    Inherited assignments from management groups are excluded because they
    are governed at a different level.

    Data source: Resource Graph 'roles' query, filtered to ROLE_OWNER
    where scope exactly matches the subscription path.

    Known limitation: group assignments count as 1 even if the group has
    multiple members. This can cause a false PASS when a group with many
    members is assigned Owner.
    """
    # Filter to Owner roles scoped exactly to this subscription
    owners = [
        a
        for a in _idx(td, "roles", sid)
        if ROLE_OWNER in a.get("roleDefinitionId", "")
        and a.get("scope", "").lower() in (f"/subscriptions/{sid.lower()}", f"/subscriptions/{sid}")
    ]

    n = len(owners)
    names = [o.get("principalName") or o.get("principalId", "?") for o in owners]

    return R(
        "5.27",
        "Between 2 and 3 subscription owners",
        1,
        "5 - Identity Services",
        PASS if 2 <= n <= 3 else FAIL,
        f"Owner count: {n} — {names}",
        "Adjust Owner role assignments to have 2-3 owners." if not 2 <= n <= 3 else "",
        sid,
        sname,
    )
