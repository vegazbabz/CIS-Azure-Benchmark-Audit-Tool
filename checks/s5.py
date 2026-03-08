"""
checks_s5.py — CIS Azure Benchmark Section 5 checks.

SECTION 5 — IDENTITY SERVICES
These checks target the Entra ID tenant and run ONCE (not per subscription).
Most use the Microsoft Graph API via az_rest rather than az CLI.
"""

from __future__ import annotations

from typing import Any

from cis.config import PASS, FAIL, INFO, ERROR, MANUAL, TIMEOUTS, ROLE_OWNER, ROLE_UAA, CALLER_TYPE
from cis.models import R
from cis.check_helpers import _err, _idx
from azure.helpers import az, az_rest, az_rest_paged
from azure.client import is_authz_error
from azure.graph_auth import is_configured as msal_is_configured, msal_rest


def check_5_1_1() -> R:
    """
    5.1.1 — Security defaults enabled in Microsoft Entra ID (Level 1)

    Security defaults provide a baseline level of security at no additional
    cost. They are designed for tenants that do NOT have Microsoft Entra ID
    P1/P2 licences and cannot use Conditional Access.

    Logic:
      1. Query identitySecurityDefaultsEnforcementPolicy → PASS if isEnabled=true
      2. If disabled, query conditionalAccessPolicies → INFO if at least one CA
         policy exists (tenant relies on CA instead, which is the stronger control)
      3. Neither enabled → FAIL (no baseline identity protection in place)

    Graph APIs used:
      GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy
      GET /v1.0/policies/conditionalAccessPolicies?$top=1
    """
    _CTRL = "5.1.1"
    _TITLE = "Security defaults enabled in Microsoft Entra ID"
    _SEC = "5 - Identity Services"

    url = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"

    if msal_is_configured():
        rc, data = msal_rest(url)
        if rc != 0:
            return R(
                _CTRL,
                _TITLE,
                1,
                _SEC,
                ERROR,
                f"Graph API call failed (MSAL): {str(data)[:200]}",
                "Verify the app registration has Policy.Read.All delegated permission and admin consent.",
            )
    else:
        rc, data = az_rest(url)
        if rc != 0:
            if is_authz_error(str(data)):
                if CALLER_TYPE == "servicePrincipal":
                    detail = (
                        "The service principal lacks the Policy.Read.All application permission. "
                        "Grant it in Entra ID → App registrations → API permissions, "
                        "or configure [graph_auth] in cis_audit.toml — see README."
                    )
                else:
                    detail = (
                        "The az CLI cannot request the Policy.Read.All scope — this is a "
                        "Microsoft limitation on the built-in az CLI app, and applies to all login types. "
                        "To automate this check, configure [graph_auth] in cis_audit.toml "
                        "with a dedicated app registration that has Policy.Read.All delegated permission "
                        "— see README for setup steps."
                    )
                return R(_CTRL, _TITLE, 1, _SEC, ERROR, detail, "")
            return _err(_CTRL, _TITLE, 1, _SEC, str(data))

    is_enabled = data.get("isEnabled", False) if isinstance(data, dict) else False
    if is_enabled:
        return R(_CTRL, _TITLE, 1, _SEC, PASS, "Security defaults are enabled.", "")

    # Security defaults are disabled — check whether Conditional Access is in use.
    # A tenant with CA policies disables security defaults intentionally; the
    # control goal (enforced sign-in security) is fulfilled by CA instead.
    rc_ca, ca_data = az_rest("https://graph.microsoft.com/v1.0/policies/conditionalAccessPolicies?$top=1")
    if rc_ca == 0 and isinstance(ca_data, dict) and ca_data.get("value"):
        return R(
            _CTRL,
            _TITLE,
            1,
            _SEC,
            INFO,
            "Security defaults disabled — tenant uses Conditional Access. "
            "Verify CA policies enforce MFA for all users.",
            "Verify Conditional Access policies enforce MFA for all users.",
        )

    return R(
        _CTRL,
        _TITLE,
        1,
        _SEC,
        FAIL,
        "Security defaults are disabled and no Conditional Access policies were found.",
        "Entra ID > Properties > Manage security defaults, or configure Conditional Access to enforce MFA.",
    )


def check_5_1_2() -> R:
    """
    5.1.2 — MFA enabled for all users (Level 1)

    Queries the Microsoft Graph beta authentication-methods registration
    report for ALL users (no admin filter).  Any user without
    ``isMfaRegistered = true`` is non-compliant.

    In large tenants this call may paginate across many pages; the timeout
    is set to TIMEOUTS["graph"] (120 s by default) to accommodate that.

    API:
      GET /beta/reports/authenticationMethods/userRegistrationDetails
          ?$select=userPrincipalName,isMfaRegistered

    Required Graph permission (application):
      UserAuthenticationMethod.Read.All  *or*  Reports.Read.All
    """
    _CTRL = "5.1.2"
    _TITLE = "MFA enabled for all users"
    _SEC = "5 - Identity Services"

    url = (
        "https://graph.microsoft.com/beta/reports/authenticationMethods/"
        "userRegistrationDetails?$select=userPrincipalName,isMfaRegistered"
    )
    rc, users = az_rest_paged(url, timeout=TIMEOUTS["graph"])
    if rc != 0:
        if CALLER_TYPE == "servicePrincipal":
            detail = (
                "Unable to retrieve MFA registration details — grant the service principal "
                "UserAuthenticationMethod.Read.All or Reports.Read.All application permission "
                "in Entra ID → App registrations → API permissions."
            )
        else:
            detail = (
                "Unable to retrieve MFA registration details — assign the signed-in account "
                "the Reports Reader or Global Reader role in Entra ID."
            )
        return _err(_CTRL, _TITLE, 1, _SEC, detail)

    without_mfa = [u.get("userPrincipalName") or u.get("id", "?") for u in users if not u.get("isMfaRegistered")]

    if not without_mfa:
        n = len(users)
        msg = f"All {n} user(s) have MFA registered." if n else "No users found."
        return R(_CTRL, _TITLE, 1, _SEC, PASS, msg, "")

    detail = f"{len(without_mfa)} user(s) without MFA registered."
    return R(
        _CTRL,
        _TITLE,
        1,
        _SEC,
        FAIL,
        detail,
        "Entra ID > Per-user MFA or Conditional Access > Require MFA for all users.",
    )


def check_5_1_3() -> R:
    """
    5.1.3 — Allow users to remember MFA on trusted devices is disabled (Manual, Level 1)

    The 'Allow users to remember multi-factor authentication on devices they
    trust' setting lets users skip MFA for up to 90 days on a trusted device.
    It is a legacy Per-user MFA feature (deprecated by Microsoft) and should
    be disabled. Tenants that have migrated to Conditional Access should
    enforce sign-in frequency instead.

    There is no stable Microsoft Graph API for this setting (it lives in the
    deprecated Per-user MFA portal), so this control cannot be automated.
    """
    return R(
        "5.1.3",
        "Allow users to remember MFA on trusted devices is disabled",
        1,
        "5 - Identity Services",
        MANUAL,
        "Manual verification required — setting is in the deprecated Per-user MFA portal.",
        "Disable 'Allow users to remember MFA on trusted devices' in the legacy MFA portal, "
        "or migrate to Conditional Access sign-in frequency policies.",
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

    Group assignments are counted as a single owner (the group object itself).
    When groups are detected, the details flag this so auditors can verify the
    true member count manually. Automatic group expansion is not performed
    because it requires additional Graph API permissions and nested groups
    require recursive traversal — the benchmark audit procedure itself counts
    role assignments, not individual members.
    """
    # Filter to Owner roles scoped exactly to this subscription
    owners = [
        a
        for a in _idx(td, "roles", sid)
        if ROLE_OWNER in a.get("roleDefinitionId", "")
        and a.get("scope", "").lower() in (f"/subscriptions/{sid.lower()}", f"/subscriptions/{sid}")
    ]

    n = len(owners)

    # Build a display label per assignment that includes the principal type
    # so auditors can immediately see which assignments are groups vs. users.
    def _label(o: dict[str, Any]) -> str:
        ptype = o.get("principalType", "").lower()
        name = o.get("principalName") or o.get("principalId", "?")
        if ptype == "group":
            return f"Group:{name}"
        if ptype == "serviceprincipal":
            return f"SP:{name}"
        return str(name)

    labels = [_label(o) for o in owners]
    has_groups = any(o.get("principalType", "").lower() == "group" for o in owners)

    details = f"Owner count: {n} — {labels}"
    if has_groups:
        details += " — group assignments detected: verify member count manually"

    if not 2 <= n <= 3:
        remediation = "Adjust Owner role assignments to have 2-3 owners."
    elif has_groups:
        remediation = (
            "Group assignments counted as 1 owner each — "
            "expand group memberships to confirm true owner count is 2-3."
        )
    else:
        remediation = ""

    return R(
        "5.27",
        "Between 2 and 3 subscription owners",
        1,
        "5 - Identity Services",
        PASS if 2 <= n <= 3 else FAIL,
        details,
        remediation,
        sid,
        sname,
    )
