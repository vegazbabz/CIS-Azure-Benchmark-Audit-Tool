"""
checks_s6.py — CIS Azure Benchmark Section 6 checks.

SECTION 6 — MANAGEMENT & GOVERNANCE (MONITORING)
"""

from __future__ import annotations

from typing import Any

from cis.config import PASS, FAIL, INFO, TIMEOUTS
from cis.models import R
from cis.check_helpers import _err, _idx, _info
from azure.helpers import az, az_rest


def check_6_1_1_1(sid: str, sname: str) -> R:
    """
    6.1.1.1 — A Diagnostic Setting exists for Subscription Activity Logs (Level 1)

    Subscription Activity Logs record all control-plane operations: who created,
    deleted, or modified resources, and when. Without a diagnostic setting
    forwarding these logs, they are only retained for 90 days and cannot be
    queried in bulk by SIEM tools.

    Data source: az monitor diagnostic-settings subscription list
    This is a subscription-scoped call (not resource-scoped), so it returns
    settings configured at the subscription level rather than on individual
    resources.
    """
    # Note: --subscription must be passed as a positional arg here, not via
    # the sub parameter of az(), because this command has its own --subscription
    rc, data = az(
        ["monitor", "diagnostic-settings", "subscription", "list", "--subscription", sid], timeout=TIMEOUTS["default"]
    )
    if rc != 0:
        return _err(
            "6.1.1.1",
            "Diagnostic Setting for Subscription Activity Logs",
            1,
            "6 - Management & Governance",
            str(data),
            sid,
            sname,
        )

    settings = data if isinstance(data, list) else (data or {}).get("value", [])

    return R(
        "6.1.1.1",
        "Diagnostic Setting for Subscription Activity Logs",
        1,
        "6 - Management & Governance",
        PASS if settings else FAIL,
        f"Found {len(settings)} diagnostic setting(s)." if settings else "No subscription diagnostic settings found.",
        "Monitor > Activity Log > Export Activity Logs > Add diagnostic setting" if not settings else "",
        sid,
        sname,
    )


def check_6_1_1_2(sid: str, sname: str) -> R:
    """
    6.1.1.2 — Diagnostic Setting captures required log categories (Level 1)

    Even when a diagnostic setting exists, it must capture the four categories
    that contain security-relevant events:
      Administrative — resource creation/deletion/modification events
      Alert          — Azure Monitor alert firings
      Policy         — Azure Policy evaluation results
      Security       — Microsoft Defender for Cloud alerts

    This check reads all enabled log categories across all diagnostic settings
    and fails if any of the four required categories is absent.

    Data source: same endpoint as check_6_1_1_1.
    """
    rc, data = az(
        ["monitor", "diagnostic-settings", "subscription", "list", "--subscription", sid], timeout=TIMEOUTS["default"]
    )
    if rc != 0:
        return _err(
            "6.1.1.2",
            "Diagnostic Setting captures required log categories",
            1,
            "6 - Management & Governance",
            str(data),
            sid,
            sname,
        )

    settings = data if isinstance(data, list) else (data or {}).get("value", [])
    required = {"security", "administrative", "alert", "policy"}

    # Collect all enabled categories across all diagnostic settings
    found = {log.get("category", "").lower() for s in settings for log in s.get("logs", []) if log.get("enabled")}

    missing = required - found

    return R(
        "6.1.1.2",
        "Diagnostic Setting captures required log categories",
        1,
        "6 - Management & Governance",
        PASS if not missing else FAIL,
        (
            f"Missing categories: {sorted(missing)}"
            if missing
            else "All required categories enabled (Security/Administrative/Alert/Policy)."
        ),
        "Enable missing categories in subscription diagnostic settings." if missing else "",
        sid,
        sname,
    )


def check_6_1_1_3(sid: str, sname: str) -> R:
    """
    6.1.1.3 — Activity log retention >= 365 days (Level 1)

    Classic log profiles are the legacy mechanism for controlling activity log
    retention.  Modern Azure deployments use diagnostic settings instead, but
    the CIS benchmark still checks log profiles for backwards compatibility.

    Data source: az monitor log-profiles list --subscription <sid>
    A log profile with retentionPolicy.enabled == true must have days >= 365
    (or 0, which means infinite retention).  If retention is disabled entirely
    or no log profile exists at all, the check fails.
    """
    rc, data = az(
        ["monitor", "log-profiles", "list", "--subscription", sid], timeout=TIMEOUTS["default"]
    )
    if rc != 0:
        return _err(
            "6.1.1.3",
            "Activity log retention >= 365 days",
            1,
            "6 - Management & Governance",
            str(data),
            sid,
            sname,
        )

    profiles = data if isinstance(data, list) else []

    if not profiles:
        return R(
            "6.1.1.3",
            "Activity log retention >= 365 days",
            1,
            "6 - Management & Governance",
            FAIL,
            "No activity log profile found. Retention not configured.",
            "Monitor > Activity Log > Export Activity Log > Add diagnostic setting with retention >= 365 days",
            sid,
            sname,
        )

    profile = profiles[0]
    ret_policy = profile.get("retentionPolicy") or {}
    enabled = ret_policy.get("enabled", False)
    days = int(ret_policy.get("days", 0))
    # Compliant if retention is disabled (infinite) or days >= 365
    compliant = not enabled or days >= 365

    return R(
        "6.1.1.3",
        "Activity log retention >= 365 days",
        1,
        "6 - Management & Governance",
        PASS if compliant else FAIL,
        f"Retention: {days} days (enabled: {enabled}).",
        "Monitor > Activity Log > Export > Retention >= 365 days" if not compliant else "",
        sid,
        sname,
    )


def check_6_1_1_4(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    6.1.1.4 — Key Vault diagnostic logging is enabled (Level 1)

    Each Key Vault must have a diagnostic setting that captures audit logs.
    Audit logs record every data-plane operation: who accessed a secret,
    which key was used for an operation, when certificates were listed.
    This is critical evidence for security incidents involving vault access.

    Accepted log category names: "audit" or "allLogs" (category group).
    Either satisfies the requirement.

    Data source: az monitor diagnostic-settings list --resource <vault_id>
    Vault IDs come from the Resource Graph 'keyvaults' query.
    """
    vaults = _idx(td, "keyvaults", sid)
    if not vaults:
        return [
            _info(
                "6.1.1.4",
                "Key Vault diagnostic logging enabled",
                1,
                "6 - Management & Governance",
                "No Key Vaults found.",
                sid,
                sname,
            )
        ]

    results = []
    for v in vaults:
        vid, vname = v.get("id"), v.get("name", "?")
        rc, diag = az(["monitor", "diagnostic-settings", "list", "--resource", vid], sid, timeout=TIMEOUTS["default"])
        if rc != 0:
            results.append(
                _err(
                    "6.1.1.4",
                    "Key Vault diagnostic logging enabled",
                    1,
                    "6 - Management & Governance",
                    str(diag),
                    sid,
                    sname,
                )
            )
            continue

        diag_list = diag if isinstance(diag, list) else (diag or {}).get("value", [])

        # Check for audit category OR allLogs category group across all settings.
        # categoryGroup is a newer field that supersedes individual categories.
        enabled = any(
            log.get("enabled") and log.get("categoryGroup", log.get("category", "")).lower() in ("audit", "alllogs")
            for s in diag_list
            for log in s.get("logs", [])
        )

        results.append(
            R(
                "6.1.1.4",
                "Key Vault diagnostic logging enabled",
                1,
                "6 - Management & Governance",
                PASS if enabled else FAIL,
                f"Vault '{vname}': audit logging {'enabled' if enabled else 'NOT enabled'}.",
                "Key Vault > Diagnostic settings > Enable audit/allLogs" if not enabled else "",
                sid,
                sname,
                vname if not enabled else "",
            )
        )

    return results


def check_6_1_1_6(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    6.1.1.6 — App Service resource logs enabled (Level 2)

    The CIS benchmark does not prescribe a specific CLI audit command for this
    control. This implementation mirrors the logic of the Azure built-in policy
    "App Service apps should have resource logs enabled"
    (policy ID: 91a78b24-f231-4a8a-8da9-02c35b2b6510).

    SCOPE — Function apps are excluded, matching the policy condition:
      kind notContains "functionapp"
    Only standard web apps (App Service) are evaluated.

    COMPLIANCE CONDITION — At least one diagnostic log entry must satisfy
    EITHER of the two branches defined in the policy's existenceCondition:

      Branch A (retention enforced):
        log.enabled == true
        AND retentionPolicy.enabled == true
        AND retentionPolicy.days == 0 (infinite) OR >= 365 days

      Branch B (no storage account — e.g. Log Analytics destination):
        log.enabled == true
        AND (retentionPolicy.enabled != true OR no storageAccountId configured)

    In practice: any enabled log entry that is either going to Log Analytics
    (no retention policy required) OR to a storage account with >= 365-day
    retention satisfies the control.

    Note: The policy checks for ANY enabled log category — not just HTTP logs.
    The CIS control title says "HTTP logs" but the underlying policy audits
    resource logs broadly. This implementation follows the policy, not the title.

    Data source: az monitor diagnostic-settings list --resource <app_id>
    App IDs come from the Resource Graph 'app_services' query (kind field added
    so function apps can be filtered out here).
    """
    all_apps = _idx(td, "app_services", sid)
    if not all_apps:
        return [
            _info(
                "6.1.1.6",
                "App Service resource logs enabled",
                2,
                "6 - Management & Governance",
                "No App Services found.",
                sid,
                sname,
            )
        ]

    # Exclude function apps — the Azure policy explicitly scopes to
    # Microsoft.Web/sites where kind does NOT contain "functionapp"
    apps = [a for a in all_apps if "functionapp" not in str(a.get("kind", "")).lower()]

    if not apps:
        return [
            _info(
                "6.1.1.6",
                "App Service resource logs enabled",
                2,
                "6 - Management & Governance",
                f"No standard App Services found ({len(all_apps)} function app(s) excluded).",
            )
        ]

    REQUIRED_RETENTION = 365  # Days required when logs go to a storage account

    results = []
    for app in apps:
        aname = app.get("name", "?")
        aid = app.get("id")
        kind = app.get("kind", "web")

        rc, diag = az(["monitor", "diagnostic-settings", "list", "--resource", aid], sid, timeout=TIMEOUTS["default"])
        if rc != 0:
            results.append(
                _err(
                    "6.1.1.6",
                    "App Service resource logs enabled",
                    2,
                    "6 - Management & Governance",
                    str(diag),
                    sid,
                    sname,
                    aname,
                )
            )
            continue

        diag_list = diag if isinstance(diag, list) else (diag or {}).get("value", [])

        # Evaluate each diagnostic setting against the two-branch policy condition
        compliant = False
        compliant_setting = None

        for setting in diag_list:
            has_storage = bool(setting.get("storageAccountId"))

            for log in setting.get("logs", []):
                if not log.get("enabled"):
                    continue  # Log category not enabled — skip

                ret_policy = log.get("retentionPolicy") or {}
                ret_enabled = bool(ret_policy.get("enabled", False))
                ret_days = int(ret_policy.get("days", 0))

                # Branch A: retention enforced, days == 0 (infinite) or >= 365
                if ret_enabled and (ret_days == 0 or ret_days >= REQUIRED_RETENTION):
                    compliant = True
                    compliant_setting = setting.get("name", "?")
                    break

                # Branch B: no storage account, so no retention policy needed
                # (logs going to Log Analytics workspace or Event Hub)
                if not has_storage:
                    compliant = True
                    compliant_setting = setting.get("name", "?")
                    break

                # Branch B also fires when retention policy is not enforced
                # even if a storage account exists
                if not ret_enabled:
                    compliant = True
                    compliant_setting = setting.get("name", "?")
                    break

            if compliant:
                break

        if compliant:
            results.append(
                R(
                    "6.1.1.6",
                    "App Service resource logs enabled",
                    2,
                    "6 - Management & Governance",
                    PASS,
                    f"App '{aname}' (kind: {kind}): " f"compliant diagnostic setting '{compliant_setting}' found.",
                    "",
                    sid,
                    sname,
                    aname,
                )
            )
        elif diag_list:
            # Settings exist but none satisfy the retention condition
            categories = [
                log.get("category") or log.get("categoryGroup", "?")
                for s in diag_list
                for log in s.get("logs", [])
                if log.get("enabled")
            ]
            results.append(
                R(
                    "6.1.1.6",
                    "App Service resource logs enabled",
                    2,
                    "6 - Management & Governance",
                    FAIL,
                    f"App '{aname}' (kind: {kind}): diagnostic settings exist but "
                    f"no log meets the retention requirement (>= {REQUIRED_RETENTION} days "
                    f"or Log Analytics destination). Enabled categories: {categories or 'none'}.",
                    "App Service > Monitoring > Diagnostic settings > "
                    "Ensure logs are sent to Log Analytics, or set storage retention >= 365 days.",
                    sid,
                    sname,
                    aname,
                )
            )
        else:
            # No diagnostic settings at all
            results.append(
                R(
                    "6.1.1.6",
                    "App Service resource logs enabled",
                    2,
                    "6 - Management & Governance",
                    FAIL,
                    f"App '{aname}' (kind: {kind}): no diagnostic settings configured.",
                    "App Service > Monitoring > Diagnostic settings > Add diagnostic setting > "
                    "Enable resource logs and send to Log Analytics workspace.",
                    sid,
                    sname,
                    aname,
                )
            )

    return results


def check_6_1_2_alerts(sid: str, sname: str) -> list[R]:
    """
    6.1.2.1–6.1.2.11 — Activity Log Alerts for critical operations (Level 1)

    Azure Activity Log Alerts fire when a specified operation occurs on a
    subscription. These 11 alerts cover operations that could indicate
    configuration tampering, privilege escalation, or security control removal.

    The list of required operation names comes directly from the CIS benchmark
    PDF — each corresponds to an Azure Resource Manager operation type.

    Implementation approach:
      1. Fetch all activity log alerts for the subscription in one call.
      2. For each required operation, scan the allOf conditions in all alerts
         to find one that matches by operationName.
      3. Control 6.1.2.11 uses category = "ServiceHealth" instead of
         operationName — it is handled separately after the main loop.

    Data source: az monitor activity-log alert list
    """
    rc, data = az(["monitor", "activity-log", "alert", "list"], sid, timeout=TIMEOUTS["default"])
    # If the call fails, continue with an empty list — all checks will FAIL
    alerts = data if (rc == 0 and isinstance(data, list)) else []

    # (control_id, display_title, operation_name_to_match_lowercase)
    required = [
        ("6.1.2.1", "Activity Log Alert: Create Policy Assignment", "microsoft.authorization/policyassignments/write"),
        ("6.1.2.2", "Activity Log Alert: Delete Policy Assignment", "microsoft.authorization/policyassignments/delete"),
        ("6.1.2.3", "Activity Log Alert: Create or Update NSG", "microsoft.network/networksecuritygroups/write"),
        ("6.1.2.4", "Activity Log Alert: Delete NSG", "microsoft.network/networksecuritygroups/delete"),
        (
            "6.1.2.5",
            "Activity Log Alert: Create or Update Security Solution",
            "microsoft.security/securitysolutions/write",
        ),
        ("6.1.2.6", "Activity Log Alert: Delete Security Solution", "microsoft.security/securitysolutions/delete"),
        (
            "6.1.2.7",
            "Activity Log Alert: Create or Update SQL Firewall Rule",
            "microsoft.sql/servers/firewallrules/write",
        ),
        ("6.1.2.8", "Activity Log Alert: Delete SQL Firewall Rule", "microsoft.sql/servers/firewallrules/delete"),
        ("6.1.2.9", "Activity Log Alert: Create or Update Public IP", "microsoft.network/publicipaddresses/write"),
        ("6.1.2.10", "Activity Log Alert: Delete Public IP", "microsoft.network/publicipaddresses/delete"),
    ]

    results = []
    for ctrl, title, op in required:
        # An alert is compliant if ANY alert has a condition block with
        # field == "operationName" and equals == the target operation (case-insensitive)
        found = any(
            cond.get("field") == "operationName" and cond.get("equals", "").lower() == op
            for alert in alerts
            for cond in alert.get("condition", {}).get("allOf", [])
        )

        results.append(
            R(
                ctrl,
                title,
                1,
                "6 - Management & Governance",
                PASS if found else FAIL,
                f"Alert for '{op}' {'found' if found else 'NOT found'}.",
                f"Monitor > Alerts > Create activity log alert > Operation name: {op}" if not found else "",
                sid,
                sname,
            )
        )

    # 6.1.2.11 — Service Health uses the "category" field, not "operationName"
    sh_found = any(
        cond.get("field") == "category" and cond.get("equals", "").lower() == "servicehealth"
        for alert in alerts
        for cond in alert.get("condition", {}).get("allOf", [])
    )

    results.append(
        R(
            "6.1.2.11",
            "Activity Log Alert: Service Health",
            1,
            "6 - Management & Governance",
            PASS if sh_found else FAIL,
            "Service Health activity alert found." if sh_found else "No Service Health activity alert found.",
            "Monitor > Alerts > Create alert > Category = ServiceHealth" if not sh_found else "",
            sid,
            sname,
        )
    )

    return results


def check_6_1_3_1(sid: str, sname: str) -> R:
    """
    6.1.3.1 — Application Insights is configured (Level 2)

    Application Insights provides application-level monitoring including
    request tracing, dependency tracking, exception logging, and custom
    telemetry. The presence of at least one component in the subscription
    is sufficient for this control.

    Data source: ARM REST API — microsoft.insights/components
    Using REST instead of 'az monitor app-insights component list' because
    the app-insights sub-command requires the optional application-insights
    CLI extension which may not be installed in all environments.

    API: GET /subscriptions/{id}/providers/microsoft.insights/components
    """
    url = (
        f"https://management.azure.com/subscriptions/{sid}/"
        f"providers/microsoft.insights/components?api-version=2020-02-02"
    )
    rc, data = az_rest(url, timeout=TIMEOUTS["default"])
    if rc != 0:
        return _err(
            "6.1.3.1", "Application Insights configured", 2, "6 - Management & Governance", str(data), sid, sname
        )

    components = data.get("value", []) if isinstance(data, dict) else []
    names = [c.get("name", "?") for c in components]

    return R(
        "6.1.3.1",
        "Application Insights configured",
        2,
        "6 - Management & Governance",
        PASS if components else FAIL,
        (
            f"Found {len(components)} Application Insights component(s): {names}"
            if components
            else "No Application Insights components found."
        ),
        "Create an Application Insights resource linked to your application(s)." if not components else "",
        sid,
        sname,
    )
