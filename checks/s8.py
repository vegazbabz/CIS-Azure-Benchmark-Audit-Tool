"""
checks_s8.py — CIS Azure Benchmark Section 8 checks.

SECTION 8 — SECURITY SERVICES
"""

from __future__ import annotations

from typing import Any

from cis.config import PASS, FAIL, ERROR, INFO, TIMEOUTS
from cis.models import R
from cis.check_helpers import _err, _idx, _info
from azure.helpers import az, az_rest, is_firewall_error, _friendly_error


def check_8_1_defender(sid: str, sname: str) -> list[R]:
    """
    8.1.x — Microsoft Defender for Cloud plan statuses (Level 2)

    Each Defender plan provides threat detection and security posture
    management for a specific Azure service category. The Free tier provides
    basic posture recommendations only; Standard (paid) adds threat detection,
    vulnerability assessment, and advanced alerts.

    All 12 plans are checked in a single loop to reduce function count.
    Each plan name maps to an 'az security pricing show -n <plan>' call.

    Compliant state: pricingTier == "Standard"

    Controls covered:
      8.1.1.1  CSPM
      8.1.2.1  APIs
      8.1.3.1  Servers (VirtualMachines)
      8.1.4.1  Containers
      8.1.5.1  Storage
      8.1.6.1  App Services
      8.1.7.1  Cosmos DB
      8.1.7.2  Open-Source Relational Databases
      8.1.7.3  SQL (Managed Instance)
      8.1.7.4  SQL Servers on Machines
      8.1.8.1  Key Vault
      8.1.9.1  Resource Manager (ARM)
    """
    plans = [
        ("8.1.1.1", "Microsoft Defender CSPM", "CloudPosture", 2),
        ("8.1.2.1", "Microsoft Defender for APIs", "Api", 2),
        ("8.1.3.1", "Microsoft Defender for Servers", "VirtualMachines", 2),
        ("8.1.4.1", "Microsoft Defender for Containers", "Containers", 2),
        ("8.1.5.1", "Microsoft Defender for Storage", "StorageAccounts", 2),
        ("8.1.6.1", "Microsoft Defender for App Services", "AppServices", 2),
        ("8.1.7.1", "Microsoft Defender for Azure Cosmos DB", "CosmosDbs", 2),
        ("8.1.7.2", "Microsoft Defender for Open-Source Relational DBs", "OpenSourceRelationalDatabases", 2),
        ("8.1.7.3", "Microsoft Defender for SQL (Managed Instance)", "SqlServers", 2),
        ("8.1.7.4", "Microsoft Defender for SQL Servers on Machines", "SqlServerVirtualMachines", 2),
        ("8.1.8.1", "Microsoft Defender for Key Vault", "KeyVaults", 2),
        ("8.1.9.1", "Microsoft Defender for Resource Manager", "Arm", 2),
    ]

    results = []
    for ctrl, title, plan, level in plans:
        rc, data = az(["security", "pricing", "show", "-n", plan], sid, timeout=TIMEOUTS["default"])
        if rc != 0:
            results.append(_err(ctrl, title, level, "8 - Security Services", str(data), sid, sname))
            continue

        tier = data.get("pricingTier", "Free") if isinstance(data, dict) else "Unknown"
        results.append(
            R(
                ctrl,
                title,
                level,
                "8 - Security Services",
                PASS if tier == "Standard" else FAIL,
                f"Pricing tier: {tier}",
                f"Defender for Cloud > Environment settings > Enable '{plan}'" if tier != "Standard" else "",
                sid,
                sname,
            )
        )
    return results


def check_8_1_3_3(sid: str, sname: str) -> R:
    """
    8.1.3.3 — Endpoint protection (WDATP) component is enabled (Level 2)

    Windows Defender ATP (WDATP) integration allows Defender for Cloud to
    consume endpoint detection signals from Microsoft Defender for Endpoint.
    This cannot be checked via 'az security pricing' — it requires a direct
    ARM REST call to the security settings endpoint.

    API: GET /subscriptions/{id}/providers/Microsoft.Security/settings
    The WDATP setting object has properties.enabled = true/false.
    """
    url = (
        f"https://management.azure.com/subscriptions/{sid}/"
        f"providers/Microsoft.Security/settings?api-version=2022-05-01"
    )
    rc, data = az_rest(url, timeout=TIMEOUTS["default"])
    if rc != 0:
        return _err(
            "8.1.3.3",
            "Endpoint protection (WDATP) component enabled",
            1,
            "8 - Security Services",
            str(data),
            sid,
            sname,
        )

    # The response is a list of security settings objects; find the WDATP one
    settings = data.get("value", []) if isinstance(data, dict) else []
    wdatp = next((s for s in settings if s.get("name") == "WDATP"), None)
    enabled = (wdatp or {}).get("properties", {}).get("enabled", False) if wdatp else False

    return R(
        "8.1.3.3",
        "Endpoint protection (WDATP) component enabled",
        1,
        "8 - Security Services",
        PASS if enabled else FAIL,
        f"WDATP integration: {'enabled' if enabled else 'NOT enabled'}",
        (
            "Defender for Cloud > Environment settings > Integrations > Enable Microsoft Defender for Endpoint"
            if not enabled
            else ""
        ),
        sid,
        sname,
    )


def check_8_1_10(sid: str, sname: str) -> R:
    """
    8.1.10 — Defender is configured to check VM OS updates (Level 1)

    Microsoft Defender Vulnerability Management (MDE TVM) performs OS-level
    vulnerability assessment on VMs. The selectedProvider must be "MdeTvm"
    to satisfy this control.

    API: GET /subscriptions/{id}/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings
    """
    url = (
        f"https://management.azure.com/subscriptions/{sid}/"
        f"providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings?"
        f"api-version=2023-05-01"
    )
    rc, data = az_rest(url, timeout=TIMEOUTS["default"])
    if rc != 0:
        return _err(
            "8.1.10", "Defender configured to check VM OS updates", 1, "8 - Security Services", str(data), sid, sname
        )

    settings = data.get("value", []) if isinstance(data, dict) else []
    enabled = any(s.get("properties", {}).get("selectedProvider") == "MdeTvm" for s in settings)

    return R(
        "8.1.10",
        "Defender configured to check VM OS updates",
        1,
        "8 - Security Services",
        PASS if enabled else FAIL,
        f"MDE TVM vulnerability assessment: {'enabled' if enabled else 'NOT enabled'}",
        (
            "Defender for Cloud > Environment settings > VM vulnerability assessment: "
            "Microsoft Defender Vulnerability Management."
            if not enabled
            else ""
        ),
        sid,
        sname,
    )


def check_8_1_12_to_15(sid: str, sname: str) -> list[R]:
    """
    8.1.12–8.1.15 — Security contact notification settings (Level 1)

    Defender for Cloud can notify designated contacts when alerts are raised
    or attack paths are detected. These four controls verify that notification
    channels and alert thresholds are correctly configured.

    Controls covered:
      8.1.12 — Subscription Owners receive security alert notifications
      8.1.13 — Additional email address is configured for security alerts
      8.1.14 — Alert notification state is On (not Off)
      8.1.15 — Attack path notifications are configured

    Data sources:
      - az security contact list  (for 8.1.12 and 8.1.13 — stable GA API)
      - az rest preview endpoint  (for 8.1.14 and 8.1.15 — newer notification model)
    """
    results = []

    # Fetch contact list from stable GA API
    rc, contacts = az(["security", "contact", "list"], sid, timeout=TIMEOUTS["default"])
    contact_list = contacts if (rc == 0 and isinstance(contacts, list)) else []

    # 8.1.12 — Owner role must be in the notificationsByRole.roles list
    owners_notified = any("Owner" in c.get("notificationsByRole", {}).get("roles", []) for c in contact_list)
    results.append(
        R(
            "8.1.12",
            "Security alerts notify subscription Owners",
            1,
            "8 - Security Services",
            PASS if owners_notified else FAIL,
            (
                "Owner role configured for security alert notifications."
                if owners_notified
                else "Owner role NOT configured for notifications."
            ),
            (
                "Defender for Cloud > Environment settings > Email notifications > " "All users with Owner role."
                if not owners_notified
                else ""
            ),
            sid,
            sname,
        )
    )

    # 8.1.13 — At least one additional email address is configured.
    # The field is "emails" in newer API versions, "email" in older ones.
    has_email = any(c.get("emails", c.get("email", "")) for c in contact_list)
    results.append(
        R(
            "8.1.13",
            "Additional email address for security contact",
            1,
            "8 - Security Services",
            PASS if has_email else FAIL,
            "Additional email address(es) configured." if has_email else "No additional email addresses configured.",
            (
                "Defender for Cloud > Environment settings > Email notifications > " "Additional email addresses."
                if not has_email
                else ""
            ),
            sid,
            sname,
        )
    )

    # 8.1.14 and 8.1.15 need the preview API for the notificationsSource structure
    url = (
        f"https://management.azure.com/subscriptions/{sid}/"
        f"providers/Microsoft.Security/securityContacts"
        f"?api-version=2023-12-01-preview"
    )
    rc2, cdata = az_rest(url, timeout=TIMEOUTS["default"])
    contact_items = cdata.get("value") or [] if rc2 == 0 and isinstance(cdata, dict) else []

    # 8.1.14 — Alert notification state must be "On"
    alert_on = any(
        c.get("properties", {}).get("notificationsByRole", {}).get("state", "").lower() == "on" for c in contact_items
    )
    results.append(
        R(
            "8.1.14",
            "Alert severity notifications configured",
            1,
            "8 - Security Services",
            PASS if alert_on else FAIL,
            "Alert notification state: On." if alert_on else "Alert notification state is not 'On'.",
            (
                "Defender for Cloud > Environment settings > Email notifications > "
                "Notify about alerts with severity: High."
                if not alert_on
                else ""
            ),
            sid,
            sname,
        )
    )

    # 8.1.15 — At least one notificationsSource entry must have sourceType == "AttackPath"
    attack_on = any(
        isinstance(src, dict) and src.get("sourceType") == "AttackPath"
        for c in contact_items
        for src in (c.get("properties", {}).get("notificationsSource") or [])
        if isinstance(c.get("properties", {}).get("notificationsSource"), list)
    )
    results.append(
        R(
            "8.1.15",
            "Attack path notifications configured",
            1,
            "8 - Security Services",
            PASS if attack_on else FAIL,
            "Attack path notifications configured." if attack_on else "Attack path notifications NOT configured.",
            (
                "Defender for Cloud > Environment settings > Email notifications > "
                "Notify about attack paths with risk level: Critical."
                if not attack_on
                else ""
            ),
            sid,
            sname,
        )
    )

    return results


def check_8_3_keyvaults(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    8.3.x — Key Vault security controls (multiple controls, one loop per vault)

    All Key Vault checks are batched per vault to minimise separate function
    calls and make the relationship between controls and vaults clear in code.

    Controls covered per vault:
      8.3.1  — Key expiration set (RBAC vaults)      [L1]
      8.3.2  — Key expiration set (non-RBAC vaults)  [L1]
      8.3.3  — Secret expiration set (RBAC vaults)   [L1]
      8.3.4  — Secret expiration set (non-RBAC)      [L1]
      8.3.5  — Purge protection enabled              [L1]
      8.3.6  — RBAC authorization enabled            [L2]
      8.3.7  — Public network access disabled        [L1]
      8.3.8  — Private endpoints configured          [L2]
      8.3.9  — Automatic key rotation policy set     [L2]
      8.3.11 — Certificate validity <= 12 months     [L1]

    Data sources:
      Resource Graph 'keyvaults' query → vault-level properties (8.3.5-8.3.8)
      az keyvault key list             → key names and expiry dates (8.3.1-8.3.2)
      az keyvault secret list          → secret names and expiry dates (8.3.3-8.3.4)
      az keyvault key rotation-policy  → rotation policy per key (8.3.9)
      az keyvault certificate list/show → cert validity periods (8.3.11)

    RBAC vs non-RBAC distinction:
      Key Vaults can use either RBAC (8.3.1 for keys, 8.3.3 for secrets) or
      Vault Access Policies (8.3.2 for keys, 8.3.4 for secrets) for authorization.
      The split controls exist because the remediation path differs between models.
    """
    vaults = _idx(td, "keyvaults", sid)
    if not vaults:
        controls = [
            ("8.3.1", 1),
            ("8.3.2", 1),
            ("8.3.3", 1),
            ("8.3.4", 1),
            ("8.3.5", 1),
            ("8.3.6", 2),
            ("8.3.7", 1),
            ("8.3.8", 2),
            ("8.3.9", 2),
            ("8.3.11", 1),
        ]
        return [
            _info(
                ctrl,
                f"Key Vault security check {ctrl}",
                lvl,
                "8 - Security Services",
                "No Key Vaults found.",
                sid,
                sname,
            )
            for ctrl, lvl in controls
        ]

    results = []
    for v in vaults:
        vname = v.get("name", "?")
        is_rbac = bool(v.get("rbac"))  # True = RBAC mode, False = access policy mode

        # ── 8.3.5 — Purge protection ─────────────────────────────────────────
        # Purge protection prevents permanent deletion of vault objects during
        # the soft-delete retention period. Without it, a compromised admin
        # account can permanently destroy all secrets immediately.
        purge = v.get("purgeProtection")
        results.append(
            R(
                "8.3.5",
                "Key Vault purge protection enabled",
                1,
                "8 - Security Services",
                PASS if purge else FAIL,
                f"Vault '{vname}': enablePurgeProtection = {purge}",
                "Key Vault > Properties > Enable purge protection" if not purge else "",
                sid,
                sname,
                vname if not purge else "",
            )
        )

        # ── 8.3.6 — RBAC authorization (L2) ─────────────────────────────────
        # RBAC is the recommended authorization model. Access policies are
        # legacy and cannot be managed with the same IAM tooling as the rest
        # of Azure's RBAC. L2 because some organisations legitimately use
        # access policies for compatibility with older SDK versions.
        results.append(
            R(
                "8.3.6",
                "Key Vault RBAC authorization enabled",
                2,
                "8 - Security Services",
                PASS if is_rbac else FAIL,
                f"Vault '{vname}': enableRbacAuthorization = {is_rbac}",
                (
                    "Key Vault > Access configuration > Permission model: " "Azure role-based access control"
                    if not is_rbac
                    else ""
                ),
                sid,
                sname,
                vname if not is_rbac else "",
            )
        )

        # ── 8.3.7 — Public network access ────────────────────────────────────
        # When public access is enabled, the vault's management plane (and in
        # some cases data plane) is reachable from the internet. Disabling it
        # forces all access through private endpoints or approved virtual networks.
        pub = v.get("publicAccess", "Enabled")
        results.append(
            R(
                "8.3.7",
                "Key Vault public network access disabled",
                1,
                "8 - Security Services",
                PASS if str(pub).lower() == "disabled" else FAIL,
                f"Vault '{vname}': publicNetworkAccess = {pub}",
                "Key Vault > Networking > Public network access: Disabled" if str(pub).lower() != "disabled" else "",
                sid,
                sname,
                vname if str(pub).lower() != "disabled" else "",
            )
        )

        # ── 8.3.8 — Private endpoints (L2) ────────────────────────────────────
        # Private endpoints provide a private IP address for vault access within
        # the customer's VNet, eliminating public internet exposure entirely.
        pe_count = v.get("privateEps") or 0
        results.append(
            R(
                "8.3.8",
                "Private endpoints used to access Key Vault",
                2,
                "8 - Security Services",
                PASS if pe_count > 0 else FAIL,
                f"Vault '{vname}': private endpoints = {pe_count}",
                "Key Vault > Networking > Private endpoint connections > Add" if pe_count == 0 else "",
                sid,
                sname,
                vname if pe_count == 0 else "",
            )
        )

        # ── 8.3.1 / 8.3.2 — Key expiration ───────────────────────────────────
        # CIS requires that all enabled keys have an expiration date set.
        # Keys without expiry can remain valid indefinitely, violating least
        # privilege for cryptographic material. The control number depends on
        # whether the vault uses RBAC (8.3.1) or access policy mode (8.3.2).
        for ctrl, vault_type in [("8.3.1", True), ("8.3.2", False)]:
            if is_rbac != vault_type:
                continue  # Skip — this control applies to the other vault type
            label = "RBAC" if vault_type else "non-RBAC"
            rc, keys = az(
                [
                    "keyvault",
                    "key",
                    "list",
                    "--vault-name",
                    vname,
                    "--query",
                    "[?attributes.enabled==`true`].{name:name,expires:attributes.expires}",
                ],
                sid,
                timeout=TIMEOUTS["default"],
            )
            if rc != 0:
                error_msg = (
                    str(keys)
                    if isinstance(keys, str)
                    else "Access denied or error listing keys (requires Key Vault data plane permissions)"
                )
                results.append(
                    R(
                        ctrl,
                        f"Key Vault keys have expiration date set ({label})",
                        1,
                        "8 - Security Services",
                        INFO if is_firewall_error(error_msg) else ERROR,
                        f"Vault '{vname}': Failed to enumerate keys - {_friendly_error(error_msg)}",
                        "",
                        sid,
                        sname,
                        vname,
                    )
                )
            elif isinstance(keys, list):
                for k in keys:
                    exp = k.get("expires")
                    results.append(
                        R(
                            ctrl,
                            f"Key Vault keys have expiration date set ({label})",
                            1,
                            "8 - Security Services",
                            PASS if exp else FAIL,
                            f"Vault '{vname}' key '{k.get('name')}': expires = {exp or 'NOT SET'}",
                            "Key Vault > Keys > Set expiration date" if not exp else "",
                            sid,
                            sname,
                            vname if not exp else "",
                        )
                    )

        # ── 8.3.3 / 8.3.4 — Secret expiration ────────────────────────────────
        # Same principle as key expiration, applied to secrets.
        # Secrets without expiry may contain credentials that are never rotated,
        # such as database passwords or API keys.
        for ctrl, vault_type in [("8.3.3", True), ("8.3.4", False)]:
            if is_rbac != vault_type:
                continue
            label = "RBAC" if vault_type else "non-RBAC"
            rc, secrets = az(
                [
                    "keyvault",
                    "secret",
                    "list",
                    "--vault-name",
                    vname,
                    "--query",
                    "[?attributes.enabled==`true`].{name:name,expires:attributes.expires}",
                ],
                sid,
                timeout=TIMEOUTS["default"],
            )
            if rc != 0:
                error_msg = (
                    str(secrets)
                    if isinstance(secrets, str)
                    else "Access denied or error listing secrets (requires Key Vault data plane permissions)"
                )
                results.append(
                    R(
                        ctrl,
                        f"Key Vault secrets have expiration date set ({label})",
                        1,
                        "8 - Security Services",
                        INFO if is_firewall_error(error_msg) else ERROR,
                        f"Vault '{vname}': Failed to enumerate secrets - {_friendly_error(error_msg)}",
                        "",
                        sid,
                        sname,
                        vname,
                    )
                )
            elif isinstance(secrets, list):
                for s in secrets:
                    exp = s.get("expires")
                    results.append(
                        R(
                            ctrl,
                            f"Key Vault secrets have expiration date set ({label})",
                            1,
                            "8 - Security Services",
                            PASS if exp else FAIL,
                            f"Vault '{vname}' secret '{s.get('name')}': expires = {exp or 'NOT SET'}",
                            "Key Vault > Secrets > Set expiration date" if not exp else "",
                            sid,
                            sname,
                            vname if not exp else "",
                        )
                    )

        # ── 8.3.9 — Automatic key rotation (L2) ──────────────────────────────
        # A rotation policy with a "Rotate" lifetime action automates key
        # rotation, eliminating the risk of keys being left unrotated because
        # no one remembers to do it manually. One result per key.
        rc, keys2 = az(
            ["keyvault", "key", "list", "--vault-name", vname, "--query", "[].name"], sid, timeout=TIMEOUTS["default"]
        )
        if rc != 0:
            error_msg = (
                str(keys2)
                if isinstance(keys2, str)
                else "Access denied or error listing keys (requires Key Vault data plane permissions)"
            )
            results.append(
                R(
                    "8.3.9",
                    "Key Vault automatic key rotation enabled",
                    2,
                    "8 - Security Services",
                    INFO if is_firewall_error(error_msg) else ERROR,
                    f"Vault '{vname}': Failed to enumerate keys - {_friendly_error(error_msg)}",
                    "",
                    sid,
                    sname,
                    vname,
                )
            )
        elif isinstance(keys2, list):
            for kname in keys2:
                rc2, pol = az(
                    ["keyvault", "key", "rotation-policy", "show", "--vault-name", vname, "--name", kname],
                    sid,
                    timeout=TIMEOUTS["default"],
                )
                if rc2 != 0:
                    error_msg = (
                        str(pol)
                        if isinstance(pol, str)
                        else "Access denied (requires Key Vault data plane permissions)"
                    )
                    results.append(
                        R(
                            "8.3.9",
                            "Key Vault automatic key rotation enabled",
                            2,
                            "8 - Security Services",
                            INFO if is_firewall_error(error_msg) else ERROR,
                            (
                                f"Vault '{vname}' key '{kname}': "
                                f"Failed to fetch rotation policy - {_friendly_error(error_msg)}"
                            ),
                            "",
                            sid,
                            sname,
                            vname,
                        )
                    )
                elif isinstance(pol, dict):
                    # A rotation policy is compliant if at least one lifetimeAction
                    # has type == "Rotate" (as opposed to "Notify")
                    has_rotate = any(
                        la.get("action", {}).get("type", "").lower() == "rotate"
                        for la in pol.get("lifetimeActions", [])
                    )
                    results.append(
                        R(
                            "8.3.9",
                            "Key Vault automatic key rotation enabled",
                            2,
                            "8 - Security Services",
                            PASS if has_rotate else FAIL,
                            f"Vault '{vname}' key '{kname}': auto-rotation "
                            f"{'configured' if has_rotate else 'NOT configured'}",
                            "Key Vault > Keys > Rotation policy > Set rotation action" if not has_rotate else "",
                            sid,
                            sname,
                            vname if not has_rotate else "",
                        )
                    )

        # ── 8.3.11 — Certificate validity <= 12 months ────────────────────────
        # Short-lived certificates limit the window of exposure if a private key
        # is compromised. Certificates with >12 month validity require long-term
        # private key protection and delay detection of key compromise.
        rc, certs = az(
            ["keyvault", "certificate", "list", "--vault-name", vname, "--query", "[].id"],
            sid,
            timeout=TIMEOUTS["default"],
        )
        if rc != 0:
            error_msg = (
                str(certs)
                if isinstance(certs, str)
                else "Access denied or error listing certificates (requires Key Vault data plane permissions)"
            )
            results.append(
                R(
                    "8.3.11",
                    "Certificate validity period <= 12 months",
                    1,
                    "8 - Security Services",
                    INFO if is_firewall_error(error_msg) else ERROR,
                    f"Vault '{vname}': Failed to enumerate certificates - {_friendly_error(error_msg)}",
                    "",
                    sid,
                    sname,
                    vname,
                )
            )
        elif isinstance(certs, list):
            for cert_id in certs:
                # Fetch just the validity period from the certificate policy
                rc2, cert = az(
                    [
                        "keyvault",
                        "certificate",
                        "show",
                        "--id",
                        cert_id,
                        "--query",
                        "policy.x509CertificateProperties.validityInMonths",
                    ],
                    sid,
                    timeout=TIMEOUTS["default"],
                )
                if rc2 != 0:
                    error_msg = (
                        str(cert)
                        if isinstance(cert, str)
                        else "Access denied (requires Key Vault data plane permissions)"
                    )
                    cname = cert_id.split("/")[-1]
                    results.append(
                        R(
                            "8.3.11",
                            "Certificate validity period <= 12 months",
                            1,
                            "8 - Security Services",
                            INFO if is_firewall_error(error_msg) else ERROR,
                            (
                                f"Vault '{vname}' cert '{cname}': "
                                f"Failed to fetch certificate - {_friendly_error(error_msg)}"
                            ),
                            "",
                            sid,
                            sname,
                            vname,
                        )
                    )
                elif cert is not None:
                    try:
                        months = int(cert)
                        ok = months <= 12
                    except (ValueError, TypeError):
                        ok = False
                        months = cert  # Return raw value for display if not int
                    # Certificate name is the last segment of its ID URL path
                    cname = cert_id.split("/")[-1]
                    results.append(
                        R(
                            "8.3.11",
                            "Certificate validity period <= 12 months",
                            1,
                            "8 - Security Services",
                            PASS if ok else FAIL,
                            f"Vault '{vname}' cert '{cname}': validityInMonths = {months}",
                            (
                                "Key Vault > Certificates > Issuance policy > " "Set validity <= 12 months"
                                if not ok
                                else ""
                            ),
                            sid,
                            sname,
                            vname if not ok else "",
                        )
                    )
    return results


def check_8_4_1(sid: str, sname: str, td: dict[str, Any]) -> R:
    """
    8.4.1 — Azure Bastion Host exists in the subscription (Level 2)

    Azure Bastion provides browser-based RDP/SSH access to VMs without
    requiring the VMs to have public IP addresses or NSG rules for port
    3389/22. It replaces the need for a jump box VM.

    Bastion is only relevant if the subscription has Virtual Machines.
    A subscription with no VMs has nothing to connect to via Bastion, so
    the result is INFO rather than FAIL in that case.

    Data source: Resource Graph 'bastion' and 'vms' queries.
    """
    hosts = _idx(td, "bastion", sid)
    if hosts:
        names = [h.get("name") for h in hosts]
        return R(
            "8.4.1",
            "Azure Bastion Host exists",
            2,
            "8 - Security Services",
            PASS,
            f"Bastion host(s) found: {names}",
            "",
            sid,
            sname,
        )

    # No Bastion — only FAIL if there are VMs that would need it
    vms = _idx(td, "vms", sid)
    if not vms:
        return R(
            "8.4.1",
            "Azure Bastion Host exists",
            2,
            "8 - Security Services",
            INFO,
            "No VMs found in this subscription — Bastion not required.",
            "",
            sid,
            sname,
        )

    vm_names = [v.get("name") for v in vms]
    return R(
        "8.4.1",
        "Azure Bastion Host exists",
        2,
        "8 - Security Services",
        FAIL,
        f"No Bastion host found. Subscription has {len(vms)} VM(s): {vm_names}.",
        "Deploy Azure Bastion to enable secure RDP/SSH access without public IPs.",
        sid,
        sname,
    )


def check_8_5(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    8.5 — DDoS Network Protection is enabled on Virtual Networks (Level 2)

    Azure DDoS Standard provides adaptive tuning, attack analytics, and
    guaranteed SLA during a volumetric DDoS attack. Without it, VMs and
    load balancers receive only Basic (infrastructure-level) protection
    which does not provide application-layer mitigation.

    One result per VNet — each VNet must have a DDoS plan linked to it.
    Data source: Resource Graph 'vnets' query (hasDdos field).
    """
    vnets = _idx(td, "vnets", sid)
    if not vnets:
        return [
            _info(
                "8.5",
                "DDoS Network Protection enabled on VNets",
                2,
                "8 - Security Services",
                "No VNets found.",
                sid,
                sname,
            )
        ]

    return [
        R(
            "8.5",
            "DDoS Network Protection enabled on VNets",
            2,
            "8 - Security Services",
            PASS if v.get("hasDdos") else FAIL,
            f"VNet '{v.get('name')}': DDoS {'enabled' if v.get('hasDdos') else 'NOT enabled'}",
            "VNet > DDoS protection > Enable Standard plan" if not v.get("hasDdos") else "",
            sid,
            sname,
            v.get("name", "") if not v.get("hasDdos") else "",
        )
        for v in vnets
    ]
