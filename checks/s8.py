"""
checks_s8.py — CIS Azure Benchmark Section 8 checks.

SECTION 8 — SECURITY SERVICES
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from cis.config import PASS, FAIL, ERROR, INFO, MANUAL, TIMEOUTS, LOGGER
from cis.models import R
from cis.check_helpers import _err, _idx, _info
from azure.helpers import az, az_rest, _friendly_error

# Maximum Key Vaults audited concurrently within one subscription.
_VAULT_WORKERS = 10

# Maximum concurrent per-key or per-cert calls within a single vault.
# With _VAULT_WORKERS=10 and _KEY_WORKERS=5, up to 50 concurrent az CLI
# subprocesses can be running rotation-policy or cert-show calls at once.
_KEY_WORKERS = 5


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

    def _check_plan(entry: tuple[str, str, str, int]) -> R:
        ctrl, title, plan, level = entry
        rc, data = az(["security", "pricing", "show", "-n", plan], sid, timeout=TIMEOUTS["default"])
        if rc != 0:
            return _err(ctrl, title, level, "8 - Security Services", str(data), sid, sname)
        tier = data.get("pricingTier", "Free") if isinstance(data, dict) else "Unknown"
        return R(
            ctrl,
            title,
            level,
            "8 - Security Services",
            PASS if tier == "Standard" else FAIL,
            (
                "Microsoft Defender pricing tier: Standard (enabled)."
                if tier == "Standard"
                else f"Microsoft Defender pricing tier: {tier} \u2014 must be upgraded to Standard."
            ),
            f"Defender for Cloud > Environment settings > Enable '{plan}'" if tier != "Standard" else "",
            sid,
            sname,
        )

    # All 12 plan checks are independent — fetch concurrently and restore
    # the original declaration order so the report is stable across runs.
    with ThreadPoolExecutor(max_workers=len(plans)) as pool:
        results = list(pool.map(_check_plan, plans))
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
        f"Microsoft Defender for Endpoint integration: {'Enabled' if enabled else 'Disabled'}.",
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
        f"MDE TVM vulnerability assessment: {'enabled.' if enabled else 'NOT enabled.'}",
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
      az keyvault key list             → key names, expiry dates (8.3.1-8.3.2, 8.3.9)
      az keyvault secret list          → secret names and expiry dates (8.3.3-8.3.4)
      az keyvault key rotation-policy  → rotation policy per key (8.3.9) — parallelised
      az keyvault certificate list/show → cert validity periods (8.3.11) — parallelised

    RBAC vs non-RBAC distinction:
      Key Vaults can use either RBAC (8.3.1 for keys, 8.3.3 for secrets) or
      Vault Access Policies (8.3.2 for keys, 8.3.4 for secrets) for authorization.
      The split controls exist because the remediation path differs between models.

    Performance:
      Vaults are audited concurrently (_VAULT_WORKERS). Within each vault,
      the key list call is reused for both expiry (8.3.1/8.3.2) and rotation
      (8.3.9), eliminating a redundant CLI call. Rotation-policy and
      certificate-show calls are fetched in parallel (_KEY_WORKERS).
    """
    vaults = _idx(td, "keyvaults", sid)
    # Deduplicate by resource ID — Azure Resource Graph occasionally returns
    # duplicate rows for the same vault (e.g. across pagination boundaries).
    _seen_vault_ids: set[str] = set()
    _deduped_vaults: list[dict[str, Any]] = []
    for _v in vaults:
        _vid = _v.get("id", "").lower()
        if _vid not in _seen_vault_ids:
            _seen_vault_ids.add(_vid)
            _deduped_vaults.append(_v)
    vaults = _deduped_vaults
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

    def _check_one_vault(v: dict[str, Any]) -> list[R]:
        """Audit one Key Vault (all controls). Called in parallel by the outer pool."""
        vname = v.get("name", "?")
        LOGGER.debug("    [%s] key vault: %s", sname[:24], vname)
        is_rbac = bool(v.get("rbac"))
        acc: list[R] = []

        # ── 8.3.5 — Purge protection ─────────────────────────────────────────
        # Purge protection prevents permanent deletion of vault objects during
        # the soft-delete retention period. Without it, a compromised admin
        # account can permanently destroy all secrets immediately.
        purge = v.get("purgeProtection")
        acc.append(
            R(
                "8.3.5",
                "Key Vault purge protection enabled",
                1,
                "8 - Security Services",
                PASS if purge else FAIL,
                f"Purge protection {'enabled' if purge else 'not enabled'}.",
                "Key Vault > Properties > Enable purge protection" if not purge else "",
                sid,
                sname,
                vname,
            )
        )

        # ── 8.3.6 — RBAC authorization (L2) ─────────────────────────────────
        # RBAC is the recommended authorization model. Access policies are
        # legacy and cannot be managed with the same IAM tooling as the rest
        # of Azure's RBAC. L2 because some organisations legitimately use
        # access policies for compatibility with older SDK versions.
        acc.append(
            R(
                "8.3.6",
                "Key Vault RBAC authorization enabled",
                2,
                "8 - Security Services",
                PASS if is_rbac else FAIL,
                "RBAC authorization model enabled." if is_rbac else "Using legacy Vault Access Policy, not RBAC.",
                (
                    "Key Vault > Access configuration > Permission model: " "Azure role-based access control"
                    if not is_rbac
                    else ""
                ),
                sid,
                sname,
                vname,
            )
        )

        # ── 8.3.7 — Public network access ────────────────────────────────────
        # When public access is enabled, the vault's management plane (and in
        # some cases data plane) is reachable from the internet. Disabling it
        # forces all access through private endpoints or approved virtual networks.
        pub = v.get("publicAccess", "Enabled")
        acc.append(
            R(
                "8.3.7",
                "Key Vault public network access disabled",
                1,
                "8 - Security Services",
                PASS if str(pub).lower() == "disabled" else FAIL,
                f"Public network access: {pub}.",
                "Key Vault > Networking > Public network access: Disabled" if str(pub).lower() != "disabled" else "",
                sid,
                sname,
                vname,
            )
        )

        # ── 8.3.8 — Private endpoints (L2) ────────────────────────────────────
        # Private endpoints provide a private IP address for vault access within
        # the customer's VNet, eliminating public internet exposure entirely.
        pe_count = v.get("privateEps") or 0
        acc.append(
            R(
                "8.3.8",
                "Private endpoints used to access Key Vault",
                2,
                "8 - Security Services",
                PASS if pe_count > 0 else FAIL,
                f"Private endpoint(s) configured: {pe_count}." if pe_count > 0 else "No private endpoints configured.",
                "Key Vault > Networking > Private endpoint connections > Add" if pe_count == 0 else "",
                sid,
                sname,
                vname,
            )
        )

        # ── 8.3.1 / 8.3.2 + 8.3.9 — Merged key list ─────────────────────────
        # A single 'az keyvault key list' call returns the data needed for both
        # the expiry checks (8.3.1/8.3.2) and the rotation-policy checks (8.3.9),
        # eliminating the redundant second list call from the original code.
        #
        # CIS requires that all enabled keys have an expiration date set.
        # Keys without expiry can remain valid indefinitely, violating least
        # privilege for cryptographic material. The control number depends on
        # whether the vault uses RBAC (8.3.1) or access policy mode (8.3.2).
        rc_keys, keys_raw = az(
            [
                "keyvault",
                "key",
                "list",
                "--vault-name",
                vname,
                "--query",
                "[].{name:name,expires:attributes.expires,enabled:attributes.enabled}",
            ],
            sid,
            timeout=TIMEOUTS["default"],
        )

        ctrl_key_exp = "8.3.1" if is_rbac else "8.3.2"
        label = "RBAC" if is_rbac else "non-RBAC"

        if rc_keys != 0:
            # Single error covers both key expiry and rotation policy checks
            error_msg = (
                str(keys_raw)
                if isinstance(keys_raw, str)
                else "Access denied or error listing keys (requires Key Vault data plane permissions)"
            )
            friendly = _friendly_error(error_msg)
            status = ERROR
            acc.append(
                R(
                    ctrl_key_exp,
                    f"Key Vault keys have expiration date set ({label})",
                    1,
                    "8 - Security Services",
                    status,
                    f"Vault '{vname}': Failed to enumerate keys: {friendly}",
                    "",
                    sid,
                    sname,
                    vname,
                )
            )
            acc.append(
                R(
                    "8.3.9",
                    "Key Vault automatic key rotation enabled",
                    2,
                    "8 - Security Services",
                    status,
                    f"Vault '{vname}': Failed to enumerate keys: {friendly}",
                    "",
                    sid,
                    sname,
                    vname,
                )
            )
        else:
            all_keys = keys_raw if isinstance(keys_raw, list) else []
            enabled_keys = [k for k in all_keys if k.get("enabled")]
            key_names = [k["name"] for k in all_keys if k.get("name")]

            # 8.3.1 / 8.3.2 — expiry check (enabled keys only)
            for k in enabled_keys:
                exp = k.get("expires")
                acc.append(
                    R(
                        ctrl_key_exp,
                        f"Key Vault keys have expiration date set ({label})",
                        1,
                        "8 - Security Services",
                        PASS if exp else FAIL,
                        (
                            f"Key '{k.get('name')}': expiration set ({exp})."
                            if exp
                            else f"Key '{k.get('name')}': expiration NOT set."
                        ),
                        "Key Vault > Keys > Set expiration date" if not exp else "",
                        sid,
                        sname,
                        vname,
                    )
                )

            # 8.3.9 — Automatic key rotation (L2)
            # A rotation policy with a "Rotate" lifetime action automates key
            # rotation, eliminating the risk of keys being left unrotated because
            # no one remembers to do it manually. One result per key.
            # Rotation-policy calls are independent per key — fetch in parallel.
            if key_names:

                def _fetch_rotation(kname: str) -> tuple[int, Any]:
                    return az(
                        ["keyvault", "key", "rotation-policy", "show", "--vault-name", vname, "--name", kname],
                        sid,
                        timeout=TIMEOUTS["default"],
                    )

                workers = min(_KEY_WORKERS, len(key_names))
                with ThreadPoolExecutor(max_workers=workers) as kpool:
                    pol_results = list(kpool.map(_fetch_rotation, key_names))

                for kname, (rc2, pol) in zip(key_names, pol_results):
                    if rc2 != 0:
                        error_msg = (
                            str(pol)
                            if isinstance(pol, str)
                            else "Access denied (requires Key Vault data plane permissions)"
                        )
                        acc.append(
                            R(
                                "8.3.9",
                                "Key Vault automatic key rotation enabled",
                                2,
                                "8 - Security Services",
                                ERROR,
                                (
                                    f"Vault '{vname}' key '{kname}': Failed to fetch rotation policy:"
                                    f" {_friendly_error(error_msg)}"
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
                        acc.append(
                            R(
                                "8.3.9",
                                "Key Vault automatic key rotation enabled",
                                2,
                                "8 - Security Services",
                                PASS if has_rotate else FAIL,
                                f"Key '{kname}': automatic rotation"
                                f" {'configured' if has_rotate else 'NOT configured'}.",
                                "Key Vault > Keys > Rotation policy > Set rotation action" if not has_rotate else "",
                                sid,
                                sname,
                                vname,
                            )
                        )

        # ── 8.3.3 / 8.3.4 — Secret expiration ────────────────────────────────
        # Same principle as key expiration, applied to secrets.
        # Secrets without expiry may contain credentials that are never rotated,
        # such as database passwords or API keys.
        for ctrl, vault_type in [("8.3.3", True), ("8.3.4", False)]:
            if is_rbac != vault_type:
                continue
            sec_label = "RBAC" if vault_type else "non-RBAC"
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
                acc.append(
                    R(
                        ctrl,
                        f"Key Vault secrets have expiration date set ({sec_label})",
                        1,
                        "8 - Security Services",
                        ERROR,
                        (f"Vault '{vname}': Failed to enumerate secrets:" f" {_friendly_error(error_msg)}"),
                        "",
                        sid,
                        sname,
                        vname,
                    )
                )
            elif isinstance(secrets, list):
                for s in secrets:
                    exp = s.get("expires")
                    acc.append(
                        R(
                            ctrl,
                            f"Key Vault secrets have expiration date set ({sec_label})",
                            1,
                            "8 - Security Services",
                            PASS if exp else FAIL,
                            (
                                f"Secret '{s.get('name')}': expiration set ({exp})."
                                if exp
                                else f"Secret '{s.get('name')}': expiration NOT set."
                            ),
                            "Key Vault > Secrets > Set expiration date" if not exp else "",
                            sid,
                            sname,
                            vname,
                        )
                    )

        # ── 8.3.11 — Certificate validity <= 12 months ────────────────────────
        # Short-lived certificates limit the window of exposure if a private key
        # is compromised. Certificates with >12 month validity require long-term
        # private key protection and delay detection of key compromise.
        # Certificate-show calls are independent per cert — fetch in parallel.
        rc_certs, cert_ids_raw = az(
            ["keyvault", "certificate", "list", "--vault-name", vname, "--query", "[].id"],
            sid,
            timeout=TIMEOUTS["default"],
        )

        if rc_certs != 0:
            error_msg = (
                str(cert_ids_raw)
                if isinstance(cert_ids_raw, str)
                else "Access denied or error listing certificates (requires Key Vault data plane permissions)"
            )
            acc.append(
                R(
                    "8.3.11",
                    "Certificate validity period <= 12 months",
                    1,
                    "8 - Security Services",
                    ERROR,
                    (f"Vault '{vname}': Failed to enumerate certificates:" f" {_friendly_error(error_msg)}"),
                    "",
                    sid,
                    sname,
                    vname,
                )
            )
        elif isinstance(cert_ids_raw, list) and cert_ids_raw:
            cert_ids: list[str] = cert_ids_raw

            def _fetch_cert(cert_id: str) -> tuple[int, Any]:
                return az(
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

            workers = min(_KEY_WORKERS, len(cert_ids))
            with ThreadPoolExecutor(max_workers=workers) as cpool:
                cert_results = list(cpool.map(_fetch_cert, cert_ids))

            for cert_id, (rc2, cert) in zip(cert_ids, cert_results):
                cname = cert_id.split("/")[-1]
                if rc2 != 0:
                    error_msg = (
                        str(cert)
                        if isinstance(cert, str)
                        else "Access denied (requires Key Vault data plane permissions)"
                    )
                    acc.append(
                        R(
                            "8.3.11",
                            "Certificate validity period <= 12 months",
                            1,
                            "8 - Security Services",
                            ERROR,
                            (
                                f"Vault '{vname}' cert '{cname}': Failed to fetch certificate:"
                                f" {_friendly_error(error_msg)}"
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
                    acc.append(
                        R(
                            "8.3.11",
                            "Certificate validity period <= 12 months",
                            1,
                            "8 - Security Services",
                            PASS if ok else FAIL,
                            (
                                f"Certificate '{cname}': validity {months} month(s) (<= 12)."
                                if ok
                                else f"Certificate '{cname}': validity {months} month(s) (> 12 months)."
                            ),
                            (
                                "Key Vault > Certificates > Issuance policy > " "Set validity <= 12 months"
                                if not ok
                                else ""
                            ),
                            sid,
                            sname,
                            vname,
                        )
                    )

        return acc

    # ── Process all vaults in parallel ───────────────────────────────────────
    results: list[R] = []
    with ThreadPoolExecutor(max_workers=min(_VAULT_WORKERS, len(vaults))) as pool:
        futures = [pool.submit(_check_one_vault, v) for v in vaults]
        for fut in as_completed(futures):
            results.extend(fut.result())
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
        names = ", ".join(h.get("name", "?") for h in hosts)
        return R(
            "8.4.1",
            "Azure Bastion Host exists",
            2,
            "8 - Security Services",
            PASS,
            f"Azure Bastion found: {names}",
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
            "No VMs found in subscription.",
            "",
            sid,
            sname,
        )

    return R(
        "8.4.1",
        "Azure Bastion Host exists",
        2,
        "8 - Security Services",
        FAIL,
        f"No Azure Bastion found. {len(vms)} VM(s) present.",
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
            f"DDoS Network Protection {'enabled' if v.get('hasDdos') else 'not enabled'}.",
            "VNet > DDoS protection > Enable Standard plan" if not v.get("hasDdos") else "",
            sid,
            sname,
            v.get("name", ""),
        )
        for v in vnets
    ]


def check_8_3_10(sid: str, sname: str) -> R:
    """
    8.3.10 — Key Vault Managed HSM is used when required (Manual, Level 2)

    Managed HSM provides FIPS 140-2 Level 3 validated HSMs for cryptographic
    key operations. Whether it is required depends on regulatory and
    compliance needs that cannot be determined programmatically.
    """
    return R(
        "8.3.10",
        "Key Vault Managed HSM used when required",
        2,
        "8 - Security Services",
        MANUAL,
        "Manual verification required — determine if regulatory or compliance "
        "requirements mandate FIPS 140-2 Level 3 HSMs and verify Managed HSM is "
        "provisioned accordingly (az keyvault list --hsm-name).",
        "Azure Portal > Key Vaults > Create Managed HSM for workloads requiring FIPS 140-2 Level 3.",
        sid,
        sname,
    )
