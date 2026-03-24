"""
checks_s9.py — CIS Azure Benchmark Section 9 checks.

SECTION 9 — STORAGE SERVICES
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from cis.config import PASS, FAIL, ERROR, INFO, TIMEOUTS, LOGGER
from cis.models import R
from cis.check_helpers import _err, _idx, _info
from azure.helpers import az, _CLEAN_STORAGE_AUTHZ_MSG, _friendly_error, is_authz_error, is_notapplicable_error

# Maximum number of storage accounts audited concurrently within one subscription.
# Each account makes 4 az CLI calls (blob props, file props, key policy, activity log).
# At 10 workers this yields ~40 concurrent subprocesses per subscription — well within
# typical system limits. Adjust down if you see resource exhaustion on your runner.
_ACCOUNT_WORKERS = 10


def check_9_storage(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    9.x — All storage account security checks (Sections 9.1, 9.2, 9.3)

    Storage checks are split into four logical groups to isolate failures:
    an exception in blob service checks does NOT prevent static or file
    service checks from running on the same account.

    Group 1 — Static checks (no extra API calls)
      Properties available directly from the Resource Graph 'storage' query.
      Zero additional az CLI calls required. Checks: 9.3.4, 9.3.2.2,
      9.3.7, 9.3.8, 9.3.2.3, 9.3.6, 9.3.1.3, 9.3.3.1, 9.3.5, 9.3.2.1, 9.3.11

    Group 2 — Blob service properties
      Requires: az storage account blob-service-properties show
      Checks: 9.2.1 (blob soft delete), 9.2.2 (container soft delete),
              9.2.3 (blob versioning)
      Also requires: az storage blob service-properties show (data-plane)
      Checks: 9.2.4 (blob logging read), 9.2.5 (blob logging write),
              9.2.6 (blob logging delete)

    Group 3 — File service properties
      Requires: az storage account file-service-properties show
      Checks: 9.1.1 (file soft delete), 9.1.2 (SMB version), 9.1.3 (SMB encryption)

    Group 4 — Key management
      Requires: az storage account show (key policy) + az monitor activity-log list
      Checks: 9.3.1.1 (rotation reminders), 9.3.1.2 (keys rotated within 90 days)

    Group 5 — Resource locks (subscription-wide)
      Single az lock list call fetched once before per-account processing.
      Checks: 9.3.9 (CanNotDelete lock), 9.3.10 (ReadOnly lock)

    Data source (Group 1): Resource Graph 'storage' query
    Data sources (Groups 2-4): az CLI per-account calls, parallelised across accounts
    Data source (Group 5): az lock list (one call per subscription)
    """
    accounts = _idx(td, "storage", sid)

    # If Resource Graph returned nothing, fall back to az storage account list.
    # This happens when a subscription was loaded from a stale checkpoint that
    # pre-dates the Resource Graph prefetch, or when the Graph query timed out.
    # Rather than returning a single ERROR, we fetch the full account details
    # via az CLI and normalise the field names to match what Resource Graph
    # returns — so the complete set of per-control checks can still run.
    if not accounts:
        rc_list, az_accounts = az(["storage", "account", "list"], sid, timeout=TIMEOUTS["storage_list"])
        if rc_list != 0 or not az_accounts:
            # Genuinely no storage accounts (or CLI also failed).
            # Instead of returning a single aggregated "9.x" control id, emit
            # an INFO result for each individual storage control so the report
            # shows the specific control ids (e.g. 9.1.1, 9.2.1, 9.3.4).
            storage_ctrls = [
                "9.1.1",
                "9.1.2",
                "9.1.3",  # File service
                "9.2.1",
                "9.2.2",
                "9.2.3",  # Blob service
                "9.2.4",
                "9.2.5",
                "9.2.6",  # Blob logging
                "9.3.1.1",
                "9.3.1.2",
                "9.3.1.3",  # Key management / keys
                "9.3.2.1",
                "9.3.2.2",
                "9.3.2.3",  # Network access
                "9.3.3.1",
                "9.3.4",
                "9.3.5",
                "9.3.6",  # Misc storage checks
                "9.3.7",
                "9.3.8",
                "9.3.9",
                "9.3.10",
                "9.3.11",
            ]
            _STORAGE_LEVELS: dict[str, int] = {
                "9.2.3": 2,
                "9.2.4": 2,
                "9.2.5": 2,
                "9.2.6": 2,
                "9.3.1.3": 2,
                "9.3.2.1": 2,
                "9.3.3.1": 2,
                "9.3.5": 2,
                "9.3.10": 2,
                "9.3.11": 2,
            }
            return [
                _info(
                    cid,
                    f"Storage check {cid}",
                    _STORAGE_LEVELS.get(cid, 1),
                    "9 - Storage Services",
                    "No storage accounts found.",
                    sid,
                    sname,
                )
                for cid in storage_ctrls
            ]

        # Normalise az CLI field names → Resource Graph field names.
        # az storage account list returns the full ARM object; the field paths
        # differ slightly from the Kusto projections in the _QUERIES dict.
        normalised = []
        for a in (az_accounts if isinstance(az_accounts, list) else []):
            props = a.get("properties", a)  # some API versions nest under "properties"
            acls = props.get("networkAcls") or {}
            bypass = acls.get("bypass") or []
            # bypass is a list ["AzureServices", "Logging"] in CLI vs a
            # comma-separated string "AzureServices, Logging" in Resource Graph.
            # Normalise to a comma-joined string so the downstream check works.
            bypass_str = ", ".join(bypass) if isinstance(bypass, list) else str(bypass)
            pe_count = len(a.get("privateEndpointConnections") or [])

            normalised.append(
                {
                    "id": a.get("id", ""),
                    "name": a.get("name", "?"),
                    "resourceGroup": a.get("resourceGroup", "?"),
                    "subscriptionId": sid,
                    # Map CLI property names → Resource Graph projection names
                    "httpsOnly": props.get("supportsHttpsTrafficOnly"),
                    "publicAccess": props.get("publicNetworkAccess", ""),
                    "crossTenant": props.get("allowCrossTenantReplication"),
                    "blobAnon": props.get("allowBlobPublicAccess"),
                    "defaultAction": acls.get("defaultAction", ""),
                    "bypass": bypass_str,
                    "minTls": props.get("minimumTlsVersion", ""),
                    "keyAccess": props.get("allowSharedKeyAccess"),
                    "oauthDefault": props.get("defaultToOAuthAuthentication"),
                    "sku": (a.get("sku") or {}).get("name", ""),
                    "privateEps": pe_count,
                }
            )
        accounts = normalised

    # ── Group 5 — fetch subscription-wide lock list once before the per-account loop ──
    # Fetched here so it can complete while per-account work is parallelised below.
    rc_lk, all_locks = az(["lock", "list", "--subscription", sid], sid, timeout=TIMEOUTS["default"])

    def _check_one_account(acct: dict[str, Any]) -> list[R]:
        """Audit one storage account (Groups 1–4). Called in parallel by the outer pool."""
        aname = acct.get("name", "?")
        LOGGER.debug("    [%s] storage account: %s", sname[:24], aname)
        rg = acct.get("resourceGroup", "?")
        acc_results: list[R] = []

        # ────────────────────────────────────────────────────────────────────
        # GROUP 1 — Static checks using Resource Graph data only
        # Each tuple: (control_id, title, compliant_bool, level, remediation)
        # ────────────────────────────────────────────────────────────────────

        # Pre-compute compound values used in multiple checks
        bypass = str(acct.get("bypass", "")).lower()  # "AzureServices, Logging, ..."
        sku = str(acct.get("sku", "")).upper()  # "Standard_LRS", "Standard_GRS", etc.
        has_pe = (acct.get("privateEps") or 0) > 0
        is_grs = any(x in sku for x in ("GRS", "GZRS", "RAGRS", "RAGZRS"))

        static = [
            # Each tuple: (ctrl, title, lvl, compliant, detail, remediation)
            # detail is the text shown in the report — matches PowerShell tool output.
            # 9.3.4 — All traffic must use HTTPS (TLS). HTTP requests are rejected.
            (
                "9.3.4",
                "Secure transfer (HTTPS) required",
                1,
                bool(acct.get("httpsOnly")),
                "Secure transfer (HTTPS only): Required."
                if bool(acct.get("httpsOnly"))
                else "Secure transfer (HTTPS only): Not required \u2014 HTTP connections are allowed.",
                "Storage Account > Configuration > Secure transfer required: Enabled",
            ),
            # 9.3.2.2 — Public network access disabled prevents all internet traffic
            # regardless of firewall rules or IP restrictions.
            (
                "9.3.2.2",
                "Storage account public network access disabled",
                1,
                str(acct.get("publicAccess", "")).lower() == "disabled",
                f"publicNetworkAccess = {acct.get('publicAccess')}",
                "Storage Account > Networking > Public network access: Disabled",
            ),
            # 9.3.7 — Cross-tenant replication allows data to be replicated to storage
            # accounts in OTHER tenants, creating a potential data exfiltration vector.
            (
                "9.3.7",
                "Cross-tenant replication disabled",
                1,
                not acct.get("crossTenant"),
                "Cross-tenant replication: Disabled."
                if not acct.get("crossTenant")
                else "Cross-tenant replication: Enabled \u2014 data can be replicated to storage accounts in other tenants.",
                "Storage Account > Data Management > Object replication > " "Allow cross-tenant replication: Disabled",
            ),
            # 9.3.8 — Anonymous blob access allows unauthenticated public read
            # access to any container configured for anonymous access.
            (
                "9.3.8",
                "Blob anonymous access disabled",
                1,
                not acct.get("blobAnon"),
                "Blob public access: Disabled."
                if not acct.get("blobAnon")
                else "Blob public access: Enabled \u2014 anonymous access to blob containers is allowed.",
                "Storage Account > Configuration > Allow Blob anonymous access: Disabled",
            ),
            # 9.3.2.3 — Default deny ensures traffic must match an explicit allow rule
            # (IP range, VNet, or service) to reach the storage account.
            (
                "9.3.2.3",
                "Default network access rule is Deny",
                1,
                str(acct.get("defaultAction", "")).lower() == "deny",
                f"networkAcls.defaultAction = {acct.get('defaultAction')}",
                "Storage Account > Networking > Default action: Deny",
            ),
            # 9.3.6 — TLS 1.0 and 1.1 are deprecated and have known vulnerabilities.
            (
                "9.3.6",
                "Minimum TLS version 1.2",
                1,
                str(acct.get("minTls", "")).lower() in ("tls1_2", "tls1_3"),
                f"Minimum TLS version: {acct.get('minTls')}."
                if str(acct.get("minTls", "")).lower() in ("tls1_2", "tls1_3")
                else f"Minimum TLS version: {acct.get('minTls')} \u2014 must be TLS 1.2 or higher.",
                "Storage Account > Configuration > Minimum TLS version: TLS 1.2",
            ),
            # 9.3.1.3 — Shared Key (storage account key) access allows any holder of
            # the key to perform any operation. Disabling it forces Azure AD auth.
            (
                "9.3.1.3",
                "Storage account key access disabled",
                2,
                acct.get("keyAccess") is False,
                "Shared key (storage account key) access: Disabled."
                if acct.get("keyAccess") is False
                else "Shared key (storage account key) access: Enabled \u2014 disable to enforce Entra ID authentication.",
                "Storage Account > Configuration > Allow storage account key access: Disabled",
            ),
            # 9.3.3.1 — Sets the portal UI default to Entra ID auth rather than
            # storage account keys, reducing accidental key usage.
            (
                "9.3.3.1",
                "Default to Microsoft Entra authorization in Azure portal",
                2,
                acct.get("oauthDefault") is True,
                "Default to Microsoft Entra ID authorization: Enabled."
                if acct.get("oauthDefault") is True
                else "Default to Microsoft Entra ID authorization: Disabled \u2014 storage data requests are not automatically authorized with Entra ID.",
                "Storage Account > Configuration > Default to Microsoft Entra authorization: Enabled",
            ),
            # 9.3.5 — Trusted Azure services (backup, Defender, Event Grid, etc.)
            # must be able to reach storage even when the default action is Deny.
            # "AzureServices" must appear in the bypass list.
            (
                "9.3.5",
                "Allow Azure trusted services to access storage account",
                2,
                "azureservices" in bypass,
                "networkAcls.bypass includes AzureServices."
                if "azureservices" in bypass
                else f"networkAcls.bypass: {acct.get('bypass')} \u2014 AzureServices not listed.",
                "Storage Account > Networking > Exceptions > Allow Azure services",
            ),
            # 9.3.2.1 — Private endpoints give storage a private IP within the VNet,
            # eliminating public internet exposure for data plane access. (L2)
            (
                "9.3.2.1",
                "Private endpoints used to access storage accounts",
                2,
                has_pe,
                f"Private endpoints: {acct.get('privateEps') or 0} configured."
                if has_pe
                else f"Private endpoints: {acct.get('privateEps') or 0} \u2014 at least one private endpoint is required.",
                "Storage Account > Networking > Private endpoint connections",
            ),
            # 9.3.11 — Geo-redundant storage replicates data to a secondary Azure region,
            # protecting against regional disasters. GRS/GZRS variants all qualify. (L2)
            (
                "9.3.11",
                "Storage redundancy set to geo-redundant (GRS)",
                2,
                is_grs,
                f"Storage SKU: {sku}"
                if is_grs
                else f"Storage SKU: {sku} \u2014 not geo-redundant",
                "Storage Account > Data Management > Redundancy",
            ),
        ]

        # Emit one R per static check
        for ctrl, title, lvl, compliant, detail, remediation in static:
            acc_results.append(
                R(
                    ctrl,
                    title,
                    lvl,
                    "9 - Storage Services",
                    PASS if compliant else FAIL,
                    detail,
                    remediation if not compliant else "",
                    sid,
                    sname,
                    aname if not compliant else "",
                )
            )

        # ────────────────────────────────────────────────────────────────────
        # GROUPS 2 + 3 — Blob and file service properties (fetched concurrently)
        # The two calls are independent so we run them in parallel to halve
        # the per-account latency for this pair.
        # ────────────────────────────────────────────────────────────────────
        with ThreadPoolExecutor(max_workers=2) as svc_pool:
            f_blob = svc_pool.submit(
                az,
                [
                    "storage",
                    "account",
                    "blob-service-properties",
                    "show",
                    "--account-name",
                    aname,
                    "--resource-group",
                    rg,
                ],
                sid,
                timeout=TIMEOUTS["storage_svc"],
            )
            f_file = svc_pool.submit(
                az,
                [
                    "storage",
                    "account",
                    "file-service-properties",
                    "show",
                    "--account-name",
                    aname,
                    "--resource-group",
                    rg,
                ],
                sid,
                timeout=TIMEOUTS["storage_svc"],
            )
            rc_blob, blob_props = f_blob.result()
            rc_file, file_props = f_file.result()

        # GROUP 2 — process blob results
        if rc_blob == 0 and isinstance(blob_props, dict):
            # deleteRetentionPolicy — applies to individual blob versions
            drp = blob_props.get("deleteRetentionPolicy", {}) or {}
            # containerDeleteRetentionPolicy — applies to entire containers
            crp = blob_props.get("containerDeleteRetentionPolicy", {}) or {}
            ver = blob_props.get("isVersioningEnabled", False)

            # 9.2.1 — Blob soft delete allows recovery of deleted blobs within
            # the retention period. Essential for ransomware recovery.
            _sd_on = drp.get("enabled", False)
            _sd_days = drp.get("days", 0)
            _sd_ok = bool(_sd_on) and (isinstance(_sd_days, int) and _sd_days >= 7)
            acc_results.append(
                R(
                    "9.2.1",
                    "Blob soft delete enabled",
                    1,
                    "9 - Storage Services",
                    PASS if _sd_ok else FAIL,
                    f"Blob soft delete: enabled={_sd_on}, days={_sd_days}",
                    (
                        "Storage Account > Data protection > Enable soft delete for blobs (>= 7 days)"
                        if not _sd_ok
                        else ""
                    ),
                    sid,
                    sname,
                    aname if not _sd_ok else "",
                )
            )

            # 9.2.2 — Container soft delete allows recovery of deleted containers
            # (and all blobs within) within the retention period.
            _cd_on = crp.get("enabled", False)
            _cd_days = crp.get("days", 0)
            _cd_ok = bool(_cd_on) and (isinstance(_cd_days, int) and _cd_days >= 7)
            acc_results.append(
                R(
                    "9.2.2",
                    "Container soft delete enabled",
                    1,
                    "9 - Storage Services",
                    PASS if _cd_ok else FAIL,
                    f"Container soft delete: enabled={_cd_on}, days={_cd_days}",
                    (
                        "Storage Account > Data protection > Enable soft delete for containers (>= 7 days)"
                        if not _cd_ok
                        else ""
                    ),
                    sid,
                    sname,
                    aname if not _cd_ok else "",
                )
            )

            # 9.2.3 — Versioning automatically saves a copy of a blob before every
            # write/delete, allowing point-in-time recovery. (L2)
            acc_results.append(
                R(
                    "9.2.3",
                    "Blob versioning enabled",
                    2,
                    "9 - Storage Services",
                    PASS if ver else FAIL,
                    f"Blob versioning: {'Enabled' if ver else 'Disabled'}",
                    "Storage Account > Data protection > Enable blob versioning" if not ver else "",
                    sid,
                    sname,
                    aname if not ver else "",
                )
            )

            # 9.2.4/5/6 — Blob logging (Read/Write/Delete) [L2]
            # Classic storage logging is only available via the data-plane API
            # (az storage blob service-properties show), not the management-plane
            # blob-service-properties endpoint used above.
            rc_log, log_props = az(
                [
                    "storage",
                    "blob",
                    "service-properties",
                    "show",
                    "--account-name",
                    aname,
                    "--auth-mode",
                    "login",
                ],
                sid,
                timeout=TIMEOUTS["storage_svc"],
            )

            if rc_log == 0 and isinstance(log_props, dict):
                blog = log_props.get("logging") or {}
                for cid, title, label, flag in [
                    ("9.2.4", "Storage logging enabled for Blob Service read requests", "read", bool(blog.get("read"))),
                    ("9.2.5", "Storage logging enabled for Blob Service write requests", "write", bool(blog.get("write"))),
                    ("9.2.6", "Storage logging enabled for Blob Service delete requests", "delete", bool(blog.get("delete"))),
                ]:
                    acc_results.append(
                        R(
                            cid,
                            title,
                            2,
                            "9 - Storage Services",
                            PASS if flag else FAIL,
                            f"Blob logging {label}: {flag}",
                            f"Storage Account > Monitoring > Diagnostic settings > Enable {label.capitalize()} logging"
                            if not flag
                            else "",
                            sid,
                            sname,
                            aname if not flag else "",
                        )
                    )
            else:
                _log_err = str(log_props)
                if is_notapplicable_error(_log_err):
                    _log_status = INFO
                    _log_detail = "Blob service not supported for this account type"
                elif is_authz_error(_log_err):
                    _log_status = ERROR
                    _log_detail = _CLEAN_STORAGE_AUTHZ_MSG
                else:
                    _log_status = ERROR
                    _log_detail = _friendly_error(_log_err)
                for cid, title in [
                    ("9.2.4", "Storage logging enabled for Blob Service read requests"),
                    ("9.2.5", "Storage logging enabled for Blob Service write requests"),
                    ("9.2.6", "Storage logging enabled for Blob Service delete requests"),
                ]:
                    acc_results.append(
                        R(
                            cid,
                            title,
                            2,
                            "9 - Storage Services",
                            _log_status,
                            f"Account '{aname}': {_log_detail}",
                            "",
                            sid,
                            sname,
                            aname if _log_status == ERROR else "",
                        )
                    )
        else:
            # API call failed — emit result for all three blob checks.
            _blob_err = str(blob_props)
            if is_notapplicable_error(_blob_err):
                # FeatureNotSupportedForAccount: ADLS Gen2 has no blob service — INFO.
                _blob_status = INFO
                _blob_detail = "Feature not supported for this account type"
                _blob_remediation = ""
            elif is_authz_error(_blob_err):
                # Missing read access to storage management plane — ERROR.
                _blob_status = ERROR
                _blob_detail = _CLEAN_STORAGE_AUTHZ_MSG
                _blob_remediation = "Assign 'Reader' role at the subscription or storage account scope"
            else:
                _blob_status = ERROR
                _blob_detail = _friendly_error(_blob_err)
                _blob_remediation = ""
            for ctrl, title, lvl in [
                ("9.2.1", "Blob soft delete enabled", 1),
                ("9.2.2", "Container soft delete enabled", 1),
                ("9.2.3", "Blob versioning enabled", 2),
                ("9.2.4", "Storage logging enabled for Blob Service read requests", 2),
                ("9.2.5", "Storage logging enabled for Blob Service write requests", 2),
                ("9.2.6", "Storage logging enabled for Blob Service delete requests", 2),
            ]:
                acc_results.append(
                    R(
                        ctrl,
                        title,
                        lvl,
                        "9 - Storage Services",
                        _blob_status,
                        f"Account '{aname}': {_blob_detail}",
                        _blob_remediation,
                        sid,
                        sname,
                        aname if _blob_status == ERROR else "",
                    )
                )

        # GROUP 3 — process file results
        if rc_file == 0 and isinstance(file_props, dict):
            # shareDeleteRetentionPolicy — applies to Azure File Share soft delete
            srp = file_props.get("shareDeleteRetentionPolicy", {}) or {}

            # 9.1.1 — File share soft delete allows recovery of deleted shares
            _fs_on = srp.get("enabled", False)
            _fs_days = srp.get("days", 0)
            _fs_ok = bool(_fs_on) and (isinstance(_fs_days, int) and _fs_days >= 7)
            acc_results.append(
                R(
                    "9.1.1",
                    "Azure Files soft delete enabled",
                    1,
                    "9 - Storage Services",
                    PASS if _fs_ok else FAIL,
                    f"File share soft delete: enabled={_fs_on}, days={_fs_days}",
                    (
                        "Storage Account > Data protection > Enable soft delete for file shares (>= 7 days)"
                        if not _fs_ok
                        else ""
                    ),
                    sid,
                    sname,
                    aname if not _fs_ok else "",
                )
            )

            # SMB settings nested under protocolSettings.smb
            smb = (file_props.get("protocolSettings") or {}).get("smb") or {}
            smb_versions = str(smb.get("versions", "")).split(";")
            smb_enc = str(smb.get("channelEncryption", "")).split(";")
            good_versions = {"smb3.1.1", "smb3.11"}
            good_enc = {"aes-256-gcm", "aes256gcm"}

            has_good_ver = any(v.strip().lower() in good_versions for v in smb_versions)
            has_good_enc = any(e.strip().lower() in good_enc for e in smb_enc)

            # 9.1.2 — SMB 3.1.1 adds pre-authentication integrity protection.
            # If the account has no SMB settings (e.g. BlobStorage tier), treat as PASS.
            acc_results.append(
                R(
                    "9.1.2",
                    "SMB protocol version >= 3.1.1",
                    1,
                    "9 - Storage Services",
                    PASS if has_good_ver or not smb else FAIL,
                    f"SMB protocol versions: {smb.get('versions') or 'Not configured'}",
                    (
                        "Storage Account > File shares > SMB settings > " "SMB protocol version: 3.1.1"
                        if not has_good_ver and smb
                        else ""
                    ),
                    sid,
                    sname,
                    aname if not has_good_ver and smb else "",
                )
            )

            # 9.1.3 — AES-256-GCM provides authenticated encryption of the SMB channel,
            # preventing eavesdropping and tampering on the network.
            acc_results.append(
                R(
                    "9.1.3",
                    "SMB channel encryption AES-256-GCM or higher",
                    1,
                    "9 - Storage Services",
                    PASS if has_good_enc or not smb else FAIL,
                    f"SMB channel encryption: {smb.get('channelEncryption') or 'Not configured'}",
                    (
                        "Storage Account > File shares > SMB settings > " "Channel encryption: AES-256-GCM"
                        if not has_good_enc and smb
                        else ""
                    ),
                    sid,
                    sname,
                    aname if not has_good_enc and smb else "",
                )
            )
        else:
            # API call failed — emit result for all three file checks.
            _file_err = str(file_props)
            if is_notapplicable_error(_file_err):
                # FeatureNotSupportedForAccount: ADLS Gen2 has no file service — INFO.
                _file_status = INFO
                _file_detail = "Feature not supported for this account type"
                _file_remediation = ""
            elif is_authz_error(_file_err):
                # Missing read access to storage management plane — ERROR.
                _file_status = ERROR
                _file_detail = _CLEAN_STORAGE_AUTHZ_MSG
                _file_remediation = "Assign 'Reader' role at the subscription or storage account scope"
            else:
                _file_status = ERROR
                _file_detail = _friendly_error(_file_err)
                _file_remediation = ""
            for ctrl, title, lvl in [
                ("9.1.1", "Azure Files soft delete enabled", 1),
                ("9.1.2", "SMB protocol version >= 3.1.1", 1),
                ("9.1.3", "SMB channel encryption AES-256-GCM", 1),
            ]:
                acc_results.append(
                    R(
                        ctrl,
                        title,
                        lvl,
                        "9 - Storage Services",
                        _file_status,
                        f"Account '{aname}': {_file_detail}",
                        _file_remediation,
                        sid,
                        sname,
                        aname if _file_status == ERROR else "",
                    )
                )

        # ────────────────────────────────────────────────────────────────────
        # GROUP 4 — Key management
        # Single az storage account show call fetches both keyPolicy (for
        # 9.3.1.1) and keyCreationTime (for 9.3.1.2). This mirrors the
        # PowerShell tool's approach and avoids the 90-day activity log
        # retention limitation of the previous implementation.
        # ────────────────────────────────────────────────────────────────────
        rc_acct, acct_details = az(
            [
                "storage", "account", "show",
                "--name", aname, "--resource-group", rg,
                "--query", "{keyCreationTime:keyCreationTime,keyExpirationPeriodInDays:keyPolicy.keyExpirationPeriodInDays}",
            ],
            sid,
            timeout=TIMEOUTS["storage_svc"],
        )

        # 9.3.1.1 — Key rotation reminder
        # keyExpirationPeriodInDays triggers an Azure Portal warning when keys
        # approach the expiry threshold, prompting manual rotation.
        if rc_acct == 0:
            key_data = acct_details if isinstance(acct_details, dict) else {}
            reminder_days = key_data.get("keyExpirationPeriodInDays")
            acc_results.append(
                R(
                    "9.3.1.1",
                    "Storage account key rotation reminders enabled",
                    1,
                    "9 - Storage Services",
                    PASS if reminder_days else FAIL,
                    f"Account '{aname}': keyExpirationPeriodInDays = {reminder_days}",
                    "Storage Account > Access keys > Set rotation reminder" if not reminder_days else "",
                    sid,
                    sname,
                    aname if not reminder_days else "",
                )
            )

            # 9.3.1.2 — Access keys rotated within 90 days
            # Uses keyCreationTime (key1/key2 creation timestamps) to calculate
            # key age. This avoids the 90-day activity log retention limitation.
            from datetime import datetime, timezone

            key_times = key_data.get("keyCreationTime")
            if key_times and isinstance(key_times, dict):
                now = datetime.now(timezone.utc)
                old_keys: list[str] = []
                for prop in ("key1", "key2"):
                    kt = key_times.get(prop)
                    if kt:
                        try:
                            created = datetime.fromisoformat(str(kt).replace("Z", "+00:00"))
                            days = int((now - created).total_seconds() / 86400)
                            if days > 90:
                                old_keys.append(f"{prop} ({days} days old)")
                        except (ValueError, TypeError):
                            old_keys.append(f"{prop} (unable to parse creation time)")

                rotated = len(old_keys) == 0
                acc_results.append(
                    R(
                        "9.3.1.2",
                        "Storage access keys regenerated within 90 days",
                        1,
                        "9 - Storage Services",
                        PASS if rotated else FAIL,
                        "Both access keys rotated within 90 days."
                        if rotated
                        else f"Key(s) not rotated in 90 days: {'; '.join(old_keys)}",
                        "Storage account > Access keys > Rotate key" if not rotated else "",
                        sid,
                        sname,
                        aname if not rotated else "",
                    )
                )
            else:
                acc_results.append(
                    _err(
                        "9.3.1.2",
                        "Storage access keys regenerated within 90 days",
                        1,
                        "9 - Storage Services",
                        "Could not retrieve key creation times.",
                        sid,
                        sname,
                    )
                )
        else:
            acc_results.append(
                _err(
                    "9.3.1.1",
                    "Storage account key rotation reminders enabled",
                    1,
                    "9 - Storage Services",
                    str(acct_details),
                    sid,
                    sname,
                )
            )
            acc_results.append(
                _err(
                    "9.3.1.2",
                    "Storage access keys regenerated within 90 days",
                    1,
                    "9 - Storage Services",
                    str(acct_details),
                    sid,
                    sname,
                )
            )

        return acc_results

    # ── Process all accounts in parallel ─────────────────────────────────────
    results: list[R] = []
    with ThreadPoolExecutor(max_workers=_ACCOUNT_WORKERS) as pool:
        futures = [pool.submit(_check_one_account, acct) for acct in accounts]
        for fut in as_completed(futures):
            results.extend(fut.result())

    # ────────────────────────────────────────────────────────────────────────
    # GROUP 5 — Resource locks (9.3.9, 9.3.10)
    # Single subscription-wide az lock list call; matched against every account.
    # ────────────────────────────────────────────────────────────────────────
    if rc_lk != 0:
        lk_msg = _friendly_error(str(all_locks))
        for acct in accounts:
            aname = acct.get("name", "?")
            results.append(
                _err(
                    "9.3.9",
                    "Storage account has CanNotDelete resource lock",
                    1,
                    "9 - Storage Services",
                    lk_msg,
                    sid,
                    sname,
                )
            )
            results.append(
                _err(
                    "9.3.10",
                    "Storage account has ReadOnly resource lock",
                    2,
                    "9 - Storage Services",
                    lk_msg,
                    sid,
                    sname,
                )
            )
    else:
        lock_list = all_locks if isinstance(all_locks, list) else []
        locks_by_id = {str(lk.get("id", "")).lower(): str(lk.get("level", "")).lower() for lk in lock_list}
        sub_scope = f"/subscriptions/{sid}".lower()

        for acct in accounts:
            aname = acct.get("name", "?")
            acct_id = str(acct.get("id", "")).lower()
            rg_scope = acct_id.split("/providers/")[0].lower()

            covering: set = set()
            for lid, level in locks_by_id.items():
                if (
                    lid.startswith(acct_id + "/providers/microsoft.authorization/locks/")
                    or lid.startswith(rg_scope + "/providers/microsoft.authorization/locks/")
                    or lid.startswith(sub_scope + "/providers/microsoft.authorization/locks/")
                ):
                    covering.add(level)

            has_delete = bool(covering & {"cannotdelete", "readonly"})
            has_read = "readonly" in covering
            summary = (
                f"Lock(s) found: {', '.join(sorted(covering))}"
                if covering
                else "No resource locks found at account, RG, or subscription scope."
            )

            results.append(
                R(
                    "9.3.9",
                    "Storage account has CanNotDelete resource lock",
                    1,
                    "9 - Storage Services",
                    PASS if has_delete else FAIL,
                    f"{aname}: {summary}",
                    "Storage Account > Locks > Add lock > Lock type: Delete" if not has_delete else "",
                    sid,
                    sname,
                    aname if not has_delete else "",
                )
            )
            results.append(
                R(
                    "9.3.10",
                    "Storage account has ReadOnly resource lock",
                    2,
                    "9 - Storage Services",
                    PASS if has_read else FAIL,
                    f"{aname}: {summary}",
                    "Storage Account > Locks > Add lock > Lock type: Read-only" if not has_read else "",
                    sid,
                    sname,
                    aname if not has_read else "",
                )
            )

    return results
