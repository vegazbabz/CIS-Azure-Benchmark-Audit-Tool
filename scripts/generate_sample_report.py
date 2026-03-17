"""
generate_sample_report.py — Generate a sample HTML report with synthetic data.

Run from the repo root:
    python scripts/generate_sample_report.py

Produces docs/sample_report.html using the real generate_html() function but
with entirely fabricated tenant/subscription/resource data — no real Azure
environment is accessed and no real credentials are needed.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow imports from the repo root
sys.path.insert(0, str(Path(__file__).parent.parent))

from cis.models import R
from cis.report import generate_html

PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"
INFO = "INFO"
MANUAL = "MANUAL"
SUPPRESSED = "SUPPRESSED"

PROD = "Contoso-Production"
DEV = "Contoso-Development"
PROD_ID = "00000000-0000-0000-0000-000000000001"
DEV_ID = "00000000-0000-0000-0000-000000000002"

# ── Section 2 — Microsoft Defender for Cloud ──────────────────────────────────
S2 = "2 - Microsoft Defender for Cloud"
results: list[R] = [
    R(
        "2.1.2",
        "Ensure that Microsoft Defender for App Service is set to 'On'",
        2,
        S2,
        PASS,
        "Defender for App Service is enabled.",
        "",
        PROD_ID,
        PROD,
    ),
    R(
        "2.1.2",
        "Ensure that Microsoft Defender for App Service is set to 'On'",
        2,
        S2,
        FAIL,
        "Defender for App Service is not enabled.",
        "Azure Portal → Microsoft Defender for Cloud → Environment Settings → select subscription → Defender plans → App Service → On",
        DEV_ID,
        DEV,
    ),
    R(
        "2.1.7",
        "Ensure that Microsoft Defender for Containers is set to 'On'",
        2,
        S2,
        PASS,
        "Defender for Containers is enabled.",
        "",
        PROD_ID,
        PROD,
    ),
    R(
        "2.1.7",
        "Ensure that Microsoft Defender for Containers is set to 'On'",
        2,
        S2,
        FAIL,
        "Defender for Containers is not enabled.",
        "Azure Portal → Microsoft Defender for Cloud → Environment Settings → select subscription → Defender plans → Containers → On",
        DEV_ID,
        DEV,
    ),
    R(
        "2.1.9",
        "Ensure that Microsoft Defender for Key Vault is set to 'On'",
        2,
        S2,
        PASS,
        "Defender for Key Vault is enabled.",
        "",
        PROD_ID,
        PROD,
    ),
    R(
        "2.1.9",
        "Ensure that Microsoft Defender for Key Vault is set to 'On'",
        2,
        S2,
        PASS,
        "Defender for Key Vault is enabled.",
        "",
        DEV_ID,
        DEV,
    ),
    R(
        "2.1.10",
        "Ensure that Microsoft Defender for DNS is set to 'On'",
        2,
        S2,
        FAIL,
        "Defender for DNS is not enabled.",
        "Azure Portal → Microsoft Defender for Cloud → Environment Settings → select subscription → Defender plans → DNS → On",
        PROD_ID,
        PROD,
    ),
    R(
        "2.1.10",
        "Ensure that Microsoft Defender for DNS is set to 'On'",
        2,
        S2,
        PASS,
        "Defender for DNS is enabled.",
        "",
        DEV_ID,
        DEV,
    ),
    R(
        "2.1.11",
        "Ensure that Microsoft Defender for open-source relational databases is set to 'On'",
        2,
        S2,
        PASS,
        "Defender for open-source relational databases is enabled.",
        "",
        PROD_ID,
        PROD,
    ),
    R(
        "2.1.11",
        "Ensure that Microsoft Defender for open-source relational databases is set to 'On'",
        2,
        S2,
        PASS,
        "Defender for open-source relational databases is enabled.",
        "",
        DEV_ID,
        DEV,
    ),
]

# ── Section 5 — Identity and Access Management ────────────────────────────────
S5 = "5 - Identity and Access Management"
results += [
    R(
        "5.1.1",
        "Ensure Security Defaults are disabled on Azure Active Directory",
        1,
        S5,
        MANUAL,
        "Security Defaults status requires Policy.Read.All scope. "
        "Configure [graph_auth] in cis_audit.toml for automated evaluation. "
        "Manual check: Entra ID → Properties → Manage Security Defaults.",
    ),
    R(
        "5.1.2",
        "Ensure that 'Multi-Factor Authentication' is enabled for all non-service accounts",
        1,
        S5,
        FAIL,
        "3 users are not registered for MFA: alice@contoso.example, bob@contoso.example, charlie@contoso.example.",
        "Entra ID → Users → select user → Authentication methods → require MFA registration",
    ),
    R(
        "5.1.3",
        "Ensure that 'Allow users to remember multi-factor authentication on trusted devices' is disabled",
        1,
        S5,
        MANUAL,
        "This setting lives in the deprecated per-user MFA portal and has no stable Graph API surface. "
        "Manual check: aka.ms/mfasettings → service settings → trusted devices.",
    ),
    R(
        "5.3.3",
        "Ensure that 'Guest users access restrictions' are set to 'Guest user access is restricted to properties and memberships of their own directory objects'",
        1,
        S5,
        PASS,
        "Guest access is restricted to own objects only.",
    ),
    R(
        "5.4",
        "Ensure that 'Guest invite restrictions' are set to 'Only users assigned to specific admin roles can invite guest users'",
        2,
        S5,
        FAIL,
        "All users can invite guest users.",
        "Entra ID → External Identities → External collaboration settings → Guest invite settings → Only users assigned to specific admin roles",
    ),
    R(
        "5.14",
        "Ensure that 'Restrict access to the Azure AD administration portal' is set to 'Yes'",
        1,
        S5,
        PASS,
        "Access to the Azure AD administration portal is restricted to admins.",
    ),
    R(
        "5.15",
        "Ensure that 'Users can register applications' is set to 'No'",
        1,
        S5,
        FAIL,
        "All users can register applications.",
        "Entra ID → User settings → App registrations → Users can register applications → No",
    ),
    R(
        "5.16",
        "Ensure that 'Guest users can register applications' is set to 'No'",
        1,
        S5,
        PASS,
        "Guest users cannot register applications.",
    ),
    R(
        "5.23",
        "Ensure that no custom subscription owner roles are created",
        1,
        S5,
        PASS,
        "No custom roles with owner-level subscription scope were found across 2 subscriptions.",
    ),
    R(
        "5.27",
        "Ensure that 'Subscription leaving Entra ID directory' and 'Subscription entering Entra ID directory' is set to 'Permit no one'",
        2,
        S5,
        FAIL,
        "Subscription directory transfer is not restricted.",
        "Entra ID → Properties → Access management for Azure resources → restrict subscription transfer",
    ),
]

# ── Section 6 — Logging and Monitoring ───────────────────────────────────────
S6 = "6 - Logging and Monitoring"
results += [
    R(
        "6.1.1.1",
        "Ensure the storage container storing the activity logs is not publicly accessible",
        1,
        S6,
        PASS,
        "Storage container for activity logs is not publicly accessible.",
        "",
        PROD_ID,
        PROD,
    ),
    R(
        "6.1.1.2",
        "Ensure the storage account containing the container with activity logs is encrypted with Customer Managed Key",
        2,
        S6,
        FAIL,
        "Storage account 'contosologsstorage' is not encrypted with a Customer Managed Key.",
        "Azure Portal → Storage accounts → contosologsstorage → Encryption → Customer-managed keys",
        PROD_ID,
        PROD,
        "contosologsstorage",
    ),
    R(
        "6.1.1.4",
        "Ensure the activity log retention period is set to at least one year",
        1,
        S6,
        PASS,
        "Activity log retention is set to 365 days.",
        "",
        PROD_ID,
        PROD,
    ),
    R(
        "6.1.1.6",
        "Ensure that Activity Log Alert exists for Create or Update Network Security Group",
        1,
        S6,
        FAIL,
        "No activity log alert for 'Create or Update Network Security Group' was found.",
        "Azure Monitor → Alerts → Create alert rule → signal: Create or Update Network Security Group",
        PROD_ID,
        PROD,
    ),
    R(
        "6.1.1.6",
        "Ensure that Activity Log Alert exists for Create or Update Network Security Group",
        1,
        S6,
        PASS,
        "Activity log alert for 'Create or Update Network Security Group' is configured.",
        "",
        DEV_ID,
        DEV,
    ),
    R(
        "6.1.2",
        "Ensure that Activity Log Alert exists for Delete Network Security Group",
        1,
        S6,
        FAIL,
        "No activity log alert for 'Delete Network Security Group' was found.",
        "Azure Monitor → Alerts → Create alert rule → signal: Delete Network Security Group",
        PROD_ID,
        PROD,
    ),
    R(
        "6.1.3.1",
        "Ensure that logging for Azure Key Vault is 'Enabled'",
        1,
        S6,
        PASS,
        "Diagnostic settings with AuditEvent logging are enabled on all 3 key vaults.",
        "",
        PROD_ID,
        PROD,
        "contoso-prod-kv, contoso-shared-kv, contoso-secrets-kv",
    ),
]

# ── Section 7 — Networking ────────────────────────────────────────────────────
S7 = "7 - Networking Services"
results += [
    R(
        "7.1",
        "Ensure that RDP access from the Internet is evaluated and restricted",
        1,
        S7,
        FAIL,
        "NSG 'webserver-nsg' allows RDP (port 3389) from 0.0.0.0/0.",
        "Azure Portal → Network security groups → webserver-nsg → Inbound rules → remove or restrict the RDP rule",
        PROD_ID,
        PROD,
        "webserver-nsg",
    ),
    R(
        "7.1",
        "Ensure that RDP access from the Internet is evaluated and restricted",
        1,
        S7,
        PASS,
        "No NSGs allow unrestricted RDP access from the internet.",
        "",
        DEV_ID,
        DEV,
    ),
    R(
        "7.2",
        "Ensure that SSH access from the Internet is evaluated and restricted",
        1,
        S7,
        PASS,
        "No NSGs allow unrestricted SSH access from the internet.",
        "",
        PROD_ID,
        PROD,
    ),
    R(
        "7.2",
        "Ensure that SSH access from the Internet is evaluated and restricted",
        1,
        S7,
        PASS,
        "No NSGs allow unrestricted SSH access from the internet.",
        "",
        DEV_ID,
        DEV,
    ),
    R(
        "7.3",
        "Ensure that UDP access from the Internet is evaluated and restricted",
        1,
        S7,
        PASS,
        "No NSGs allow unrestricted UDP access from the internet.",
        "",
        PROD_ID,
        PROD,
    ),
    R(
        "7.4",
        "Ensure that HTTP (port 80) access from the Internet is evaluated and restricted",
        1,
        S7,
        SUPPRESSED,
        "NSG 'lb-nsg' allows HTTP from 0.0.0.0/0 — accepted risk: public-facing load balancer.",
        "",
        PROD_ID,
        PROD,
        "lb-nsg",
    ),
    R(
        "7.5",
        "Ensure that Network Watcher is 'Enabled' for Azure Regions",
        1,
        S7,
        PASS,
        "Network Watcher is enabled in all regions where resources are deployed (West Europe, North Europe).",
        "",
        PROD_ID,
        PROD,
    ),
    R(
        "7.6",
        "Ensure that the Expiration Date is set for all Firewall Policy Rule Collections",
        2,
        S7,
        INFO,
        "No Azure Firewall Policy Rule Collections found in this subscription.",
        "",
        PROD_ID,
        PROD,
    ),
]

# ── Section 8 — Key Vault ─────────────────────────────────────────────────────
S8 = "8 - Key Vault"
results += [
    R(
        "8.3.1",
        "Ensure that the Expiration Date is set for all Keys in Non-RBAC Key Vaults",
        1,
        S8,
        PASS,
        "All 4 keys have expiration dates set.",
        "",
        PROD_ID,
        PROD,
        "contoso-prod-kv",
    ),
    R(
        "8.3.1",
        "Ensure that the Expiration Date is set for all Keys in Non-RBAC Key Vaults",
        1,
        S8,
        ERROR,
        "Firewall blocked — resource not reachable from this runner. "
        "Enable trusted Microsoft services or add the runner IP to the firewall allowlist.",
        "Azure Portal → Key vaults → contoso-secrets-kv → Networking → Firewalls and virtual networks",
        PROD_ID,
        PROD,
        "contoso-secrets-kv",
    ),
    R(
        "8.3.2",
        "Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults",
        1,
        S8,
        PASS,
        "All 2 keys have expiration dates set.",
        "",
        PROD_ID,
        PROD,
        "contoso-shared-kv",
    ),
    R(
        "8.3.4",
        "Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults",
        1,
        S8,
        FAIL,
        "2 secrets have no expiration date: 'db-connection-string', 'api-key-external'.",
        "Azure Portal → Key vaults → contoso-prod-kv → Secrets → select secret → Set expiration date",
        PROD_ID,
        PROD,
        "contoso-prod-kv",
    ),
    R(
        "8.3.9",
        "Ensure the key vault is recoverable",
        2,
        S8,
        PASS,
        "Soft delete and purge protection are both enabled.",
        "",
        PROD_ID,
        PROD,
        "contoso-prod-kv",
    ),
    R(
        "8.3.9",
        "Ensure the key vault is recoverable",
        2,
        S8,
        PASS,
        "Soft delete and purge protection are both enabled.",
        "",
        PROD_ID,
        PROD,
        "contoso-shared-kv",
    ),
    R(
        "8.3.11",
        "Ensure that Private Endpoints are used for Azure Key Vault",
        2,
        S8,
        FAIL,
        "No private endpoint is configured for this Key Vault.",
        "Azure Portal → Key vaults → contoso-prod-kv → Networking → Private endpoint connections → Add",
        PROD_ID,
        PROD,
        "contoso-prod-kv",
    ),
]

# ── Section 9 — Storage ───────────────────────────────────────────────────────
S9 = "9 - Storage"
results += [
    R(
        "9.1.1",
        "Ensure that 'Secure transfer required' is set to 'Enabled'",
        1,
        S9,
        PASS,
        "Secure transfer is required.",
        "",
        PROD_ID,
        PROD,
        "contosoproddata",
    ),
    R(
        "9.1.1",
        "Ensure that 'Secure transfer required' is set to 'Enabled'",
        1,
        S9,
        PASS,
        "Secure transfer is required.",
        "",
        PROD_ID,
        PROD,
        "contosoprodlogs",
    ),
    R(
        "9.1.1",
        "Ensure that 'Secure transfer required' is set to 'Enabled'",
        1,
        S9,
        FAIL,
        "Secure transfer is not required.",
        "Azure Portal → Storage accounts → contosodevtest → Configuration → Secure transfer required → Enabled",
        DEV_ID,
        DEV,
        "contosodevtest",
    ),
    R(
        "9.1.2",
        "Ensure that storage account access keys are periodically regenerated",
        1,
        S9,
        FAIL,
        "Access key was last rotated 187 days ago (threshold: 90 days).",
        "Azure Portal → Storage accounts → contosoproddata → Access keys → Rotate key",
        PROD_ID,
        PROD,
        "contosoproddata",
    ),
    R(
        "9.2.1",
        "Ensure that 'Enable Infrastructure Encryption' for each Storage Account is set to 'checked'",
        2,
        S9,
        PASS,
        "Infrastructure encryption is enabled.",
        "",
        PROD_ID,
        PROD,
        "contosoproddata",
    ),
    R(
        "9.2.2",
        "Ensure that 'Enable Soft Delete for Blobs' is set to 'Enabled'",
        1,
        S9,
        PASS,
        "Blob soft delete is enabled with a retention of 14 days.",
        "",
        PROD_ID,
        PROD,
        "contosoproddata",
    ),
    R(
        "9.2.2",
        "Ensure that 'Enable Soft Delete for Blobs' is set to 'Enabled'",
        1,
        S9,
        FAIL,
        "Blob soft delete is not enabled.",
        "Azure Portal → Storage accounts → contosodevtest → Data protection → Enable soft delete for blobs",
        DEV_ID,
        DEV,
        "contosodevtest",
    ),
    R(
        "9.2.3",
        "Ensure that 'Enable Soft Delete for Containers' is set to 'Enabled'",
        1,
        S9,
        PASS,
        "Container soft delete is enabled with a retention of 14 days.",
        "",
        PROD_ID,
        PROD,
        "contosoproddata",
    ),
    R(
        "9.3.1",
        "Ensure that the storage account public access is disabled",
        1,
        S9,
        PASS,
        "Public blob access is disabled.",
        "",
        PROD_ID,
        PROD,
        "contosoproddata",
    ),
    R(
        "9.3.1",
        "Ensure that the storage account public access is disabled",
        1,
        S9,
        FAIL,
        "Public blob access is enabled.",
        "Azure Portal → Storage accounts → contosodevtest → Configuration → Allow Blob public access → Disabled",
        DEV_ID,
        DEV,
        "contosodevtest",
    ),
    R(
        "9.4",
        "Ensure Storage Logging is Enabled for Queue Service for Read, Write, and Delete Requests",
        2,
        S9,
        INFO,
        "No Queue service found on this account (blob-only storage).",
        "",
        PROD_ID,
        PROD,
        "contosoproddata",
    ),
]

# ── Scope info ────────────────────────────────────────────────────────────────
scope_info = {
    "tenant": "Contoso Corp — contoso.example (sample-tenant-id)",
    "user": "audit-runner@contoso.example",
    "caller_type": "servicePrincipal",
    "scope_label": "All subscriptions (2 enabled)",
    "subscriptions": [PROD, DEV],
    "level_filter": None,
}

# ── Fake run history (compliance trend) ───────────────────────────────────────
history = [
    {
        "timestamp": "2025-10-01T08:00:00Z",
        "score": 54.2,
        "pass": 28,
        "fail": 20,
        "error": 4,
        "info": 5,
        "manual": 2,
        "suppressed": 0,
        "total": 59,
    },
    {
        "timestamp": "2025-11-01T08:00:00Z",
        "score": 61.8,
        "pass": 34,
        "fail": 17,
        "error": 4,
        "info": 5,
        "manual": 2,
        "suppressed": 0,
        "total": 62,
    },
    {
        "timestamp": "2025-12-01T08:00:00Z",
        "score": 66.7,
        "pass": 38,
        "fail": 15,
        "error": 4,
        "info": 5,
        "manual": 2,
        "suppressed": 1,
        "total": 65,
    },
    {
        "timestamp": "2026-01-15T08:00:00Z",
        "score": 69.5,
        "pass": 41,
        "fail": 14,
        "error": 3,
        "info": 5,
        "manual": 2,
        "suppressed": 1,
        "total": 66,
    },
    {
        "timestamp": "2026-02-01T08:00:00Z",
        "score": 72.1,
        "pass": 44,
        "fail": 13,
        "error": 3,
        "info": 5,
        "manual": 2,
        "suppressed": 1,
        "total": 68,
    },
    {
        "timestamp": "2026-03-01T08:00:00Z",
        "score": 74.6,
        "pass": 46,
        "fail": 12,
        "error": 3,
        "info": 5,
        "manual": 2,
        "suppressed": 1,
        "total": 69,
    },
]

# ── Subscription audit timestamps ─────────────────────────────────────────────
sub_timestamps = {
    PROD: "2026-03-17T06:30:00Z",
    DEV: "2026-03-17T06:32:00Z",
}

# ── Generate ───────────────────────────────────────────────────────────────────
output_dir = Path(__file__).parent.parent / "docs"
output_dir.mkdir(exist_ok=True)
output_path = str(output_dir / "sample_report.html")

generate_html(
    results=results,
    output=output_path,
    scope_info=scope_info,
    history=history,
    sub_timestamps=sub_timestamps,
)

print(f"Sample report written to: {output_path}")
print(f"  Total results : {len(results)}")
print(f"  PASS          : {sum(1 for r in results if r.status == PASS)}")
print(f"  FAIL          : {sum(1 for r in results if r.status == FAIL)}")
print(f"  ERROR         : {sum(1 for r in results if r.status == ERROR)}")
print(f"  INFO          : {sum(1 for r in results if r.status == INFO)}")
print(f"  MANUAL        : {sum(1 for r in results if r.status == MANUAL)}")
print(f"  SUPPRESSED    : {sum(1 for r in results if r.status == SUPPRESSED)}")
