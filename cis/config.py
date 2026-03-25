"""
cis_config.py — Configuration constants for the CIS Azure Audit Tool.

All tuneable values live here. An optional ``cis_audit.toml`` file next to this
module (or at the path given by the ``CIS_AUDIT_CONFIG`` environment variable)
can override any value in the ``[timeouts]``, ``[audit]``, and ``[report]``
sections. Values not present in the file keep their built-in defaults.

Example cis_audit.toml
─────────────────────────
[audit]
parallel    = 5
executor    = "thread"
checkpoint_dir = "cis_checkpoints"

[timeouts]
default      = 20
storage_list = 30
storage_svc  = 15
activity_log = 25
graph        = 120
"""

from __future__ import annotations

import functools
import logging
import os
import sys
from pathlib import Path
from typing import Any

# TOML parsing: tomllib is stdlib on Python 3.11+; fall back to tomli on 3.10.
# The sys.version_info guard lets mypy resolve the right branch per version.
if sys.version_info >= (3, 11):
    import tomllib as _tomllib
else:
    try:
        import tomli as _tomllib
    except ImportError:
        _tomllib = None  # type: ignore[assignment]

# ── Tool / benchmark identity ──────────────────────────────────────────────────
VERSION = "1.2.0"  # Written into checkpoints for change detection
BENCHMARK_VER = "5.0.0"  # CIS Benchmark version this tool targets


@functools.lru_cache(maxsize=None)
def _git_hash() -> str:
    """Return the short git commit hash, or 'unknown' if git is unavailable."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def version_full() -> str:
    """Return the full version string including git hash (computed on first call)."""
    return f"{VERSION}+{_git_hash()}"


# ── Filesystem ────────────────────────────────────────────────────────────────
CHECKPOINT_DIR = Path("cis_checkpoints")  # Per-subscription result cache

# ── Azure CLI call timeouts (seconds) ─────────────────────────────────────────
TIMEOUTS: dict[str, int] = {
    "default": 20,  # Most az CLI calls (diagnostics, security, keyvault, network)
    "storage_list": 30,  # az storage account list — larger payload per subscription
    "storage_svc": 15,  # Per-account blob/file/table service property queries
    "activity_log": 25,  # Activity log queries with 90-day window
    "graph": 120,  # Resource Graph bulk queries (az graph query)
}

# ── Default parallel execution settings ───────────────────────────────────────
DEFAULT_PARALLEL: int = 3
DEFAULT_EXECUTOR: str = "thread"  # "thread" or "process"

# ── Audit result status values ────────────────────────────────────────────────
PASS = "PASS"  # Control requirement is met
FAIL = "FAIL"  # Control requirement is NOT met — action required
ERROR = "ERROR"  # Could not evaluate — az CLI call failed or timed out
INFO = "INFO"  # Not applicable (e.g. no resources of this type in subscription)
MANUAL = "MANUAL"  # Requires human review — cannot be automated via az CLI
SUPPRESSED = "SUPPRESSED"  # Accepted risk — suppressed via suppressions.toml

# ── Custom log level ──────────────────────────────────────────────────────────
TRACE_LEVEL = 5  # Below DEBUG — very chatty execution traces

# ── Module logger ─────────────────────────────────────────────────────────────
LOGGER = logging.getLogger("cis_audit")

# ── MSAL / Graph auth config ─────────────────────────────────────────────────
# Populated by load_config_file() from [graph_auth] in cis_audit.toml and/or
# CIS_GRAPH_* environment variables.  Used by azure/graph_auth.py for Graph
# endpoints whose required scopes are not available in the az CLI app token.
GRAPH_AUTH: dict[str, str] = {}

# ── Caller identity (set at startup from az account show) ────────────────────
# Either "user" or "servicePrincipal".  Used by checks to tailor error messages
# so remediation guidance matches the authentication method in use.
CALLER_TYPE: str = "user"  # default to user; overwritten in main()

# ── Azure built-in role definition GUIDs (stable, defined by Microsoft) ──────
# These GUIDs are identical in every tenant — safe to hardcode.
ROLE_OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  # Owner
ROLE_UAA = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"  # User Access Administrator

# ── Source addresses meaning "open to the internet" in NSG rules ─────────────
# "0.0.0.0/0" is covered by the endswith("/0") check, not this set.
INTERNET_SRCS: frozenset[str] = frozenset({"*", "0.0.0.0", "internet", "any"})

# ── Platform-managed subnets that Azure prohibits attaching NSGs to ───────────
# check_7_11 skips these to avoid false FAIL results.
EXEMPT_SUBNETS: frozenset[str] = frozenset(
    {
        "gatewaysubnet",  # VPN / ExpressRoute Gateway
        "azurebastionsubnet",  # Azure Bastion
        "azurefirewallsubnet",  # Azure Firewall
        "azurefirewallmanagementsubnet",  # Azure Firewall management traffic
        "routeserversubnet",  # Azure Route Server
    }
)

# ══════════════════════════════════════════════════════════════════════════════
# CONTROL CATALOG — single source of truth for --preview cross-reference
# ══════════════════════════════════════════════════════════════════════════════
# Each entry: (control_id, level, section, title, audit_method)
# audit_method describes what CLI command, API, or data source the tool uses.

CONTROL_CATALOG: tuple[tuple[str, int, str, str, str], ...] = (
    # ── Section 2 — Azure Databricks ──────────────────────────────────────
    ("2.1.1", 2, "2 - Azure Databricks", "Databricks deployed in customer-managed VNet", "Resource Graph: databricks"),
    (
        "2.1.2",
        1,
        "2 - Azure Databricks",
        "NSGs configured on Databricks subnets",
        "Resource Graph: databricks + subnets",
    ),
    (
        "2.1.7",
        2,
        "2 - Azure Databricks",
        "Diagnostic logging configured for Azure Databricks",
        "az monitor diagnostic-settings list --resource",
    ),
    ("2.1.9", 2, "2 - Azure Databricks", "Databricks 'No Public IP' is enabled", "Resource Graph: databricks"),
    ("2.1.10", 2, "2 - Azure Databricks", "Databricks public network access is disabled", "Resource Graph: databricks"),
    (
        "2.1.8",
        2,
        "2 - Azure Databricks",
        "Databricks encryption uses customer-managed keys",
        "Resource Graph: databricks",
    ),
    ("2.1.11", 2, "2 - Azure Databricks", "Private endpoints used to access Databricks", "Resource Graph: databricks"),
    # ── Section 3 — Compute Services ──────────────────────────────────────
    (
        "3.1.1",
        2,
        "3 - Compute Services",
        "Only MFA-enabled identities can access privileged VMs",
        "MANUAL — requires human verification",
    ),
    # ── Section 5 — Identity Services (tenant-level) ─────────────────────
    (
        "5.1.1",
        1,
        "5 - Identity Services",
        "Security defaults enabled in Microsoft Entra ID",
        "Graph API: GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
    ),
    (
        "5.1.2",
        1,
        "5 - Identity Services",
        "MFA enabled for all users",
        "Graph API: GET /beta/reports/authenticationMethods/userRegistrationDetails",
    ),
    (
        "5.1.3",
        1,
        "5 - Identity Services",
        "Allow users to remember MFA on trusted devices is disabled",
        "MANUAL — setting lives in per-user MFA portal, no API",
    ),
    (
        "5.4",
        1,
        "5 - Identity Services",
        "Restrict non-admin users from creating tenants",
        "Graph API: GET /v1.0/policies/authorizationPolicy",
    ),
    (
        "5.14",
        1,
        "5 - Identity Services",
        "'Users can register applications' set to No",
        "Graph API: GET /v1.0/policies/authorizationPolicy",
    ),
    (
        "5.15",
        1,
        "5 - Identity Services",
        "Guest access restricted to own directory objects",
        "Graph API: GET /v1.0/policies/authorizationPolicy",
    ),
    (
        "5.16",
        2,
        "5 - Identity Services",
        "Guest invite restrictions set to admins or no one",
        "Graph API: GET /v1.0/policies/authorizationPolicy",
    ),
    (
        "5.28",
        1,
        "5 - Identity Services",
        "Privileged users protected by phishing-resistant MFA",
        "MANUAL — no Graph API for per-user MFA method strength",
    ),
    # ── Section 5 — Identity Services (per-subscription) ─────────────────
    (
        "5.3.3",
        1,
        "5 - Identity Services",
        "User Access Administrator role restricted at subscription scope",
        "Resource Graph: role assignments",
    ),
    (
        "5.23",
        1,
        "5 - Identity Services",
        "No custom subscription administrator roles",
        "az role definition list --custom-role-only true",
    ),
    ("5.27", 1, "5 - Identity Services", "Between 2 and 3 subscription owners", "Resource Graph: role assignments"),
    # ── Section 5 — Identity Services (MANUAL) ────────────────────────────
    (
        "5.2.2",
        1,
        "5 - Identity Services",
        "Exclusionary geographic Conditional Access policy considered",
        "MANUAL — requires Entra ID portal review",
    ),
    (
        "5.3.2",
        1,
        "5 - Identity Services",
        "Guest users reviewed on a regular basis",
        "MANUAL — requires human review of guest accounts",
    ),
    # ── Section 5 — Identity Services (automated via Graph API) ───────────
    (
        "5.6",
        1,
        "5 - Identity Services",
        "Account lockout threshold is ≤ 10",
        "Graph API: GET /v1.0/policies/authenticationMethodsPolicy",
    ),
    # ── Section 6 — Management & Governance ──────────────────────────────
    (
        "6.1.1.1",
        1,
        "6 - Management and Governance",
        "Diagnostic Setting exists for subscription",
        "az monitor diagnostic-settings subscription list",
    ),
    (
        "6.1.1.2",
        1,
        "6 - Management and Governance",
        "Diagnostic Setting captures required log categories",
        "az monitor diagnostic-settings subscription list",
    ),
    (
        "6.1.1.3",
        1,
        "6 - Management and Governance",
        "Activity log retention >= 365 days",
        "az monitor log-profiles list",
    ),
    (
        "6.1.1.4",
        1,
        "6 - Management and Governance",
        "Key Vault diagnostic logging enabled",
        "az monitor diagnostic-settings list --resource",
    ),
    (
        "6.1.1.6",
        2,
        "6 - Management and Governance",
        "Storage account for activity logs not publicly accessible",
        "Resource Graph: storage + diagnostic settings",
    ),
    (
        "6.1.2.1",
        1,
        "6 - Management and Governance",
        "Alert: Create Policy Assignment",
        "az monitor activity-log alert list",
    ),
    (
        "6.1.2.2",
        1,
        "6 - Management and Governance",
        "Alert: Delete Policy Assignment",
        "az monitor activity-log alert list",
    ),
    ("6.1.2.3", 1, "6 - Management and Governance", "Alert: Create/Update NSG", "az monitor activity-log alert list"),
    ("6.1.2.4", 1, "6 - Management and Governance", "Alert: Delete NSG", "az monitor activity-log alert list"),
    (
        "6.1.2.5",
        1,
        "6 - Management and Governance",
        "Alert: Create/Update NSG Rule",
        "az monitor activity-log alert list",
    ),
    ("6.1.2.6", 1, "6 - Management and Governance", "Alert: Delete NSG Rule", "az monitor activity-log alert list"),
    (
        "6.1.2.7",
        1,
        "6 - Management and Governance",
        "Alert: Create/Update Security Solution",
        "az monitor activity-log alert list",
    ),
    (
        "6.1.2.8",
        1,
        "6 - Management and Governance",
        "Alert: Delete Security Solution",
        "az monitor activity-log alert list",
    ),
    (
        "6.1.2.9",
        1,
        "6 - Management and Governance",
        "Alert: Create/Update SQL Server Firewall Rule",
        "az monitor activity-log alert list",
    ),
    (
        "6.1.2.10",
        1,
        "6 - Management and Governance",
        "Alert: Delete SQL Server Firewall Rule",
        "az monitor activity-log alert list",
    ),
    (
        "6.1.2.11",
        1,
        "6 - Management and Governance",
        "Alert: Create/Update Role Assignment",
        "az monitor activity-log alert list",
    ),
    (
        "6.1.3.1",
        2,
        "6 - Management and Governance",
        "Application Insights configured",
        "ARM REST: GET /providers/microsoft.insights/components",
    ),
    (
        "6.1.4",
        1,
        "6 - Management and Governance",
        "Azure Monitor resource logging enabled for all services",
        "MANUAL — requires per-resource diagnostic settings review",
    ),
    (
        "6.1.5",
        1,
        "6 - Management and Governance",
        "SKU Basic/Consumption not used on production artifacts",
        "MANUAL — requires business context to identify production resources",
    ),
    (
        "6.2",
        2,
        "6 - Management and Governance",
        "Resource Locks set for mission-critical Azure resources",
        "MANUAL — requires business context to identify mission-critical resources",
    ),
    # ── Section 7 — Networking Services ───────────────────────────────────
    (
        "7.1",
        1,
        "7 - Networking Services",
        "RDP access from internet restricted",
        "Resource Graph: NSG security rules (port 3389)",
    ),
    (
        "7.2",
        1,
        "7 - Networking Services",
        "SSH access from internet restricted",
        "Resource Graph: NSG security rules (port 22)",
    ),
    (
        "7.3",
        1,
        "7 - Networking Services",
        "UDP access from internet restricted",
        "Resource Graph: NSG security rules (UDP)",
    ),
    (
        "7.4",
        1,
        "7 - Networking Services",
        "HTTP/HTTPS access from internet evaluated and restricted",
        "Resource Graph: NSG security rules (ports 80/443)",
    ),
    ("7.5", 2, "7 - Networking Services", "NSG flow log retention > 90 days", "az network watcher flow-log list"),
    (
        "7.6",
        2,
        "7 - Networking Services",
        "Network Watcher enabled for all regions",
        "Resource Graph: locations + Network Watchers",
    ),
    (
        "7.8",
        2,
        "7 - Networking Services",
        "NSG flow logs enabled and sent to Log Analytics",
        "az network watcher flow-log list",
    ),
    (
        "7.9",
        2,
        "7 - Networking Services",
        "VPN Gateway P2S uses Azure AD authentication",
        "ARM REST: GET /providers/Microsoft.Network/virtualNetworkGateways",
    ),
    (
        "7.10",
        2,
        "7 - Networking Services",
        "WAF enabled on Azure Application Gateway",
        "Resource Graph: application gateways",
    ),
    (
        "7.11",
        1,
        "7 - Networking Services",
        "Subnets associated with network security groups",
        "Resource Graph: subnets",
    ),
    (
        "7.12",
        1,
        "7 - Networking Services",
        "Application Gateway min TLS version 1.2+",
        "Resource Graph: application gateways",
    ),
    (
        "7.13",
        2,
        "7 - Networking Services",
        "HTTP2 enabled on Application Gateway",
        "Resource Graph: application gateways",
    ),
    (
        "7.14",
        2,
        "7 - Networking Services",
        "WAF request body inspection enabled",
        "Resource Graph: application gateways",
    ),
    ("7.15", 2, "7 - Networking Services", "WAF set to Prevention mode", "Resource Graph: WAF policies"),
    (
        "7.7",
        1,
        "7 - Networking Services",
        "Public IP addresses evaluated on a periodic basis",
        "MANUAL — requires periodic review of public IPs",
    ),
    (
        "7.16",
        2,
        "7 - Networking Services",
        "Azure Network Security Perimeter (NSP) is used",
        "MANUAL — requires architecture review",
    ),
    # ── Section 8 — Security Services ─────────────────────────────────────
    (
        "8.1.1.1",
        2,
        "8 - Security Services",
        "Microsoft Defender for Servers is On",
        "az security pricing show -n VirtualMachines",
    ),
    (
        "8.1.2.1",
        2,
        "8 - Security Services",
        "Microsoft Defender for App Service is On",
        "az security pricing show -n AppServices",
    ),
    (
        "8.1.3.1",
        2,
        "8 - Security Services",
        "Microsoft Defender for Azure SQL Databases is On",
        "az security pricing show -n SqlServers",
    ),
    (
        "8.1.3.3",
        1,
        "8 - Security Services",
        "Defender for Endpoint integration enabled",
        "ARM REST: GET /providers/Microsoft.Security/settings",
    ),
    (
        "8.1.4.1",
        2,
        "8 - Security Services",
        "Microsoft Defender for SQL Servers on Machines is On",
        "az security pricing show -n SqlServerVirtualMachines",
    ),
    (
        "8.1.5.1",
        2,
        "8 - Security Services",
        "Microsoft Defender for Storage is On",
        "az security pricing show -n StorageAccounts",
    ),
    (
        "8.1.6.1",
        2,
        "8 - Security Services",
        "Microsoft Defender for Containers is On",
        "az security pricing show -n Containers",
    ),
    (
        "8.1.7.1",
        2,
        "8 - Security Services",
        "Microsoft Defender for Key Vault is On",
        "az security pricing show -n KeyVaults",
    ),
    (
        "8.1.7.2",
        2,
        "8 - Security Services",
        "Microsoft Defender for Resource Manager is On",
        "az security pricing show -n Arm",
    ),
    ("8.1.7.3", 2, "8 - Security Services", "Microsoft Defender for DNS is On", "az security pricing show -n Dns"),
    (
        "8.1.7.4",
        2,
        "8 - Security Services",
        "Microsoft Defender for Open-Source Relational Databases is On",
        "az security pricing show -n OpenSourceRelationalDatabases",
    ),
    (
        "8.1.8.1",
        2,
        "8 - Security Services",
        "Microsoft Defender for Azure Cosmos DB is On",
        "az security pricing show -n CosmosDbs",
    ),
    ("8.1.9.1", 2, "8 - Security Services", "Microsoft Defender for APIs is On", "az security pricing show -n Api"),
    (
        "8.1.10",
        1,
        "8 - Security Services",
        "Defender configured to assess VMs for OS updates",
        "ARM REST: GET /providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings",
    ),
    (
        "8.1.12",
        1,
        "8 - Security Services",
        "Security contact email set for Defender notifications",
        "az security contact list + ARM REST",
    ),
    (
        "8.1.13",
        1,
        "8 - Security Services",
        "Notifications for high-severity alerts enabled",
        "az security contact list + ARM REST",
    ),
    (
        "8.1.14",
        1,
        "8 - Security Services",
        "'All users with Owner role' get alerts",
        "az security contact list + ARM REST",
    ),
    ("8.1.15", 1, "8 - Security Services", "Security contact phone number set", "az security contact list + ARM REST"),
    ("8.3.1", 1, "8 - Security Services", "Key Vault recoverable (soft delete enabled)", "Resource Graph: Key Vaults"),
    ("8.3.2", 1, "8 - Security Services", "Key Vault private endpoints configured", "Resource Graph: Key Vaults"),
    (
        "8.3.3",
        2,
        "8 - Security Services",
        "Key Vault logging enabled",
        "az monitor diagnostic-settings list --resource",
    ),
    (
        "8.3.4",
        1,
        "8 - Security Services",
        "Expiration date set on all keys",
        "az keyvault key list + az keyvault key show",
    ),
    (
        "8.3.5",
        1,
        "8 - Security Services",
        "Expiration date set on all secrets",
        "az keyvault secret list + az keyvault secret show",
    ),
    ("8.3.6", 2, "8 - Security Services", "Expiration date set on all certificates", "az keyvault certificate list"),
    ("8.3.7", 2, "8 - Security Services", "Key Vaults use RBAC (not access policies)", "Resource Graph: Key Vaults"),
    ("8.3.8", 2, "8 - Security Services", "Key Vault purge protection enabled", "Resource Graph: Key Vaults"),
    ("8.3.9", 2, "8 - Security Services", "Private endpoints used for Key Vaults", "Resource Graph: Key Vaults"),
    (
        "8.3.10",
        2,
        "8 - Security Services",
        "Key Vault Managed HSM used when required",
        "MANUAL — requires regulatory/compliance assessment",
    ),
    ("8.3.11", 2, "8 - Security Services", "Key Vault key rotation enabled", "az keyvault key rotation-policy show"),
    ("8.4.1", 2, "8 - Security Services", "Azure Bastion Host exists", "Resource Graph: Bastion hosts + VMs"),
    ("8.5", 2, "8 - Security Services", "DDoS Network Protection enabled on VNets", "Resource Graph: VNets"),
    # ── Section 9 — Storage Services ──────────────────────────────────────
    (
        "9.1.1",
        1,
        "9 - Storage Services",
        "Soft delete enabled for Azure Files",
        "az storage account file-service-properties show",
    ),
    ("9.1.2", 1, "9 - Storage Services", "Soft delete enabled for blob containers", "Resource Graph: storage accounts"),
    ("9.1.3", 1, "9 - Storage Services", "Blob versioning enabled", "Resource Graph: storage accounts"),
    ("9.2.1", 1, "9 - Storage Services", "Secure transfer required (HTTPS only)", "Resource Graph: storage accounts"),
    (
        "9.2.2",
        1,
        "9 - Storage Services",
        "Infrastructure encryption enabled (double encryption)",
        "Resource Graph: storage accounts",
    ),
    ("9.2.3", 1, "9 - Storage Services", "Storage account public access disabled", "Resource Graph: storage accounts"),
    ("9.2.4", 1, "9 - Storage Services", "Default network access rule set to Deny", "Resource Graph: storage accounts"),
    (
        "9.2.5",
        1,
        "9 - Storage Services",
        "Trusted Azure Services can access storage account",
        "Resource Graph: storage accounts",
    ),
    (
        "9.2.6",
        1,
        "9 - Storage Services",
        "Private endpoints used for storage accounts",
        "Resource Graph: storage accounts",
    ),
    (
        "9.3.1.1",
        1,
        "9 - Storage Services",
        "Storage account key rotation reminders enabled",
        "az storage account show --query keyPolicy",
    ),
    (
        "9.3.1.2",
        1,
        "9 - Storage Services",
        "Storage access keys regenerated within 90 days",
        "az storage account show --query keyCreationTime",
    ),
    (
        "9.3.1.3",
        1,
        "9 - Storage Services",
        "Storage account access keys periodically regenerated",
        "az storage account show --query keyPolicy",
    ),
    ("9.3.2.1", 1, "9 - Storage Services", "Minimum TLS version set to 1.2", "Resource Graph: storage accounts"),
    ("9.3.2.2", 1, "9 - Storage Services", "Shared key access disabled", "'Not Applicable' — deprecated by Microsoft"),
    (
        "9.3.2.3",
        1,
        "9 - Storage Services",
        "SAS tokens expire within an hour",
        "'Not Applicable' — no API to verify SAS expiry policy",
    ),
    ("9.3.3.1", 1, "9 - Storage Services", "Storage account encryption using CMK", "Resource Graph: storage accounts"),
    ("9.3.4", 2, "9 - Storage Services", "Storage logging enabled for Blob Service", "az storage logging show"),
    ("9.3.5", 2, "9 - Storage Services", "Storage logging enabled for Table Service", "az storage logging show"),
    ("9.3.6", 2, "9 - Storage Services", "Storage logging enabled for Queue Service", "az storage logging show"),
    (
        "9.3.7",
        1,
        "9 - Storage Services",
        "Azure Storage blob public access disabled",
        "Resource Graph: storage accounts",
    ),
    (
        "9.3.8",
        1,
        "9 - Storage Services",
        "Storage account cross-tenant replication disabled",
        "Resource Graph: storage accounts",
    ),
    (
        "9.3.9",
        2,
        "9 - Storage Services",
        "Storage account zone-redundant storage (ZRS/GZRS)",
        "Resource Graph: storage accounts",
    ),
    (
        "9.3.10",
        1,
        "9 - Storage Services",
        "Immutable blob storage with locked retention policy",
        "az storage container immutability-policy show",
    ),
    ("9.3.11", 1, "9 - Storage Services", "Resource lock configured on storage accounts", "az lock list --resource"),
)

# ══════════════════════════════════════════════════════════════════════════════
# TOML CONFIG LOADER
# ══════════════════════════════════════════════════════════════════════════════

_DEFAULT_CONFIG_NAME = "cis_audit.toml"


def load_config_file(path: Path | None = None) -> None:
    """Load ``cis_audit.toml`` and override module-level defaults in place.

    Looks for the config file in this order:
    1. *path* argument (if supplied)
    2. ``CIS_AUDIT_CONFIG`` environment variable
    3. ``cis_audit.toml`` next to ``cis_config.py``

    Missing file → silently ignored (all defaults kept).
    Unknown keys → logged as warnings, not errors.
    """
    # TIMEOUTS and GRAPH_AUTH are mutated in-place (dict item assignment) — no global declaration needed.
    # The other three are reassigned, so they require global.
    global DEFAULT_PARALLEL, DEFAULT_EXECUTOR, CHECKPOINT_DIR  # noqa: PLW0603

    # --- resolve config path ---
    if path is None:
        env_path = os.environ.get("CIS_AUDIT_CONFIG")
        if env_path:
            path = Path(env_path)
        else:
            path = Path(__file__).parent / _DEFAULT_CONFIG_NAME

    if not path.exists():
        return  # No config file — use built-in defaults, that's fine

    # --- parse TOML ---
    if _tomllib is None:
        LOGGER.warning(
            "cis_audit.toml found but tomllib/tomli is not available. "
            "Install tomli (pip install tomli) on Python < 3.11 to use config files."
        )
        return

    try:
        with open(path, "rb") as fh:
            data: dict[str, Any] = _tomllib.load(fh)
    except Exception as exc:
        LOGGER.warning("Failed to parse config file %s: %s", path, exc)
        return

    LOGGER.info("Loaded config from %s", path)

    # --- [timeouts] section ---
    _KNOWN_TIMEOUT_KEYS = set(TIMEOUTS)
    for key, val in data.get("timeouts", {}).items():
        if key not in _KNOWN_TIMEOUT_KEYS:
            LOGGER.warning("Unknown [timeouts] key in config: %r (ignored)", key)
            continue
        if not isinstance(val, int) or val <= 0:
            LOGGER.warning("[timeouts].%s must be a positive integer (got %r) — ignored", key, val)
            continue
        TIMEOUTS[key] = val

    # --- [audit] section ---
    audit = data.get("audit", {})

    if "parallel" in audit:
        val = audit["parallel"]
        if isinstance(val, int) and val >= 1:
            DEFAULT_PARALLEL = val
        else:
            LOGGER.warning("[audit].parallel must be a positive integer (got %r) — ignored", val)

    if "executor" in audit:
        val = audit["executor"]
        if val in ("thread", "process"):
            DEFAULT_EXECUTOR = val
        else:
            LOGGER.warning("[audit].executor must be 'thread' or 'process' (got %r) — ignored", val)

    if "checkpoint_dir" in audit:
        val = audit["checkpoint_dir"]
        if isinstance(val, str) and val.strip():
            CHECKPOINT_DIR = Path(val)
        else:
            LOGGER.warning("[audit].checkpoint_dir must be a non-empty string (got %r) — ignored", val)

    # --- [graph_auth] section ---
    _KNOWN_GRAPH_AUTH_KEYS = {"client_id", "tenant_id", "client_secret"}
    for key, val in data.get("graph_auth", {}).items():
        if key not in _KNOWN_GRAPH_AUTH_KEYS:
            LOGGER.warning("Unknown [graph_auth] key in config: %r (ignored)", key)
            continue
        if not isinstance(val, str) or not val.strip():
            LOGGER.warning("[graph_auth].%s must be a non-empty string (got %r) — ignored", key, val)
            continue
        GRAPH_AUTH[key] = val
