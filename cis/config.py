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

# ── Audit tenant scope (set from --tenant at startup) ────────────────────────
# Empty string preserves the Azure CLI's current tenant context. When set, Graph
# token acquisition and tenant-scoped checkpoint loading use this tenant.
AUDIT_TENANT_ID: str = ""

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
    # -- Section 2: Azure Databricks --
    (
        "2.1.1",
        1,
        "2 - Azure Databricks",
        "Ensure that Azure Databricks is deployed in a customer-managed virtual network (VNet)",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "2.1.2",
        1,
        "2 - Azure Databricks",
        "Ensure that network security groups are configured for Databricks subnets",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "2.1.3",
        2,
        "2 - Azure Databricks",
        "Ensure that traffic is encrypted between cluster worker nodes",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "2.1.4",
        1,
        "2 - Azure Databricks",
        "Ensure that users and groups are synced from Microsoft Entra ID to Azure Databricks",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "2.1.5",
        1,
        "2 - Azure Databricks",
        "Ensure that Unity Catalog is configured for Azure Databricks",
        "MANUAL — requires CIS Benchmark manual review",
    ),
    (
        "2.1.6",
        1,
        "2 - Azure Databricks",
        "Ensure that usage is restricted and expiry is enforced for Databricks personal access tokens",
        "MANUAL — requires CIS Benchmark manual review",
    ),
    (
        "2.1.7",
        1,
        "2 - Azure Databricks",
        "Ensure that diagnostic log delivery is configured for Azure Databricks",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "2.1.8",
        2,
        "2 - Azure Databricks",
        "Ensure critical data in Azure Databricks is encrypted with customer-managed keys (CMK)",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "2.1.9",
        1,
        "2 - Azure Databricks",
        "Ensure 'No Public IP' is set to 'Enabled'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "2.1.10",
        1,
        "2 - Azure Databricks",
        "Ensure 'Allow Public Network Access' is set to 'Disabled'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "2.1.11",
        2,
        "2 - Azure Databricks",
        "Ensure private endpoints are used to access Azure Databricks workspaces",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    # -- Section 3: Compute Services --
    (
        "3.1.1",
        2,
        "3 - Compute Services",
        "Ensure only MFA enabled identities can access privileged Virtual Machine",
        "Azure Portal audit in CIS Benchmark",
    ),
    # -- Section 5: Identity Services --
    (
        "5.1.1",
        1,
        "5 - Identity Services",
        "Ensure that 'security defaults' is enabled in Microsoft Entra ID",
        "Azure CLI / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.1.2",
        1,
        "5 - Identity Services",
        "Ensure that 'multifactor authentication' is 'enabled' for all users",
        "PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.1.3",
        1,
        "5 - Identity Services",
        "Ensure that 'Allow users to remember multifactor authentication on devices they trust' is disabled",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.2.1",
        2,
        "5 - Identity Services",
        "Ensure that 'trusted locations' are defined",
        "PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.2.2",
        2,
        "5 - Identity Services",
        "Ensure that an exclusionary geographic Conditional Access policy is considered",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.2.3",
        2,
        "5 - Identity Services",
        "Ensure that an exclusionary device code flow policy is considered",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.2.4",
        2,
        "5 - Identity Services",
        "Ensure that a multifactor authentication policy exists for all users",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.2.5",
        2,
        "5 - Identity Services",
        "Ensure that multifactor authentication is required for risky sign-ins",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.2.6",
        2,
        "5 - Identity Services",
        "Ensure that multifactor authentication is required for Windows Azure Service Management API",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.2.7",
        2,
        "5 - Identity Services",
        "Ensure that multifactor authentication is required to access Microsoft Admin Portals",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.2.8",
        2,
        "5 - Identity Services",
        "Ensure a Token Protection Conditional Access policy is considered",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.3.1",
        1,
        "5 - Identity Services",
        "Ensure that Azure admin accounts are not used for daily operations",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.3.2",
        1,
        "5 - Identity Services",
        "Ensure that guest users are reviewed on a regular basis",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.3.3",
        1,
        "5 - Identity Services",
        "Ensure that use of the 'User Access Administrator' role is restricted",
        "Azure CLI / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.3.4",
        1,
        "5 - Identity Services",
        "Ensure that all 'privileged' role assignments are periodically reviewed",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.3.5",
        1,
        "5 - Identity Services",
        "Ensure disabled user accounts do not have read, write, or owner permissions",
        "Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.3.6",
        1,
        "5 - Identity Services",
        "Ensure 'Tenant Creator' role assignments are periodically reviewed",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.3.7",
        1,
        "5 - Identity Services",
        "Ensure all non-privileged role assignments are periodically reviewed",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.4",
        1,
        "5 - Identity Services",
        "Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'",
        "PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.5",
        1,
        "5 - Identity Services",
        "Ensure that 'Number of methods required to reset' is set to '2'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.6",
        1,
        "5 - Identity Services",
        "Ensure that account 'Lockout threshold' is less than or equal to '10'",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.7",
        1,
        "5 - Identity Services",
        "Ensure that account 'Lockout duration in seconds' is greater than or equal to '60'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.8",
        1,
        "5 - Identity Services",
        "Ensure that a 'Custom banned password list' is set to 'Enforce'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.9",
        1,
        "5 - Identity Services",
        (
            "Ensure that 'Number of days before users are asked to re-confirm their "
            "authentication information' is not set to '0'"
        ),
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.10",
        1,
        "5 - Identity Services",
        "Ensure that 'Notify users on password resets?' is set to 'Yes'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.11",
        1,
        "5 - Identity Services",
        "Ensure that 'Notify all admins when other admins reset their password?' is set to 'Yes'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.12",
        1,
        "5 - Identity Services",
        "Ensure that 'User consent for applications' is set to 'Do not allow user consent'",
        "PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.13",
        2,
        "5 - Identity Services",
        (
            "Ensure that 'User consent for applications' is set to 'Allow user consent for apps "
            "from verified publishers, for selected permissions'"
        ),
        "PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.14",
        1,
        "5 - Identity Services",
        "Ensure that 'Users can register applications' is set to 'No'",
        "PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.15",
        1,
        "5 - Identity Services",
        (
            "Ensure that 'Guest users access restrictions' is set to 'Guest user access is "
            "restricted to properties and memberships of their own directory objects'"
        ),
        "PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.16",
        2,
        "5 - Identity Services",
        (
            "Ensure that 'Guest invite restrictions' is set to 'Only users assigned to specific "
            "admin roles [...]' or 'No one [..]'"
        ),
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.17",
        1,
        "5 - Identity Services",
        "Ensure that 'Restrict access to Microsoft Entra admin center' is set to 'Yes'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.18",
        2,
        "5 - Identity Services",
        "Ensure that 'Restrict user ability to access groups features in My Groups' is set to 'Yes'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.19",
        2,
        "5 - Identity Services",
        "Ensure that 'Users can create security groups in Azure portals, API or PowerShell' is set to 'No'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.20",
        2,
        "5 - Identity Services",
        "Ensure that 'Owners can manage group membership requests in My Groups' is set to 'No'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.21",
        2,
        "5 - Identity Services",
        "Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.22",
        1,
        "5 - Identity Services",
        (
            "Ensure that 'Require Multifactor Authentication to register or join devices with "
            "Microsoft Entra' is set to 'Yes'"
        ),
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.23",
        1,
        "5 - Identity Services",
        "Ensure that no custom subscription administrator roles exist",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.24",
        2,
        "5 - Identity Services",
        "Ensure that a custom role is assigned permissions for administering resource locks",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.25",
        2,
        "5 - Identity Services",
        (
            "Ensure that 'Subscription leaving Microsoft Entra tenant' and 'Subscription "
            "entering Microsoft Entra tenant' is set to 'Permit no one'"
        ),
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.26",
        1,
        "5 - Identity Services",
        "Ensure fewer than 5 users have global administrator assignment",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.27",
        1,
        "5 - Identity Services",
        "Ensure there are between 2 and 3 subscription owners",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "5.28",
        2,
        "5 - Identity Services",
        "Ensure passwordless authentication methods are considered",
        "Azure Portal audit in CIS Benchmark",
    ),
    # -- Section 6: Management & Governance --
    (
        "6.1.1.1",
        1,
        "6 - Management & Governance",
        "Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.1.2",
        1,
        "6 - Management & Governance",
        "Ensure Diagnostic Setting captures appropriate categories",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.1.3",
        2,
        "6 - Management & Governance",
        (
            "Ensure the storage account containing the container with activity logs is "
            "encrypted with customer-managed key (CMK)"
        ),
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.1.4",
        1,
        "6 - Management & Governance",
        "Ensure that logging for Azure Key Vault is 'Enabled'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.1.5",
        2,
        "6 - Management & Governance",
        "Ensure that Network Security Group Flow logs are captured and sent to Log Analytics",
        "Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.1.6",
        2,
        "6 - Management & Governance",
        "Ensure that logging for Azure AppService 'HTTP logs' is enabled",
        "Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.1.7",
        2,
        "6 - Management & Governance",
        "Ensure that virtual network flow logs are captured and sent to Log Analytics",
        "Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.1.8",
        2,
        "6 - Management & Governance",
        (
            "Ensure that a Microsoft Entra diagnostic setting exists to send Microsoft Graph "
            "activity logs to an appropriate destination"
        ),
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.1.9",
        2,
        "6 - Management & Governance",
        (
            "Ensure that a Microsoft Entra diagnostic setting exists to send Microsoft Entra "
            "activity logs to an appropriate destination"
        ),
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.1.10",
        2,
        "6 - Management & Governance",
        "Ensure that Intune logs are captured and sent to Log Analytics",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.2.1",
        1,
        "6 - Management & Governance",
        "Ensure that Activity Log Alert exists for Create Policy Assignment",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.2.2",
        1,
        "6 - Management & Governance",
        "Ensure that Activity Log Alert exists for Delete Policy Assignment",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.2.3",
        1,
        "6 - Management & Governance",
        "Ensure that Activity Log Alert exists for Create or Update Network Security Group",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.2.4",
        1,
        "6 - Management & Governance",
        "Ensure that Activity Log Alert exists for Delete Network Security Group",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.2.5",
        1,
        "6 - Management & Governance",
        "Ensure that Activity Log Alert exists for Create or Update Security Solution",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.2.6",
        1,
        "6 - Management & Governance",
        "Ensure that Activity Log Alert exists for Delete Security Solution",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.2.7",
        1,
        "6 - Management & Governance",
        "Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.2.8",
        1,
        "6 - Management & Governance",
        "Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.2.9",
        1,
        "6 - Management & Governance",
        "Ensure that Activity Log Alert exists for Create or Update Public IP Address rule",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.2.10",
        1,
        "6 - Management & Governance",
        "Ensure that Activity Log Alert exists for Delete Public IP Address rule",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.2.11",
        1,
        "6 - Management & Governance",
        "Ensure that an Activity Log Alert exists for Service Health",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.3.1",
        2,
        "6 - Management & Governance",
        "Ensure Application Insights are Configured",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.4",
        1,
        "6 - Management & Governance",
        "Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.1.5",
        2,
        "6 - Management & Governance",
        (
            "Ensure that SKU Basic/Consumption is not used on artifacts that need to be "
            "monitored (Particularly for Production Workloads)"
        ),
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "6.2",
        2,
        "6 - Management & Governance",
        "Ensure that Resource Locks are set for Mission-Critical Azure Resources",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    # -- Section 7: Networking Services --
    (
        "7.1",
        1,
        "7 - Networking Services",
        "Ensure that RDP access from the Internet is evaluated and restricted",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.2",
        1,
        "7 - Networking Services",
        "Ensure that SSH access from the Internet is evaluated and restricted",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.3",
        1,
        "7 - Networking Services",
        "Ensure that UDP access from the Internet is evaluated and restricted",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.4",
        1,
        "7 - Networking Services",
        "Ensure that HTTP(S) access from the Internet is evaluated and restricted",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.5",
        2,
        "7 - Networking Services",
        "Ensure that network security group flow log retention days is set to greater than or equal to 90",
        "Azure CLI / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.6",
        2,
        "7 - Networking Services",
        "Ensure that Network Watcher is 'Enabled' for Azure Regions that are in use",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.7",
        1,
        "7 - Networking Services",
        "Ensure that Public IP addresses are Evaluated on a Periodic Basis",
        "Azure CLI / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.8",
        2,
        "7 - Networking Services",
        "Ensure that virtual network flow log retention days is set to greater than or equal to 90",
        "Azure CLI / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.9",
        2,
        "7 - Networking Services",
        (
            "Ensure 'Authentication type' is set to 'Azure Active Directory' only for Azure VPN "
            "Gateway point-to-site configuration"
        ),
        "Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.10",
        2,
        "7 - Networking Services",
        "Ensure Azure Web Application Firewall (WAF) is enabled on Azure Application Gateway",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.11",
        1,
        "7 - Networking Services",
        "Ensure subnets are associated with network security groups",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.12",
        1,
        "7 - Networking Services",
        "Ensure the SSL policy's 'Min protocol version' is set to 'TLSv1_2' or higher on Azure Application Gateway",
        "Azure CLI / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.13",
        1,
        "7 - Networking Services",
        "Ensure 'HTTP2' is set to 'Enabled' on Azure Application Gateway",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.14",
        2,
        "7 - Networking Services",
        (
            "Ensure request body inspection is enabled in Azure Web Application Firewall policy "
            "on Azure Application Gateway"
        ),
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.15",
        2,
        "7 - Networking Services",
        "Ensure bot protection is enabled in Azure Web Application Firewall policy on Azure Application Gateway",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "7.16",
        2,
        "7 - Networking Services",
        "Ensure Azure Network Security Perimeter is used to secure Azure platform-as-a-service resources",
        "Azure CLI / Azure Portal audit in CIS Benchmark",
    ),
    # -- Section 8: Security Services --
    (
        "8.1.1.1",
        2,
        "8 - Security Services",
        "Ensure Microsoft Defender CSPM is set to 'On'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.2.1",
        2,
        "8 - Security Services",
        "Ensure Microsoft Defender for APIs is set to 'On'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.3.1",
        2,
        "8 - Security Services",
        "Ensure that Defender for Servers is set to 'On'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.3.2",
        2,
        "8 - Security Services",
        "Ensure that 'Vulnerability assessment for machines' component status is set to 'On'",
        "Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.3.3",
        2,
        "8 - Security Services",
        "Ensure that 'Endpoint protection' component status is set to 'On'",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.3.4",
        2,
        "8 - Security Services",
        "Ensure that 'Agentless scanning for machines' component status is set to 'On'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.3.5",
        2,
        "8 - Security Services",
        "Ensure that 'File Integrity Monitoring' component status is set to 'On'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.4.1",
        2,
        "8 - Security Services",
        "Ensure That Microsoft Defender for Containers Is Set To 'On'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.5.1",
        2,
        "8 - Security Services",
        "Ensure That Microsoft Defender for Storage Is Set To 'On'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.5.2",
        2,
        "8 - Security Services",
        "Ensure Advanced Threat Protection Alerts for Storage Accounts Are Monitored",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.6.1",
        2,
        "8 - Security Services",
        "Ensure That Microsoft Defender for App Services Is Set To 'On'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.7.1",
        2,
        "8 - Security Services",
        "Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.7.2",
        2,
        "8 - Security Services",
        "Ensure That Microsoft Defender for Open-Source Relational Databases Is Set To 'On'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.7.3",
        2,
        "8 - Security Services",
        "Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.7.4",
        2,
        "8 - Security Services",
        "Ensure That Microsoft Defender for SQL Servers on Machines Is Set To 'On'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.8.1",
        2,
        "8 - Security Services",
        "Ensure That Microsoft Defender for Key Vault Is Set To 'On'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.9.1",
        2,
        "8 - Security Services",
        "Ensure That Microsoft Defender for Resource Manager Is Set To 'On'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.10",
        1,
        "8 - Security Services",
        "Ensure that Microsoft Defender for Cloud is configured to check VM operating systems for updates",
        "Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.11",
        1,
        "8 - Security Services",
        "Ensure that Microsoft Cloud Security Benchmark policies are not set to 'Disabled'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.12",
        1,
        "8 - Security Services",
        "Ensure That 'All users with the following roles' is set to 'Owner'",
        "Azure CLI / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.13",
        1,
        "8 - Security Services",
        "Ensure 'Additional email addresses' is Configured with a Security Contact Email",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.14",
        1,
        "8 - Security Services",
        "Ensure that 'Notify about alerts with the following severity (or higher)' is enabled",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.15",
        1,
        "8 - Security Services",
        "Ensure that 'Notify about attack paths with the following risk level (or higher)' is enabled",
        "Azure CLI / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.1.16",
        2,
        "8 - Security Services",
        "Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.2.1",
        2,
        "8 - Security Services",
        "Ensure That Microsoft Defender for IoT Hub Is Set To 'On'",
        "Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.3.1",
        1,
        "8 - Security Services",
        "Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.3.2",
        1,
        "8 - Security Services",
        "Ensure that the Expiration Date is set for all Keys in Non-RBAC Key Vaults.",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.3.3",
        1,
        "8 - Security Services",
        "Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.3.4",
        1,
        "8 - Security Services",
        "Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.3.5",
        1,
        "8 - Security Services",
        "Ensure 'Purge protection' is set to 'Enabled'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.3.6",
        2,
        "8 - Security Services",
        "Ensure that Role Based Access Control for Azure Key Vault is enabled",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.3.7",
        1,
        "8 - Security Services",
        "Ensure Public Network Access is Disabled",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.3.8",
        2,
        "8 - Security Services",
        "Ensure Private Endpoints are used to access Azure Key Vault",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.3.9",
        2,
        "8 - Security Services",
        "Ensure automatic key rotation is enabled within Azure Key Vault",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.3.10",
        2,
        "8 - Security Services",
        "Ensure that Azure Key Vault Managed HSM is used when required",
        "Azure CLI / Azure Policy audit in CIS Benchmark",
    ),
    (
        "8.3.11",
        1,
        "8 - Security Services",
        "Ensure certificate 'Validity Period (in months)' is less than or equal to '12'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.4.1",
        2,
        "8 - Security Services",
        "Ensure an Azure Bastion Host Exists",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "8.5",
        2,
        "8 - Security Services",
        "Ensure Azure DDoS Network Protection is enabled on virtual networks",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    # -- Section 9: Storage Services --
    (
        "9.1.1",
        1,
        "9 - Storage Services",
        "Ensure soft delete for Azure File Shares is Enabled",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.1.2",
        1,
        "9 - Storage Services",
        "Ensure 'SMB protocol version' is set to 'SMB 3.1.1' or higher for SMB file shares",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.1.3",
        1,
        "9 - Storage Services",
        "Ensure 'SMB channel encryption' is set to 'AES-256-GCM' or higher for SMB file shares",
        "Azure CLI / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.2.1",
        1,
        "9 - Storage Services",
        "Ensure that soft delete for blobs on Azure Blob Storage storage accounts is Enabled",
        "Azure CLI / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.2.2",
        1,
        "9 - Storage Services",
        "Ensure that soft delete for containers on Azure Blob Storage storage accounts is Enabled",
        "Azure CLI / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.2.3",
        2,
        "9 - Storage Services",
        "Ensure 'Versioning' is set to 'Enabled' on Azure Blob Storage storage accounts",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.1.1",
        1,
        "9 - Storage Services",
        "Ensure that 'Enable key rotation reminders' is enabled for each Storage Account",
        "Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.1.2",
        1,
        "9 - Storage Services",
        "Ensure that Storage Account access keys are periodically regenerated",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.1.3",
        1,
        "9 - Storage Services",
        "Ensure 'Allow storage account key access' for Azure Storage Accounts is 'Disabled'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.2.1",
        2,
        "9 - Storage Services",
        "Ensure Private Endpoints are used to access Storage Accounts",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.2.2",
        1,
        "9 - Storage Services",
        "Ensure that 'Public Network Access' is 'Disabled' for storage accounts",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.2.3",
        1,
        "9 - Storage Services",
        "Ensure default network access rule for storage accounts is set to deny",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.3.1",
        1,
        "9 - Storage Services",
        "Ensure that 'Default to Microsoft Entra authorization in the Azure portal' is set to 'Enabled'",
        "Azure CLI / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.4",
        1,
        "9 - Storage Services",
        "Ensure that 'Secure transfer required' is set to 'Enabled'",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.5",
        2,
        "9 - Storage Services",
        (
            "Ensure 'Allow Azure services on the trusted services list to access this storage "
            "account' is Enabled for Storage Account Access"
        ),
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.6",
        1,
        "9 - Storage Services",
        "Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.7",
        1,
        "9 - Storage Services",
        "Ensure 'Cross Tenant Replication' is not enabled",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.8",
        1,
        "9 - Storage Services",
        "Ensure that 'Allow Blob Anonymous Access' is set to 'Disabled'",
        "Azure CLI / Azure Policy / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.9",
        1,
        "9 - Storage Services",
        "Ensure Azure Resource Manager Delete locks are applied to Azure Storage Accounts",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.10",
        2,
        "9 - Storage Services",
        "Ensure Azure Resource Manager ReadOnly locks are considered for Azure Storage Accounts",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
    (
        "9.3.11",
        2,
        "9 - Storage Services",
        "Ensure Redundancy is set to 'geo-redundant storage (GRS)' on critical Azure Storage Accounts",
        "Azure CLI / Azure Policy / PowerShell / Azure Portal audit in CIS Benchmark",
    ),
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
