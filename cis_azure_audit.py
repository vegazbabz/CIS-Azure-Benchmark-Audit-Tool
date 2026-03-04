#!/usr/bin/env python3
"""
CIS Microsoft Azure Foundations Benchmark v5.0.0 — Audit Tool v1.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHAT THIS TOOL DOES
────────────────────
Automatically audits an Azure tenant against the CIS Microsoft Azure
Foundations Benchmark v5.0.0 and generates a self-contained HTML report
with pass/fail status, compliance scores, and remediation guidance.

HOW IT WORKS — THE THREE DATA COLLECTION METHODS
──────────────────────────────────────────────────
1. Azure Resource Graph  (bulk, fast, tenant-wide)
   A single Kusto query fetches all resources of a given type across every
   subscription at once. Results are indexed by subscription ID in memory
   so every check function can look up its data in O(1) without extra calls.
   Used for: NSGs, storage accounts, Key Vaults, VNets, subnets, role
   assignments, Application Gateways, Databricks workspaces, etc.

2. az CLI per-subscription  (targeted, slower, needed for settings)
   Some properties cannot be queried via Resource Graph (e.g. diagnostic
   settings, activity log alerts, Key Vault data-plane: keys/secrets/certs,
   blob/file service properties, flow logs). These are fetched individually
   per subscription, per resource, via az CLI subprocess calls.

3. az rest  (Microsoft Graph API and ARM preview APIs)
   Identity checks (Entra ID tenant policy, guest settings, invite policy)
   live in Microsoft Graph, not ARM. These are fetched via `az rest`.
   Also used for security settings that lack a dedicated az CLI command.

CHECKPOINT / RESUME SYSTEM
────────────────────────────
After each subscription is fully audited, its results are written to a JSON
file in `cis_checkpoints/<subscription-id>.json`. On the next run, completed
subscriptions are loaded from disk and skipped, so you can safely interrupt
and resume a long audit without losing progress.

Checkpoints are written atomically (write to .tmp, then rename) so a crash
during a write never produces a corrupt checkpoint file.

PARALLEL EXECUTION
───────────────────
Subscriptions are audited concurrently using either a ThreadPoolExecutor or
ProcessPoolExecutor. The default is process mode with 2 workers
(`--executor process --parallel 2`). You can override both values via CLI.
Higher parallelism can speed up large tenants but may increase Azure API
throttling (HTTP 429).

REQUIREMENTS
─────────────
  • Python 3.8+  (no pip installs needed — only standard library)
  • Azure CLI    (az login completed before running)
  • Reader + Security Reader on each subscription being audited
  • Global Reader / Directory Reader in Entra ID (for Section 5 identity checks)
  • resource-graph CLI extension (auto-installed if missing)

USAGE
──────
  python cis_azure_audit.py                           # all subscriptions
  python cis_azure_audit.py -s "Production"           # one subscription
  python cis_azure_audit.py -s "Dev" "Test" "Prod"   # multiple subscriptions
  python cis_azure_audit.py --parallel 5              # 5 concurrent workers
  python cis_azure_audit.py --fresh                   # clear checkpoints, start over
  python cis_azure_audit.py --report-only             # regenerate HTML from checkpoints
  python cis_azure_audit.py --level 1                 # Level 1 controls only
"""

from __future__ import annotations

from typing import Any

# ─── Standard library imports ─────────────────────────────────────────────────
# No third-party packages required — everything ships with Python 3.8+
import json  # Parsing az CLI JSON output
import sys  # sys.exit(), sys.platform (Windows vs Unix az path)
import argparse  # CLI argument parsing
import datetime  # Timestamps in checkpoints and reports
import logging
import html  # HTML entity escaping for safe output in the report
import os  # operating system interfaces (environment variables)
import threading  # Lock for thread-safe console output in parallel runs
import shutil  # shutil.rmtree() used by --fresh to clear checkpoints
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed  # Parallel workers
from dataclasses import dataclass, asdict  # Result data model + JSON serialisation
from pathlib import Path  # Cross-platform file paths

# Azure CLI helpers delegated to azure_helpers.py
from azure_helpers import (
    _friendly_error,
    az,
    az_rest,
    get_and_reset_rate_limit_retry_count,
    graph_query,
    get_signed_in_user_id,
    list_role_names_for_user,
    check_user_permissions,
)

# Optional rich progress bar (used if installed). Falls back to builtin UI
try:
    from rich.progress import (
        Progress,
        SpinnerColumn,
        BarColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
        MofNCompleteColumn,
    )

    HAS_RICH = True
except Exception:
    HAS_RICH = False

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"  # Tool version (written into checkpoints for change detection)
BENCHMARK_VER = "5.0.0"  # CIS Benchmark version this tool targets
CHECKPOINT_DIR = Path("cis_checkpoints")  # Directory where per-subscription results are saved

# ── Audit result status values ────────────────────────────────────────────────
# These are the only five valid statuses a Result can have.
PASS = "PASS"  # Control requirement is met
FAIL = "FAIL"  # Control requirement is NOT met — action required
ERROR = "ERROR"  # Could not evaluate — az CLI call failed or timed out
INFO = "INFO"  # Not applicable (e.g. no resources of this type in subscription)
MANUAL = "MANUAL"  # Requires human review — cannot be automated via az CLI

# Custom log level below DEBUG for very chatty execution traces.
TRACE_LEVEL = 5

# Module logger. Effective level/handlers are configured in setup_logging().
LOGGER = logging.getLogger("cis_audit")

# ── Azure built-in role definition GUIDs (stable, defined by Microsoft) ──────
# These GUIDs are the same in every tenant — safe to hardcode.
ROLE_OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  # Owner
ROLE_UAA = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"  # User Access Administrator

# ── Source address values that mean "open to the internet" in NSG rules ───────
# Used by nsg_bad_rules() to identify inbound rules that are publicly accessible.
# Note: "0.0.0.0/0" is covered by the endswith("/0") check below, not this set.
INTERNET_SRCS = {"*", "0.0.0.0", "internet", "any"}

# ── Platform-managed subnets that Azure prohibits NSGs on ─────────────────────
# check_7_11 skips these subnets to avoid false FAIL results.
EXEMPT_SUBNETS = {
    "gatewaysubnet",  # VPN / ExpressRoute Gateway
    "azurebastionsubnet",  # Azure Bastion
    "azurefirewallsubnet",  # Azure Firewall
    "azurefirewallmanagementsubnet",  # Azure Firewall management traffic
    "routeserversubnet",  # Azure Route Server
}

# ══════════════════════════════════════════════════════════════════════════════
# DATA MODEL
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class R:
    """
    A single audit finding. One R instance is created per resource per control.

    For example: if a subscription has 20 storage accounts and there are 10
    storage checks, up to 200 R instances are produced for that subscription.

    Named R (short) rather than Result because it appears hundreds of times
    in check functions — brevity makes the check code readable.

    Fields
    ──────
    control_id        CIS control number, e.g. "7.11" or "9.3.1.2"
    title             Human-readable control title (from CIS benchmark PDF)
    level             CIS Profile Applicability: 1 (basic) or 2 (advanced)
    section           Section name used for grouping in the report
    status            One of the five constants: PASS / FAIL / ERROR / INFO / MANUAL
    details           Explanation shown in the report — what was found
    remediation       Azure portal path to fix the issue (empty string for PASS/INFO)
    subscription_id   Azure subscription GUID (empty for tenant-level checks)
    subscription_name Display name of the subscription
    resource          Specific resource name (NSG, vault, storage account, etc.)
                      Empty string means the finding applies to the subscription overall.
    """

    control_id: str
    title: str
    level: int
    section: str
    status: str
    details: str = ""
    remediation: str = ""
    subscription_id: str = ""
    subscription_name: str = ""
    resource: str = ""


# ══════════════════════════════════════════════════════════════════════════════
# THREAD-SAFE CONSOLE OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

# A single lock shared by all threads. Without it, parallel workers would
# interleave progress updates and produce garbled console lines.
_lock = threading.Lock()

# Simple console UI state for in-place progress updates
_console = {"total": 0, "last_len": 0}


def setup_logging(log_level: str, verbose: bool = False, debug: bool = False, log_file: str | None = None) -> None:
    """Configure root logging for console output and optional log file.

    Precedence: --debug > --verbose > --log-level.
    """
    if debug:
        effective_level = TRACE_LEVEL
    elif verbose:
        effective_level = logging.DEBUG
    elif log_level.upper() == "TRACE":
        effective_level = TRACE_LEVEL
    else:
        effective_level = getattr(logging, log_level.upper(), logging.INFO)

    logging.addLevelName(TRACE_LEVEL, "TRACE")

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(effective_level)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(effective_level)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(effective_level)
        file_handler.setFormatter(
            logging.Formatter("time=%(asctime)s level=%(levelname)s name=%(name)s msg=%(message)s")
        )
        root_logger.addHandler(file_handler)


def console_init(total: int) -> None:
    """Initialize console progress UI.

    Prints an initial progress line and stores total for later updates.
    """
    _console["total"] = total
    _console["last_len"] = 0
    with _lock:
        sys.stdout.write(f"Progress: 0/{total}\n")
        sys.stdout.flush()


def console_update(done: int, total: int, current: str = "") -> None:
    """Update the single-line progress indicator in-place.

    Called by worker threads to show overall progress and the current
    subscription being processed.
    """
    s = f"Progress: [{done}/{total}] {current}"
    with _lock:
        # Overwrite the previous line (pad with spaces to clear)
        pad = max(0, _console.get("last_len", 0) - len(s))
        sys.stdout.write("\r" + s + (" " * pad))
        sys.stdout.flush()
        _console["last_len"] = len(s)


def console_finish() -> None:
    """Finish the progress UI and move to the next line."""
    with _lock:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ══════════════════════════════════════════════════════════════════════════════
# NSG RULE HELPERS
# ══════════════════════════════════════════════════════════════════════════════


def port_in_range(s: str, p: int) -> bool:
    """
    Return True if port number p falls within the NSG port specification s.

    Azure NSG port fields accept three formats:
      "*"          — wildcard, matches any port
      "22"         — exact port number
      "1024-65535" — inclusive range

    Parameters
    ──────────
    s : Port specification string from an NSG rule
    p : Integer port number to test
    """
    s = str(s).strip()
    if s in ("*", ""):
        return True  # Wildcard matches everything
    if "-" in s:
        try:
            lo, hi = s.split("-", 1)
            return int(lo) <= p <= int(hi)
        except ValueError:
            return False  # Malformed range — treat as non-matching
    try:
        return int(s) == p  # Exact match
    except ValueError:
        return False  # Non-numeric — treat as non-matching


def nsg_bad_rules(rules: list[Any], port: int, protos: tuple[str, ...] = ("tcp", "*")) -> list[str]:
    """
    Find NSG inbound rules that allow internet traffic on a given port.

    A rule is considered non-compliant if ALL of the following are true:
      1. access    == Allow      (not a Deny rule)
      2. direction == Inbound    (not an outbound rule)
      3. protocol  is in protos  (TCP, UDP, or wildcard *)
      4. source    is an internet wildcard (*, 0.0.0.0/0, Internet, Any)
         Note: source prefixes starting with "/" are ASG resource IDs,
         not internet wildcards — these are explicitly skipped.
      5. at least one destination port range covers the target port

    Parameters
    ──────────
    rules  : List of NSG security rule objects (from Resource Graph)
    port   : Port number to check (e.g. 22 for SSH, 3389 for RDP)
    protos : Protocols to flag. Default ("tcp", "*") catches TCP + wildcard.
             Use ("udp", "*") for UDP checks like check_7_3.

    Returns
    ───────
    List of rule names that are non-compliant (empty list = all OK).
    """
    bad = []
    for rule in rules or []:
        # Resource Graph returns properties at the top level; az CLI wraps them
        # in a "properties" key. Support both formats with .get("properties", rule).
        pr = rule.get("properties", rule)

        if str(pr.get("access", "")).lower() != "allow":
            continue
        if str(pr.get("direction", "")).lower() != "inbound":
            continue

        proto = str(pr.get("protocol", "*")).lower()
        if proto not in protos:
            continue

        src = str(pr.get("sourceAddressPrefix", "")).lower()
        # Application Security Groups have IDs like "/subscriptions/..."
        # They are not internet wildcards, so skip them to avoid false positives.
        if src.startswith("/"):
            continue
        if src not in INTERNET_SRCS and not src.endswith("/0"):
            continue

        # Collect all destination ports — Azure allows either a single value
        # or a list in destinationPortRanges
        dest = str(pr.get("destinationPortRange", ""))
        dests = pr.get("destinationPortRanges", [])
        ports = ([dest] if dest else []) + (dests if isinstance(dests, list) else [])

        if any(port_in_range(p, port) for p in ports):
            bad.append(rule.get("name", "unknown"))

    return bad


# ══════════════════════════════════════════════════════════════════════════════
# RESOURCE GRAPH PREFETCH
# All Kusto queries are defined here and run ONCE before the subscription loop.
# Results are indexed by subscription ID for O(1) lookup in check functions.
# ══════════════════════════════════════════════════════════════════════════════

_QUERIES = {
    # ── NSGs ─────────────────────────────────────────────────────────────────
    # Fetches all NSGs with their security rules.
    # The 'rules' field returns the custom rules array; default rules are omitted
    # because they cannot be deleted and don't affect compliance.
    "nsgs": """
        resources | where type =~ 'microsoft.network/networksecuritygroups'
        | project id, name, resourceGroup, subscriptionId, rules = properties.securityRules
    """,
    # ── Storage accounts ─────────────────────────────────────────────────────
    # Projects only the fields used by check_9_storage's static checks.
    # Blob/file service properties and key policy are NOT available in Resource
    # Graph — those require separate az CLI calls per account.
    "storage": """
        resources | where type =~ 'microsoft.storage/storageaccounts'
        | project id, name, resourceGroup, subscriptionId,
            httpsOnly       = properties.supportsHttpsTrafficOnly,
            publicAccess    = properties.publicNetworkAccess,
            crossTenant     = properties.allowCrossTenantReplication,
            blobAnon        = properties.allowBlobPublicAccess,
            defaultAction   = properties.networkAcls.defaultAction,
            bypass          = properties.networkAcls.bypass,
            minTls          = properties.minimumTlsVersion,
            keyAccess       = properties.allowSharedKeyAccess,
            oauthDefault    = properties.defaultToOAuthAuthentication,
            sku             = sku.name,
            privateEps      = array_length(properties.privateEndpointConnections)
    """,
    # ── Key Vaults ───────────────────────────────────────────────────────────
    # Data-plane properties (key expiry, rotation policy, certificates) are NOT
    # in Resource Graph — those require az keyvault CLI calls in check_8_3.
    "keyvaults": """
        resources | where type =~ 'microsoft.keyvault/vaults'
        | project id, name, resourceGroup, subscriptionId,
            purgeProtection = properties.enablePurgeProtection,
            rbac            = properties.enableRbacAuthorization,
            publicAccess    = properties.publicNetworkAccess,
            privateEps      = array_length(properties.privateEndpointConnections)
    """,
    # ── Virtual Networks ─────────────────────────────────────────────────────
    # hasDdos checks whether a DDoS Standard plan is linked to the VNet.
    # isnotnull() returns true if the ddosProtectionPlan.id path exists and is
    # not null — a missing path also returns false, which is correct behaviour.
    "vnets": """
        resources | where type =~ 'microsoft.network/virtualnetworks'
        | project id, name, resourceGroup, subscriptionId, location,
            hasDdos = isnotnull(properties.ddosProtectionPlan.id)
    """,
    # ── Subnets ───────────────────────────────────────────────────────────────
    # VNets contain subnets as a nested array. mv-expand "unrolls" the array
    # so each subnet becomes its own row. vnetName is projected BEFORE mv-expand
    # so it is preserved on every expanded row — projecting it after loses it.
    "subnets": """
        resources | where type =~ 'microsoft.network/virtualnetworks'
        | project subscriptionId,
            vnetName      = tostring(name),
            resourceGroup = tostring(resourceGroup),
            subnets       = properties.subnets
        | mv-expand subnet = subnets
        | project subscriptionId, vnetName, resourceGroup,
            subnetName = tostring(subnet.name),
            hasNsg     = isnotnull(subnet.properties.networkSecurityGroup.id)
    """,
    # ── Azure Bastion ─────────────────────────────────────────────────────────
    "bastion": """
        resources | where type =~ 'microsoft.network/bastionhosts'
        | project id, name, resourceGroup, subscriptionId
    """,
    # ── Virtual Machines ──────────────────────────────────────────────────────
    # Used by check_8_4_1 to determine whether Bastion is relevant.
    # Bastion only makes sense if there are VMs to connect to — a subscription
    # with no VMs should return INFO, not FAIL, for the Bastion check.
    "vms": """
        resources | where type =~ 'microsoft.compute/virtualmachines'
        | project id, name, subscriptionId
    """,
    # ── Network Watchers ──────────────────────────────────────────────────────
    # Used by check_7_6 to determine which regions have Network Watcher enabled.
    # state == "Succeeded" means the watcher is active (not deleting/failed).
    "watchers": """
        resources | where type =~ 'microsoft.network/networkwatchers'
        | project id, name, subscriptionId, location, state = properties.provisioningState
    """,
    # ── Regions in use ────────────────────────────────────────────────────────
    # Distinct list of (subscription, location) pairs across all resources.
    # Used by check_7_6 to compare against the regions where Network Watcher
    # is deployed, identifying regions that are missing coverage.
    "locations": """
        resources | project subscriptionId, location | distinct subscriptionId, location
    """,
    # ── Role assignments ──────────────────────────────────────────────────────
    # Filters to only Owner and User Access Administrator assignments —
    # the two roles relevant to sections 5.3.3 and 5.27.
    # endswith() matches the GUID suffix of the roleDefinitionId path,
    # which takes the form "/subscriptions/.../roleDefinitions/<GUID>".
    "roles": """
        authorizationresources
        | where type =~ 'microsoft.authorization/roleassignments'
        | where properties.roleDefinitionId endswith '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
            or  properties.roleDefinitionId endswith '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
        | project subscriptionId = tostring(subscriptionId),
            principalId = tostring(properties.principalId),
            principalName = tostring(properties.principalName),
            roleDefinitionId = tostring(properties.roleDefinitionId),
            scope = tostring(properties.scope)
    """,
    # ── Application Gateways ──────────────────────────────────────────────────
    # Used by checks 7.10, 7.12, 7.13, 7.14 (WAF, TLS, HTTP2, request body).
    # wafPolicyId is projected for completeness but WAF mode is read from
    # the embedded webApplicationFirewallConfiguration property instead.
    "app_gateways": """
        resources | where type =~ 'microsoft.network/applicationgateways'
        | project id, name, resourceGroup, subscriptionId,
            enableHttp2  = properties.enableHttp2,
            wafEnabled   = properties.webApplicationFirewallConfiguration.enabled,
            wafMode      = properties.webApplicationFirewallConfiguration.firewallMode,
            wafReqBody   = properties.webApplicationFirewallConfiguration.requestBodyCheck,
            sslMinProto  = properties.sslPolicy.minProtocolVersion,
            wafPolicyId  = tostring(properties.firewallPolicy.id)
    """,
    # ── Databricks workspaces ─────────────────────────────────────────────────
    # vnetId is the custom VNet resource ID (empty for managed-VNet workspaces).
    # noPublicIp and publicAccess come from workspace parameters.
    "databricks": """
        resources | where type =~ 'microsoft.databricks/workspaces'
        | project id, name, resourceGroup, subscriptionId,
            noPublicIp   = properties.parameters.enableNoPublicIp.value,
            publicAccess = properties.publicNetworkAccess,
            vnetId       = tostring(properties.parameters.customVirtualNetworkId.value),
            privateEps   = array_length(properties.privateEndpointConnections)
    """,
    # ── App Services ──────────────────────────────────────────────────────────
    # Only id, name, resourceGroup, subscriptionId are needed — diagnostic
    # settings cannot be queried via Resource Graph and require per-app az calls.
    "app_services": """
        resources | where type =~ 'microsoft.web/sites'
        | project id, name, resourceGroup, subscriptionId,
            kind = tostring(kind)
    """,
    # ── WAF policies ──────────────────────────────────────────────────────────
    # Standalone WAF policy resources (used by check_7_15 for bot protection).
    # This is distinct from WAF embedded in Application Gateways (app_gateways query).
    "waf_policies": """
        resources | where type =~ 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies'
        | project id, name, subscriptionId,
            botEnabled         = properties.policySettings.mode,
            requestBodyInspect = properties.policySettings.requestBodyInspect
    """,
}


def prefetch(sub_ids: list[str]) -> dict[str, dict[str, list[Any]]]:
    """
    Run all Resource Graph queries and return results indexed by subscription ID.

    This is called ONCE before the parallel subscription loop begins.
    The returned structure is:
        {
          "nsgs":    { "sub-id-lowercase": [record, record, ...], ... },
          "storage": { "sub-id-lowercase": [record, ...], ... },
          ...
        }

    Indexing by lowercase subscription ID allows O(1) lookup in _idx()
    rather than scanning the full record list for every check.

    Parameters
    ──────────
    sub_ids : List of subscription GUIDs to query across

    Returns
    ───────
    dict with one key per query name, each mapping sub_id → list of records
    """
    LOGGER.info("\n📡 Fetching tenant data via Resource Graph...")
    raw: dict[str, list[dict[str, Any]]] = {}

    for name, query in _QUERIES.items():
        LOGGER.log(TRACE_LEVEL, "TRACE query=%s chars=%d", name, len(query))
        rc, data = graph_query(query, sub_ids)
        if rc != 0:
            # Non-fatal — log the warning and continue with an empty list.
            # Checks that depend on this data will return ERROR results.
            LOGGER.warning("   %-20s ⚠️  %s", name, str(data)[:80])
            raw[name] = []
        else:
            LOGGER.info("   %-20s ✅  %5d records", name, len(data) if isinstance(data, list) else 0)
            if isinstance(data, list):
                raw[name] = [r for r in data if isinstance(r, dict)]
            else:
                raw[name] = []

    # Build the subscription-indexed lookup structure.
    # All subscription IDs are lowercased for consistent matching
    # (Azure returns them in mixed case depending on the API).
    indexed: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for key, records in raw.items():
        idx: dict[str, list[dict[str, Any]]] = {}
        for r in records:
            sid = str(r.get("subscriptionId", "")).lower()
            idx.setdefault(sid, []).append(r)
        indexed[key] = idx

    return indexed


# ══════════════════════════════════════════════════════════════════════════════
# LOOKUP AND RESULT BUILDER HELPERS
# ══════════════════════════════════════════════════════════════════════════════


def _idx(td: dict[str, Any], key: str, sid: str) -> list[Any]:
    """
    Retrieve prefetched Resource Graph records for a specific subscription.

    Parameters
    ──────────
    td  : The tenant data dict returned by prefetch()
    key : Query name, e.g. "nsgs", "storage", "keyvaults"
    sid : Subscription ID (case-insensitive — lowercased internally)

    Returns
    ───────
    List of record dicts for this subscription, or [] if none found.
    Returning an empty list (not None) means callers can always iterate
    safely without an extra None check.
    """
    by_sub = td.get(key, {})
    if not isinstance(by_sub, dict):
        return []
    records = by_sub.get(sid.lower(), [])
    return records if isinstance(records, list) else []


def _err(
    cid: str,
    title: str,
    lvl: int,
    sec: str,
    msg: str,
    sid: str = "",
    sname: str = "",
    resource: str = "",
) -> R:
    """
    Convenience constructor for ERROR results.

    Used when an az CLI call fails and we cannot evaluate the control.
    The error message is truncated at 200 characters to keep the report readable.
    """
    return R(cid, title, lvl, sec, ERROR, msg[:200], "", sid, sname, resource)


def _info(
    cid: str,
    title: str,
    lvl: int,
    sec: str,
    msg: str,
    sid: str = "",
    sname: str = "",
) -> R:
    """
    Convenience constructor for INFO results.

    Used when a control is not applicable — typically because no resources
    of the required type exist in the subscription (e.g. no Databricks
    workspaces, no Application Gateways, no Key Vaults).

    sid/sname are optional so tenant-level checks (Section 5) can call _info()
    without them and correctly appear as "Tenant-wide" in the report.
    Per-subscription checks must pass sid/sname so the subscription column
    shows the correct subscription name rather than "Tenant-wide".
    """
    return R(cid, title, lvl, sec, INFO, msg, "", sid, sname)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — AZURE DATABRICKS
# ══════════════════════════════════════════════════════════════════════════════


def check_2_1_2(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    2.1.2 — NSGs are configured on Databricks subnets (Level 1)

    Databricks workspaces deployed into a customer-managed VNet (BYO-VNet)
    have two subnets: a public subnet and a private subnet. Both must have
    NSGs attached or Databricks will refuse to deploy clusters.

    Workspaces using Azure-managed VNets (the default) are skipped because
    Azure manages the NSGs internally for managed-VNet workspaces.

    Data source: Resource Graph 'databricks' and 'subnets' queries.
    The 'vnetId' field contains the custom VNet resource ID, which is
    parsed to get the VNet name used to filter the subnets list.
    """
    workspaces = _idx(td, "databricks", sid)
    if not workspaces:
        return [
            _info(
                "2.1.2",
                "NSGs configured for Databricks subnets",
                1,
                "2 - Databricks",
                "No Databricks workspaces found.",
                sid,
                sname,
            )
        ]

    results = []
    for ws in workspaces:
        wname = ws.get("name", "?")
        vnet = ws.get("vnetId", "")

        if not vnet:
            # Empty vnetId means the workspace uses an Azure-managed VNet.
            # NSGs on managed-VNet workspaces are Azure's responsibility.
            results.append(
                R(
                    "2.1.2",
                    "NSGs configured for Databricks subnets",
                    1,
                    "2 - Databricks",
                    INFO,
                    f"Workspace '{wname}': no custom VNet (managed VNet in use).",
                    "",
                    sid,
                    sname,
                    wname,
                )
            )
            continue

        # Extract VNet name from the full resource ID path, e.g.:
        # "/subscriptions/.../virtualNetworks/my-vnet" → "my-vnet"
        vnet_name = vnet.split("/")[-1] if vnet else ""

        # Filter subnets to those belonging to this workspace's VNet
        # Databricks subnet names conventionally contain "databricks"
        all_subnets = _idx(td, "subnets", sid)
        db_subnets = [
            s
            for s in all_subnets
            if s.get("vnetName", "").lower() == vnet_name.lower() and "databricks" in s.get("subnetName", "").lower()
        ]

        if not db_subnets:
            # VNet exists but subnets couldn't be matched — naming may differ
            results.append(
                R(
                    "2.1.2",
                    "NSGs configured for Databricks subnets",
                    1,
                    "2 - Databricks",
                    INFO,
                    f"Workspace '{wname}': could not identify Databricks subnets in VNet '{vnet_name}'.",
                    "",
                    sid,
                    sname,
                    wname,
                )
            )
            continue

        # Collect subnets that are missing NSGs
        missing = [s.get("subnetName") for s in db_subnets if not s.get("hasNsg")]
        results.append(
            R(
                "2.1.2",
                "NSGs configured for Databricks subnets",
                1,
                "2 - Databricks",
                FAIL if missing else PASS,
                (
                    f"Workspace '{wname}': subnets without NSG: {missing}"
                    if missing
                    else f"Workspace '{wname}': all Databricks subnets have NSGs."
                ),
                "Associate NSGs with the public and private Databricks subnets." if missing else "",
                sid,
                sname,
                wname if missing else "",
            )
        )

    return results


def check_2_1_7(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    2.1.7 — Diagnostic logging configured for Azure Databricks (Level 1)

    Checks that at least one diagnostic setting exists for each workspace.
    Diagnostic settings forward logs to a Log Analytics workspace, storage
    account, or Event Hub for security monitoring and audit purposes.

    Data source: az monitor diagnostic-settings list --resource <workspace_id>
    The workspace resource ID comes from the Resource Graph 'databricks' query.
    """
    workspaces = _idx(td, "databricks", sid)
    if not workspaces:
        return [
            _info(
                "2.1.7",
                "Diagnostic logging configured for Azure Databricks",
                1,
                "2 - Databricks",
                "No Databricks workspaces found.",
                sid,
                sname,
            )
        ]

    results = []
    for ws in workspaces:
        wname, wid = ws.get("name", "?"), ws.get("id")
        rc, diag = az(["monitor", "diagnostic-settings", "list", "--resource", wid], sid, timeout=20)
        if rc != 0:
            results.append(
                _err(
                    "2.1.7",
                    "Diagnostic logging configured for Azure Databricks",
                    1,
                    "2 - Databricks",
                    str(diag),
                    sid,
                    sname,
                )
            )
            continue

        # az monitor diagnostic-settings list returns either a list directly
        # or a dict with a "value" key depending on API version
        diag_list = diag if isinstance(diag, list) else (diag or {}).get("value", [])
        enabled = bool(diag_list)

        results.append(
            R(
                "2.1.7",
                "Diagnostic logging configured for Azure Databricks",
                1,
                "2 - Databricks",
                PASS if enabled else FAIL,
                f"Workspace '{wname}': diagnostic settings {'found' if enabled else 'NOT configured'}.",
                "Databricks > Monitoring > Diagnostic settings > Add diagnostic setting" if not enabled else "",
                sid,
                sname,
                wname if not enabled else "",
            )
        )

    return results


def check_2_1_9(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    2.1.9 — Databricks 'No Public IP' is Enabled (Level 1)

    When enableNoPublicIp is true, cluster nodes do not get public IP addresses.
    All cluster traffic flows through the private subnet, reducing attack surface.
    This is a workspace-level setting that cannot be changed after deployment.

    Data source: Resource Graph 'databricks' query (noPublicIp field).
    """
    workspaces = _idx(td, "databricks", sid)
    if not workspaces:
        return [
            _info(
                "2.1.9",
                "Databricks 'No Public IP' is Enabled",
                1,
                "2 - Databricks",
                "No Databricks workspaces found.",
                sid,
                sname,
            )
        ]

    # List comprehension produces one R per workspace
    return [
        R(
            "2.1.9",
            "Databricks 'No Public IP' is Enabled",
            1,
            "2 - Databricks",
            PASS if ws.get("noPublicIp") else FAIL,
            f"Workspace '{ws.get('name')}': enableNoPublicIp = {ws.get('noPublicIp')}",
            "Databricks workspace > Configure > Disable public IP" if not ws.get("noPublicIp") else "",
            sid,
            sname,
            ws.get("name", "") if not ws.get("noPublicIp") else "",
        )
        for ws in workspaces
    ]


def check_2_1_10(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    2.1.10 — Databricks 'Allow Public Network Access' is Disabled (Level 1)

    publicNetworkAccess controls whether the Databricks workspace web UI
    and REST API are accessible from the public internet. Disabling it
    forces all access through private endpoints or approved network paths.

    Data source: Resource Graph 'databricks' query (publicAccess field).
    Compliant state: publicNetworkAccess == "Disabled" (case-insensitive).
    """
    workspaces = _idx(td, "databricks", sid)
    if not workspaces:
        return [
            _info(
                "2.1.10",
                "Databricks 'Allow Public Network Access' is Disabled",
                1,
                "2 - Databricks",
                "No Databricks workspaces found.",
                sid,
                sname,
            )
        ]

    return [
        R(
            "2.1.10",
            "Databricks 'Allow Public Network Access' is Disabled",
            1,
            "2 - Databricks",
            PASS if str(ws.get("publicAccess", "Enabled")).lower() == "disabled" else FAIL,
            f"Workspace '{ws.get('name')}': publicNetworkAccess = {ws.get('publicAccess')}",
            (
                "Databricks workspace > Networking > Disable public network access"
                if str(ws.get("publicAccess", "Enabled")).lower() != "disabled"
                else ""
            ),
            sid,
            sname,
            ws.get("name", "") if str(ws.get("publicAccess", "Enabled")).lower() != "disabled" else "",
        )
        for ws in workspaces
    ]


def check_2_1_11(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    2.1.11 — Private endpoints configured for Azure Databricks workspaces (Level 2)

    Private endpoints give the Databricks control plane and data plane a
    private IP address within the customer's VNet, eliminating public
    internet exposure even when publicNetworkAccess is Enabled.

    Data source: Resource Graph 'databricks' query (privateEps field).
    privateEps is the count of configured private endpoint connections.
    """
    workspaces = _idx(td, "databricks", sid)
    if not workspaces:
        return [
            _info(
                "2.1.11",
                "Private endpoints used to access Azure Databricks",
                2,
                "2 - Databricks",
                "No Databricks workspaces found.",
                sid,
                sname,
            )
        ]

    return [
        R(
            "2.1.11",
            "Private endpoints used to access Azure Databricks",
            2,
            "2 - Databricks",
            PASS if (ws.get("privateEps") or 0) > 0 else FAIL,
            f"Workspace '{ws.get('name')}': private endpoints = {ws.get('privateEps') or 0}",
            "Configure private endpoint for Databricks workspace." if not (ws.get("privateEps") or 0) > 0 else "",
            sid,
            sname,
            ws.get("name", "") if not (ws.get("privateEps") or 0) > 0 else "",
        )
        for ws in workspaces
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — IDENTITY SERVICES
# These checks target the Entra ID tenant and run ONCE (not per subscription).
# Most use the Microsoft Graph API via az_rest rather than az CLI.
# ══════════════════════════════════════════════════════════════════════════════


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
    rc, data = az(["role", "definition", "list", "--custom-role-only", "true"], sid, timeout=20)
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


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — MANAGEMENT & GOVERNANCE (MONITORING)
# ══════════════════════════════════════════════════════════════════════════════


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
    rc, data = az(["monitor", "diagnostic-settings", "subscription", "list", "--subscription", sid], timeout=20)
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
    rc, data = az(["monitor", "diagnostic-settings", "subscription", "list", "--subscription", sid], timeout=20)
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
        rc, diag = az(["monitor", "diagnostic-settings", "list", "--resource", vid], sid, timeout=20)
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

        rc, diag = az(["monitor", "diagnostic-settings", "list", "--resource", aid], sid, timeout=20)
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
    rc, data = az(["monitor", "activity-log", "alert", "list"], sid, timeout=20)
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
    rc, data = az_rest(url, timeout=20)
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


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — NETWORKING SERVICES
# ══════════════════════════════════════════════════════════════════════════════


def check_7_1(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    7.1 — RDP access from the internet is restricted (Level 1)

    RDP (TCP port 3389) exposed to the internet is one of the most common
    vectors for ransomware and brute-force attacks. No NSG should have an
    inbound allow rule for port 3389 with a source of * / Internet / Any.

    Data source: Resource Graph 'nsgs' query. Each NSG's security rules are
    checked by nsg_bad_rules() for internet-accessible port 3389 rules.
    """
    nsgs = _idx(td, "nsgs", sid)
    if not nsgs:
        return [
            _info(
                "7.1", "RDP access from internet restricted", 1, "7 - Networking Services", "No NSGs found.", sid, sname
            )
        ]

    results = []
    for nsg in nsgs:
        name = nsg.get("name", "?")
        bad = nsg_bad_rules(nsg.get("rules") or [], 3389, ("tcp", "*"))
        results.append(
            R(
                "7.1",
                "RDP access from internet restricted",
                1,
                "7 - Networking Services",
                FAIL if bad else PASS,
                f"NSG '{name}': {'non-compliant rules: ' + str(bad) if bad else 'compliant'}",
                f"NSG '{name}' > Inbound rules > Remove or restrict rules {bad}" if bad else "",
                sid,
                sname,
                name if bad else "",
            )
        )
    return results


def check_7_2(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    7.2 — SSH access from the internet is restricted (Level 1)

    SSH (TCP port 22) exposed to the internet allows brute-force and
    credential stuffing attacks against Linux VMs. No NSG should permit
    inbound SSH from * / Internet / Any.

    Implementation is identical to check_7_1 but for port 22.
    """
    nsgs = _idx(td, "nsgs", sid)
    if not nsgs:
        return [
            _info(
                "7.2", "SSH access from internet restricted", 1, "7 - Networking Services", "No NSGs found.", sid, sname
            )
        ]

    results = []
    for nsg in nsgs:
        name = nsg.get("name", "?")
        bad = nsg_bad_rules(nsg.get("rules") or [], 22, ("tcp", "*"))
        results.append(
            R(
                "7.2",
                "SSH access from internet restricted",
                1,
                "7 - Networking Services",
                FAIL if bad else PASS,
                f"NSG '{name}': {'non-compliant rules: ' + str(bad) if bad else 'compliant'}",
                f"NSG '{name}' > Inbound rules > Remove or restrict rules {bad}" if bad else "",
                sid,
                sname,
                name if bad else "",
            )
        )
    return results


def check_7_3(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    7.3 — UDP access from the internet is restricted (Level 1)

    UDP services exposed to the internet are frequently exploited for
    amplification/reflection DDoS attacks and direct exploitation.
    Unlike 7.1/7.2 which check a specific port, this check flags ANY
    UDP allow rule with an internet source, regardless of port.

    The nsg_bad_rules() function cannot be reused directly here because
    we want to flag any port rather than a specific one. Instead, rules
    are iterated directly with the protocol filter set to ("udp", "*").

    Note: port 0 is passed as a dummy — the function is not called here.
    Instead we inline the loop to check all destination ports.
    """
    nsgs = _idx(td, "nsgs", sid)
    if not nsgs:
        return [
            _info(
                "7.3", "UDP access from internet restricted", 1, "7 - Networking Services", "No NSGs found.", sid, sname
            )
        ]

    results = []
    for nsg in nsgs:
        name = nsg.get("name", "?")
        bad = []
        for rule in nsg.get("rules") or []:
            pr = rule.get("properties", rule)
            if str(pr.get("access", "")).lower() != "allow":
                continue
            if str(pr.get("direction", "")).lower() != "inbound":
                continue
            # Match UDP rules and wildcard protocol rules
            proto = str(pr.get("protocol", "*")).lower()
            if proto not in ("udp", "*"):
                continue
            src = str(pr.get("sourceAddressPrefix", "")).lower()
            # Skip Application Security Group references (they start with "/")
            if src.startswith("/"):
                continue
            if src not in INTERNET_SRCS and not src.endswith("/0"):
                continue
            bad.append(rule.get("name", "unknown"))

        results.append(
            R(
                "7.3",
                "UDP access from internet restricted",
                1,
                "7 - Networking Services",
                FAIL if bad else PASS,
                f"NSG '{name}': {'inbound UDP rules open to internet: ' + str(bad) if bad else 'compliant'}",
                f"NSG '{name}' > Inbound rules > Remove or restrict UDP rules {bad}" if bad else "",
                sid,
                sname,
                name if bad else "",
            )
        )
    return results


def check_7_4(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    7.4 — HTTP/HTTPS access from the internet is evaluated and restricted (Level 1)

    Unlike RDP and SSH (which should almost never be internet-accessible),
    HTTP (port 80) and HTTPS (port 443) being open to the internet is
    intentional for public-facing web applications. This control does NOT
    require these ports to be blocked — it requires them to be EVALUATED.

    The FAIL status here means "this needs review" rather than "this is
    definitely wrong". If a WAF (Web Application Firewall) is in front of
    the application, the risk is significantly reduced.

    Both port 80 and port 443 violations are merged into a single set of
    non-compliant rule names per NSG.
    """
    nsgs = _idx(td, "nsgs", sid)
    if not nsgs:
        return [
            _info(
                "7.4",
                "HTTP/HTTPS access from internet evaluated and restricted",
                1,
                "7 - Networking Services",
                "No NSGs found.",
                sid,
                sname,
            )
        ]

    results = []
    for nsg in nsgs:
        name = nsg.get("name", "?")
        rules = nsg.get("rules") or []
        # Check both ports and merge into one deduplicated list of rule names
        bad80 = nsg_bad_rules(rules, 80)
        bad443 = nsg_bad_rules(rules, 443)
        bad = list(set(bad80 + bad443))

        results.append(
            R(
                "7.4",
                "HTTP/HTTPS access from internet evaluated and restricted",
                1,
                "7 - Networking Services",
                FAIL if bad else PASS,
                f"NSG '{name}': {'non-compliant rules (80/443): ' + str(bad) if bad else 'compliant'}",
                "Ensure HTTP/HTTPS inbound from internet is intentional and restricted." if bad else "",
                sid,
                sname,
                name if bad else "",
            )
        )
    return results


def check_7_5(sid: str, sname: str) -> list[R]:
    """
    7.5 — NSG flow log retention >= 90 days (Level 2)

    NSG flow logs record source/destination IP, port, protocol, and allow/deny
    decision for every IP flow through an NSG. They are critical for network
    forensics after a security incident. The CIS benchmark requires retention
    of at least 90 days.

    Implementation:
      1. List all Network Watchers in the subscription
      2. For each watcher, list its flow logs
      3. For each flow log, check retention period >= 90 AND enabled == true

    If no flow logs are found at all, returns INFO (not FAIL) because this
    check requires flow logs to already exist — their absence may mean the
    subscription has no NSGs (covered by check_7_11).
    """
    rc, watchers = az(["network", "watcher", "list"], sid, timeout=20)
    if rc != 0:
        return [
            _err("7.5", "NSG flow log retention > 90 days", 2, "7 - Networking Services", str(watchers), sid, sname)
        ]

    results = []
    for watcher in watchers or []:
        # Flow logs are listed per Network Watcher, scoped by location only
        rc2, flows = az(
            ["network", "watcher", "flow-log", "list", "--location", watcher.get("location", "")], sid, timeout=20
        )
        if rc2 != 0:
            continue  # Skip this watcher if flow log list fails

        for fl in flows or []:
            fname = fl.get("name", "?")
            ret = (fl.get("retentionPolicy") or {}).get("days", 0)
            enabled = (fl.get("retentionPolicy") or {}).get("enabled", False)
            # Both conditions must be true: enabled AND >= 90 days
            ok = enabled and int(ret) >= 90
            results.append(
                R(
                    "7.5",
                    "NSG flow log retention > 90 days",
                    2,
                    "7 - Networking Services",
                    PASS if ok else FAIL,
                    f"Flow log '{fname}': retention = {ret} days, enabled = {enabled}",
                    "Network Watcher > Flow logs > Set retention >= 90 days" if not ok else "",
                    sid,
                    sname,
                    fname if not ok else "",
                )
            )

    if not results:
        results.append(
            _info(
                "7.5",
                "NSG flow log retention > 90 days",
                2,
                "7 - Networking Services",
                "No NSG flow logs found.",
                sid,
                sname,
            )
        )
    return results


def check_7_6(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    7.6 — Network Watcher is enabled in all regions where resources exist (Level 2)

    Network Watcher provides network diagnostic and monitoring capabilities.
    It must be enabled in every Azure region where the subscription deploys
    resources — a watcher in East US does not cover resources in West Europe.

    Implementation:
      1. From Resource Graph 'locations' query: get all distinct regions used
         by this subscription's resources.
      2. From Resource Graph 'watchers' query: get all provisioned watchers.
      3. Report the difference: regions in use that have no watcher.

    Both sets are compared as lowercase strings to handle case mismatches
    between the two data sources (e.g. "eastus" vs "EastUS").
    """
    watchers = _idx(td, "watchers", sid)
    locations = _idx(td, "locations", sid)

    # Set of all regions where this subscription has at least one resource
    used_locs = {r.get("location", "").lower() for r in locations}

    # Set of regions where a Network Watcher is successfully provisioned
    # "Succeeded" state means the watcher is active (not creating/failed/deleting)
    watch_locs = {w.get("location", "").lower() for w in watchers if str(w.get("state", "")).lower() == "succeeded"}

    if not used_locs:
        return [
            _info(
                "7.6",
                "Network Watcher enabled for all regions",
                1,
                "7 - Networking Services",
                "No resources found to determine regions.",
                sid,
                sname,
            )
        ]

    # Regions that have resources but no Network Watcher
    missing = used_locs - watch_locs

    return [
        R(
            "7.6",
            "Network Watcher enabled for all regions",
            1,
            "7 - Networking Services",
            FAIL if missing else PASS,
            (
                f"Missing Network Watcher in: {sorted(missing)}"
                if missing
                else f"Network Watcher enabled in all {len(used_locs)} regions."
            ),
            "Network Watcher > Regions > Enable for each region in use." if missing else "",
            sid,
            sname,
        )
    ]


def check_7_8(sid: str, sname: str) -> list[R]:
    """
    7.8 — VNet flow log retention >= 90 days (Level 2)

    VNet flow logs (VNet-level, as opposed to NSG-level) are a newer feature
    that capture flows at the Virtual Network boundary. Like NSG flow logs
    (check_7_5), they require >= 90 day retention.

    Filters flow logs to only those targeting VNet resources (identified by
    "virtualnetworks" appearing in the targetResourceId path).
    """
    rc, watchers = az(["network", "watcher", "list"], sid, timeout=20)
    if rc != 0:
        return [
            _err("7.8", "VNet flow log retention > 90 days", 2, "7 - Networking Services", str(watchers), sid, sname)
        ]

    results = []
    for watcher in watchers or []:
        rc2, flows = az(
            ["network", "watcher", "flow-log", "list", "--location", watcher.get("location", "")], sid, timeout=20
        )
        if rc2 != 0:
            continue

        # Filter to flow logs targeting VNets (not NSGs — those are check_7_5)
        vnet_flows = [f for f in (flows or []) if "virtualnetworks" in str(f.get("targetResourceId", "")).lower()]

        for fl in vnet_flows:
            fname = fl.get("name", "?")
            ret = (fl.get("retentionPolicy") or {}).get("days", 0)
            enabled = (fl.get("retentionPolicy") or {}).get("enabled", False)
            ok = enabled and int(ret) >= 90
            results.append(
                R(
                    "7.8",
                    "VNet flow log retention > 90 days",
                    2,
                    "7 - Networking Services",
                    PASS if ok else FAIL,
                    f"VNet flow log '{fname}': {ret} days, enabled = {enabled}",
                    "Network Watcher > Flow logs > Set retention >= 90 days" if not ok else "",
                    sid,
                    sname,
                    fname if not ok else "",
                )
            )

    if not results:
        results.append(
            _info(
                "7.8",
                "VNet flow log retention > 90 days",
                2,
                "7 - Networking Services",
                "No VNet flow logs found.",
                sid,
                sname,
            )
        )
    return results


def check_7_10(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    7.10 — WAF is enabled on Azure Application Gateway (Level 2)

    A Web Application Firewall on the Application Gateway filters and monitors
    HTTP traffic based on OWASP rules. It must be enabled (not just configured)
    to provide protection. The WAF mode (Detection vs Prevention) is logged
    in the details for reviewer context but is not evaluated here.

    Data source: Resource Graph 'app_gateways' query (wafEnabled field).
    """
    gws = _idx(td, "app_gateways", sid)
    if not gws:
        return [
            _info(
                "7.10",
                "WAF enabled on Azure Application Gateway",
                2,
                "7 - Networking Services",
                "No Application Gateways found.",
                sid,
                sname,
            )
        ]

    return [
        R(
            "7.10",
            "WAF enabled on Azure Application Gateway",
            2,
            "7 - Networking Services",
            PASS if gw.get("wafEnabled") else FAIL,
            f"Gateway '{gw.get('name')}': WAF enabled = {gw.get('wafEnabled')}, " f"mode = {gw.get('wafMode', 'N/A')}",
            "Application Gateway > Web application firewall > Enable WAF" if not gw.get("wafEnabled") else "",
            sid,
            sname,
            gw.get("name", "") if not gw.get("wafEnabled") else "",
        )
        for gw in gws
    ]


def check_7_11(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    7.11 — Subnets are associated with Network Security Groups (Level 1)

    Every subnet should have an NSG to control inbound and outbound traffic.
    Without an NSG, resources in the subnet rely solely on VM-level controls,
    which may not exist or may be misconfigured.

    Exemptions — Azure prohibits NSGs on these platform-managed subnets:
      GatewaySubnet              — VPN / ExpressRoute gateway
      AzureBastionSubnet         — Bastion host
      AzureFirewallSubnet        — Azure Firewall
      AzureFirewallManagementSubnet — Firewall management traffic
      RouteServerSubnet          — Azure Route Server

    Data source: Resource Graph 'subnets' query. Both vnetName and subnetName
    are normalised with fallback strings to avoid displaying "None/?" in the
    report if the Resource Graph query returns unexpected null values.

    The subnet query uses mv-expand to unroll the VNet's subnets array.
    vnetName is projected BEFORE mv-expand to ensure it is preserved on
    every expanded row — a common Resource Graph pitfall.
    """
    subnets = _idx(td, "subnets", sid)
    if not subnets:
        return [
            _info(
                "7.11",
                "Subnets associated with network security groups",
                1,
                "7 - Networking Services",
                "No subnets found.",
                sid,
                sname,
            )
        ]

    # Lowercase set for O(1) exempt check
    SKIP = {
        "gatewaysubnet",
        "azurebastionsubnet",
        "azurefirewallsubnet",
        "azurefirewallmanagementsubnet",
        "routeserversubnet",
    }

    results = []
    for s in subnets:
        vnet_name = s.get("vnetName") or ""
        subnet_name = s.get("subnetName") or ""

        # Skip subnets with null/empty names — these are service-injected or
        # delegated subnets (e.g. AKS node pools, ACI, API Management) that
        # Azure manages internally and that do not appear in the portal subnet list.
        # Reporting them as FAIL would produce confusing "(unknown-vnet)/(unknown-subnet)"
        # entries that the customer cannot act on.
        if not vnet_name or not subnet_name:
            continue

        resource = f"{vnet_name}/{subnet_name}"

        # Skip Azure platform subnets where NSGs are not permitted
        if subnet_name.lower() in SKIP:
            continue

        has_nsg = bool(s.get("hasNsg"))

        if has_nsg:
            results.append(
                R(
                    "7.11",
                    "Subnets associated with network security groups",
                    1,
                    "7 - Networking Services",
                    PASS,
                    f"Subnet '{resource}': NSG associated.",
                    "",
                    sid,
                    sname,
                    resource,
                )
            )
        else:
            results.append(
                R(
                    "7.11",
                    "Subnets associated with network security groups",
                    1,
                    "7 - Networking Services",
                    FAIL,
                    f"Subnet '{resource}': no NSG associated.",
                    f"VNet '{vnet_name}' > Subnets > '{subnet_name}' > " f"Network security group: assign an NSG.",
                    sid,
                    sname,
                    resource,
                )
            )

    return results or [
        _info(
            "7.11",
            "Subnets associated with network security groups",
            1,
            "7 - Networking Services",
            "No applicable subnets found (only platform subnets exist).",
            sid,
            sname,
        )
    ]


def check_7_12(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    7.12 — Application Gateway SSL policy enforces minimum TLS 1.2 (Level 1)

    TLS 1.0 and 1.1 have known vulnerabilities (POODLE, BEAST, etc.) and
    are considered deprecated. All inbound HTTPS connections should use
    TLS 1.2 or higher.

    Compliant values for minProtocolVersion: TLSv1_2 or TLSv1_3
    Data source: Resource Graph 'app_gateways' query (sslMinProto field).
    """
    gws = _idx(td, "app_gateways", sid)
    if not gws:
        return [
            _info(
                "7.12",
                "App Gateway SSL policy min TLS version 1.2+",
                1,
                "7 - Networking Services",
                "No Application Gateways found.",
                sid,
                sname,
            )
        ]

    # Acceptable TLS version identifiers (lowercase for comparison)
    GOOD_PROTOS = {"tlsv1_2", "tlsv1_3"}

    return [
        R(
            "7.12",
            "App Gateway SSL policy min TLS version 1.2+",
            1,
            "7 - Networking Services",
            PASS if str(gw.get("sslMinProto", "")).lower() in GOOD_PROTOS else FAIL,
            f"Gateway '{gw.get('name')}': minProtocolVersion = {gw.get('sslMinProto', 'not set')}",
            (
                "Application Gateway > Listeners > SSL policy > Set minimum TLS to 1.2"
                if str(gw.get("sslMinProto", "")).lower() not in GOOD_PROTOS
                else ""
            ),
            sid,
            sname,
            gw.get("name", "") if str(gw.get("sslMinProto", "")).lower() not in GOOD_PROTOS else "",
        )
        for gw in gws
    ]


def check_7_13(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    7.13 — HTTP/2 is enabled on Application Gateway (Level 1)

    HTTP/2 provides multiplexing, header compression, and server push —
    improving performance and reducing latency. More importantly from a
    security perspective, HTTP/2 requires TLS, reinforcing encrypted transport.

    Data source: Resource Graph 'app_gateways' query (enableHttp2 field).
    """
    gws = _idx(td, "app_gateways", sid)
    if not gws:
        return [
            _info(
                "7.13",
                "HTTP2 enabled on Azure Application Gateway",
                1,
                "7 - Networking Services",
                "No Application Gateways found.",
                sid,
                sname,
            )
        ]

    return [
        R(
            "7.13",
            "HTTP2 enabled on Azure Application Gateway",
            1,
            "7 - Networking Services",
            PASS if gw.get("enableHttp2") else FAIL,
            f"Gateway '{gw.get('name')}': enableHttp2 = {gw.get('enableHttp2')}",
            "Application Gateway > Configuration > HTTP2: Enabled" if not gw.get("enableHttp2") else "",
            sid,
            sname,
            gw.get("name", "") if not gw.get("enableHttp2") else "",
        )
        for gw in gws
    ]


def check_7_14(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    7.14 — WAF request body inspection is enabled (Level 2)

    By default, the WAF inspects headers and URIs but not request bodies.
    Disabling request body inspection allows attackers to smuggle malicious
    payloads in POST body content, bypassing WAF rules. This setting must
    be explicitly enabled.

    Data source: Resource Graph 'app_gateways' query (wafReqBody field).
    """
    gws = _idx(td, "app_gateways", sid)
    if not gws:
        return [
            _info(
                "7.14",
                "WAF request body inspection enabled",
                2,
                "7 - Networking Services",
                "No Application Gateways found.",
                sid,
                sname,
            )
        ]

    return [
        R(
            "7.14",
            "WAF request body inspection enabled",
            2,
            "7 - Networking Services",
            PASS if gw.get("wafReqBody") else FAIL,
            f"Gateway '{gw.get('name')}': requestBodyCheck = {gw.get('wafReqBody')}",
            "Application Gateway > WAF > Advanced > Enable Request body inspection" if not gw.get("wafReqBody") else "",
            sid,
            sname,
            gw.get("name", "") if not gw.get("wafReqBody") else "",
        )
        for gw in gws
    ]


def check_7_15(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    """
    7.15 — WAF bot protection is enabled (Level 2)

    Bot protection rules block known malicious bots (crawlers, scanners,
    scrapers) based on Microsoft's threat intelligence feed. Prevention mode
    actively blocks; Detection mode only logs. Only Prevention mode is
    considered compliant.

    Note: This check targets standalone WAF POLICY resources
    (type: applicationGatewayWebApplicationFirewallPolicies), which are
    separate from WAF configuration embedded in Application Gateways.
    A WAF policy must exist and be in Prevention mode.

    Data source: Resource Graph 'waf_policies' query (botEnabled field,
    which maps to policySettings.mode).
    """
    policies = _idx(td, "waf_policies", sid)
    if not policies:
        return [
            _info(
                "7.15", "WAF bot protection enabled", 2, "7 - Networking Services", "No WAF policies found.", sid, sname
            )
        ]

    return [
        R(
            "7.15",
            "WAF bot protection enabled",
            2,
            "7 - Networking & Governance",
            # botEnabled field contains the mode string: "Prevention" or "Detection"
            PASS if str(pol.get("botEnabled", "")).lower() == "prevention" else FAIL,
            f"WAF policy '{pol.get('name')}': mode = {pol.get('botEnabled')}",
            (
                "WAF policy > Bot protection > Set to Prevention mode"
                if str(pol.get("botEnabled", "")).lower() != "prevention"
                else ""
            ),
            sid,
            sname,
            pol.get("name", "") if str(pol.get("botEnabled", "")).lower() != "prevention" else "",
        )
        for pol in policies
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — SECURITY SERVICES
# ══════════════════════════════════════════════════════════════════════════════


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
        rc, data = az(["security", "pricing", "show", "-n", plan], sid, timeout=20)
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
    rc, data = az_rest(url, timeout=20)
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
    rc, data = az_rest(url, timeout=20)
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
    rc, contacts = az(["security", "contact", "list"], sid, timeout=20)
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
    rc2, cdata = az_rest(url, timeout=20)
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
                timeout=20,
            )
            if rc != 0:
                # Permission denied or other error; report as ERROR result
                error_msg = str(keys) if isinstance(keys, str) else "Access denied or error listing keys"
                results.append(
                    R(
                        ctrl,
                        f"Key Vault keys have expiration date set ({label})",
                        1,
                        "8 - Security Services",
                        ERROR,
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
                timeout=20,
            )
            if rc != 0:
                # Permission denied or other error; report as ERROR result
                error_msg = str(secrets) if isinstance(secrets, str) else "Access denied or error listing secrets"
                results.append(
                    R(
                        ctrl,
                        f"Key Vault secrets have expiration date set ({label})",
                        1,
                        "8 - Security Services",
                        ERROR,
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
        rc, keys2 = az(["keyvault", "key", "list", "--vault-name", vname, "--query", "[].name"], sid, timeout=20)
        if rc != 0:
            # Permission denied or other error; report as ERROR result
            error_msg = str(keys2) if isinstance(keys2, str) else "Access denied or error listing keys"
            results.append(
                R(
                    "8.3.9",
                    "Key Vault automatic key rotation enabled",
                    2,
                    "8 - Security Services",
                    ERROR,
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
                    timeout=20,
                )
                if rc2 != 0:
                    # Permission denied or other error for this specific key
                    error_msg = str(pol) if isinstance(pol, str) else "Access denied"
                    results.append(
                        R(
                            "8.3.9",
                            "Key Vault automatic key rotation enabled",
                            2,
                            "8 - Security Services",
                            ERROR,
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
        rc, certs = az(["keyvault", "certificate", "list", "--vault-name", vname, "--query", "[].id"], sid, timeout=20)
        if rc != 0:
            # Permission denied or other error; report as ERROR result
            error_msg = str(certs) if isinstance(certs, str) else "Access denied or error listing certificates"
            results.append(
                R(
                    "8.3.11",
                    "Certificate validity period <= 12 months",
                    1,
                    "8 - Security Services",
                    ERROR,
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
                    timeout=20,
                )
                if rc2 != 0:
                    # Permission denied or other error for this specific certificate
                    error_msg = str(cert) if isinstance(cert, str) else "Access denied"
                    cname = cert_id.split("/")[-1]
                    results.append(
                        R(
                            "8.3.11",
                            "Certificate validity period <= 12 months",
                            1,
                            "8 - Security Services",
                            ERROR,
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


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — STORAGE SERVICES
# ══════════════════════════════════════════════════════════════════════════════


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

    Group 3 — File service properties
      Requires: az storage account file-service-properties show
      Checks: 9.1.1 (file soft delete), 9.1.2 (SMB version), 9.1.3 (SMB encryption)

    Group 4 — Key management
      Requires: az storage account show (key policy) + az monitor activity-log list
      Checks: 9.3.1.1 (rotation reminders), 9.3.1.2 (keys rotated within 90 days)

    Data source (Group 1): Resource Graph 'storage' query
    Data sources (Groups 2-4): az CLI per-account calls
    """
    accounts = _idx(td, "storage", sid)

    # If Resource Graph returned nothing, fall back to az storage account list.
    # This happens when a subscription was loaded from a stale checkpoint that
    # pre-dates the Resource Graph prefetch, or when the Graph query timed out.
    # Rather than returning a single ERROR, we fetch the full account details
    # via az CLI and normalise the field names to match what Resource Graph
    # returns — so the complete set of per-control checks can still run.
    if not accounts:
        rc_list, az_accounts = az(["storage", "account", "list"], sid, timeout=30)
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
            return [
                _info(cid, f"Storage check {cid}", 1, "9 - Storage Services", "No storage accounts found.", sid, sname)
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

    results = []
    for acct in accounts:
        aname = acct.get("name", "?")
        rg = acct.get("resourceGroup", "?")

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
            # Each tuple: (ctrl, title, lvl, compliant, display_value, remediation)
            # display_value is shown in the report so the actual setting is visible —
            # this makes it easy to verify genuine FAILs vs normalisation issues.
            # 9.3.4 — All traffic must use HTTPS (TLS). HTTP requests are rejected.
            (
                "9.3.4",
                "Secure transfer (HTTPS) required",
                1,
                bool(acct.get("httpsOnly")),
                f"supportsHttpsTrafficOnly = {acct.get('httpsOnly')}",
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
                f"allowCrossTenantReplication = {acct.get('crossTenant')}",
                "Storage Account > Data Management > Object replication > " "Allow cross-tenant replication: Disabled",
            ),
            # 9.3.8 — Anonymous blob access allows unauthenticated public read
            # access to any container configured for anonymous access.
            (
                "9.3.8",
                "Blob anonymous access disabled",
                1,
                not acct.get("blobAnon"),
                f"allowBlobPublicAccess = {acct.get('blobAnon')}",
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
                f"minimumTlsVersion = {acct.get('minTls')}",
                "Storage Account > Configuration > Minimum TLS version: TLS 1.2",
            ),
            # 9.3.1.3 — Shared Key (storage account key) access allows any holder of
            # the key to perform any operation. Disabling it forces Azure AD auth.
            (
                "9.3.1.3",
                "Storage account key access disabled",
                1,
                acct.get("keyAccess") is False,
                f"allowSharedKeyAccess = {acct.get('keyAccess')}",
                "Storage Account > Configuration > Allow storage account key access: Disabled",
            ),
            # 9.3.3.1 — Sets the portal UI default to Entra ID auth rather than
            # storage account keys, reducing accidental key usage.
            (
                "9.3.3.1",
                "Default to Microsoft Entra authorization in Azure portal",
                1,
                acct.get("oauthDefault") is True,
                f"defaultToOAuthAuthentication = {acct.get('oauthDefault')}",
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
                f"networkAcls.bypass = {acct.get('bypass')}",
                "Storage Account > Networking > Exceptions > Allow Azure services",
            ),
            # 9.3.2.1 — Private endpoints give storage a private IP within the VNet,
            # eliminating public internet exposure for data plane access. (L2)
            (
                "9.3.2.1",
                "Private endpoints used to access storage accounts",
                2,
                has_pe,
                f"privateEndpointConnections count = {acct.get('privateEps') or 0}",
                "Storage Account > Networking > Private endpoint connections",
            ),
            # 9.3.11 — Geo-redundant storage replicates data to a secondary Azure region,
            # protecting against regional disasters. GRS/GZRS variants all qualify. (L2)
            (
                "9.3.11",
                "Storage redundancy set to geo-redundant (GRS)",
                2,
                is_grs,
                f"sku = {acct.get('sku')}",
                "Storage Account > Data Management > Redundancy",
            ),
        ]

        # Emit one R per static check — show actual value in details for easy verification
        for ctrl, title, lvl, compliant, display_val, remediation in static:
            results.append(
                R(
                    ctrl,
                    title,
                    lvl,
                    "9 - Storage Services",
                    PASS if compliant else FAIL,
                    f"Account '{aname}': {display_val}",
                    remediation if not compliant else "",
                    sid,
                    sname,
                    aname if not compliant else "",
                )
            )

        # ────────────────────────────────────────────────────────────────────
        # GROUP 2 — Blob service properties
        # ────────────────────────────────────────────────────────────────────

        rc_blob, blob_props = az(
            ["storage", "account", "blob-service-properties", "show", "--account-name", aname, "--resource-group", rg],
            sid,
            timeout=15,
        )

        if rc_blob == 0 and isinstance(blob_props, dict):
            # deleteRetentionPolicy — applies to individual blob versions
            drp = blob_props.get("deleteRetentionPolicy", {}) or {}
            # containerDeleteRetentionPolicy — applies to entire containers
            crp = blob_props.get("containerDeleteRetentionPolicy", {}) or {}
            ver = blob_props.get("isVersioningEnabled", False)

            # 9.2.1 — Blob soft delete allows recovery of deleted blobs within
            # the retention period. Essential for ransomware recovery.
            results.append(
                R(
                    "9.2.1",
                    "Blob soft delete enabled",
                    1,
                    "9 - Storage Services",
                    PASS if drp.get("enabled") else FAIL,
                    f"Account '{aname}': blob soft delete = {drp.get('enabled')}",
                    (
                        "Storage Account > Data protection > Enable soft delete for blobs"
                        if not drp.get("enabled")
                        else ""
                    ),
                    sid,
                    sname,
                    aname if not drp.get("enabled") else "",
                )
            )

            # 9.2.2 — Container soft delete allows recovery of deleted containers
            # (and all blobs within) within the retention period.
            results.append(
                R(
                    "9.2.2",
                    "Container soft delete enabled",
                    1,
                    "9 - Storage Services",
                    PASS if crp.get("enabled") else FAIL,
                    f"Account '{aname}': container soft delete = {crp.get('enabled')}",
                    (
                        "Storage Account > Data protection > Enable soft delete for containers"
                        if not crp.get("enabled")
                        else ""
                    ),
                    sid,
                    sname,
                    aname if not crp.get("enabled") else "",
                )
            )

            # 9.2.3 — Versioning automatically saves a copy of a blob before every
            # write/delete, allowing point-in-time recovery. (L2)
            results.append(
                R(
                    "9.2.3",
                    "Blob versioning enabled",
                    2,
                    "9 - Storage Services",
                    PASS if ver else FAIL,
                    f"Account '{aname}': isVersioningEnabled = {ver}",
                    "Storage Account > Data protection > Enable blob versioning" if not ver else "",
                    sid,
                    sname,
                    aname if not ver else "",
                )
            )
        else:
            # API call failed — emit ERRORs for all three blob checks rather
            # than silently skipping them (which would artificially inflate PASS count)
            for ctrl, title, lvl in [
                ("9.2.1", "Blob soft delete enabled", 1),
                ("9.2.2", "Container soft delete enabled", 1),
                ("9.2.3", "Blob versioning enabled", 2),
            ]:
                results.append(
                    R(
                        ctrl,
                        title,
                        lvl,
                        "9 - Storage Services",
                        ERROR,
                        f"Account '{aname}': {str(blob_props)[:100]}",
                        "",
                        sid,
                        sname,
                        aname,
                    )
                )

        # ────────────────────────────────────────────────────────────────────
        # GROUP 3 — File service properties
        # ────────────────────────────────────────────────────────────────────

        rc_file, file_props = az(
            ["storage", "account", "file-service-properties", "show", "--account-name", aname, "--resource-group", rg],
            sid,
            timeout=15,
        )

        if rc_file == 0 and isinstance(file_props, dict):
            # shareDeleteRetentionPolicy — applies to Azure File Share soft delete
            srp = file_props.get("shareDeleteRetentionPolicy", {}) or {}

            # 9.1.1 — File share soft delete allows recovery of deleted shares
            results.append(
                R(
                    "9.1.1",
                    "Azure Files soft delete enabled",
                    1,
                    "9 - Storage Services",
                    PASS if srp.get("enabled") else FAIL,
                    f"Account '{aname}': file share soft delete = {srp.get('enabled')}",
                    (
                        "Storage Account > Data protection > Enable soft delete for file shares"
                        if not srp.get("enabled")
                        else ""
                    ),
                    sid,
                    sname,
                    aname if not srp.get("enabled") else "",
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
            results.append(
                R(
                    "9.1.2",
                    "SMB protocol version >= 3.1.1",
                    1,
                    "9 - Storage Services",
                    PASS if has_good_ver or not smb else FAIL,
                    f"Account '{aname}': SMB versions = {smb.get('versions', 'N/A')}",
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
            results.append(
                R(
                    "9.1.3",
                    "SMB channel encryption AES-256-GCM or higher",
                    1,
                    "9 - Storage Services",
                    PASS if has_good_enc or not smb else FAIL,
                    f"Account '{aname}': SMB encryption = {smb.get('channelEncryption', 'N/A')}",
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
            for ctrl, title, lvl in [
                ("9.1.1", "Azure Files soft delete enabled", 1),
                ("9.1.2", "SMB protocol version >= 3.1.1", 1),
                ("9.1.3", "SMB channel encryption AES-256-GCM", 1),
            ]:
                results.append(
                    R(
                        ctrl,
                        title,
                        lvl,
                        "9 - Storage Services",
                        ERROR,
                        f"Account '{aname}': {str(file_props)[:100]}",
                        "",
                        sid,
                        sname,
                        aname,
                    )
                )

        # ────────────────────────────────────────────────────────────────────
        # GROUP 4 — Key management checks
        # ────────────────────────────────────────────────────────────────────

        # 9.3.1.1 — Key rotation reminder
        # keyExpirationPeriodInDays triggers an Azure Portal warning when keys
        # approach the expiry threshold, prompting manual rotation.
        rc_acct, acct_details = az(
            ["storage", "account", "show", "--name", aname, "--resource-group", rg, "--query", "keyPolicy"],
            sid,
            timeout=15,
        )
        if rc_acct == 0:
            key_policy = acct_details if isinstance(acct_details, dict) else {}
            reminder_days = key_policy.get("keyExpirationPeriodInDays")
            results.append(
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
        else:
            results.append(
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

        # 9.3.1.2 — Access keys regenerated within 90 days
        # Queries the Activity Log for 'regenerateKey' operations in the past 90 days.
        # If no event is found, the keys may not have been rotated in this period.
        # Limitation: Activity Log only retains 90 days by default, so a rotation
        # that occurred on exactly day 91 will not appear and will produce a false FAIL.
        # 9.3.1.2 — fetch without --query to avoid JMESPath null crash
        # Some activity log entries have null authorization.action, which causes
        # contains() to fail in JMESPath. Fetch all events and filter in Python.
        rc_log, log_data = az(
            [
                "monitor",
                "activity-log",
                "list",
                "--namespace",
                "Microsoft.Storage",
                "--offset",
                "90d",
                "--resource-id",
                acct.get("id", ""),
            ],
            sid,
            timeout=25,
        )

        if rc_log == 0:
            all_events = log_data if isinstance(log_data, list) else []
            # Filter in Python — safe against null authorization.action values
            regen_events = [
                e.get("eventTimestamp", "")
                for e in all_events
                if "regeneratekey" in str((e.get("authorization") or {}).get("action", "")).lower()
            ]
            last = regen_events[-1][:10] if regen_events else None
            results.append(
                R(
                    "9.3.1.2",
                    "Storage access keys regenerated within 90 days",
                    1,
                    "9 - Storage Services",
                    PASS if regen_events else FAIL,
                    (
                        f"Account '{aname}': key last regenerated {last}."
                        if regen_events
                        else f"Account '{aname}': no key regeneration found in last 90 days."
                    ),
                    "Storage Account > Access keys > Rotate key(s)." if not regen_events else "",
                    sid,
                    sname,
                    aname if not regen_events else "",
                )
            )
        else:
            results.append(
                _err(
                    "9.3.1.2",
                    "Storage access keys regenerated within 90 days",
                    1,
                    "9 - Storage Services",
                    str(log_data),
                    sid,
                    sname,
                )
            )

    # ────────────────────────────────────────────────────────────────────────
    # GROUP 5 — Resource locks (9.3.9, 9.3.10)
    # Single subscription-wide az lock list call; matched against every account.
    # ────────────────────────────────────────────────────────────────────────
    rc_lk, all_locks = az(["lock", "list", "--subscription", sid], sid, timeout=20)
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
                f"lock(s) found: {sorted(covering)}"
                if covering
                else "no resource locks found at account, RG, or subscription scope"
            )

            results.append(
                R(
                    "9.3.9",
                    "Storage account has CanNotDelete resource lock",
                    1,
                    "9 - Storage Services",
                    PASS if has_delete else FAIL,
                    f"Account '{aname}': {summary}",
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
                    f"Account '{aname}': {summary}",
                    "Storage Account > Locks > Add lock > Lock type: Read-only" if not has_read else "",
                    sid,
                    sname,
                    aname if not has_read else "",
                )
            )

    return results


# ══════════════════════════════════════════════════════════════════════════════
# CHECKPOINT SYSTEM
# ══════════════════════════════════════════════════════════════════════════════


def save_checkpoint(sid: str, sname: str, results: list[R], status: str = "completed") -> None:
    """
    Write audit results for one subscription to a JSON checkpoint file.

    Uses an atomic write pattern to prevent corrupt checkpoint files:
      1. Write to <sid>.json.tmp
      2. Rename .tmp → <sid>.json  (atomic on POSIX; near-atomic on Windows NTFS)

    This ensures that if the process crashes during a write, the partially
    written .tmp file is ignored on the next run (only .json files are loaded).
    The previous checkpoint (if any) remains intact until the rename completes.

    Parameters
    ──────────
    sid     : Subscription GUID (used as the filename)
    sname   : Subscription display name (stored for informational purposes)
    results : List of R dataclass instances to serialise
    status  : "completed" (default) or "failed" — only "completed" is resumed
    """
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

    data = {
        "tool_version": VERSION,
        "benchmark_version": BENCHMARK_VER,
        "subscription_id": sid,
        "subscription_name": sname,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": status,
        "results": [asdict(r) for r in results],  # Convert dataclasses to dicts
    }

    target = CHECKPOINT_DIR / f"{sid}.json"
    tmp = CHECKPOINT_DIR / f"{sid}.json.tmp"

    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    # Atomic rename — replaces the target file in a single OS operation
    tmp.rename(target)


def load_checkpoints() -> dict[str, Any]:
    """
    Load all completed checkpoint files from CHECKPOINT_DIR.

    Defensively handles:
      - Missing directory (returns empty dict — no checkpoints exist yet)
      - Corrupt JSON (logs a warning, skips the file)
      - Failed subscriptions (status != "completed" — skips the file)

    Returns
    ───────
    dict mapping subscription_id → checkpoint_data_dict
    Only subscriptions with status == "completed" are included.
    """
    if not CHECKPOINT_DIR.exists():
        return {}

    loaded = {}
    for p in CHECKPOINT_DIR.glob("*.json"):
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            # Only load checkpoints that successfully completed
            if data.get("status") == "completed":
                loaded[data["subscription_id"]] = data
        except (json.JSONDecodeError, KeyError) as e:
            LOGGER.warning("   ⚠️  Skipping corrupt checkpoint %s: %s", p.name, e)

    return loaded


def results_from_checkpoint(cp: dict[str, Any]) -> list[R]:
    """
    Deserialise a list of R dataclass instances from a checkpoint dict.

    Uses a defensive approach: only fields that exist on the R dataclass
    are passed to the constructor. Extra fields in the checkpoint (from a
    future version of the tool) are ignored. Missing fields fall back to
    the dataclass defaults.

    This allows old checkpoints to load cleanly even when new fields are
    added to the R dataclass in a later version.

    Parameters
    ──────────
    cp : Checkpoint dict loaded by load_checkpoints()

    Returns
    ───────
    List of R instances, one per record in cp["results"]
    """
    # Get the set of valid field names from the dataclass definition
    valid_fields = set(R.__dataclass_fields__.keys())

    results = []
    for r in cp.get("results", []):
        # Only pass fields that the current R dataclass knows about
        filtered = {k: v for k, v in r.items() if k in valid_fields}
        try:
            results.append(R(**filtered))
        except TypeError:
            pass  # Skip records that cannot be reconstructed

    return results


# ══════════════════════════════════════════════════════════════════════════════
# PER-SUBSCRIPTION AUDIT ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════


def audit_subscription(sub: dict[str, Any], td: dict[str, Any], progress: str = "") -> list[R]:
    """
    Run all per-subscription check functions and return a flat list of results.

    Each entry in 'checks' is a (label, lambda) tuple. The lambda is called
    to produce one or more R instances. The label is only used for console
    progress output — it does not affect the results.

    Error isolation: each check is wrapped in a try/except so that an exception
    in one check (e.g. an unexpected API response format) does not prevent
    subsequent checks from running. Failed checks are recorded as ERROR results.

    Parameters
    ──────────
    sub      : Dict with 'id' and 'name' keys for the subscription
    td       : Tenant data dict returned by prefetch()
    progress : Optional progress prefix for console output, e.g. "3/12 "

    Returns
    ───────
    Flat list of R instances from all checks in this subscription.
    """
    sid, sname = sub["id"], sub["name"]
    results = []

    # Cache grouped/batch check outputs so each expensive function runs once
    # even when we dispatch by individual control IDs.
    batch_cache = {}

    def _batch_once(key: str, fn: Any) -> list[R]:
        if key not in batch_cache:
            out = fn()
            batch_cache[key] = out if isinstance(out, list) else [out]
        return batch_cache[key]

    def _from_batch(key: str, fn: Any, control_id: str) -> list[R]:
        return [r for r in _batch_once(key, fn) if r.control_id == control_id]

    # Each tuple: (console_label, callable_returning_list_or_single_R)
    checks = [
        # ── Section 2 — Azure Databricks ──────────────────────────────────
        ("2.1.2", lambda: check_2_1_2(sid, sname, td)),
        ("2.1.7", lambda: check_2_1_7(sid, sname, td)),
        ("2.1.9", lambda: check_2_1_9(sid, sname, td)),
        ("2.1.10", lambda: check_2_1_10(sid, sname, td)),
        ("2.1.11", lambda: check_2_1_11(sid, sname, td)),
        # ── Section 5 — Identity (per-subscription checks only) ────────────
        # Tenant-level identity checks (5.1.1, 5.1.2, 5.4, 5.14, 5.15, 5.16)
        # are run ONCE in run_audit() and not repeated here.
        ("5.3.3", lambda: check_5_3_3(sid, sname, td)),
        ("5.23", lambda: [check_5_23(sid, sname)]),  # Returns single R — wrap in list
        ("5.27", lambda: [check_5_27(sid, sname, td)]),
        # ── Section 6 — Monitoring ─────────────────────────────────────────
        ("6.1.1.1", lambda: [check_6_1_1_1(sid, sname)]),
        ("6.1.1.2", lambda: [check_6_1_1_2(sid, sname)]),
        ("6.1.1.4", lambda: check_6_1_1_4(sid, sname, td)),
        ("6.1.1.6", lambda: check_6_1_1_6(sid, sname, td)),
        ("6.1.2.1", lambda: _from_batch("6.1.2", lambda: check_6_1_2_alerts(sid, sname), "6.1.2.1")),
        ("6.1.2.2", lambda: _from_batch("6.1.2", lambda: check_6_1_2_alerts(sid, sname), "6.1.2.2")),
        ("6.1.2.3", lambda: _from_batch("6.1.2", lambda: check_6_1_2_alerts(sid, sname), "6.1.2.3")),
        ("6.1.2.4", lambda: _from_batch("6.1.2", lambda: check_6_1_2_alerts(sid, sname), "6.1.2.4")),
        ("6.1.2.5", lambda: _from_batch("6.1.2", lambda: check_6_1_2_alerts(sid, sname), "6.1.2.5")),
        ("6.1.2.6", lambda: _from_batch("6.1.2", lambda: check_6_1_2_alerts(sid, sname), "6.1.2.6")),
        ("6.1.2.7", lambda: _from_batch("6.1.2", lambda: check_6_1_2_alerts(sid, sname), "6.1.2.7")),
        ("6.1.2.8", lambda: _from_batch("6.1.2", lambda: check_6_1_2_alerts(sid, sname), "6.1.2.8")),
        ("6.1.2.9", lambda: _from_batch("6.1.2", lambda: check_6_1_2_alerts(sid, sname), "6.1.2.9")),
        ("6.1.2.10", lambda: _from_batch("6.1.2", lambda: check_6_1_2_alerts(sid, sname), "6.1.2.10")),
        ("6.1.2.11", lambda: _from_batch("6.1.2", lambda: check_6_1_2_alerts(sid, sname), "6.1.2.11")),
        ("6.1.3.1", lambda: [check_6_1_3_1(sid, sname)]),
        # ── Section 7 — Networking ─────────────────────────────────────────
        ("7.1", lambda: check_7_1(sid, sname, td)),
        ("7.2", lambda: check_7_2(sid, sname, td)),
        ("7.3", lambda: check_7_3(sid, sname, td)),
        ("7.4", lambda: check_7_4(sid, sname, td)),
        ("7.5", lambda: check_7_5(sid, sname)),
        ("7.6", lambda: check_7_6(sid, sname, td)),
        ("7.8", lambda: check_7_8(sid, sname)),
        ("7.10", lambda: check_7_10(sid, sname, td)),
        ("7.11", lambda: check_7_11(sid, sname, td)),
        ("7.12", lambda: check_7_12(sid, sname, td)),
        ("7.13", lambda: check_7_13(sid, sname, td)),
        ("7.14", lambda: check_7_14(sid, sname, td)),
        ("7.15", lambda: check_7_15(sid, sname, td)),
        # ── Section 8 — Security ───────────────────────────────────────────
        ("8.1.1.1", lambda: _from_batch("8.1.defender", lambda: check_8_1_defender(sid, sname), "8.1.1.1")),
        ("8.1.2.1", lambda: _from_batch("8.1.defender", lambda: check_8_1_defender(sid, sname), "8.1.2.1")),
        ("8.1.3.1", lambda: _from_batch("8.1.defender", lambda: check_8_1_defender(sid, sname), "8.1.3.1")),
        ("8.1.4.1", lambda: _from_batch("8.1.defender", lambda: check_8_1_defender(sid, sname), "8.1.4.1")),
        ("8.1.5.1", lambda: _from_batch("8.1.defender", lambda: check_8_1_defender(sid, sname), "8.1.5.1")),
        ("8.1.6.1", lambda: _from_batch("8.1.defender", lambda: check_8_1_defender(sid, sname), "8.1.6.1")),
        ("8.1.7.1", lambda: _from_batch("8.1.defender", lambda: check_8_1_defender(sid, sname), "8.1.7.1")),
        ("8.1.7.2", lambda: _from_batch("8.1.defender", lambda: check_8_1_defender(sid, sname), "8.1.7.2")),
        ("8.1.7.3", lambda: _from_batch("8.1.defender", lambda: check_8_1_defender(sid, sname), "8.1.7.3")),
        ("8.1.7.4", lambda: _from_batch("8.1.defender", lambda: check_8_1_defender(sid, sname), "8.1.7.4")),
        ("8.1.8.1", lambda: _from_batch("8.1.defender", lambda: check_8_1_defender(sid, sname), "8.1.8.1")),
        ("8.1.9.1", lambda: _from_batch("8.1.defender", lambda: check_8_1_defender(sid, sname), "8.1.9.1")),
        ("8.1.3.3", lambda: [check_8_1_3_3(sid, sname)]),
        ("8.1.10", lambda: [check_8_1_10(sid, sname)]),
        ("8.1.12", lambda: _from_batch("8.1.12-15", lambda: check_8_1_12_to_15(sid, sname), "8.1.12")),
        ("8.1.13", lambda: _from_batch("8.1.12-15", lambda: check_8_1_12_to_15(sid, sname), "8.1.13")),
        ("8.1.14", lambda: _from_batch("8.1.12-15", lambda: check_8_1_12_to_15(sid, sname), "8.1.14")),
        ("8.1.15", lambda: _from_batch("8.1.12-15", lambda: check_8_1_12_to_15(sid, sname), "8.1.15")),
        ("8.3.1", lambda: _from_batch("8.3", lambda: check_8_3_keyvaults(sid, sname, td), "8.3.1")),
        ("8.3.2", lambda: _from_batch("8.3", lambda: check_8_3_keyvaults(sid, sname, td), "8.3.2")),
        ("8.3.3", lambda: _from_batch("8.3", lambda: check_8_3_keyvaults(sid, sname, td), "8.3.3")),
        ("8.3.4", lambda: _from_batch("8.3", lambda: check_8_3_keyvaults(sid, sname, td), "8.3.4")),
        ("8.3.5", lambda: _from_batch("8.3", lambda: check_8_3_keyvaults(sid, sname, td), "8.3.5")),
        ("8.3.6", lambda: _from_batch("8.3", lambda: check_8_3_keyvaults(sid, sname, td), "8.3.6")),
        ("8.3.7", lambda: _from_batch("8.3", lambda: check_8_3_keyvaults(sid, sname, td), "8.3.7")),
        ("8.3.8", lambda: _from_batch("8.3", lambda: check_8_3_keyvaults(sid, sname, td), "8.3.8")),
        ("8.3.9", lambda: _from_batch("8.3", lambda: check_8_3_keyvaults(sid, sname, td), "8.3.9")),
        ("8.3.11", lambda: _from_batch("8.3", lambda: check_8_3_keyvaults(sid, sname, td), "8.3.11")),
        ("8.4.1", lambda: [check_8_4_1(sid, sname, td)]),
        ("8.5", lambda: check_8_5(sid, sname, td)),
        # ── Section 9 — Storage ────────────────────────────────────────────
        ("9.1.1", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.1.1")),
        ("9.1.2", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.1.2")),
        ("9.1.3", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.1.3")),
        ("9.2.1", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.2.1")),
        ("9.2.2", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.2.2")),
        ("9.2.3", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.2.3")),
        ("9.3.1.1", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.1.1")),
        ("9.3.1.2", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.1.2")),
        ("9.3.1.3", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.1.3")),
        ("9.3.2.1", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.2.1")),
        ("9.3.2.2", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.2.2")),
        ("9.3.2.3", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.2.3")),
        ("9.3.3.1", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.3.1")),
        ("9.3.4", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.4")),
        ("9.3.5", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.5")),
        ("9.3.6", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.6")),
        ("9.3.7", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.7")),
        ("9.3.8", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.8")),
        ("9.3.9", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.9")),
        ("9.3.10", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.10")),
        ("9.3.11", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.3.11")),
    ]

    for ctrl_id, fn in checks:
        LOGGER.debug("    [%s%s] %-12s", progress, sname[:24], ctrl_id)
        try:
            result = fn()
            # Normalise to list (some functions return a single R, some a list)
            result = result if isinstance(result, list) else [result]
            results.extend(result)
            # Count outcomes for the console progress line
            p = sum(1 for r in result if r.status == PASS)
            f = sum(1 for r in result if r.status == FAIL)
            e = sum(1 for r in result if r.status in (ERROR, MANUAL))
            LOGGER.debug(
                "    [%s%s] %-12s ✅%d ❌%d%s",
                progress,
                sname[:24],
                ctrl_id,
                p,
                f,
                f" ⚠️{e}" if e else "",
            )
        except Exception as ex:
            # Catch unexpected exceptions so one broken check doesn't kill the subscription
            LOGGER.warning("    [%s%s] %-12s ⚠️  %s", progress, sname[:24], ctrl_id, ex)
            results.append(R(ctrl_id, ctrl_id, 1, "unknown", ERROR, str(ex), "", sid, sname))

    return results


# ══════════════════════════════════════════════════════════════════════════════
# SUBSCRIPTION HELPERS
# ══════════════════════════════════════════════════════════════════════════════


def get_subscriptions(
    filter_subs: str | list[str] | None = None,
) -> list[dict[str, str]]:
    """
    List enabled Azure subscriptions, optionally filtered to a specific set.

    Parameters
    ──────────
    filter_subs : None              — return all enabled subscriptions
                  "single-name"     — return one subscription by name or ID
                  ["a", "b", "c"]  — return multiple subscriptions by name or ID

    Matching is exact (case-sensitive) on either subscription name or GUID.
    Partial name matches are not supported to avoid ambiguity.

    Exits with a clear error message if any requested subscription is not found,
    listing the available subscription names to help correct typos.
    """
    rc, data = az(["account", "list", "--query", "[?state=='Enabled'].{id:id, name:name}"])
    if rc != 0:
        LOGGER.error("❌ Could not list subscriptions: %s", data)
        sys.exit(1)

    subs = data if isinstance(data, list) else []

    if not filter_subs:
        return subs  # No filter — return all enabled subscriptions

    # Normalise: a single string becomes a one-element list
    requested = [filter_subs] if isinstance(filter_subs, str) else list(filter_subs)

    filtered = []
    not_found = []
    for req in requested:
        # Match on subscription ID (GUID) or display name
        match = [s for s in subs if s["id"] == req or s["name"] == req]
        if match:
            filtered.extend(match)
        else:
            not_found.append(req)

    if not_found:
        LOGGER.error("❌ Subscription(s) not found: %s", not_found)
        LOGGER.error("   Available: %s", [s["name"] for s in subs])
        sys.exit(1)

    return filtered


def _audit_subscription_worker(
    sub: dict[str, Any], td: dict[str, dict[str, list[Any]]], progress_label: str
) -> tuple[list[R], str | None]:
    """Execute one subscription audit in a worker and capture exceptions."""
    try:
        return audit_subscription(sub, td, progress=progress_label), None
    except Exception as exc:
        return [], str(exc)


def run_audit(
    subs: list[dict[str, Any]],
    parallel: int = 2,
    resume: bool = True,
    executor_mode: str = "process",
    adaptive_concurrency: bool = True,
) -> list[R]:
    """
    Orchestrate the full audit across all subscriptions.

    Steps:
      1. Load existing checkpoints (if resume=True). Completed subscriptions
         are skipped — their results are loaded directly from disk.
      2. Run tenant-level identity checks ONCE (not per subscription).
         These produce results without a subscription_id / subscription_name.
      3. Prefetch all Resource Graph data across all remaining subscriptions.
        4. Audit remaining subscriptions in parallel using thread or process workers.
      5. Merge all results and return.

    Thread-safe counter: A locked counter tracks how many subscriptions have
    started processing. Output lines include [N/Total] progress indicators
    that account for subscriptions already completed in a previous run.

    Parameters
    ──────────
    subs     : Full list of subscription dicts to audit (id, name)
    parallel             : Max concurrent workers requested (default 2)
    resume               : If True, skip subscriptions with existing checkpoints
    executor_mode        : "process" (default) or "thread"
    adaptive_concurrency : If True, reduce/increase workers based on throttling

    Returns
    ───────
    Flat list of all R instances across all subscriptions + tenant checks.
    """
    checkpoints = load_checkpoints() if resume else {}
    if checkpoints:
        LOGGER.info("\n💾 Found checkpoints for %d subscription(s).", len(checkpoints))

    # Split subscriptions into already-done (skip) and still-todo (audit)
    done = [s for s in subs if s["id"] in checkpoints]
    todo = [s for s in subs if s["id"] not in checkpoints]

    if done:
        LOGGER.info("⏭️  Skipping (checkpointed): %s", ", ".join(s["name"] for s in done))

    # Seed the results with data from completed checkpoints
    all_results = []
    for sub in done:
        all_results.extend(results_from_checkpoint(checkpoints[sub["id"]]))

    if not todo:
        LOGGER.info("✅ All subscriptions already checkpointed.")
        return all_results

    requested_parallel = max(1, parallel)
    if requested_parallel != parallel:
        LOGGER.warning("⚠️  --parallel must be >= 1; using %d", requested_parallel)
    if requested_parallel > 5:
        LOGGER.warning(
            "⚠️  Requested --parallel=%d may trigger API throttling; adaptive mode will tune this if needed.",
            requested_parallel,
        )

    mode = (executor_mode or "thread").lower()
    if mode not in {"thread", "process"}:
        LOGGER.warning("⚠️  Unknown executor mode '%s'; falling back to thread.", mode)
        mode = "thread"

    adaptive_enabled = adaptive_concurrency and mode == "thread"
    if adaptive_concurrency and not adaptive_enabled:
        LOGGER.warning("⚠️  Adaptive concurrency is only supported with thread executor; disabling it for '%s'.", mode)

    if mode == "process" and sys.platform == "win32":
        LOGGER.warning(
            "⚠️  Process executor on Windows may be slower due to process spawn and data serialization overhead."
        )

    # ── Tenant-level identity checks ─────────────────────────────────────────
    # These checks target the Entra ID tenant, not any individual subscription.
    # Run them ONCE here rather than inside the per-subscription loop to avoid
    # duplicate results when auditing multiple subscriptions.
    LOGGER.info("\n  [Tenant] Running tenant-level identity checks...")
    tenant_results = []
    for fn in [check_5_1_1, check_5_1_2, check_5_4, check_5_14, check_5_15, check_5_16]:
        try:
            r = fn()
            tenant_results.append(r)
            icon = _STATUS_STYLE.get(r.status, ("", "", "?"))[2]
            LOGGER.info("    %-10s %s %s", r.control_id, icon, r.status)
        except Exception as e:
            LOGGER.warning("    ⚠️  ERROR in tenant check: %s", e)

    # ── Resource Graph prefetch ───────────────────────────────────────────────
    # Fetch all Resource Graph data ONCE before the parallel loop.
    # The results are shared read-only across all workers (no locking needed
    # because the dict is only written during prefetch, never during audit_subscription).
    td = prefetch([s["id"] for s in todo])
    current_parallel = min(requested_parallel, len(todo))
    LOGGER.info(
        "\n  Auditing %d subscription(s) [mode=%s, workers=%d]...\n",
        len(todo),
        mode,
        current_parallel,
    )
    # If rich is available, use a nicer progress bar; otherwise use the
    # lightweight console UI that requires no external deps.
    if HAS_RICH:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            transient=True,
        )
        progress.start()
        task_id: Any = progress.add_task("Preparing...", total=len(todo))
    else:
        progress = None
        task_id = 0
        console_init(len(todo))

    # ── Thread-safe subscription counter ─────────────────────────────────────
    # _started tracks how many subscriptions have begun processing.
    # Initialised to len(done) so the counter continues from the checkpoint count.
    # Example: 3 of 12 subscriptions were checkpointed → first new sub shows [4/12].
    _total = len(subs)  # Total including already-checkpointed
    _done_n = len(done)  # Already completed from checkpoints
    _counter = threading.Lock()
    _started = [_done_n]  # Mutable list used as a thread-safe integer counter

    completed_in_todo = 0
    stable_batches = 0
    remaining = list(todo)
    _ = get_and_reset_rate_limit_retry_count()

    # ── Parallel execution (batch-based for adaptive concurrency) ───────────
    while remaining:
        batch = remaining[:current_parallel]
        remaining = remaining[current_parallel:]

        executor_cls: Any = ProcessPoolExecutor if mode == "process" else ThreadPoolExecutor
        with executor_cls(max_workers=current_parallel) as pool:
            futures: dict[Any, tuple[dict[str, Any], int]] = {}
            for sub in batch:
                with _counter:
                    _started[0] += 1
                    n = _started[0]

                if progress is not None:
                    progress.update(task_id, description=sub.get("name", ""))
                else:
                    console_update(n, _total, sub.get("name", ""))

                LOGGER.debug("  ▶  [%d/%d] Starting:  %s", n, _total, sub["name"])
                progress_label = f"{n}/{_total} "
                fut = pool.submit(_audit_subscription_worker, sub, td, progress_label)
                futures[fut] = (sub, n)

            for future in as_completed(futures):
                sub, n = futures[future]
                try:
                    sub_results, err = future.result()
                except Exception as ex:
                    sub_results, err = [], str(ex)

                if err:
                    LOGGER.error("  ❌ [%d/%d] Failed:    %s — %s", n, _total, sub["name"], err)
                    save_checkpoint(sub["id"], sub["name"], [], status="failed")
                else:
                    all_results.extend(sub_results)
                    save_checkpoint(sub["id"], sub["name"], sub_results)
                    LOGGER.debug("  ✅ [%d/%d] Completed: %s", n, _total, sub["name"])

                completed_in_todo += 1
                if progress is not None:
                    progress.update(task_id, completed=completed_in_todo, description=sub.get("name", ""))

        if adaptive_enabled:
            throttled_retries = get_and_reset_rate_limit_retry_count()
            reduce_threshold = max(2, len(batch))

            if throttled_retries >= reduce_threshold and current_parallel > 1:
                new_parallel = max(1, current_parallel - 1)
                LOGGER.warning(
                    "⚠️  Detected %d transient throttling retries in last batch; reducing workers %d → %d",
                    throttled_retries,
                    current_parallel,
                    new_parallel,
                )
                current_parallel = new_parallel
                stable_batches = 0
            elif throttled_retries == 0 and current_parallel < requested_parallel and remaining:
                stable_batches += 1
                if stable_batches >= 2:
                    new_parallel = min(requested_parallel, current_parallel + 1)
                    LOGGER.info(
                        "✅ No throttling for %d batch(es); increasing workers %d → %d",
                        stable_batches,
                        current_parallel,
                        new_parallel,
                    )
                    current_parallel = new_parallel
                    stable_batches = 0
            else:
                stable_batches = 0
        else:
            _ = get_and_reset_rate_limit_retry_count()

    # Ensure the progress UI finishes cleanly after workers complete
    if progress:
        try:
            progress.stop()
        except Exception:
            pass
    else:
        console_finish()

    # Tenant results are added ONCE after all subscription workers complete.
    # They must not be inside the parallel loop or they will be duplicated
    # once per subscription.
    all_results.extend(tenant_results)
    return all_results


# ══════════════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════════════

# Visual style for each status type used in table rows and badges.
# Format: (text_hex_colour, background_hex_colour, emoji)
_STATUS_STYLE = {
    PASS: ("#16a34a", "#f0fdf4", "✅"),  # Green
    FAIL: ("#dc2626", "#fef2f2", "❌"),  # Red
    ERROR: ("#ea580c", "#fff7ed", "⚠️"),  # Orange
    INFO: ("#2563eb", "#eff6ff", "ℹ️"),  # Blue
    MANUAL: ("#7c3aed", "#f5f3ff", "📋"),  # Purple
}


def _ctrl_sort_key(control_id: str) -> tuple[int, ...]:
    """Return a numeric sort key for a CIS control ID.

    Splits the ID on '.' and converts each segment to an integer so that
    e.g. '9.3.10' sorts after '9.3.9' instead of before '9.3.2'.
    Non-numeric segments fall back to 0.
    """
    return tuple(int(p) if p.isdigit() else 0 for p in str(control_id).split("."))


def generate_html(
    results: list[R],
    output: str,
    scope_info: dict[str, Any] | None = None,
) -> None:
    """
    Generate a self-contained HTML audit report from a list of R instances.

    The report is a single .html file with:
      - Embedded CSS (no external stylesheets)
      - Embedded JavaScript (no external scripts)
      - Summary cards (total counts per status)
      - Per-section table with colour-coded rows
      - Live filter by search text, status, and CIS level
      - Subscription / resource column for context
      - Remediation guidance on every FAIL row

    All user data (resource names, subscription names, error messages) is
    passed through html.escape() before embedding to prevent XSS.

    Parameters
    ──────────
    results    : List of R instances to render
    output     : Output file path (e.g. "cis_azure_audit_report.html")
    scope_info : Optional dict with keys: tenant, user, scope_label,
                 subscriptions (list of name strings), level_filter
    """
    # ── Counts and score ──────────────────────────────────────────────────────
    counts = {s: sum(1 for r in results if r.status == s) for s in [PASS, FAIL, ERROR, INFO, MANUAL]}
    total = len(results)

    # Compliance score excludes INFO (not applicable) and MANUAL (human review).
    # Score = PASS / (PASS + FAIL + ERROR) expressed as a percentage.
    denom = max(total - counts[INFO] - counts[MANUAL], 1)  # Avoid division by zero
    score = round(counts[PASS] / denom * 100, 1)

    # ── Build table rows grouped by section ───────────────────────────────────
    # Group results by their section field and sort alphabetically
    sections: dict = {}
    for r in results:
        sections.setdefault(r.section, []).append(r)

    rows = ""
    for sec in sorted(sections, key=lambda s: _ctrl_sort_key(s.split(" ")[0])):
        grp = sections[sec]
        # Count passing checks in this section (INFO and MANUAL excluded)
        sp = sum(1 for r in grp if r.status == PASS)
        rows += (
            f'<tr class="sh"><td colspan="6">'
            f"<b>{html.escape(sec)}</b>"
            f'<span class="ss">{sp} of {len(grp)} checks passed</span>'
            f"</td></tr>\n"
        )

        # Sort within section: numerically by control_id, then subscription, then resource
        for r in sorted(grp, key=lambda x: (_ctrl_sort_key(x.control_id), x.subscription_name, x.resource)):
            col, bg, icon = _STATUS_STYLE.get(r.status, ("#374151", "#f9fafb", "?"))

            # Build the Subscription / Resource cell content
            # Tenant-wide checks have no subscription_name
            sub_cell = ""
            if r.subscription_name:
                sub_cell += f'<div class="sub-name">📋 {html.escape(r.subscription_name)}</div>'
            else:
                sub_cell += '<div class="sub-name" style="color:#94a3b8">Tenant-wide</div>'
            if r.resource:
                sub_cell += f'<div class="res-name">' f"🔹 <code>{html.escape(r.resource)}</code></div>"

            # Remediation hint only appears on FAIL rows
            fix = (
                f'<div class="fix">💡 {html.escape(r.remediation)}</div>' if r.remediation and r.status == FAIL else ""
            )

            # data-* attributes are used by the JavaScript filter function
            rows += (
                f'<tr style="background:{bg}" '
                f'data-status="{r.status}" data-level="L{r.level}">'
                f"<td><code>{html.escape(r.control_id)}</code></td>"
                f'<td><span class="lv">L{r.level}</span></td>'
                f"<td>{html.escape(r.title)}</td>"
                f'<td class="sub-col">{sub_cell}</td>'
                f'<td><span class="badge" style="color:{col}">{icon} {r.status}</span></td>'
                f"<td>{html.escape(r.details)}{fix}</td>"
                f"</tr>\n"
            )

    # ── Report timestamp ──────────────────────────────────────────────────────
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Scope info block ─────────────────────────────────────────────────────
    si = scope_info or {}
    scope_rows = ""
    if si.get("tenant"):
        scope_rows += f'<tr><th>Tenant</th><td>{html.escape(si["tenant"])}</td></tr>\n'
    if si.get("user"):
        scope_rows += f'<tr><th>Audited by</th><td>{html.escape(si["user"])}</td></tr>\n'
    if si.get("scope_label"):
        scope_rows += f'<tr><th>Scope</th><td>{html.escape(si["scope_label"])}</td></tr>\n'
    if si.get("subscriptions"):
        subs_html = ", ".join(html.escape(s) for s in si["subscriptions"])
        scope_rows += f'<tr><th>Subscriptions ({len(si["subscriptions"])})</th><td>{subs_html}</td></tr>\n'
    if si.get("level_filter"):
        scope_rows += f'<tr><th>Level filter</th><td>Level {html.escape(str(si["level_filter"]))} only</td></tr>\n'
    scope_block = f'<div class="scope-info"><table>{scope_rows}</table></div>' if scope_rows else ""

    # ── Full HTML page ────────────────────────────────────────────────────────
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CIS Azure Audit Report — {ts}</title>
<style>
/* ── Reset and base ── */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        background: #f8fafc; color: #1e293b; line-height: 1.5; }}

/* ── Header ── */
header {{ background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);
          color: #fff; padding: 2rem; }}
header h1 {{ font-size: 1.6rem; font-weight: 700; margin-bottom: .25rem; }}
header p  {{ opacity: .8; font-size: .9rem; }}

/* ── Score cards ── */
.cards {{ display: flex; gap: 1rem; padding: 1.5rem 2rem; flex-wrap: wrap; }}
.card  {{ flex: 1; min-width: 120px; background: #fff; border-radius: 10px;
          padding: 1.2rem; text-align: center;
          box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
.card .n {{ font-size: 2rem; font-weight: 800; line-height: 1; }}
.card .l {{ font-size: .78rem; color: #64748b; margin-top: .3rem; }}
.c-sc .n {{ font-size: 2.4rem; }}
.c-pa .n {{ color: #16a34a; }}
.c-fa .n {{ color: #dc2626; }}
.c-er .n {{ color: #ea580c; }}
.c-in .n {{ color: #2563eb; }}
.c-ma .n {{ color: #7c3aed; }}

/* ── Filter bar ── */
.filters {{ display: flex; align-items: center; gap: .75rem; padding: .8rem 2rem;
             background: #fff; border-bottom: 1px solid #e2e8f0; flex-wrap: wrap; }}
.filters label {{ font-weight: 600; font-size: .85rem; color: #475569; }}
.filters input, .filters select {{
    border: 1px solid #cbd5e1; border-radius: 6px; padding: .4rem .7rem;
    font-size: .85rem; outline: none; }}
.filters input {{ min-width: 220px; }}
.filters input:focus {{ border-color: #2563eb; }}

/* ── Table wrapper ── */
.wrap  {{ overflow-x: auto; padding: 0 2rem 2rem; }}
table  {{ width: 100%; border-collapse: collapse; font-size: .84rem;
           background: #fff; border-radius: 10px; overflow: hidden;
           box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
thead  {{ background: #1e3a5f; color: #fff; }}
th, td {{ padding: .55rem .8rem; text-align: left; border-bottom: 1px solid #e2e8f0; }}
th     {{ font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }}

/* ── Section header rows ── */
tr.sh td {{ background: #f1f5f9; font-size: .8rem; color: #475569;
             border-top: 2px solid #cbd5e1; padding: .5rem .8rem; }}
.ss    {{ float: right; color: #94a3b8; font-weight: normal; }}

/* ── Status badge ── */
.badge {{ font-size: .78rem; font-weight: 700; white-space: nowrap; }}
.lv    {{ font-size: .7rem; background: #e2e8f0; border-radius: 4px;
           padding: 1px 5px; font-weight: 600; color: #475569; }}

/* ── Subscription / resource column ── */
.sub-col  {{ min-width: 180px; max-width: 240px; vertical-align: top; }}
.sub-name {{ font-size: .78rem; color: #374151; font-weight: 600;
              padding: 1px 0; margin-bottom: 2px; }}
.res-name {{ font-size: .76rem; color: #6b7280; margin-top: 3px; }}
.res-name code {{ background: rgba(0,0,0,.06); padding: 1px 4px; border-radius: 3px; }}

/* ── Remediation hint ── */
.fix {{ margin-top: .4rem; font-size: .78rem; color: #64748b; font-style: italic; }}

/* ── Scope info table ── */
.scope-info {{ margin-top: 1rem; }}
.scope-info table {{ border-collapse: collapse; font-size: .82rem; background: rgba(255,255,255,.12);
    border-radius: 6px; overflow: hidden; }}
.scope-info th {{ color: rgba(255,255,255,.7); font-weight: 600; padding: .25rem .8rem;
    text-align: right; white-space: nowrap; border-right: 1px solid rgba(255,255,255,.2); }}
.scope-info td {{ color: #fff; padding: .25rem .8rem; }}

/* ── Footer ── */
footer {{ text-align: center; padding: 1.5rem; color: #94a3b8; font-size: .8rem; }}

/* ── Print stylesheet ── */
@media print {{
    .filters {{ display: none; }}
    header {{ background: #1e3a5f !important; -webkit-print-color-adjust: exact; }}
    body {{ background: white; }}
    .cards .card {{ box-shadow: none; border: 1px solid #e2e8f0; }}
    table {{ box-shadow: none; }}
    tr {{ page-break-inside: avoid; }}
}}
</style>
</head>
<body>
<header>
  <h1>🔒 CIS Azure Audit Report — {ts}</h1>
  <p>Audit Tool v{VERSION} &nbsp;·&nbsp; Generated: {ts}</p>
  {scope_block}
</header>
<div class="cards">
  <div class="card c-sc">
    <div class="n">{score}%</div>
    <div class="l">Compliance Score</div>
  </div>
  <div class="card c-pa"><div class="n">{counts[PASS]}</div><div class="l">✅ Passed</div></div>
  <div class="card c-fa"><div class="n">{counts[FAIL]}</div><div class="l">❌ Failed</div></div>
  <div class="card c-er"><div class="n">{counts[ERROR]}</div><div class="l">⚠️ Errors</div></div>
  <div class="card c-in"><div class="n">{counts[INFO]}</div><div class="l">ℹ️ Info/N/A</div></div>
  <div class="card c-ma"><div class="n">{counts[MANUAL]}</div><div class="l">📋 Manual</div></div>
</div>
<canvas id="pie" width="160" height="160" style="margin:1rem auto; display:block;"></canvas>
<div class="filters">
  <label>Filter:</label>
  <input id="s" placeholder="Search control ID or title...">
  <select id="st">
    <option value="">All statuses</option>
    <option>PASS</option><option>FAIL</option><option>ERROR</option>
    <option>INFO</option><option>MANUAL</option>
  </select>
  <select id="lv">
    <option value="">All levels</option>
    <option value="L1">Level 1</option><option value="L2">Level 2</option>
  </select>
  <button id="btn-json">Export JSON</button>
  <button id="btn-csv">Export CSV</button>
</div>
<div class="wrap"><table>
<thead><tr>
  <th>Control</th><th>Level</th><th>Title</th><th>Subscription / Resource</th><th>Status</th><th>Details</th>
</tr></thead>
<tbody id="tb">{rows}</tbody>
</table></div>
<footer>
  CIS Microsoft Azure Foundations Benchmark v{BENCHMARK_VER} (Sep 2025) &nbsp;·&nbsp;
  Tool v{VERSION} &nbsp;·&nbsp;
  Compliance score excludes INFO and MANUAL checks.
  Manual controls require separate review per the CIS PDF.
</footer>
<script>
/* ── Live filter ────────────────────────────────────────────────────────────
   Filters table rows in real-time as the user types or changes dropdowns.
   Section header rows (class "sh") are hidden when all their data rows are
   hidden, preventing empty section headers in the filtered view.
────────────────────────────────────────────────────────────────────────── */
(function(){{
  var s  = document.getElementById('s');    // Search text input
  var st = document.getElementById('st');   // Status dropdown
  var lv = document.getElementById('lv');   // Level dropdown
  var btnJSON = document.getElementById('btn-json');
  var btnCSV  = document.getElementById('btn-csv');

  /* Counts passed from Python for chart drawing */
  var JS_COUNTS = {{PASS: {counts[PASS]}, FAIL: {counts[FAIL]}, ERROR: {counts[ERROR]}}};
  function filter(){{
    var sv  = s.value.toLowerCase();    // Search value (lowercase for case-insensitive match)
    var stv = st.value;                 // Selected status ("PASS", "FAIL", etc. or "")
    var lvv = lv.value;                 // Selected level ("L1", "L2", or "")

    /* Show/hide data rows based on all three filters */
    document.querySelectorAll('#tb tr:not(.sh)').forEach(function(r){{
      var badge = r.querySelector('.badge');  // Status badge element
      var lb    = r.querySelector('.lv');     // Level badge element

      var ok = (!sv  || r.textContent.toLowerCase().includes(sv))    // Text search
              && (!stv || (badge && badge.textContent.includes(stv))) // Status filter
              && (!lvv || (lb    && lb.textContent === lvv));         // Level filter

      r.style.display = ok ? '' : 'none';
    }});

    /* Hide section header rows when all their data rows are hidden */
    document.querySelectorAll('#tb tr.sh').forEach(function(h){{
      var sib = h.nextElementSibling;
      var vis = false;
      /* Walk siblings until the next section header (or end of tbody) */
      while (sib && !sib.classList.contains('sh')) {{
        if (sib.style.display !== 'none') vis = true;
        sib = sib.nextElementSibling;
      }}
      h.style.display = vis ? '' : 'none';
    }});
  }}

  /* Attach event listeners to all three filter controls */
  s.addEventListener('input', filter);
  st.addEventListener('change', filter);
  lv.addEventListener('change', filter);

  /* Export button handlers */
  btnJSON.addEventListener('click', exportJSON);
  btnCSV.addEventListener('click', exportCSV);

  /* draw the compliance pie chart once the DOM is ready */
  drawPie();

  /* Helper functions for export and chart */
  function download(filename, text) {{
    var a = document.createElement('a');
    a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(text);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }}

  function exportJSON() {{
    var rows = document.querySelectorAll('#tb tr:not(.sh)');
    var arr = [];
    rows.forEach(function(r) {{
      if (r.style.display === 'none') return;
      arr.push({{
        control: r.cells[0].textContent.trim(),
        level: r.cells[1].textContent.trim(),
        title: r.cells[2].textContent.trim(),
        subscription: r.cells[3].textContent.trim(),
        status: r.cells[4].textContent.trim(),
        details: r.cells[5].textContent.trim()
      }});
    }});
    download('audit.json', JSON.stringify(arr, null, 2));
  }}

  function exportCSV() {{
    var rows = document.querySelectorAll('#tb tr:not(.sh)');
    var lines = ['Control,Level,Title,Subscription/Resource,Status,Details'];
    rows.forEach(function(r) {{
      if (r.style.display === 'none') return;
      var vals = [];
      for (var i = 0; i < 6; i++) {{
        var txt = r.cells[i].innerText.replace(/"/g, '""');
        vals.push('"' + txt + '"');
      }}
      lines.push(vals.join(','));
    }});
    download('audit.csv', lines.join('\n'));
  }}

  function drawPie() {{
    var canvas = document.getElementById('pie');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var data = JS_COUNTS;
    var total = data.PASS + data.FAIL + data.ERROR;
    if (total === 0) return;
    var start = 0;
    var colors = {{PASS: '#16a34a', FAIL: '#dc2626', ERROR: '#ea580c'}};
    Object.keys(data).forEach(function(k) {{
      var slice = (data[k] / total) * 2 * Math.PI;
      ctx.fillStyle = colors[k];
      ctx.beginPath();
      ctx.moveTo(80, 80);
      ctx.arc(80, 80, 60, start, start + slice);
      ctx.closePath();
      ctx.fill();
      start += slice;
    }});
  }}
}})();
</script>
</body>
</html>"""

    with open(output, "w", encoding="utf-8") as fh:
        fh.write(page)
    LOGGER.info("\n✅ Report saved: %s", Path(output).resolve())


def preflight_permissions(subs_list: list[dict[str, Any]]) -> None:
    """Ensure the current user has required roles on the given subscriptions.

    If any subscription is missing Reader or a security-related role,
    the function prints a descriptive message and exits with ``sys.exit(1)``.
    On success it prints a confirmation line.
    """
    user = get_signed_in_user_id()
    if not user:
        LOGGER.error("❌ Unable to determine signed-in user identifier (AD object ID or UPN).")
        LOGGER.error("   Make sure you're logged in (`az login`) and the CLI has permission")
        LOGGER.error("   to read your profile.  Interactive login often fixes this.")
        sys.exit(1)
    # every subscription must have at least Reader plus some kind of
    # "security" role; customers may hold Security Reader, Security Admin,
    # or another security-focused built-in/custom role.
    problems = []
    for s in subs_list:
        rc, roles = list_role_names_for_user(user, s["id"])
        if rc != 0:
            problems.append(f"{s['name']} ({s['id']}): query failed ({roles})")
            continue
        have = set(roles)
        # check reader
        if "Reader" not in have:
            problems.append(f"{s['name']} ({s['id']}): missing Reader")
            continue
        # check for any security role
        if not any(r.lower().startswith("security") for r in have):
            problems.append(f"{s['name']} ({s['id']}): missing Security Reader/Admin")
    if problems:
        LOGGER.error("\n❌ Permission preflight failed:")
        for p in problems:
            LOGGER.error("  - %s", p)
        LOGGER.error("Ensure the account has the required roles and re-run.")
        sys.exit(1)
    else:
        LOGGER.info("✅ Permission preflight passed")


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════


def main() -> None:
    """
    CLI entry point. Parses arguments, validates prerequisites, runs the audit,
    prints a summary to the console, and generates the HTML report.

    Prerequisite checks performed before auditing begins:
      1. az CLI is installed and on PATH
      2. resource-graph extension is installed (auto-installs if missing)
      3. az login has been completed (account show succeeds)
    """
    parser = argparse.ArgumentParser(
        description=f"CIS Azure Foundations Benchmark v{BENCHMARK_VER} — Audit Tool v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cis_azure_audit.py
  python cis_azure_audit.py -s "Production"
  python cis_azure_audit.py -s "Dev" "Test" "Prod"
  python cis_azure_audit.py --parallel 5
  python cis_azure_audit.py --fresh
  python cis_azure_audit.py --report-only
  python cis_azure_audit.py --level 1
        """,
    )

    parser.add_argument(
        "--subscription",
        "-s",
        nargs="+",
        metavar="SUB",
        help="One or more subscription names or IDs to audit. " "Accepts multiple values: -s Sub1 Sub2 Sub3",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="cis_azure_audit_report.html",
        help="Output HTML report filename (default: cis_azure_audit_report.html)",
    )
    parser.add_argument(
        "--parallel",
        "-p",
        type=int,
        default=2,
        help="Number of concurrent subscription workers (default: 2, max recommended: 5)",
    )
    parser.add_argument(
        "--executor",
        choices=["thread", "process"],
        default="process",
        help="Worker backend for per-subscription audits (default: process)",
    )
    parser.add_argument(
        "--no-adaptive-concurrency",
        action="store_true",
        help="Disable dynamic worker tuning based on throttling retries",
    )
    parser.add_argument(
        "--level", "-l", type=int, choices=[1, 2], help="Restrict report to Level 1 or Level 2 controls only"
    )
    parser.add_argument("--fresh", action="store_true", help="Clear all existing checkpoints and start a full re-audit")
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Skip auditing — regenerate the HTML report from existing checkpoints",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the verbosity for internal logging (default: INFO)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging (DEBUG level)")
    parser.add_argument("--debug", action="store_true", help="Enable trace logging (TRACE level)")
    parser.add_argument("--log-file", help="Optional file path to write logs")
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip permission preflight checks (useful for testing or when roles are unavailable)",
    )

    args = parser.parse_args()

    setup_logging(args.log_level, verbose=args.verbose, debug=args.debug, log_file=args.log_file)

    # Start timer for elapsed time display in final summary
    start_time = datetime.datetime.now(datetime.timezone.utc)

    LOGGER.info("\n🔒 CIS Azure Foundations Benchmark v%s — Audit Tool v%s\n", BENCHMARK_VER, VERSION)

    # ── Prerequisite: az CLI available ────────────────────────────────────────
    rc, ver = az(["version"])
    if rc != 0:
        LOGGER.error("❌ Azure CLI not found.\n   Install: https://aka.ms/install-azure-cli")
        sys.exit(1)
    LOGGER.info("✅ Azure CLI v%s", ver.get("azure-cli", "?") if isinstance(ver, dict) else "?")

    # ── Prerequisite: resource-graph extension ────────────────────────────────
    # Required for 'az graph query' commands used in prefetch().
    # Automatically installs if missing to reduce setup friction.
    rc, exts = az(["extension", "list", "--query", "[?name=='resource-graph'].name"])
    if not exts:
        LOGGER.info("📦 Installing resource-graph extension...")
        rc2, out = az(["extension", "add", "--name", "resource-graph"])
        if rc2 != 0:
            LOGGER.error("❌ Install failed: %s\n   Run manually: az extension add --name resource-graph", out)
            sys.exit(1)
        LOGGER.info("✅ resource-graph extension installed")
    else:
        LOGGER.info("✅ resource-graph extension ready")

    # ── Prerequisite: authenticated session ───────────────────────────────────
    rc, acc = az(["account", "show", "--query", "{user:user.name, tenant:tenantId}"])
    if rc != 0:
        LOGGER.error("❌ Not logged in.\n   Run: az login")
        sys.exit(1)
    LOGGER.info("✅ Authenticated as: %s  |  Tenant: %s", acc.get("user"), acc.get("tenant"))

    # ── Resolve subscriptions ─────────────────────────────────────────────────
    subs = get_subscriptions(args.subscription)
    LOGGER.info("\n📋 Subscriptions (%d):", len(subs))
    for s in subs:
        LOGGER.info("   • %s  (%s)", s["name"], s["id"])

    if not args.skip_preflight and not os.environ.get("SKIP_PREFLIGHT"):
        LOGGER.info("\n🔐 Checking permissions...")
        preflight = check_user_permissions([s["id"] for s in subs])
        if preflight.get("user_id"):
            LOGGER.info("   User: %s", preflight["user_id"])
            roles = preflight.get("roles", [])
            role_sub_count = preflight.get("role_sub_count", {})
            total_subs = preflight.get("total_subs", len(subs))
            if roles:
                for role in roles[:5]:  # Show first 5 roles
                    count = role_sub_count.get(role, total_subs)
                    sub_label = f"({count}/{total_subs} subs)" if total_subs > 1 else ""
                    suffix = f"  {sub_label}" if sub_label else ""
                    LOGGER.info("   Role: %s%s", role, suffix)
                if len(roles) > 5:
                    LOGGER.info("   ... and %d more roles", len(roles) - 5)
        for warning in preflight.get("warnings", []):
            LOGGER.warning("   ⚠️  %s", warning)
        if preflight.get("warnings"):
            LOGGER.warning(
                "   💡 Preflight could not fully verify permissions. "
                "The audit will continue, but some checks may show as ERROR if permissions are missing."
            )
        else:
            LOGGER.info("   ✅ Preflight completed successfully.")

    # ── Audit or report-only ──────────────────────────────────────────────────
    if args.report_only:
        # Load checkpoints and build report without running any new checks
        LOGGER.info("\n📊 Report-only mode...")
        checkpoints = load_checkpoints()
        all_results = []
        for sub in subs:
            if sub["id"] in checkpoints:
                all_results.extend(results_from_checkpoint(checkpoints[sub["id"]]))
                LOGGER.info("   ✅ Loaded: %s", sub["name"])
            else:
                LOGGER.warning("   ⚠️  No checkpoint found: %s", sub["name"])
    else:
        # Clear checkpoints if --fresh was requested
        if args.fresh and CHECKPOINT_DIR.exists():
            shutil.rmtree(CHECKPOINT_DIR)
            LOGGER.info("\n🗑️  Cleared checkpoints.")
        all_results = run_audit(
            subs,
            parallel=args.parallel,
            resume=not args.fresh,
            executor_mode=args.executor,
            adaptive_concurrency=not args.no_adaptive_concurrency,
        )

    # ── Level filter ──────────────────────────────────────────────────────────
    # Applied after audit so checkpoints always store all levels
    if args.level:
        all_results = [r for r in all_results if r.level == args.level]

    # ── Final summary ─────────────────────────────────────────────────────────
    counts = {s: sum(1 for r in all_results if r.status == s) for s in [PASS, FAIL, ERROR, INFO, MANUAL]}
    total = len(all_results)
    score = round(counts[PASS] / max(total - counts[INFO] - counts[MANUAL], 1) * 100, 1)

    # Calculate elapsed time
    elapsed = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()
    mins, secs = divmod(int(elapsed), 60)
    elapsed_str = f"{mins}m {secs}s" if mins else f"{secs}s"

    LOGGER.info("\n%s", "━" * 60)
    LOGGER.info("  COMPLETE — %d checks  |  %d subscription(s)  |  ⏱ %s", total, len(subs), elapsed_str)
    LOGGER.info("  Compliance Score : %s%%  (excludes INFO/MANUAL)", score)
    LOGGER.info(
        "  ✅ PASS %4d  ❌ FAIL %4d  ⚠️ ERROR %4d  ℹ️ INFO %4d  📋 MANUAL %4d",
        counts[PASS],
        counts[FAIL],
        counts[ERROR],
        counts[INFO],
        counts[MANUAL],
    )
    LOGGER.info("%s", "━" * 60)
    LOGGER.info("  Checkpoints: %s/", CHECKPOINT_DIR)

    # ── Generate HTML report ──────────────────────────────────────────────────
    scope_info = {
        "tenant": acc.get("tenant", ""),
        "user": acc.get("user", ""),
        "scope_label": (
            "All subscriptions (tenant-wide)"
            if args.subscription is None
            else f"Selected: {', '.join(args.subscription)}"
        ),
        "subscriptions": [s["name"] for s in subs],
        "level_filter": args.level,
    }
    generate_html(all_results, args.output, scope_info)


if __name__ == "__main__":
    main()
