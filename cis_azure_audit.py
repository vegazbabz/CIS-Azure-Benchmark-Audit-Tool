#!/usr/bin/env python3
"""
CIS Microsoft Azure Foundations Benchmark v5.0.0 — Audit Tool v1.1.3
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
ProcessPoolExecutor. The default is thread mode with 3 workers.
You can override both values via CLI.
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
import sys  # sys.exit(), sys.platform (Windows vs Unix az path)
import argparse  # CLI argument parsing
import datetime  # Timestamps in checkpoints and reports
import logging  # setLevel override for --quiet
import os  # operating system interfaces (environment variables)
import threading  # Lock for thread-safe console output in parallel runs
import shutil  # shutil.rmtree() used by --fresh to clear checkpoints
from pathlib import Path  # --output-dir path manipulation
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed  # Parallel workers

# Configuration constants (version, timeouts, status codes, role GUIDs, etc.)
import cis.config as _cfg
from cis.config import (
    VERSION,
    BENCHMARK_VER,
    DEFAULT_PARALLEL,
    DEFAULT_EXECUTOR,
    PASS,
    FAIL,
    ERROR,
    INFO,
    MANUAL,
    SUPPRESSED,
    TRACE_LEVEL,
    LOGGER,
    CONTROL_CATALOG,
    load_config_file,
)

# Audit result data model
from cis.models import R

# Pure helpers: console UI, logging setup
from cis.helpers import (
    console_finish,
    console_init,
    console_update,
    setup_logging,
)
from cis.result_utils import compliance_score, count_statuses, dedup_results
from cis.tenant_checks import run_tenant_checks

# Checkpoint save/load
from cis.checkpoint import (
    load_checkpoints,
    load_tenant_checkpoint,
    results_from_checkpoint,
    save_checkpoint,
    save_tenant_checkpoint,
)

# HTML report generation
from cis.report import generate_html

# Finding suppression (accepted risks)
from cis.suppressions import apply_suppressions, list_suppressions, load_suppressions

# Run history for compliance trend tracking
from cis.history import append_history, history_path_for, load_history

# Check helpers and modular check functions
from checks.s2 import check_2_1_1, check_2_1_2, check_2_1_7, check_2_1_8, check_2_1_9, check_2_1_10, check_2_1_11
from checks.s5 import check_5_3_3, check_5_23, check_5_27
from checks.s6 import (
    check_6_1_1_1,
    check_6_1_1_2,
    check_6_1_1_3,
    check_6_1_1_4,
    check_6_1_1_5,
    check_6_1_1_6,
    check_6_1_2_alerts,
    check_6_1_3_1,
    check_6_1_4,
    check_6_1_5,
    check_6_2,
)
from checks.s7 import (
    check_7_1,
    check_7_2,
    check_7_3,
    check_7_4,
    check_7_5,
    check_7_6,
    check_7_7,
    check_7_8,
    check_7_9,
    check_7_10,
    check_7_11,
    check_7_12,
    check_7_13,
    check_7_14,
    check_7_15,
    check_7_16,
)
from checks.s8 import (
    check_8_1_defender,
    check_8_1_3_3,
    check_8_1_10,
    check_8_1_12_to_15,
    check_8_3_keyvaults,
    check_8_3_10,
    check_8_4_1,
    check_8_5,
)
from checks.s9 import check_9_storage

# Azure CLI helpers delegated to azure_helpers.py
from azure.helpers import (
    az,
    get_and_reset_rate_limit_retry_count,
    graph_query,
    get_signed_in_user_id,
    list_role_names_for_user,
    check_user_permissions,
    kill_running_procs,
)

# Optional rich progress bar + coloured console (used if installed). Falls back to builtin UI
try:
    from rich.console import Console as _RichConsole
    from rich.progress import (
        Progress,
        SpinnerColumn,
        BarColumn,
        TextColumn,
        TimeElapsedColumn,
        MofNCompleteColumn,
    )

    HAS_RICH = True
    _rcon: Any = _RichConsole(highlight=False)
except Exception:
    HAS_RICH = False
    _rcon = None


def _dedup_results(results: list[R]) -> list[R]:
    """Compatibility wrapper for callers that import the old private helper."""
    return dedup_results(results)


def _print_control_catalog(level_filter: int | None = None) -> None:
    """Print a formatted table of all CIS controls the tool audits, then exit."""
    rows = CONTROL_CATALOG
    if level_filter:
        rows = tuple(r for r in rows if r[1] == level_filter)

    print(f"CIS Azure Foundations Benchmark v{BENCHMARK_VER} — Audit Tool v{VERSION}")
    print(f"{len(rows)} controls" + (f" (Level {level_filter} only)" if level_filter else ""))
    print()

    # Column widths
    w_id, w_lv, w_title = 10, 4, 62
    hdr = f"{'Control':<{w_id}} {'Lv':<{w_lv}} {'Title':<{w_title}} {'Audit Method'}"
    print(hdr)
    print("─" * len(hdr))

    prev_section = ""
    for cid, lv, section, title, method in rows:
        if section != prev_section:
            print(f"\n── {section} {'─' * max(1, len(hdr) - len(section) - 4)}")
            prev_section = section
        print(f"{cid:<{w_id}} L{lv:<{w_lv - 1}} {title:<{w_title}} {method}")

    print()


def _print_summary(counts: dict[str, int], total: int, n_subs: int, elapsed_str: str, score: float) -> None:
    """Print the final audit summary box.

    Uses Rich markup for coloured output when Rich is installed; falls back to
    plain LOGGER.info so the output is always human-readable regardless of
    whether the optional dependency is present.

    Colour scheme:
      PASS  → green        FAIL → bold red
      ERROR → yellow       score → green ≥ 80 %, yellow ≥ 50 %, red < 50 %
    """
    assessed = counts[PASS] + counts[FAIL] + counts[ERROR]
    sep = "━" * 60
    if HAS_RICH and _rcon is not None:
        score_color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")
        _rcon.print(f"\n{sep}")
        _rcon.print(f"  COMPLETE — {total} checks  |  {n_subs} subscription(s)  |  ⏱ {elapsed_str}")
        _rcon.print(
            f"  Compliance Score : [{score_color}]{score}%[/{score_color}]"
            f"  ({counts[PASS]} of {assessed} assessed controls, excludes INFO/MANUAL/SUPPRESSED)"
        )
        _rcon.print(f"  ✅ [green]PASS         {counts[PASS]:4d}[/green]")
        _rcon.print(f"  ❌ [bold red]FAIL         {counts[FAIL]:4d}[/bold red]")
        _rcon.print(f"  ⚠️  [yellow]ERROR        {counts[ERROR]:4d}[/yellow]")
        _rcon.print(f"  ℹ️  INFO         {counts[INFO]:4d}")
        _rcon.print(f"  📋 MANUAL       {counts[MANUAL]:4d}")
        _rcon.print(f"  🔇 SUPPRESSED   {counts[SUPPRESSED]:4d}")
        _rcon.print(sep)
    else:
        LOGGER.info("\n%s", sep)
        LOGGER.info("  COMPLETE — %d checks  |  %d subscription(s)  |  ⏱ %s", total, n_subs, elapsed_str)
        LOGGER.info(
            "  Compliance Score : %s%%  (%d of %d assessed controls, excludes INFO/MANUAL/SUPPRESSED)",
            score,
            counts[PASS],
            assessed,
        )
        LOGGER.info("  ✅ PASS         %4d", counts[PASS])
        LOGGER.info("  ❌ FAIL         %4d", counts[FAIL])
        LOGGER.info("  ⚠️  ERROR        %4d", counts[ERROR])
        LOGGER.info("  ℹ️  INFO         %4d", counts[INFO])
        LOGGER.info("  📋 MANUAL       %4d", counts[MANUAL])
        LOGGER.info("  🔇 SUPPRESSED   %4d", counts[SUPPRESSED])
        LOGGER.info("%s", sep)


# Section number → display label used in console progress output.
_SECTION_LABELS: dict[str, str] = {
    "2": "Databricks",
    "3": "Compute",
    "5": "Identity",
    "6": "Monitoring",
    "7": "Networking",
    "8": "Security",
    "9": "Storage",
}

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
        | project id, name, resourceGroup, subscriptionId, sku
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
            principalType = tostring(properties.principalType),
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
            privateEps   = array_length(properties.privateEndpointConnections),
            encryptionKeySource = tostring(properties.encryption.entities.managedDisk.keySource)
    """,
    # ── App Services ──────────────────────────────────────────────────────────
    # Only id, name, resourceGroup, subscriptionId are needed — diagnostic
    # settings cannot be queried via Resource Graph and require per-app az calls.
    "app_services": """
        resources | where type =~ 'microsoft.web/sites'
        | project id, name, resourceGroup, subscriptionId, kind
    """,
    # ── WAF policies ──────────────────────────────────────────────────────────
    # Standalone WAF policy resources (used by check_7_15 for bot protection).
    # This is distinct from WAF embedded in Application Gateways (app_gateways query).
    "waf_policies": """
        resources | where type =~ 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies'
        | project id, name, subscriptionId,
            managedRuleSets    = properties.managedRules.managedRuleSets,
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

    LOGGER.info("Prefetch complete. %d resource type(s) cached.\n", len(indexed))
    return indexed


# ══════════════════════════════════════════════════════════════════════════════
# CHECKPOINT SYSTEM
# ══════════════════════════════════════════════════════════════════════════════


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
        ("2.1.1", lambda: check_2_1_1(sid, sname, td)),
        ("2.1.2", lambda: check_2_1_2(sid, sname, td)),
        ("2.1.7", lambda: check_2_1_7(sid, sname, td)),
        ("2.1.8", lambda: check_2_1_8(sid, sname, td)),
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
        ("6.1.1.3", lambda: [check_6_1_1_3(sid, sname)]),
        ("6.1.1.4", lambda: check_6_1_1_4(sid, sname, td)),
        ("6.1.1.5", lambda: [check_6_1_1_5(sid, sname)]),
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
        ("6.1.4", lambda: [check_6_1_4(sid, sname)]),
        ("6.1.5", lambda: [check_6_1_5(sid, sname)]),
        ("6.2", lambda: [check_6_2(sid, sname)]),
        # ── Section 7 — Networking ─────────────────────────────────────────
        ("7.1", lambda: check_7_1(sid, sname, td)),
        ("7.2", lambda: check_7_2(sid, sname, td)),
        ("7.3", lambda: check_7_3(sid, sname, td)),
        ("7.4", lambda: check_7_4(sid, sname, td)),
        ("7.5", lambda: check_7_5(sid, sname)),
        ("7.6", lambda: check_7_6(sid, sname, td)),
        ("7.7", lambda: [check_7_7(sid, sname)]),
        ("7.8", lambda: check_7_8(sid, sname)),
        ("7.9", lambda: check_7_9(sid, sname)),
        ("7.10", lambda: check_7_10(sid, sname, td)),
        ("7.11", lambda: check_7_11(sid, sname, td)),
        ("7.12", lambda: check_7_12(sid, sname, td)),
        ("7.13", lambda: check_7_13(sid, sname, td)),
        ("7.14", lambda: check_7_14(sid, sname, td)),
        ("7.15", lambda: check_7_15(sid, sname, td)),
        ("7.16", lambda: [check_7_16(sid, sname)]),
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
        ("8.3.10", lambda: [check_8_3_10(sid, sname)]),
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
        ("9.2.4", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.2.4")),
        ("9.2.5", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.2.5")),
        ("9.2.6", lambda: _from_batch("9", lambda: check_9_storage(sid, sname, td), "9.2.6")),
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

    _cur_sec = ""
    for ctrl_id, fn in checks:
        new_sec = ctrl_id.split(".")[0]
        if new_sec != _cur_sec:
            _cur_sec = new_sec
            LOGGER.debug("    [%s] %s...", sname[:24], _SECTION_LABELS.get(new_sec, f"Section {new_sec}"))
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
    parallel: int = DEFAULT_PARALLEL,
    resume: bool = True,
    executor_mode: str = DEFAULT_EXECUTOR,
    adaptive_concurrency: bool = True,
    quiet: bool = False,
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
    parallel             : Max concurrent workers requested (default 3)
    resume               : If True, skip subscriptions with existing checkpoints
    executor_mode        : "thread" (default) or "process"
    adaptive_concurrency : If True, reduce/increase workers based on throttling

    Returns
    ───────
    Flat list of all R instances across all subscriptions + tenant checks.
    """
    checkpoints = load_checkpoints() if resume else {}
    if checkpoints:
        LOGGER.info(
            "\n💾 %d subscription(s) were already audited in a previous run — loading saved results.", len(checkpoints)
        )

    # Split subscriptions into already-done (skip) and still-todo (audit)
    done = [s for s in subs if s["id"] in checkpoints]
    todo = [s for s in subs if s["id"] not in checkpoints]

    if done:
        LOGGER.info("⏭️  Skipping (already audited): %s", ", ".join(s["name"] for s in done))

    # Seed the results with data from completed checkpoints
    all_results = []
    for sub in done:
        all_results.extend(results_from_checkpoint(checkpoints[sub["id"]]))

    if not todo:
        LOGGER.info(
            "✅ All subscriptions were already audited — nothing new to scan. Use --fresh to re-audit from scratch."
        )
        tenant_ckpt = load_tenant_checkpoint()
        if tenant_ckpt is not None:
            LOGGER.info("   💾 Loaded tenant checks from checkpoint (%d results).", len(tenant_ckpt))
            all_results.extend(tenant_ckpt)
        else:
            LOGGER.info("   🔍 No tenant checkpoint found — re-running tenant checks (requires az login)...")
            all_results.extend(run_tenant_checks())
        return all_results

    requested_parallel = max(1, parallel)
    if requested_parallel != parallel:
        LOGGER.warning("⚠️  --parallel must be >= 1; using %d", requested_parallel)
    if requested_parallel > 5:
        LOGGER.warning(
            "⚠️  --parallel=%d is high and may trigger Azure API rate limits (HTTP 429). "
            "Monitor for 429 errors; adaptive mode will reduce workers if throttling is detected.",
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

    # ── Resource Graph prefetch ───────────────────────────────────────────────
    # Fetch all Resource Graph data ONCE before the parallel loop.
    # The results are shared read-only across all workers (no locking needed
    # because the dict is only written during prefetch, never during audit_subscription).
    td = prefetch([s["id"] for s in todo])

    # ── Tenant-level identity checks ─────────────────────────────────────────
    # These checks target the Entra ID tenant, not any individual subscription.
    # Run them ONCE here rather than inside the per-subscription loop to avoid
    # duplicate results when auditing multiple subscriptions.
    tenant_ckpt = load_tenant_checkpoint() if resume else None
    if tenant_ckpt is not None:
        LOGGER.info("\n  💾 Loaded tenant checks from checkpoint (%d results).", len(tenant_ckpt))
        tenant_results = tenant_ckpt
    else:
        LOGGER.info("\n  [Tenant] Running tenant-level identity checks...")
        tenant_results = run_tenant_checks()

        try:
            save_tenant_checkpoint(tenant_results)
        except Exception as _ckpt_err:
            LOGGER.warning("⚠️  Could not save tenant checkpoint (audit will continue): %s", _ckpt_err)

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
            BarColumn(complete_style="green", finished_style="bright_green"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=True,
            console=_rcon,
        )
        progress.start()
        task_id: Any = progress.add_task("Preparing...", total=len(todo))
    else:
        progress = None
        task_id = 0
        if not quiet:
            console_init(len(todo))

    # ── Thread-safe subscription counter ─────────────────────────────────────
    # _started tracks how many subscriptions have begun processing.
    # Initialised to len(done) so the counter continues from the checkpoint count.
    # Example: 3 of 12 subscriptions were checkpointed → first new sub shows [4/12].
    _total = len(subs)  # Total including already-checkpointed
    _done_n = len(done)  # Already completed from checkpoints
    _counter = threading.Lock()
    _started: int = _done_n  # Incremented under _counter before each submission

    completed_in_todo = 0
    stable_batches = 0
    remaining = list(todo)

    # ── Parallel execution (batch-based for adaptive concurrency) ───────────
    _active_names: set[str] = set()  # subscriptions currently in-flight

    def _progress_desc() -> str:
        """Build a progress bar description from the currently-running subscriptions."""
        if not _active_names:
            return "…"
        names = sorted(_active_names)
        if len(names) == 1:
            return names[0]
        if len(names) <= 3:
            return ", ".join(names)
        return f"{names[0]} +{len(names) - 1} more"

    # Reset here so that throttles from tenant checks and prefetch don't
    # bleed into the first batch's adaptive-concurrency decision.
    _ = get_and_reset_rate_limit_retry_count()
    try:
        while remaining:
            batch = remaining[:current_parallel]
            remaining = remaining[current_parallel:]

            executor_cls: Any = ProcessPoolExecutor if mode == "process" else ThreadPoolExecutor
            # Use manual pool management instead of a context manager so that a
            # KeyboardInterrupt can call shutdown(wait=False) rather than blocking
            # indefinitely on shutdown(wait=True) waiting for in-flight az calls.
            pool = executor_cls(max_workers=current_parallel)
            try:
                futures: dict[Any, tuple[dict[str, Any], int]] = {}
                for sub in batch:
                    with _counter:
                        _started += 1
                        n = _started

                    if progress is not None:
                        _active_names.add(sub.get("name", ""))
                        progress.update(task_id, description=_progress_desc())
                    else:
                        if not quiet:
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

                    completed_in_todo += 1
                    LOGGER.debug("  ✅ [%d/%d] Completed: %s", completed_in_todo, _total, sub["name"])
                    if progress is not None:
                        _active_names.discard(sub.get("name", ""))
                        progress.update(task_id, completed=completed_in_todo, description=_progress_desc())

                pool.shutdown(wait=True)
            except KeyboardInterrupt:
                pool.shutdown(wait=False, cancel_futures=True)
                raise

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

    except KeyboardInterrupt:
        # Clean up the progress bar before printing the interrupt message.
        if progress:
            try:
                progress.stop()
            except Exception:
                pass
        elif not quiet:
            console_finish()
        raise

    # Ensure the progress UI finishes cleanly after workers complete
    if progress:
        try:
            progress.stop()
        except Exception:
            pass
    else:
        if not quiet:
            console_finish()

    # Tenant results are added ONCE after all subscription workers complete.
    # They must not be inside the parallel loop or they will be duplicated
    # once per subscription.
    all_results.extend(tenant_results)
    return _dedup_results(all_results)


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
    # Load cis_audit.toml (if present) before building argparse so that
    # DEFAULT_PARALLEL / DEFAULT_EXECUTOR reflect any user overrides.
    load_config_file()

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
        "--version",
        action="version",
        version=f"%(prog)s {_cfg.version_full()}",
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
        default=None,
        help="Output HTML report filename (default: reports/cis_azure_audit_report_<timestamp>.html)",
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Directory for the HTML report and checkpoint files (default: current working directory)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress subscription names and resource-level detail from console output",
    )
    parser.add_argument(
        "--parallel",
        "-p",
        type=int,
        default=DEFAULT_PARALLEL,
        help=f"Number of concurrent subscription workers (default: {DEFAULT_PARALLEL}, max recommended: 5)",
    )
    parser.add_argument(
        "--executor",
        choices=["thread", "process"],
        default=DEFAULT_EXECUTOR,
        help=f"Worker backend for per-subscription audits (default: {DEFAULT_EXECUTOR})",
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
    parser.add_argument(
        "--suppressions",
        metavar="FILE",
        default="suppressions.toml",
        help="Path to suppressions TOML file (default: suppressions.toml next to this script)",
    )
    parser.add_argument(
        "--list-suppressions",
        action="store_true",
        help="Print all active suppressions and exit",
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        help=(
            "Print the control catalog (ID, level, title, audit method)"
            " and exit — useful for cross-referencing against the CIS Benchmark PDF"
        ),
    )
    parser.add_argument(
        "--no-open",
        dest="open",
        action="store_false",
        default=True,
        help="Do not automatically open the HTML report in the browser when the audit is complete",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        default=False,
        help=(
            "Exit with code 2 when the audit finds any FAIL or ERROR results. "
            "Useful for CI/CD pipelines: the build fails when compliance regressions are detected. "
            "Exit code 0 means all controls passed; exit code 1 means a tool/setup error; "
            "exit code 2 means compliance failures were found."
        ),
    )

    args = parser.parse_args()

    if args.fresh and args.report_only:
        parser.error(
            "--fresh and --report-only are mutually exclusive: "
            "--fresh deletes checkpoints while --report-only reads them."
        )

    # Capture run timestamp early — used both for elapsed time and the default
    # report filename so the filename reflects when the audit started.
    start_time = datetime.datetime.now(datetime.timezone.utc)

    # ── Default output path: reports/<name>_<timestamp>.html ─────────────────
    if args.output is None:
        _reports_dir = Path("reports")
        _reports_dir.mkdir(exist_ok=True)
        args.output = str(_reports_dir / f"cis_azure_audit_report_{start_time.strftime('%Y-%m-%dT%H%M')}.html")

    setup_logging(
        args.log_level,
        verbose=args.verbose,
        debug=args.debug,
        log_file=args.log_file,
        rich_console=_rcon if HAS_RICH else None,
    )

    # ── --quiet: suppress INFO-level console output ───────────────────────────
    if args.quiet and not args.verbose and not args.debug:
        logging.getLogger().setLevel(logging.WARNING)

    # ── --output-dir: redirect report and checkpoints to a single directory ───
    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        new_ckpt_dir = out_dir / "cis_checkpoints"
        _cfg.CHECKPOINT_DIR = new_ckpt_dir
        if not Path(args.output).is_absolute():
            args.output = str(out_dir / args.output)

    # ── Load suppressions (applied at report time, not during audit) ──────────
    suppressions_path = Path(args.suppressions)
    suppressions = load_suppressions(suppressions_path)

    if args.list_suppressions:
        list_suppressions(suppressions, suppressions_path)
        return

    if args.preview:
        _print_control_catalog(args.level)
        return

    LOGGER.info("\n🔒 CIS Azure Foundations Benchmark v%s — Audit Tool v%s\n", BENCHMARK_VER, VERSION)

    # ── Report-only: skip all Azure calls, load checkpoints directly ──────────
    if args.report_only:
        LOGGER.info("\n📊 Report-only mode...")
        checkpoints = load_checkpoints()
        all_results = []
        for sub_id, cp in checkpoints.items():
            all_results.extend(results_from_checkpoint(cp))
            LOGGER.info("   ✅ Loaded: %s", cp.get("subscription_name", sub_id))
        # Load tenant check results from checkpoint if available.  Falls back
        # to re-running live checks (which make Graph API calls) if no checkpoint
        # exists — this happens on the first --report-only run after a fresh audit.
        tenant_ckpt = load_tenant_checkpoint()
        if tenant_ckpt is not None:
            LOGGER.info("   💾 Loaded tenant checks from checkpoint (%d results).", len(tenant_ckpt))
            all_results.extend(tenant_ckpt)
        else:
            LOGGER.info("   🔍 No tenant checkpoint found — re-running tenant checks (requires az login)...")
            all_results.extend(run_tenant_checks())
        if args.level:
            all_results = [r for r in all_results if r.level == args.level]
        all_results = _dedup_results(all_results)
        all_results = apply_suppressions(all_results, suppressions)
        counts = count_statuses(all_results)
        total = len(all_results)
        score = compliance_score(counts, total)
        elapsed = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()
        mins, secs = divmod(int(elapsed), 60)
        elapsed_str = f"{mins}m {secs}s" if mins else f"{secs}s"
        _print_summary(counts, total, len(checkpoints), elapsed_str, score)
        LOGGER.info("  Checkpoints: %s/", _cfg.CHECKPOINT_DIR)
        sub_timestamps = {cp["subscription_name"]: cp["timestamp"] for cp in checkpoints.values()}
        sub_names = [cp["subscription_name"] for cp in checkpoints.values()]
        # Build scope_info from az account show (best-effort, may fail if not logged in)
        _rc, _acc = az(["account", "show", "--query", "{user:user.name, tenant:tenantId, caller_type:user.type}"])
        scope_info = {
            "tenant": _acc.get("tenant", "") if isinstance(_acc, dict) else "",
            "user": _acc.get("user", "") if isinstance(_acc, dict) else "",
            "caller_type": _acc.get("caller_type", "") if isinstance(_acc, dict) else "",
            "scope_label": "All subscriptions (from checkpoint data)",
            "subscriptions": sub_names,
            "level_filter": args.level,
        }
        run_history = load_history(history_path_for(args.output))
        generate_html(all_results, args.output, scope_info, run_history, sub_timestamps)
        if args.open:
            _html_path = Path(args.output).resolve()
            try:
                if sys.platform == "win32":
                    os.startfile(str(_html_path))
                else:
                    import webbrowser

                    webbrowser.open(_html_path.as_uri())
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("Could not open report automatically: %s", exc)
        if args.exit_code and (counts[FAIL] + counts[ERROR]) > 0:
            sys.exit(2)
        return

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
    rc, acc = az(["account", "show", "--query", "{user:user.name, tenant:tenantId, caller_type:user.type}"])
    if rc != 0:
        LOGGER.error("❌ Not logged in.\n   Run: az login")
        sys.exit(1)
    _cfg.CALLER_TYPE = acc.get("caller_type", "user") or "user"
    LOGGER.info("✅ Authenticated as: %s (%s)", acc.get("user"), _cfg.CALLER_TYPE)
    LOGGER.info("✅ Tenant: %s", acc.get("tenant"))

    # ── Resolve subscriptions ─────────────────────────────────────────────────
    subs = get_subscriptions(args.subscription)
    LOGGER.info("\n📋 Subscriptions (%d):", len(subs))
    for s in subs:
        LOGGER.info("   • %s  (%s)", s["name"], s["id"])

    if not args.skip_preflight and not os.environ.get("SKIP_PREFLIGHT"):
        LOGGER.info("\n🔐 Checking permissions…")
        if HAS_RICH:
            _pf_prog = Progress(
                SpinnerColumn(),
                TextColumn("   querying {task.fields[n]} subscription(s)…"),
                TimeElapsedColumn(),
                transient=True,
                console=_rcon,
            )
            with _pf_prog:
                _pf_prog.add_task("", total=None, n=len(subs))
                preflight = check_user_permissions([s["id"] for s in subs])
        else:
            preflight = check_user_permissions([s["id"] for s in subs])
        if preflight.get("user_id"):
            LOGGER.info("   User: %s", acc.get("user") or preflight["user_id"])
            roles = preflight.get("roles", [])
            role_sub_count = preflight.get("role_sub_count", {})
            total_subs = preflight.get("total_subs", len(subs))
            if roles:
                for role in roles[:5]:  # Show first 5 roles
                    count = role_sub_count.get(role, total_subs)
                    sub_label = f"({count}/{total_subs} subs)" if total_subs > 1 else ""
                    suffix = f"  {sub_label}" if sub_label else ""
                    LOGGER.info("   ✅ Role: %s%s", role, suffix)
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

    # ── Full audit ────────────────────────────────────────────────────────────
    if args.fresh and _cfg.CHECKPOINT_DIR.exists():
        shutil.rmtree(_cfg.CHECKPOINT_DIR)
        LOGGER.info("\n🗑️  Cleared checkpoints.")
    all_results = run_audit(
        subs,
        parallel=args.parallel,
        resume=not args.fresh,
        executor_mode=args.executor,
        adaptive_concurrency=not args.no_adaptive_concurrency,
        quiet=args.quiet,
    )

    # ── Level filter ──────────────────────────────────────────────────────────
    # Applied after audit so checkpoints always store all levels
    if args.level:
        all_results = [r for r in all_results if r.level == args.level]

    # ── Apply suppressions (at report time — checkpoints always store raw FAIL) ─
    all_results = apply_suppressions(all_results, suppressions)

    # ── Final summary ─────────────────────────────────────────────────────────
    counts = count_statuses(all_results)
    total = len(all_results)
    score = compliance_score(counts, total)

    # Calculate elapsed time
    elapsed = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()
    mins, secs = divmod(int(elapsed), 60)
    elapsed_str = f"{mins}m {secs}s" if mins else f"{secs}s"

    _print_summary(counts, total, len(subs), elapsed_str, score)
    LOGGER.info("  Checkpoints: %s/", _cfg.CHECKPOINT_DIR)

    # ── Append to run history (full tenant scope only — skipped for --subscription filters) ──
    hist_path = history_path_for(args.output)
    if args.subscription is None:
        append_history(
            hist_path,
            {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "version": VERSION,
                "score": score,
                "pass": counts[PASS],
                "fail": counts[FAIL],
                "error": counts[ERROR],
                "info": counts[INFO],
                "manual": counts[MANUAL],
                "suppressed": counts[SUPPRESSED],
                "total": total,
                "subscriptions": [s["name"] for s in subs],
                "level_filter": args.level,
            },
        )
        run_history = load_history(hist_path)
    else:
        run_history = []

    # ── Generate HTML report ──────────────────────────────────────────────────
    scope_info = {
        "tenant": acc.get("tenant", ""),
        "user": acc.get("user", ""),
        "caller_type": _cfg.CALLER_TYPE,
        "scope_label": (
            "All subscriptions (tenant-wide)"
            if args.subscription is None
            else f"Selected: {', '.join(args.subscription)}"
        ),
        "subscriptions": [s["name"] for s in subs],
        "level_filter": args.level,
    }
    sub_timestamps = {cp["subscription_name"]: cp["timestamp"] for cp in load_checkpoints().values()}
    generate_html(all_results, args.output, scope_info, run_history, sub_timestamps)
    if args.open:
        _html_path = Path(args.output).resolve()
        try:
            if sys.platform == "win32":
                os.startfile(str(_html_path))
            else:
                import webbrowser

                webbrowser.open(_html_path.as_uri())
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Could not open report automatically: %s", exc)

    if args.exit_code and (counts[FAIL] + counts[ERROR]) > 0:
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        kill_running_procs()  # kill in-flight az subprocesses before exiting
        print(
            "\n\n⚠️  Interrupted. Re-run the same command to resume from where it stopped"
            " (or add --fresh to start over)."
        )
        sys.stdout.flush()
        os._exit(1)  # immediate hard exit — kills all worker threads without atexit
