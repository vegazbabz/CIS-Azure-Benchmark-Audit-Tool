"""
checks_s2.py — CIS Azure Benchmark Section 2 checks.

SECTION 2 — AZURE DATABRICKS
"""

from __future__ import annotations

from typing import Any

from cis.config import PASS, FAIL, INFO, TIMEOUTS
from cis.models import R
from cis.check_helpers import _err, _idx, _info
from azure.helpers import az


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
    2.1.7 — Diagnostic logging configured for Azure Databricks (Level 2)

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
                2,
                "2 - Databricks",
                "No Databricks workspaces found.",
                sid,
                sname,
            )
        ]

    results = []
    for ws in workspaces:
        wname, wid = ws.get("name", "?"), ws.get("id")
        rc, diag = az(["monitor", "diagnostic-settings", "list", "--resource", wid], sid, timeout=TIMEOUTS["default"])
        if rc != 0:
            results.append(
                _err(
                    "2.1.7",
                    "Diagnostic logging configured for Azure Databricks",
                    2,
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
                2,
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
    2.1.9 — Databricks 'No Public IP' is Enabled (Level 2)

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
                2,
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
            2,
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
    2.1.10 — Databricks 'Allow Public Network Access' is Disabled (Level 2)

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
                2,
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
            2,
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
