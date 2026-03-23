"""
checks_s7.py — CIS Azure Benchmark Section 7 checks.

SECTION 7 — NETWORKING SERVICES
"""

from __future__ import annotations

from typing import Any

from cis.config import PASS, FAIL, TIMEOUTS, INTERNET_SRCS, EXEMPT_SUBNETS
from cis.models import R
from cis.helpers import nsg_bad_rules
from cis.check_helpers import _err, _idx, _info


from azure.helpers import az


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

    If no flow logs are found, returns FAIL with a message stating that flow
    logging has not been enabled — absence of flow logs is non-compliant.
    """
    rc, watchers = az(["network", "watcher", "list"], sid, timeout=TIMEOUTS["default"])
    if rc != 0:
        return [
            _err("7.5", "NSG flow log retention > 90 days", 2, "7 - Networking Services", str(watchers), sid, sname)
        ]

    results = []
    for watcher in watchers or []:
        # Flow logs are listed per Network Watcher, scoped by location only
        rc2, flows = az(
            ["network", "watcher", "flow-log", "list", "--location", watcher.get("location", "")],
            sid,
            timeout=TIMEOUTS["default"],
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
            R(
                "7.5",
                "NSG flow log retention > 90 days",
                2,
                "7 - Networking Services",
                FAIL,
                "No NSG flow logs configured — flow logging has not been enabled for any NSG in this subscription."
                " See also CIS 6.1.1.5 (NSG flow logs to Log Analytics).",
                "Network Watcher > Flow logs > Create a flow log for each NSG with retention >= 90 days"
                " and Traffic Analytics enabled (CIS 6.1.1.5).",
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
    # Filter pseudo-locations (global, europe, etc.) that are not real Azure
    # regions where Network Watcher can be deployed.
    _PSEUDO = frozenset({
        "global", "europe", "asia", "northamerica", "southamerica",
        "australia", "us", "uk", "france", "germany", "japan", "korea",
        "norway", "southafrica", "switzerland", "uae", "brazil", "india",
        "canada", "china",
    })
    used_locs = {r.get("location", "").lower() for r in locations} - _PSEUDO

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
    rc, watchers = az(["network", "watcher", "list"], sid, timeout=TIMEOUTS["default"])
    if rc != 0:
        return [
            _err("7.8", "VNet flow log retention > 90 days", 2, "7 - Networking Services", str(watchers), sid, sname)
        ]

    results = []
    for watcher in watchers or []:
        rc2, flows = az(
            ["network", "watcher", "flow-log", "list", "--location", watcher.get("location", "")],
            sid,
            timeout=TIMEOUTS["default"],
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
            R(
                "7.8",
                "VNet flow log retention > 90 days",
                2,
                "7 - Networking Services",
                FAIL,
                "No VNet flow logs configured — flow logging has not been enabled for any VNet in this subscription."
                " See also CIS 6.1.1.7 (VNet flow logs to Log Analytics).",
                "Network Watcher > Flow logs > Create a flow log for each VNet with retention >= 90 days"
                " and Traffic Analytics enabled (CIS 6.1.1.7).",
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
            PASS if gw.get("wafEnabled") or gw.get("wafPolicyId") else FAIL,
            f"Gateway '{gw.get('name')}': WAF enabled = {gw.get('wafEnabled')}, "
            f"mode = {gw.get('wafMode', 'N/A')}"
            + (f", wafPolicy = {gw.get('wafPolicyId')}" if gw.get("wafPolicyId") else ""),
            "Application Gateway > Web application firewall > Enable WAF"
            if not (gw.get("wafEnabled") or gw.get("wafPolicyId"))
            else "",
            sid,
            sname,
            gw.get("name", "") if not (gw.get("wafEnabled") or gw.get("wafPolicyId")) else "",
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

    # Lowercase set for O(1) exempt check (platform-managed subnets, no NSG allowed)
    SKIP = EXEMPT_SUBNETS

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
            "7 - Networking Services",
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
