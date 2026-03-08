"""Unit tests for CIS Azure Benchmark check functions (Sections 2, 5, 6, 7, 8, 9)."""

from __future__ import annotations

from typing import Any

import unittest
from unittest.mock import patch

from cis.config import ERROR, FAIL, INFO, MANUAL, PASS

import checks.s2 as checks_s2
import checks.s5 as checks_s5
import checks.s6 as checks_s6
import checks.s7 as checks_s7
import checks.s8 as checks_s8
import checks.s9 as checks_s9

SID = "sub-test-1234"
SNAME = "Test Sub"


def _td(key: str, records: list) -> dict:
    """Build a minimal prefetch dict for _idx lookups."""
    return {key: {SID.lower(): records}}


# =============================================================================
# SECTION 2 — DATABRICKS
# =============================================================================


class TestCheck212(unittest.TestCase):
    """2.1.2 — NSGs configured for Databricks subnets."""

    def test_no_workspaces_returns_info(self) -> None:
        td = _td("databricks", [])
        results = checks_s2.check_2_1_2(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, INFO)
        self.assertEqual(results[0].control_id, "2.1.2")

    def test_workspace_no_custom_vnet_returns_info(self) -> None:
        # Empty vnetId means managed VNet — should return INFO (not a failure)
        td = _td("databricks", [{"name": "ws1", "vnetId": ""}])
        td["subnets"] = {SID.lower(): []}
        results = checks_s2.check_2_1_2(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, INFO)

    def test_subnet_missing_nsg_returns_fail(self) -> None:
        td = _td(
            "databricks",
            [
                {
                    "name": "ws1",
                    "vnetId": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/my-vnet",
                }
            ],
        )
        td["subnets"] = {
            SID.lower(): [
                {"vnetName": "my-vnet", "subnetName": "databricks-public", "hasNsg": False},
                {"vnetName": "my-vnet", "subnetName": "databricks-private", "hasNsg": True},
            ]
        }
        results = checks_s2.check_2_1_2(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)

    def test_all_nsgs_present_returns_pass(self) -> None:
        td = _td(
            "databricks",
            [
                {
                    "name": "ws1",
                    "vnetId": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/my-vnet",
                }
            ],
        )
        td["subnets"] = {
            SID.lower(): [
                {"vnetName": "my-vnet", "subnetName": "databricks-public", "hasNsg": True},
                {"vnetName": "my-vnet", "subnetName": "databricks-private", "hasNsg": True},
            ]
        }
        results = checks_s2.check_2_1_2(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, PASS)


class TestCheck217(unittest.TestCase):
    """2.1.7 — Diagnostic logging configured for Azure Databricks."""

    def test_no_workspaces_returns_info(self) -> None:
        td = _td("databricks", [])
        results = checks_s2.check_2_1_7(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, INFO)

    def test_az_fails_returns_error(self) -> None:
        td = _td("databricks", [{"name": "ws1", "id": "/ws/ws1"}])
        with patch("checks.s2.az", return_value=(1, "auth error")):
            results = checks_s2.check_2_1_7(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ERROR)

    def test_diag_settings_found_returns_pass(self) -> None:
        td = _td("databricks", [{"name": "ws1", "id": "/ws/ws1"}])
        with patch("checks.s2.az", return_value=(0, [{"name": "diag1"}])):
            results = checks_s2.check_2_1_7(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, PASS)

    def test_no_diag_settings_returns_fail(self) -> None:
        td = _td("databricks", [{"name": "ws1", "id": "/ws/ws1"}])
        with patch("checks.s2.az", return_value=(0, [])):
            results = checks_s2.check_2_1_7(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)


class TestCheck219(unittest.TestCase):
    """2.1.9 — Databricks 'No Public IP' is Enabled."""

    def test_no_workspaces_returns_info(self) -> None:
        td = _td("databricks", [])
        results = checks_s2.check_2_1_9(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, INFO)

    def test_no_public_ip_true_returns_pass(self) -> None:
        td = _td("databricks", [{"name": "ws1", "noPublicIp": True}])
        results = checks_s2.check_2_1_9(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, PASS)

    def test_no_public_ip_false_returns_fail(self) -> None:
        td = _td("databricks", [{"name": "ws1", "noPublicIp": False}])
        results = checks_s2.check_2_1_9(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)


class TestCheck2110(unittest.TestCase):
    """2.1.10 — Databricks 'Allow Public Network Access' is Disabled."""

    def test_no_workspaces_returns_info(self) -> None:
        td = _td("databricks", [])
        results = checks_s2.check_2_1_10(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, INFO)

    def test_public_access_disabled_returns_pass(self) -> None:
        td = _td("databricks", [{"name": "ws1", "publicAccess": "Disabled"}])
        results = checks_s2.check_2_1_10(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, PASS)

    def test_public_access_enabled_returns_fail(self) -> None:
        td = _td("databricks", [{"name": "ws1", "publicAccess": "Enabled"}])
        results = checks_s2.check_2_1_10(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)


class TestCheck2111(unittest.TestCase):
    """2.1.11 — Private endpoints configured for Azure Databricks workspaces."""

    def test_no_workspaces_returns_info(self) -> None:
        td = _td("databricks", [])
        results = checks_s2.check_2_1_11(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, INFO)

    def test_private_eps_present_returns_pass(self) -> None:
        td = _td("databricks", [{"name": "ws1", "privateEps": 2}])
        results = checks_s2.check_2_1_11(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, PASS)

    def test_no_private_eps_returns_fail(self) -> None:
        td = _td("databricks", [{"name": "ws1", "privateEps": 0}])
        results = checks_s2.check_2_1_11(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)


# =============================================================================
# SECTION 5 — IDENTITY SERVICES
# =============================================================================


class TestCheck511(unittest.TestCase):
    """5.1.1 — Security defaults enabled in Microsoft Entra ID."""

    @patch("checks.s5.az_rest")
    def test_security_defaults_enabled_returns_pass(self, mock_az_rest: Any) -> None:
        mock_az_rest.return_value = (0, {"isEnabled": True})
        result = checks_s5.check_5_1_1()
        self.assertEqual(result.control_id, "5.1.1")
        self.assertEqual(result.status, PASS)

    @patch("checks.s5.az_rest")
    def test_security_defaults_disabled_with_ca_returns_info(self, mock_az_rest: Any) -> None:
        mock_az_rest.side_effect = [
            (0, {"isEnabled": False}),
            (0, {"value": [{"id": "policy-1"}]}),
        ]
        result = checks_s5.check_5_1_1()
        self.assertEqual(result.control_id, "5.1.1")
        self.assertEqual(result.status, INFO)

    @patch("checks.s5.az_rest")
    def test_security_defaults_disabled_no_ca_returns_fail(self, mock_az_rest: Any) -> None:
        mock_az_rest.side_effect = [
            (0, {"isEnabled": False}),
            (0, {"value": []}),
        ]
        result = checks_s5.check_5_1_1()
        self.assertEqual(result.control_id, "5.1.1")
        self.assertEqual(result.status, FAIL)

    @patch("checks.s5.az_rest")
    def test_api_error_returns_error(self, mock_az_rest: Any) -> None:
        mock_az_rest.return_value = (1, "Access denied")
        result = checks_s5.check_5_1_1()
        self.assertEqual(result.control_id, "5.1.1")
        self.assertEqual(result.status, ERROR)


class TestCheck512(unittest.TestCase):
    """5.1.2 — MFA enabled for all privileged users."""

    @patch("checks.s5.az_rest_paged")
    def test_all_admins_have_mfa_returns_pass(self, mock: Any) -> None:
        mock.return_value = (0, [
            {"userPrincipalName": "a@t.com", "isMfaRegistered": True},
            {"userPrincipalName": "b@t.com", "isMfaRegistered": True},
        ])
        result = checks_s5.check_5_1_2()
        self.assertEqual(result.control_id, "5.1.2")
        self.assertEqual(result.status, PASS)

    @patch("checks.s5.az_rest_paged")
    def test_no_admin_users_returns_pass(self, mock: Any) -> None:
        mock.return_value = (0, [])
        result = checks_s5.check_5_1_2()
        self.assertEqual(result.control_id, "5.1.2")
        self.assertEqual(result.status, PASS)

    @patch("checks.s5.az_rest_paged")
    def test_admin_without_mfa_returns_fail(self, mock: Any) -> None:
        mock.return_value = (0, [
            {"userPrincipalName": "noMfa@t.com", "isMfaRegistered": False},
            {"userPrincipalName": "hasMfa@t.com", "isMfaRegistered": True},
        ])
        result = checks_s5.check_5_1_2()
        self.assertEqual(result.control_id, "5.1.2")
        self.assertEqual(result.status, FAIL)
        self.assertIn("noMfa@t.com", result.details)
        self.assertNotIn("hasMfa@t.com", result.details)

    @patch("checks.s5.az_rest_paged")
    def test_api_error_returns_error(self, mock: Any) -> None:
        mock.return_value = (1, [])
        result = checks_s5.check_5_1_2()
        self.assertEqual(result.control_id, "5.1.2")
        self.assertEqual(result.status, ERROR)

    @patch("checks.s5.az_rest_paged")
    def test_many_users_without_mfa_truncates_list(self, mock: Any) -> None:
        users = [{"userPrincipalName": f"admin{i}@t.com", "isMfaRegistered": False} for i in range(15)]
        mock.return_value = (0, users)
        result = checks_s5.check_5_1_2()
        self.assertEqual(result.status, FAIL)
        self.assertIn("15 privileged", result.details)
        self.assertIn("more", result.details)

    @patch("checks.s5.az_rest_paged")
    def test_upn_fallback_to_id_when_upn_missing(self, mock: Any) -> None:
        mock.return_value = (0, [{"id": "guid-1234", "isMfaRegistered": False}])
        result = checks_s5.check_5_1_2()
        self.assertEqual(result.status, FAIL)
        self.assertIn("guid-1234", result.details)


class TestCheck533(unittest.TestCase):
    """5.3.3 — User Access Administrator role is restricted."""

    def test_no_uaa_assignments_returns_pass(self) -> None:
        td = _td("roles", [])
        results = checks_s5.check_5_3_3(SID, SNAME, td)
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, PASS)

    def test_uaa_assignment_at_subscription_scope_returns_fail(self) -> None:
        from cis.config import ROLE_UAA

        td = _td(
            "roles",
            [
                {
                    "roleDefinitionId": (
                        f"/subscriptions/{SID}/providers/Microsoft.Authorization/roleDefinitions/{ROLE_UAA}"
                    ),
                    "scope": f"/subscriptions/{SID}",
                }
            ],
        )
        results = checks_s5.check_5_3_3(SID, SNAME, td)
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)


# =============================================================================
# SECTION 6 — MANAGEMENT & GOVERNANCE (MONITORING)
# =============================================================================


class TestCheck6111(unittest.TestCase):
    """6.1.1.1 — Diagnostic Setting for Subscription Activity Logs."""

    def test_az_fails_returns_error(self) -> None:
        with patch("checks.s6.az", return_value=(1, "cli error")):
            result = checks_s6.check_6_1_1_1(SID, SNAME)
        self.assertEqual(result.status, ERROR)
        self.assertEqual(result.control_id, "6.1.1.1")

    def test_settings_found_returns_pass(self) -> None:
        with patch("checks.s6.az", return_value=(0, [{"name": "diag1"}])):
            result = checks_s6.check_6_1_1_1(SID, SNAME)
        self.assertEqual(result.status, PASS)

    def test_no_settings_returns_fail(self) -> None:
        with patch("checks.s6.az", return_value=(0, [])):
            result = checks_s6.check_6_1_1_1(SID, SNAME)
        self.assertEqual(result.status, FAIL)

    def test_value_key_list_detected(self) -> None:
        # az sometimes returns {"value": [...]} rather than a direct list
        with patch("checks.s6.az", return_value=(0, {"value": [{"name": "d1"}]})):
            result = checks_s6.check_6_1_1_1(SID, SNAME)
        self.assertEqual(result.status, PASS)


class TestCheck6112(unittest.TestCase):
    """6.1.1.2 — Diagnostic Setting captures required log categories."""

    def test_az_fails_returns_error(self) -> None:
        with patch("checks.s6.az", return_value=(1, "err")):
            result = checks_s6.check_6_1_1_2(SID, SNAME)
        self.assertEqual(result.status, ERROR)

    def test_all_required_categories_enabled_returns_pass(self) -> None:
        settings = [
            {
                "logs": [
                    {"category": "Security", "enabled": True},
                    {"category": "Administrative", "enabled": True},
                    {"category": "Alert", "enabled": True},
                    {"category": "Policy", "enabled": True},
                ]
            }
        ]
        with patch("checks.s6.az", return_value=(0, settings)):
            result = checks_s6.check_6_1_1_2(SID, SNAME)
        self.assertEqual(result.status, PASS)

    def test_missing_category_returns_fail(self) -> None:
        # Only 3 of 4 required categories present
        settings = [
            {
                "logs": [
                    {"category": "Security", "enabled": True},
                    {"category": "Administrative", "enabled": True},
                    {"category": "Alert", "enabled": True},
                    # "Policy" missing
                ]
            }
        ]
        with patch("checks.s6.az", return_value=(0, settings)):
            result = checks_s6.check_6_1_1_2(SID, SNAME)
        self.assertEqual(result.status, FAIL)

    def test_category_disabled_counts_as_missing(self) -> None:
        settings = [
            {
                "logs": [
                    {"category": "Security", "enabled": True},
                    {"category": "Administrative", "enabled": True},
                    {"category": "Alert", "enabled": True},
                    {"category": "Policy", "enabled": False},  # disabled — should not count
                ]
            }
        ]
        with patch("checks.s6.az", return_value=(0, settings)):
            result = checks_s6.check_6_1_1_2(SID, SNAME)
        self.assertEqual(result.status, FAIL)


class TestCheck612Alerts(unittest.TestCase):
    """6.1.2.1–6.1.2.11 — Activity Log Alerts for critical operations."""

    def _make_alert(self, op_name: str) -> dict:
        """Build a minimal alert dict with a single operationName condition."""
        return {
            "condition": {
                "allOf": [
                    {"field": "operationName", "equals": op_name},
                ]
            }
        }

    def test_no_alerts_all_fail(self) -> None:
        with patch("checks.s6.az", return_value=(0, [])):
            results = checks_s6.check_6_1_2_alerts(SID, SNAME)
        self.assertTrue(all(r.status == FAIL for r in results))
        # 10 operation-name controls + 1 service health = 11
        self.assertEqual(len(results), 11)

    def test_all_required_alerts_present_returns_all_pass(self) -> None:
        required_ops = [
            "microsoft.authorization/policyassignments/write",
            "microsoft.authorization/policyassignments/delete",
            "microsoft.network/networksecuritygroups/write",
            "microsoft.network/networksecuritygroups/delete",
            "microsoft.security/securitysolutions/write",
            "microsoft.security/securitysolutions/delete",
            "microsoft.sql/servers/firewallrules/write",
            "microsoft.sql/servers/firewallrules/delete",
            "microsoft.network/publicipaddresses/write",
            "microsoft.network/publicipaddresses/delete",
        ]
        # Build op-name alerts
        alerts = [self._make_alert(op) for op in required_ops]
        # Add ServiceHealth alert (6.1.2.11)
        alerts.append({"condition": {"allOf": [{"field": "category", "equals": "ServiceHealth"}]}})

        with patch("checks.s6.az", return_value=(0, alerts)):
            results = checks_s6.check_6_1_2_alerts(SID, SNAME)
        self.assertTrue(all(r.status == PASS for r in results), [r for r in results if r.status != PASS])

    def test_partial_alerts_mix_pass_fail(self) -> None:
        # Provide only the first required operation alert
        alerts = [self._make_alert("microsoft.authorization/policyassignments/write")]
        with patch("checks.s6.az", return_value=(0, alerts)):
            results = checks_s6.check_6_1_2_alerts(SID, SNAME)
        statuses = {r.control_id: r.status for r in results}
        self.assertEqual(statuses["6.1.2.1"], PASS)
        self.assertEqual(statuses["6.1.2.2"], FAIL)


# =============================================================================
# SECTION 7 — NETWORKING SERVICES
# =============================================================================


class TestCheck71(unittest.TestCase):
    """7.1 — RDP access from the internet is restricted."""

    def test_no_nsgs_returns_info(self) -> None:
        td = _td("nsgs", [])
        results = checks_s7.check_7_1(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, INFO)

    def _make_nsg_with_rule(self, port: int, src: str, proto: str = "TCP") -> dict:
        return {
            "name": "test-nsg",
            "rules": [
                {
                    "name": "bad-rule",
                    "properties": {
                        "access": "Allow",
                        "direction": "Inbound",
                        "protocol": proto,
                        "destinationPortRange": str(port),
                        "sourceAddressPrefix": src,
                        "priority": 100,
                    },
                }
            ],
        }

    def test_nsg_with_rdp_rule_from_internet_returns_fail(self) -> None:
        td = _td("nsgs", [self._make_nsg_with_rule(3389, "*")])
        results = checks_s7.check_7_1(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)

    def test_nsg_with_no_bad_rdp_rules_returns_pass(self) -> None:
        # Port 3389 but restricted source (not internet)
        nsg = {
            "name": "safe-nsg",
            "rules": [
                {
                    "name": "restricted-rdp",
                    "properties": {
                        "access": "Allow",
                        "direction": "Inbound",
                        "protocol": "TCP",
                        "destinationPortRange": "3389",
                        "sourceAddressPrefix": "10.0.0.0/8",
                        "priority": 100,
                    },
                }
            ],
        }
        td = _td("nsgs", [nsg])
        results = checks_s7.check_7_1(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, PASS)


class TestCheck72(unittest.TestCase):
    """7.2 — SSH access from the internet is restricted."""

    def test_no_nsgs_returns_info(self) -> None:
        td = _td("nsgs", [])
        results = checks_s7.check_7_2(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, INFO)

    def test_nsg_with_ssh_rule_from_internet_returns_fail(self) -> None:
        nsg = {
            "name": "test-nsg",
            "rules": [
                {
                    "name": "allow-ssh",
                    "properties": {
                        "access": "Allow",
                        "direction": "Inbound",
                        "protocol": "TCP",
                        "destinationPortRange": "22",
                        "sourceAddressPrefix": "*",
                        "priority": 100,
                    },
                }
            ],
        }
        td = _td("nsgs", [nsg])
        results = checks_s7.check_7_2(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)

    def test_nsg_with_no_bad_ssh_rules_returns_pass(self) -> None:
        nsg = {
            "name": "safe-nsg",
            "rules": [
                {
                    "name": "restricted-ssh",
                    "properties": {
                        "access": "Allow",
                        "direction": "Inbound",
                        "protocol": "TCP",
                        "destinationPortRange": "22",
                        "sourceAddressPrefix": "192.168.0.0/16",
                        "priority": 100,
                    },
                }
            ],
        }
        td = _td("nsgs", [nsg])
        results = checks_s7.check_7_2(SID, SNAME, td)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, PASS)


class TestCheck75(unittest.TestCase):
    """7.5 — NSG flow log retention >= 90 days."""

    def test_az_watcher_list_fails_returns_error(self) -> None:
        with patch("checks.s7.az", return_value=(1, "err")):
            results = checks_s7.check_7_5(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ERROR)

    def test_no_watchers_returns_fail(self) -> None:
        # No watchers → no flow logs possible → non-compliant (FAIL)
        # check_7_6 separately covers the missing Network Watcher itself.
        with patch("checks.s7.az", return_value=(0, [])):
            results = checks_s7.check_7_5(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)

    def test_flow_log_retention_90_days_enabled_returns_pass(self) -> None:
        watcher = {"location": "eastus", "name": "watcher1"}
        flow_log = {
            "name": "fl1",
            "retentionPolicy": {"days": 90, "enabled": True},
        }

        def _az_side_effect(args: list, *a: Any, **kw: Any) -> tuple:
            # Check for flow-log first — its args also contain "watcher" and "list"
            if "flow-log" in args:
                return (0, [flow_log])
            if "watcher" in args and "list" in args:
                return (0, [watcher])
            return (1, "unexpected")

        with patch("checks.s7.az", side_effect=_az_side_effect):
            results = checks_s7.check_7_5(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, PASS)

    def test_flow_log_retention_below_90_returns_fail(self) -> None:
        watcher = {"location": "eastus", "name": "watcher1"}
        flow_log = {
            "name": "fl1",
            "retentionPolicy": {"days": 30, "enabled": True},
        }

        def _az_side_effect(args: list, *a: Any, **kw: Any) -> tuple:
            if "flow-log" in args:
                return (0, [flow_log])
            if "watcher" in args and "list" in args:
                return (0, [watcher])
            return (1, "unexpected")

        with patch("checks.s7.az", side_effect=_az_side_effect):
            results = checks_s7.check_7_5(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)

    def test_flow_log_enabled_false_returns_fail(self) -> None:
        watcher = {"location": "westus", "name": "watcher2"}
        flow_log = {
            "name": "fl2",
            "retentionPolicy": {"days": 90, "enabled": False},
        }

        def _az_side_effect(args: list, *a: Any, **kw: Any) -> tuple:
            if "flow-log" in args:
                return (0, [flow_log])
            if "watcher" in args and "list" in args:
                return (0, [watcher])
            return (1, "unexpected")

        with patch("checks.s7.az", side_effect=_az_side_effect):
            results = checks_s7.check_7_5(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)


# =============================================================================
# SECTION 8 — SECURITY SERVICES
# =============================================================================


class TestCheck81Defender(unittest.TestCase):
    """8.1.x — Microsoft Defender for Cloud plan statuses."""

    def test_az_fails_returns_error_results(self) -> None:
        with patch("checks.s8.az", return_value=(1, "access denied")):
            results = checks_s8.check_8_1_defender(SID, SNAME)
        # All 12 plans should produce ERROR results
        self.assertEqual(len(results), 12)
        self.assertTrue(all(r.status == ERROR for r in results))

    def test_standard_tier_returns_pass(self) -> None:
        with patch("checks.s8.az", return_value=(0, {"pricingTier": "Standard"})):
            results = checks_s8.check_8_1_defender(SID, SNAME)
        self.assertEqual(len(results), 12)
        self.assertTrue(all(r.status == PASS for r in results))

    def test_free_tier_returns_fail(self) -> None:
        with patch("checks.s8.az", return_value=(0, {"pricingTier": "Free"})):
            results = checks_s8.check_8_1_defender(SID, SNAME)
        self.assertEqual(len(results), 12)
        self.assertTrue(all(r.status == FAIL for r in results))

    def test_mixed_tiers_returns_mixed_statuses(self) -> None:
        call_count = [0]

        def _az_side_effect(args: list, *a: Any, **kw: Any) -> tuple:
            call_count[0] += 1
            # Alternate between Standard and Free
            tier = "Standard" if call_count[0] % 2 == 1 else "Free"
            return (0, {"pricingTier": tier})

        with patch("checks.s8.az", side_effect=_az_side_effect):
            results = checks_s8.check_8_1_defender(SID, SNAME)
        self.assertEqual(len(results), 12)
        pass_count = sum(1 for r in results if r.status == PASS)
        fail_count = sum(1 for r in results if r.status == FAIL)
        self.assertEqual(pass_count, 6)
        self.assertEqual(fail_count, 6)


class TestCheck83Keyvaults(unittest.TestCase):
    """8.3.x — Key Vault security controls."""

    def test_no_keyvaults_returns_info_for_each_control(self) -> None:
        td = _td("keyvaults", [])
        results = checks_s8.check_8_3_keyvaults(SID, SNAME, td)
        self.assertTrue(len(results) > 0)
        self.assertTrue(all(r.status == INFO for r in results))

    def test_purge_protection_disabled_returns_fail(self) -> None:
        # A minimal vault where purgeProtection=False
        vault = {
            "name": "kv1",
            "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
            "rbac": True,
            "purgeProtection": False,
            "publicAccess": "Enabled",
            "privateEps": 0,
        }
        td = _td("keyvaults", [vault])

        # az calls for keys/secrets/certs will return empty lists to avoid unrelated failures
        with patch("checks.s8.az", return_value=(0, [])):
            results = checks_s8.check_8_3_keyvaults(SID, SNAME, td)

        purge_results = [r for r in results if r.control_id == "8.3.5"]
        self.assertTrue(len(purge_results) > 0)
        self.assertEqual(purge_results[0].status, FAIL)

    def test_purge_protection_enabled_returns_pass(self) -> None:
        vault = {
            "name": "kv2",
            "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv2",
            "rbac": True,
            "purgeProtection": True,
            "publicAccess": "Disabled",
            "privateEps": 1,
        }
        td = _td("keyvaults", [vault])

        with patch("checks.s8.az", return_value=(0, [])):
            results = checks_s8.check_8_3_keyvaults(SID, SNAME, td)

        purge_results = [r for r in results if r.control_id == "8.3.5"]
        self.assertTrue(len(purge_results) > 0)
        self.assertEqual(purge_results[0].status, PASS)

    def test_public_access_enabled_returns_fail_for_8_3_7(self) -> None:
        vault = {
            "name": "kv3",
            "rbac": True,
            "purgeProtection": True,
            "publicAccess": "Enabled",
            "privateEps": 0,
        }
        td = _td("keyvaults", [vault])

        with patch("checks.s8.az", return_value=(0, [])):
            results = checks_s8.check_8_3_keyvaults(SID, SNAME, td)

        pub_results = [r for r in results if r.control_id == "8.3.7"]
        self.assertTrue(len(pub_results) > 0)
        self.assertEqual(pub_results[0].status, FAIL)


class TestCheck841(unittest.TestCase):
    """8.4.1 — Azure Bastion Host exists in the subscription."""

    def test_no_vms_returns_info(self) -> None:
        td = _td("bastion", [])
        td["vms"] = {SID.lower(): []}
        result = checks_s8.check_8_4_1(SID, SNAME, td)
        self.assertEqual(result.status, INFO)
        self.assertEqual(result.control_id, "8.4.1")

    def test_bastion_host_exists_returns_pass(self) -> None:
        td = _td("bastion", [{"name": "bastion1"}])
        td["vms"] = {SID.lower(): [{"name": "vm1"}]}
        result = checks_s8.check_8_4_1(SID, SNAME, td)
        self.assertEqual(result.status, PASS)

    def test_vms_without_bastion_returns_fail(self) -> None:
        td = _td("bastion", [])
        td["vms"] = {SID.lower(): [{"name": "vm1"}, {"name": "vm2"}]}
        result = checks_s8.check_8_4_1(SID, SNAME, td)
        self.assertEqual(result.status, FAIL)


# =============================================================================
# SECTION 9 — STORAGE SERVICES
# =============================================================================


class TestCheck9Storage(unittest.TestCase):
    """9.x — Storage account security checks."""

    def test_no_storage_accounts_returns_info_list(self) -> None:
        """When both the prefetch dict and az CLI fallback have no accounts, INFO is returned."""
        td = _td("storage", [])
        with patch("checks.s9.az", return_value=(1, "no accounts")):
            results = checks_s9.check_9_storage(SID, SNAME, td)
        self.assertTrue(len(results) > 0)
        self.assertTrue(all(r.status == INFO for r in results))

    def test_empty_az_list_returns_info(self) -> None:
        """az returns success but empty list — still no accounts."""
        td = _td("storage", [])
        with patch("checks.s9.az", return_value=(0, [])):
            results = checks_s9.check_9_storage(SID, SNAME, td)
        self.assertTrue(all(r.status == INFO for r in results))

    def test_https_not_required_returns_fail(self) -> None:
        # 9.3.4 — supportsHttpsTrafficOnly = False
        account = {
            "name": "sa1",
            "resourceGroup": "rg",
            "subscriptionId": SID,
            "httpsOnly": False,
            "publicAccess": "Disabled",
            "crossTenant": False,
            "blobAnon": False,
            "defaultAction": "Deny",
            "bypass": "AzureServices",
            "minTls": "TLS1_2",
            "keyAccess": False,
            "oauthDefault": True,
            "sku": "Standard_GRS",
            "privateEps": 1,
        }
        td = _td("storage", [account])
        with patch("checks.s9.az", return_value=(0, [])):
            results = checks_s9.check_9_storage(SID, SNAME, td)
        https_results = [r for r in results if r.control_id == "9.3.4"]
        self.assertTrue(len(https_results) > 0)
        self.assertEqual(https_results[0].status, FAIL)

    def test_https_required_returns_pass(self) -> None:
        account = {
            "name": "sa2",
            "resourceGroup": "rg",
            "subscriptionId": SID,
            "httpsOnly": True,
            "publicAccess": "Disabled",
            "crossTenant": False,
            "blobAnon": False,
            "defaultAction": "Deny",
            "bypass": "AzureServices",
            "minTls": "TLS1_2",
            "keyAccess": False,
            "oauthDefault": True,
            "sku": "Standard_GRS",
            "privateEps": 1,
        }
        td = _td("storage", [account])
        with patch("checks.s9.az", return_value=(0, [])):
            results = checks_s9.check_9_storage(SID, SNAME, td)
        https_results = [r for r in results if r.control_id == "9.3.4"]
        self.assertTrue(len(https_results) > 0)
        self.assertEqual(https_results[0].status, PASS)

    def test_public_access_enabled_returns_fail_for_9_3_2_2(self) -> None:
        account = {
            "name": "sa3",
            "resourceGroup": "rg",
            "subscriptionId": SID,
            "httpsOnly": True,
            "publicAccess": "Enabled",
            "crossTenant": False,
            "blobAnon": False,
            "defaultAction": "Deny",
            "bypass": "AzureServices",
            "minTls": "TLS1_2",
            "keyAccess": False,
            "oauthDefault": True,
            "sku": "Standard_LRS",
            "privateEps": 0,
        }
        td = _td("storage", [account])
        with patch("checks.s9.az", return_value=(0, [])):
            results = checks_s9.check_9_storage(SID, SNAME, td)
        pub_results = [r for r in results if r.control_id == "9.3.2.2"]
        self.assertTrue(len(pub_results) > 0)
        self.assertEqual(pub_results[0].status, FAIL)

    def test_fully_compliant_account_passes_all_static_checks(self) -> None:
        account = {
            "name": "compliant",
            "resourceGroup": "rg",
            "subscriptionId": SID,
            "httpsOnly": True,
            "publicAccess": "Disabled",
            "crossTenant": False,
            "blobAnon": False,
            "defaultAction": "Deny",
            "bypass": "AzureServices, Logging",
            "minTls": "TLS1_2",
            "keyAccess": False,
            "oauthDefault": True,
            "sku": "Standard_GRS",
            "privateEps": 2,
        }
        td = _td("storage", [account])

        # az calls for blob/file/key service checks return compliant data
        blob_svc = {
            "deleteRetentionPolicy": {"enabled": True, "days": 7},
            "containerDeleteRetentionPolicy": {"enabled": True, "days": 7},
            "isVersioningEnabled": True,
        }
        file_svc = {
            "shareDeleteRetentionPolicy": {"enabled": True, "days": 7},
            "protocolSettings": {
                "smb": {
                    "versions": "SMB3.0;SMB3.1.1",
                    "channelEncryption": "AES-128-GCM;AES-256-GCM",
                }
            },
        }

        def _az_side_effect(args: list, *a: Any, **kw: Any) -> tuple:
            if "blob-service-properties" in args:
                return (0, blob_svc)
            if "file-service-properties" in args:
                return (0, file_svc)
            return (0, [])

        with patch("checks.s9.az", side_effect=_az_side_effect):
            results = checks_s9.check_9_storage(SID, SNAME, td)

        # Static checks that have deterministic outcomes given the account data
        static_ctrl_ids = ["9.3.4", "9.3.2.2", "9.3.7", "9.3.8", "9.3.2.3", "9.3.6"]
        static_results = {r.control_id: r.status for r in results if r.control_id in static_ctrl_ids}
        for ctrl_id in static_ctrl_ids:
            self.assertIn(ctrl_id, static_results, f"{ctrl_id} not found in results")
            self.assertEqual(static_results[ctrl_id], PASS, f"{ctrl_id} expected PASS, got {static_results[ctrl_id]}")


if __name__ == "__main__":
    unittest.main()
