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

    # ── az CLI path (MSAL not configured) ─────────────────────────────────────

    @patch("checks.s5.msal_is_configured", return_value=False)
    @patch("checks.s5.az_rest")
    def test_security_defaults_enabled_returns_pass(self, mock_az_rest: Any, _mc: Any) -> None:
        mock_az_rest.return_value = (0, {"isEnabled": True})
        result = checks_s5.check_5_1_1()
        self.assertEqual(result.control_id, "5.1.1")
        self.assertEqual(result.status, PASS)

    @patch("checks.s5.msal_is_configured", return_value=False)
    @patch("checks.s5.az_rest")
    def test_security_defaults_disabled_with_ca_returns_pass(self, mock_az_rest: Any, _mc: Any) -> None:
        mock_az_rest.side_effect = [
            (0, {"isEnabled": False}),
            (0, {"value": [{"id": "policy-1"}]}),
        ]
        result = checks_s5.check_5_1_1()
        self.assertEqual(result.control_id, "5.1.1")
        self.assertEqual(result.status, PASS)

    @patch("checks.s5.msal_is_configured", return_value=False)
    @patch("checks.s5.az_rest")
    def test_security_defaults_disabled_no_ca_returns_fail(self, mock_az_rest: Any, _mc: Any) -> None:
        mock_az_rest.side_effect = [
            (0, {"isEnabled": False}),
            (0, {"value": []}),
        ]
        result = checks_s5.check_5_1_1()
        self.assertEqual(result.control_id, "5.1.1")
        self.assertEqual(result.status, FAIL)

    @patch("checks.s5.msal_is_configured", return_value=False)
    @patch("checks.s5.az_rest")
    def test_az_authz_error_returns_error_with_config_hint(self, mock_az_rest: Any, _mc: Any) -> None:
        mock_az_rest.return_value = (1, "required scopes are missing in the token")
        result = checks_s5.check_5_1_1()
        self.assertEqual(result.control_id, "5.1.1")
        self.assertEqual(result.status, ERROR)
        self.assertIn("graph_auth", result.details)

    @patch("checks.s5.msal_is_configured", return_value=False)
    @patch("checks.s5.az_rest")
    def test_az_generic_error_returns_error(self, mock_az_rest: Any, _mc: Any) -> None:
        mock_az_rest.return_value = (1, "Connection timeout")
        result = checks_s5.check_5_1_1()
        self.assertEqual(result.control_id, "5.1.1")
        self.assertEqual(result.status, ERROR)

    # ── MSAL path (configured) ─────────────────────────────────────────────────

    @patch("checks.s5.msal_is_configured", return_value=True)
    @patch("checks.s5.msal_rest")
    @patch("checks.s5.az_rest")
    def test_msal_enabled_returns_pass(self, mock_az_rest: Any, mock_msal: Any, _mc: Any) -> None:
        mock_msal.return_value = (0, {"isEnabled": True})
        result = checks_s5.check_5_1_1()
        self.assertEqual(result.status, PASS)
        mock_az_rest.assert_not_called()

    @patch("checks.s5.msal_is_configured", return_value=True)
    @patch("checks.s5.msal_rest")
    def test_msal_disabled_with_ca_returns_pass(self, mock_msal: Any, _mc: Any) -> None:
        mock_msal.return_value = (0, {"isEnabled": False})
        with patch("checks.s5.az_rest", return_value=(0, {"value": [{"id": "ca1"}]})):
            result = checks_s5.check_5_1_1()
        self.assertEqual(result.status, PASS)

    @patch("checks.s5.msal_is_configured", return_value=True)
    @patch("checks.s5.msal_rest")
    def test_msal_error_returns_error(self, mock_msal: Any, _mc: Any) -> None:
        mock_msal.return_value = (1, "MSAL token acquisition failed: consent_required")
        result = checks_s5.check_5_1_1()
        self.assertEqual(result.control_id, "5.1.1")
        self.assertEqual(result.status, ERROR)


class TestCheck512(unittest.TestCase):
    """5.1.2 — MFA enabled for all users."""

    @patch("checks.s5.az_rest_paged")
    def test_all_users_have_mfa_returns_pass(self, mock: Any) -> None:
        mock.return_value = (
            0,
            [
                {"userPrincipalName": "a@t.com", "isMfaRegistered": True},
                {"userPrincipalName": "b@t.com", "isMfaRegistered": True},
            ],
        )
        result = checks_s5.check_5_1_2()
        self.assertEqual(result.control_id, "5.1.2")
        self.assertEqual(result.status, PASS)

    @patch("checks.s5.az_rest_paged")
    def test_no_users_returns_pass(self, mock: Any) -> None:
        mock.return_value = (0, [])
        result = checks_s5.check_5_1_2()
        self.assertEqual(result.control_id, "5.1.2")
        self.assertEqual(result.status, PASS)

    @patch("checks.s5.az_rest_paged")
    def test_user_without_mfa_returns_fail(self, mock: Any) -> None:
        mock.return_value = (
            0,
            [
                {"userPrincipalName": "noMfa@t.com", "isMfaRegistered": False},
                {"userPrincipalName": "hasMfa@t.com", "isMfaRegistered": True},
            ],
        )
        result = checks_s5.check_5_1_2()
        self.assertEqual(result.control_id, "5.1.2")
        self.assertEqual(result.status, FAIL)
        self.assertIn("1 user(s)", result.details)

    @patch("checks.s5.az_rest_paged")
    def test_api_error_returns_error(self, mock: Any) -> None:
        mock.return_value = (1, [])
        result = checks_s5.check_5_1_2()
        self.assertEqual(result.control_id, "5.1.2")
        self.assertEqual(result.status, ERROR)

    @patch("checks.s5.az_rest_paged")
    def test_many_users_without_mfa_truncates_list(self, mock: Any) -> None:
        users = [{"userPrincipalName": f"user{i}@t.com", "isMfaRegistered": False} for i in range(15)]
        mock.return_value = (0, users)
        result = checks_s5.check_5_1_2()
        self.assertEqual(result.status, FAIL)
        self.assertIn("15 user(s)", result.details)

    @patch("checks.s5.az_rest_paged")
    def test_upn_fallback_to_id_when_upn_missing(self, mock: Any) -> None:
        mock.return_value = (0, [{"id": "guid-1234", "isMfaRegistered": False}])
        result = checks_s5.check_5_1_2()
        self.assertEqual(result.status, FAIL)
        self.assertIn("1 user(s)", result.details)


class TestCheck513(unittest.TestCase):
    """5.1.3 — Allow users to remember MFA on trusted devices (Manual)."""

    def test_returns_manual(self) -> None:
        result = checks_s5.check_5_1_3()
        self.assertEqual(result.control_id, "5.1.3")
        self.assertEqual(result.status, MANUAL)


class TestCheck528(unittest.TestCase):
    """5.28 — Privileged users protected by phishing-resistant MFA (Manual)."""

    def test_returns_manual(self) -> None:
        result = checks_s5.check_5_28()
        self.assertEqual(result.control_id, "5.28")
        self.assertEqual(result.status, MANUAL)


class TestCheck523(unittest.TestCase):
    """5.23 — No custom subscription administrator roles with wildcard actions."""

    def test_az_fails_returns_error(self) -> None:
        with patch("checks.s5.az", return_value=(1, "cli error")):
            result = checks_s5.check_5_23(SID, SNAME)
        self.assertEqual(result.status, ERROR)
        self.assertEqual(result.control_id, "5.23")

    def test_no_custom_roles_returns_pass(self) -> None:
        with patch("checks.s5.az", return_value=(0, [])):
            result = checks_s5.check_5_23(SID, SNAME)
        self.assertEqual(result.status, PASS)
        self.assertEqual(result.control_id, "5.23")

    def test_custom_role_without_wildcard_returns_pass(self) -> None:
        roles = [{"roleName": "MyReadRole", "permissions": [{"actions": ["Microsoft.Compute/*/read"]}]}]
        with patch("checks.s5.az", return_value=(0, roles)):
            result = checks_s5.check_5_23(SID, SNAME)
        self.assertEqual(result.status, PASS)

    def test_custom_role_with_wildcard_returns_fail(self) -> None:
        roles = [{"roleName": "DangerRole", "permissions": [{"actions": ["*"]}]}]
        with patch("checks.s5.az", return_value=(0, roles)):
            result = checks_s5.check_5_23(SID, SNAME)
        self.assertEqual(result.status, FAIL)
        self.assertIn("DangerRole", result.details)

    def test_multiple_roles_only_wildcard_flagged(self) -> None:
        roles = [
            {"roleName": "SafeRole", "permissions": [{"actions": ["Microsoft.Storage/*/read"]}]},
            {"roleName": "BadRole", "permissions": [{"actions": ["*"]}]},
        ]
        with patch("checks.s5.az", return_value=(0, roles)):
            result = checks_s5.check_5_23(SID, SNAME)
        self.assertEqual(result.status, FAIL)
        self.assertIn("BadRole", result.details)
        self.assertNotIn("SafeRole", result.details)

    def test_role_with_multiple_permission_blocks_any_wildcard_fails(self) -> None:
        # Multiple permission blocks — wildcard in any one block should trigger FAIL
        roles = [
            {"roleName": "PartialBad", "permissions": [{"actions": ["Microsoft.Network/*/read"]}, {"actions": ["*"]}]}
        ]
        with patch("checks.s5.az", return_value=(0, roles)):
            result = checks_s5.check_5_23(SID, SNAME)
        self.assertEqual(result.status, FAIL)


class TestCheck527(unittest.TestCase):
    """5.27 — Between 2 and 3 subscription owners."""

    def _owner(self, name: str, ptype: str = "User") -> dict[str, Any]:
        from cis.config import ROLE_OWNER

        return {
            "roleDefinitionId": f"/subscriptions/{SID}/providers/Microsoft.Authorization/roleDefinitions/{ROLE_OWNER}",
            "scope": f"/subscriptions/{SID}",
            "principalName": name,
            "principalType": ptype,
            "principalId": f"id-{name}",
        }

    def test_zero_owners_returns_fail(self) -> None:
        result = checks_s5.check_5_27(SID, SNAME, _td("roles", []))
        self.assertEqual(result.status, FAIL)
        self.assertIn("0", result.details)

    def test_one_owner_returns_fail(self) -> None:
        td = _td("roles", [self._owner("alice")])
        result = checks_s5.check_5_27(SID, SNAME, td)
        self.assertEqual(result.status, FAIL)

    def test_two_owners_returns_pass(self) -> None:
        td = _td("roles", [self._owner("alice"), self._owner("bob")])
        result = checks_s5.check_5_27(SID, SNAME, td)
        self.assertEqual(result.status, PASS)
        self.assertIn("2", result.details)

    def test_three_owners_returns_pass(self) -> None:
        td = _td("roles", [self._owner("alice"), self._owner("bob"), self._owner("carol")])
        result = checks_s5.check_5_27(SID, SNAME, td)
        self.assertEqual(result.status, PASS)

    def test_four_owners_returns_fail(self) -> None:
        td = _td("roles", [self._owner("a"), self._owner("b"), self._owner("c"), self._owner("d")])
        result = checks_s5.check_5_27(SID, SNAME, td)
        self.assertEqual(result.status, FAIL)

    def test_group_assignment_counted_as_one_with_note(self) -> None:
        td = _td("roles", [self._owner("Owners-Group", "Group"), self._owner("alice")])
        result = checks_s5.check_5_27(SID, SNAME, td)
        self.assertEqual(result.status, PASS)
        self.assertIn("2", result.details)

    def test_management_group_scope_not_counted(self) -> None:
        # An Owner at management group scope should NOT count towards subscription owners
        from cis.config import ROLE_OWNER

        mg_owner = {
            "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{ROLE_OWNER}",
            "scope": "/providers/Microsoft.Management/managementGroups/mg-root",
            "principalName": "mg-admin",
            "principalType": "User",
            "principalId": "id-mg-admin",
        }
        td = _td("roles", [mg_owner])
        result = checks_s5.check_5_27(SID, SNAME, td)
        # Management-group-scoped Owner must NOT count — subscription still has 0 direct owners
        self.assertEqual(result.status, FAIL)
        self.assertIn("0", result.details)

    def test_correct_subscription_scoped_owner_counted(self) -> None:
        # Owner scoped directly to subscription IS counted
        td = _td("roles", [self._owner("alice"), self._owner("bob")])
        result = checks_s5.check_5_27(SID, SNAME, td)
        self.assertEqual(result.status, PASS)
        self.assertIn("2", result.details)


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


class TestCheck6113(unittest.TestCase):
    """6.1.1.3 — Activity log retention >= 365 days."""

    def test_az_fails_returns_error(self) -> None:
        with patch("checks.s6.az", return_value=(1, "cli error")):
            result = checks_s6.check_6_1_1_3(SID, SNAME)
        self.assertEqual(result.status, ERROR)
        self.assertEqual(result.control_id, "6.1.1.3")

    def test_no_profile_returns_fail(self) -> None:
        with patch("checks.s6.az", return_value=(0, [])):
            result = checks_s6.check_6_1_1_3(SID, SNAME)
        self.assertEqual(result.status, FAIL)

    def test_retention_disabled_returns_pass(self) -> None:
        """Retention disabled means infinite retention — compliant."""
        profiles = [{"retentionPolicy": {"enabled": False, "days": 0}}]
        with patch("checks.s6.az", return_value=(0, profiles)):
            result = checks_s6.check_6_1_1_3(SID, SNAME)
        self.assertEqual(result.status, PASS)

    def test_retention_365_days_returns_pass(self) -> None:
        profiles = [{"retentionPolicy": {"enabled": True, "days": 365}}]
        with patch("checks.s6.az", return_value=(0, profiles)):
            result = checks_s6.check_6_1_1_3(SID, SNAME)
        self.assertEqual(result.status, PASS)

    def test_retention_less_than_365_returns_fail(self) -> None:
        profiles = [{"retentionPolicy": {"enabled": True, "days": 90}}]
        with patch("checks.s6.az", return_value=(0, profiles)):
            result = checks_s6.check_6_1_1_3(SID, SNAME)
        self.assertEqual(result.status, FAIL)


class TestCheck6115(unittest.TestCase):
    """6.1.1.5 — NSG flow logs with Traffic Analytics (deprecated June 2025)."""

    def test_returns_info_deprecation(self) -> None:
        result = checks_s6.check_6_1_1_5(SID, SNAME)
        self.assertEqual(result.status, INFO)
        self.assertIn("30 Jun 2025", result.details)

    def test_control_id_is_correct(self) -> None:
        result = checks_s6.check_6_1_1_5(SID, SNAME)
        self.assertEqual(result.control_id, "6.1.1.5")

    def test_remediation_is_empty(self) -> None:
        """No remediation possible — remediation field must be empty."""
        result = checks_s6.check_6_1_1_5(SID, SNAME)
        self.assertEqual(result.remediation, "")


class TestCheck612Alerts(unittest.TestCase):
    """6.1.2.1–6.1.2.11 — Activity Log Alerts for critical operations."""

    def _make_alert(self, op_name: str, enabled: bool = True) -> dict:
        """Build a minimal alert dict with a single operationName condition."""
        return {
            "enabled": enabled,
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

    def test_disabled_alert_does_not_count_as_compliant(self) -> None:
        """Regression: an alert rule with enabled=false must NOT satisfy the control."""
        alerts = [self._make_alert("microsoft.authorization/policyassignments/write", enabled=False)]
        with patch("checks.s6.az", return_value=(0, alerts)):
            results = checks_s6.check_6_1_2_alerts(SID, SNAME)
        statuses = {r.control_id: r.status for r in results}
        # Alert exists but is disabled — must be FAIL, not PASS
        self.assertEqual(statuses["6.1.2.1"], FAIL)

    def test_disabled_service_health_alert_does_not_count(self) -> None:
        """Regression: disabled ServiceHealth alert must not satisfy 6.1.2.11."""
        alerts = [
            {
                "enabled": False,
                "condition": {"allOf": [{"field": "category", "equals": "ServiceHealth"}]},
            }
        ]
        with patch("checks.s6.az", return_value=(0, alerts)):
            results = checks_s6.check_6_1_2_alerts(SID, SNAME)
        statuses = {r.control_id: r.status for r in results}
        self.assertEqual(statuses["6.1.2.11"], FAIL)


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
    """7.5 — NSG flow log retention >= 90 days (deprecated since June 2025)."""

    def test_always_returns_info_deprecation(self) -> None:
        """check_7_5 must return INFO with a deprecation notice unconditionally
        because Microsoft blocked NSG flow log creation on 30 Jun 2025."""
        results = checks_s7.check_7_5(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, INFO)
        self.assertIn("30 Jun 2025", results[0].details)

    def test_no_nsgs_still_returns_info(self) -> None:
        """Absence of NSGs does not change the deprecation result."""
        results = checks_s7.check_7_5(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, INFO)

    def test_control_id_is_correct(self) -> None:
        results = checks_s7.check_7_5(SID, SNAME)
        self.assertEqual(results[0].control_id, "7.5")

    def test_remediation_is_empty(self) -> None:
        """No remediation path is possible — remediation field must be empty."""
        results = checks_s7.check_7_5(SID, SNAME)
        self.assertEqual(results[0].remediation, "")


class TestCheck79(unittest.TestCase):
    """7.9 — VPN Gateway P2S uses Azure AD authentication only."""

    def test_no_gateways_returns_info(self) -> None:
        with patch("checks.s7.az_rest", return_value=(0, {"value": []})):
            results = checks_s7.check_7_9(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, INFO)

    def test_az_fails_returns_error(self) -> None:
        with patch("checks.s7.az_rest", return_value=(1, "err")):
            results = checks_s7.check_7_9(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ERROR)

    def test_no_p2s_config_returns_info(self) -> None:
        gw = {"name": "gw1", "properties": {"vpnClientConfiguration": None}}
        with patch("checks.s7.az_rest", return_value=(0, {"value": [gw]})):
            results = checks_s7.check_7_9(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, INFO)

    def test_aad_only_returns_pass(self) -> None:
        gw = {"name": "gw1", "properties": {"vpnClientConfiguration": {"vpnAuthenticationTypes": ["AAD"]}}}
        with patch("checks.s7.az_rest", return_value=(0, {"value": [gw]})):
            results = checks_s7.check_7_9(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, PASS)

    def test_certificate_only_returns_fail(self) -> None:
        gw = {"name": "gw1", "properties": {"vpnClientConfiguration": {"vpnAuthenticationTypes": ["Certificate"]}}}
        with patch("checks.s7.az_rest", return_value=(0, {"value": [gw]})):
            results = checks_s7.check_7_9(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)

    def test_mixed_auth_returns_fail(self) -> None:
        gw = {
            "name": "gw1",
            "properties": {"vpnClientConfiguration": {"vpnAuthenticationTypes": ["AAD", "Certificate"]}},
        }
        with patch("checks.s7.az_rest", return_value=(0, {"value": [gw]})):
            results = checks_s7.check_7_9(SID, SNAME)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FAIL)

    def test_multiple_gateways(self) -> None:
        gws = [
            {"name": "gw-aad", "properties": {"vpnClientConfiguration": {"vpnAuthenticationTypes": ["AAD"]}}},
            {"name": "gw-cert", "properties": {"vpnClientConfiguration": {"vpnAuthenticationTypes": ["Certificate"]}}},
            {"name": "gw-nop2s", "properties": {"vpnClientConfiguration": None}},
        ]
        with patch("checks.s7.az_rest", return_value=(0, {"value": gws})):
            results = checks_s7.check_7_9(SID, SNAME)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0].status, PASS)
        self.assertEqual(results[1].status, FAIL)
        self.assertEqual(results[2].status, INFO)


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

        def _az_side_effect(args: list, *a: Any, **_: Any) -> tuple:
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

    def test_rotation_policy_lifetime_actions_as_strings_does_not_crash(self) -> None:
        """Regression: Azure may return lifetimeActions as a list of strings (not dicts)."""
        vault = {
            "name": "kv-str-actions",
            "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv4",
            "rbac": True,
            "purgeProtection": True,
            "publicAccess": "Disabled",
            "privateEps": 1,
        }
        td = _td("keyvaults", [vault])

        keys = [{"name": "my-key", "expires": "2030-01-01", "enabled": True}]
        # lifetimeActions is a list of strings — malformed response from Azure
        rotation_policy = {"lifetimeActions": ["Notify", "Rotate"]}

        def _az_side(_args: list, *_a: Any, **_: Any) -> tuple:
            if "rotation-policy" in _args:
                return (0, rotation_policy)
            if "key" in _args and "list" in _args:
                return (0, keys)
            return (0, [])

        with patch("checks.s8.az", side_effect=_az_side):
            results = checks_s8.check_8_3_keyvaults(SID, SNAME, td)

        # Must not raise; 8.3.9 should FAIL (no dict action found)
        rot_results = [r for r in results if r.control_id == "8.3.9"]
        self.assertTrue(len(rot_results) > 0)
        self.assertEqual(rot_results[0].status, FAIL)

    def test_rotation_policy_lifetime_actions_string_action_value(self) -> None:
        """Regression: Azure may return lifetimeActions as dicts with a bare string
        'action' field (e.g. {"action": "Rotate", "trigger": {...}}) rather than the
        nested form {"action": {"type": "Rotate"}, ...}.  The check must not crash
        and must recognise the policy as having a Rotate action."""
        vault = {
            "name": "kv-str-action-val",
            "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv5",
            "rbac": True,
            "purgeProtection": True,
            "publicAccess": "Disabled",
            "privateEps": 1,
        }
        td = _td("keyvaults", [vault])

        keys = [{"name": "my-key", "expires": "2030-01-01", "enabled": True}]
        # Azure returns the action as a plain string, not a nested dict
        rotation_policy = {
            "lifetimeActions": [
                {"action": "Notify", "trigger": {"timeBeforeExpiry": "P30D"}},
                {"action": "Rotate", "trigger": {"timeBeforeExpiry": "P7D"}},
            ]
        }

        def _az_side(_args: list, *_a: Any, **_: Any) -> tuple:
            if "rotation-policy" in _args:
                return (0, rotation_policy)
            if "key" in _args and "list" in _args:
                return (0, keys)
            return (0, [])

        with patch("checks.s8.az", side_effect=_az_side):
            results = checks_s8.check_8_3_keyvaults(SID, SNAME, td)

        # Must not raise; 8.3.9 should PASS (Rotate action present)
        rot_results = [r for r in results if r.control_id == "8.3.9"]
        self.assertTrue(len(rot_results) > 0)
        self.assertEqual(rot_results[0].status, PASS)


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
        blob_log_svc = {
            "logging": {"read": True, "write": True, "delete": True},
        }

        def _az_side_effect(args: list, *a: Any, **_: Any) -> tuple:
            if "blob-service-properties" in args:
                return (0, blob_svc)
            if "file-service-properties" in args:
                return (0, file_svc)
            if "blob" in args and "service-properties" in args:
                return (0, blob_log_svc)
            return (0, [])

        with patch("checks.s9.az", side_effect=_az_side_effect):
            results = checks_s9.check_9_storage(SID, SNAME, td)

        # Static checks that have deterministic outcomes given the account data
        static_ctrl_ids = ["9.3.4", "9.3.2.2", "9.3.7", "9.3.8", "9.3.2.3", "9.3.6"]
        static_results = {r.control_id: r.status for r in results if r.control_id in static_ctrl_ids}
        for ctrl_id in static_ctrl_ids:
            self.assertIn(ctrl_id, static_results, f"{ctrl_id} not found in results")
            self.assertEqual(static_results[ctrl_id], PASS, f"{ctrl_id} expected PASS, got {static_results[ctrl_id]}")

    def test_firewall_blocked_blob_and_file_returns_error(self) -> None:
        """Storage accounts with PublicNetworkAccess=Disabled block the audit — compliance unknown (ERROR)."""
        account = {
            "name": "locked-down",
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
            "sku": "Standard_LRS",
            "privateEps": 1,
        }
        td = _td("storage", [account])

        fw_error = (
            "(Forbidden) Connection is not an approved private link and caller was ignored "
            "because bypass is not set to 'AzureServices' and PublicNetworkAccess is set to 'Disabled'."
        )

        def _az_fw(_args: list, *a: Any, **_: Any) -> tuple:
            return (1, fw_error)

        with patch("checks.s9.az", side_effect=_az_fw):
            results = checks_s9.check_9_storage(SID, SNAME, td)

        blob_ctrl_ids = {"9.2.1", "9.2.2", "9.2.3", "9.2.4", "9.2.5", "9.2.6"}
        file_ctrl_ids = {"9.1.1", "9.1.2", "9.1.3"}
        for r in results:
            if r.control_id in blob_ctrl_ids or r.control_id in file_ctrl_ids:
                self.assertEqual(r.status, ERROR, f"{r.control_id} expected ERROR for firewall block, got {r.status}")
                self.assertNotIn("Key Vault", r.details)

    def test_authz_error_blob_and_file_returns_error_with_storage_message(self) -> None:
        """Missing read access on storage account returns ERROR with a storage-specific message."""
        account = {
            "name": "no-access",
            "resourceGroup": "rg",
            "subscriptionId": SID,
            "httpsOnly": True,
            "publicAccess": "Enabled",
            "crossTenant": False,
            "blobAnon": False,
            "defaultAction": "Allow",
            "bypass": "AzureServices",
            "minTls": "TLS1_2",
            "keyAccess": False,
            "oauthDefault": True,
            "sku": "Standard_LRS",
            "privateEps": 0,
        }
        td = _td("storage", [account])

        auth_error = (
            "AuthorizationFailed: The client does not have authorization to perform action"
            " 'Microsoft.Storage/storageAccounts/blobServices/read'."
        )

        def _az_auth(_args: list, *a: Any, **_: Any) -> tuple:
            return (1, auth_error)

        with patch("checks.s9.az", side_effect=_az_auth):
            results = checks_s9.check_9_storage(SID, SNAME, td)

        blob_ctrl_ids = {"9.2.1", "9.2.2", "9.2.3", "9.2.4", "9.2.5", "9.2.6"}
        file_ctrl_ids = {"9.1.1", "9.1.2", "9.1.3"}
        for r in results:
            if r.control_id in blob_ctrl_ids or r.control_id in file_ctrl_ids:
                self.assertEqual(r.status, ERROR, f"{r.control_id} expected ERROR for auth failure")
                self.assertNotIn("Key Vault", r.details)
                self.assertIn("Reader", r.remediation)

    def test_blob_logging_disabled_returns_fail_for_924_925_926(self) -> None:
        """Data-plane blob logging not enabled — 9.2.4/5/6 should FAIL."""
        account = {
            "name": "nolog",
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
        blob_svc = {
            "deleteRetentionPolicy": {"enabled": True, "days": 7},
            "containerDeleteRetentionPolicy": {"enabled": True, "days": 7},
            "isVersioningEnabled": True,
        }
        blob_log_off = {
            "logging": {"read": False, "write": False, "delete": False},
        }

        def _az_side(args: list, *a: Any, **_: Any) -> tuple:
            if "blob-service-properties" in args:
                return (0, blob_svc)
            if "blob" in args and "service-properties" in args:
                return (0, blob_log_off)
            return (0, [])

        with patch("checks.s9.az", side_effect=_az_side):
            results = checks_s9.check_9_storage(SID, SNAME, td)
        log_results = {r.control_id: r for r in results if r.control_id in ("9.2.4", "9.2.5", "9.2.6")}
        for cid in ("9.2.4", "9.2.5", "9.2.6"):
            self.assertIn(cid, log_results, f"{cid} not found in results")
            self.assertEqual(log_results[cid].status, FAIL, f"{cid} expected FAIL")

    def test_blob_logging_enabled_returns_pass_for_924_925_926(self) -> None:
        """Data-plane blob logging enabled — 9.2.4/5/6 should PASS."""
        account = {
            "name": "logon",
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
        blob_svc = {
            "deleteRetentionPolicy": {"enabled": True, "days": 7},
            "containerDeleteRetentionPolicy": {"enabled": True, "days": 7},
            "isVersioningEnabled": True,
        }
        blob_log_on = {
            "logging": {"read": True, "write": True, "delete": True},
        }

        def _az_side(args: list, *a: Any, **_: Any) -> tuple:
            if "blob-service-properties" in args:
                return (0, blob_svc)
            if "blob" in args and "service-properties" in args:
                return (0, blob_log_on)
            return (0, [])

        with patch("checks.s9.az", side_effect=_az_side):
            results = checks_s9.check_9_storage(SID, SNAME, td)
        log_results = {r.control_id: r for r in results if r.control_id in ("9.2.4", "9.2.5", "9.2.6")}
        for cid in ("9.2.4", "9.2.5", "9.2.6"):
            self.assertIn(cid, log_results, f"{cid} not found in results")
            self.assertEqual(log_results[cid].status, PASS, f"{cid} expected PASS")


if __name__ == "__main__":
    unittest.main()
