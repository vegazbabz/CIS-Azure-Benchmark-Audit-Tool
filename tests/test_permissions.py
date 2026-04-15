"""Unit tests for identity, role listing, and preflight permission checks.

These tests validate helper behavior without calling real Azure APIs by
mocking CLI wrappers and selected functions in the audit module.
"""

from __future__ import annotations

import os
import unittest
from typing import Any
from unittest.mock import patch

import azure.identity as az_identity


class TestPermissionHelpers(unittest.TestCase):
    """Covers low-level identity and role helper functions."""

    @patch("azure.identity.az")
    def test_get_signed_in_user_id_success(self, mock_az: Any) -> None:
        """Returns object ID when signed-in-user query succeeds immediately."""
        mock_az.return_value = (0, {"id": "abcd-1234", "displayName": "Test User"})
        uid = az_identity.get_signed_in_user_id()
        self.assertEqual(uid, "abcd-1234")
        mock_az.assert_called_with(["ad", "signed-in-user", "show"])

    @patch("azure.identity.az")
    def test_get_signed_in_user_id_upn_fallback(self, mock_az: Any) -> None:
        """Falls back from object-id lookup to UPN resolution path."""
        # first call fails, second returns UPN, third resolves to objectId
        mock_az.side_effect = [(1, "error"), (0, "user@contoso.com"), (0, {"id": "abcd-5678"})]
        uid = az_identity.get_signed_in_user_id()
        self.assertEqual(uid, "abcd-5678")
        expected = [
            ["ad", "signed-in-user", "show"],
            ["account", "show", "--query", "user.name"],
            ["ad", "user", "show", "--id", "user@contoso.com"],
        ]
        self.assertEqual(mock_az.call_args_list, [unittest.mock.call(x) for x in expected])

    @patch("azure.identity.az")
    def test_get_signed_in_user_id_failure(self, mock_az: Any) -> None:
        """Returns ``None`` when all identity lookup attempts fail."""
        mock_az.return_value = (1, "error")
        self.assertIsNone(az_identity.get_signed_in_user_id())

    @patch("azure.identity.az")
    def test_list_roles_per_subscription(self, mock_az: Any) -> None:
        """Lists role assignments for a GUID assignee in subscription scope."""
        mock_az.return_value = (0, ["Reader", "Security Reader"])
        guid = "abcd1234-5678-1234-5678-abcdefabcdef"
        rc, roles = az_identity.list_role_names_for_user(guid, "sub")
        self.assertEqual(rc, 0)
        self.assertListEqual(roles, ["Reader", "Security Reader"])
        mock_az.assert_called_with(
            [
                "role",
                "assignment",
                "list",
                "--assignee",
                guid,
                "--include-inherited",
                "--include-groups",
                "--subscription",
                "sub",
                "--query",
                "[].roleDefinitionName",
            ]
        )

    @patch("azure.identity.az")
    def test_list_roles_no_subscription(self, mock_az: Any) -> None:
        """Lists role assignments for UPN assignee without subscription scope."""
        mock_az.return_value = (0, ["Reader"])
        rc, roles = az_identity.list_role_names_for_user("user@contoso.com")
        self.assertEqual(rc, 0)
        self.assertListEqual(roles, ["Reader"])
        mock_az.assert_called_with(
            [
                "role",
                "assignment",
                "list",
                "--assignee",
                "user@contoso.com",
                "--include-inherited",
                "--include-groups",
                "--query",
                "[].roleDefinitionName",
            ]
        )

    @patch("azure.identity.az")
    def test_list_roles_error_passthrough(self, mock_az: Any) -> None:
        """Propagates CLI error output unchanged to the caller."""
        mock_az.return_value = (2, "boom")
        rc, out = az_identity.list_role_names_for_user("u", "sub")
        self.assertEqual(rc, 2)
        self.assertEqual(out, "boom")

    @patch("azure.identity.az")
    def test_list_roles_with_scope(self, mock_az: Any) -> None:
        """Uses --scope instead of --subscription when scope is provided."""
        mock_az.return_value = (0, ["Security Reader", "Security Admin"])
        guid = "abcd1234-5678-1234-5678-abcdefabcdef"
        mg_scope = "/providers/Microsoft.Management/managementGroups/tenant-id"
        rc, roles = az_identity.list_role_names_for_user(guid, scope=mg_scope)
        self.assertEqual(rc, 0)
        self.assertListEqual(roles, ["Security Reader", "Security Admin"])
        mock_az.assert_called_with(
            [
                "role",
                "assignment",
                "list",
                "--assignee",
                guid,
                "--include-inherited",
                "--include-groups",
                "--scope",
                mg_scope,
                "--query",
                "[].roleDefinitionName",
            ]
        )


class TestCheckUserPermissions(unittest.TestCase):
    """Covers check_user_permissions aggregation and edge cases."""

    @patch("azure.identity.az")
    def test_duplicate_roles_counted_once_per_sub(self, mock_az: Any) -> None:
        """Role appearing twice in one sub's result (inherited + direct) counts as 1, not 2."""
        # Call sequence: signed-in-user, sub1 roles, sub2 roles, tenantId, MG roles
        mock_az.side_effect = [
            (0, {"id": "uid-001"}),                          # get_signed_in_user_id
            (0, ["Reader", "Reader", "Owner"]),              # sub1: Reader duplicated
            (0, ["Reader", "Owner"]),                        # sub2
            (0, "tenant-abc"),                               # account show --query tenantId
            (0, []),                                         # MG scope query
        ]
        result = az_identity.check_user_permissions(["sub1", "sub2"])
        # Reader assigned at 2 subs — must not exceed total_subs
        self.assertLessEqual(result["role_sub_count"]["Reader"], result["total_subs"])
        self.assertEqual(result["role_sub_count"]["Reader"], 2)

    @patch("azure.identity.az")
    def test_management_group_security_roles_detected(self, mock_az: Any) -> None:
        """Security roles assigned only at tenant root MG are picked up by the MG query."""
        mock_az.side_effect = [
            (0, {"id": "uid-001"}),             # get_signed_in_user_id
            (0, ["Reader", "Owner"]),            # sub1: no security role
            (0, ["Reader"]),                     # sub2: no security role
            (0, "tenant-abc"),                   # account show --query tenantId
            (0, ["Security Reader", "Security Admin"]),  # MG scope: security roles present
        ]
        result = az_identity.check_user_permissions(["sub1", "sub2"])
        self.assertIn("Security Reader", result["roles"])
        self.assertIn("Security Admin", result["roles"])
        # MG roles should be credited to all subscriptions
        self.assertEqual(result["role_sub_count"]["Security Reader"], 2)
        self.assertEqual(result["role_sub_count"]["Security Admin"], 2)
        # all_clear should be True: has reader-equivalent AND security role
        self.assertTrue(result["all_clear"])
        self.assertEqual(result["warnings"], [])


class TestPreflight(unittest.TestCase):
    """Covers preflight gate behavior before running a full audit."""

    @patch("builtins.print")
    @patch("cis_azure_audit.get_signed_in_user_id")
    @patch("cis_azure_audit.list_role_names_for_user")
    def test_preflight_success(self, mock_list: Any, mock_user: Any, _mock_print: Any) -> None:
        """Preflight passes when Reader + Security Reader are present."""
        mock_user.return_value = "u"

        def list_side(user_id: str, sub: str | None = None) -> tuple[int, list[str]]:
            if sub:
                return 0, ["Reader", "Security Reader"]
            return 0, []

        mock_list.side_effect = list_side
        import cis_azure_audit as mod

        subs = [{"name": "sub1", "id": "s1"}]
        mod.preflight_permissions(subs)

    @patch("builtins.print")
    @patch("cis_azure_audit.get_signed_in_user_id")
    @patch("cis_azure_audit.list_role_names_for_user")
    def test_preflight_missing(self, mock_list: Any, mock_user: Any, _mock_print: Any) -> None:
        """Preflight exits with error when signed-in identity is unavailable."""
        mock_user.return_value = None
        import cis_azure_audit as mod

        subs = [{"name": "sub1", "id": "s1"}]
        with self.assertRaises(SystemExit) as cm:
            mod.preflight_permissions(subs)
        self.assertEqual(cm.exception.code, 1)

    @patch("builtins.print")
    @patch("cis_azure_audit.get_signed_in_user_id")
    @patch("cis_azure_audit.list_role_names_for_user")
    def test_preflight_roles_missing(self, mock_list: Any, mock_user: Any, _mock_print: Any) -> None:
        """Preflight exits with error when no security-prefixed role exists."""
        mock_user.return_value = "u"

        def list_side(user_id: str, sub: str | None = None) -> tuple[int, list[str]]:
            if sub:
                return 0, ["Reader"]
            return 0, []

        mock_list.side_effect = list_side
        import cis_azure_audit as mod

        subs = [{"name": "sub1", "id": "s1"}]
        with self.assertRaises(SystemExit) as cm:
            mod.preflight_permissions(subs)
        self.assertEqual(cm.exception.code, 1)

    @patch("builtins.print")
    @patch("cis_azure_audit.get_signed_in_user_id")
    @patch("cis_azure_audit.list_role_names_for_user")
    def test_preflight_with_security_admin(self, mock_list: Any, mock_user: Any, _mock_print: Any) -> None:
        """Preflight passes when Security Admin is present instead of Reader role variant."""
        mock_user.return_value = "u"

        def list_side(user_id: str, sub: str | None = None) -> tuple[int, list[str]]:
            if sub:
                return 0, ["Reader", "Security Admin"]
            return 0, []

        mock_list.side_effect = list_side
        import cis_azure_audit as mod

        subs = [{"name": "sub1", "id": "s1"}]
        mod.preflight_permissions(subs)

    @patch("cis_azure_audit.generate_html")
    @patch("cis_azure_audit.run_audit", return_value=[])
    @patch("cis_azure_audit.get_subscriptions", return_value=[{"name": "sub1", "id": "s1"}])
    @patch("cis_azure_audit.check_user_permissions")
    @patch("cis_azure_audit.az")
    def test_skip_preflight_flag(
        self,
        mock_az: Any,
        mock_cpu: Any,
        _mock_subs: Any,
        _mock_audit: Any,
        _mock_html: Any,
    ) -> None:
        """--skip-preflight prevents check_user_permissions from being called in main()."""
        mock_az.side_effect = [
            (0, {"azure-cli": "2.0"}),  # az version
            (0, ["resource-graph"]),  # extension list (non-empty → skip install)
            (0, {"user": "u", "tenant": "t"}),  # account show
        ]
        import cis_azure_audit as mod

        with patch("sys.argv", ["prog", "--skip-preflight"]):
            mod.main()
        mock_cpu.assert_not_called()

    @patch("cis_azure_audit.generate_html")
    @patch("cis_azure_audit.run_audit", return_value=[])
    @patch("cis_azure_audit.get_subscriptions", return_value=[{"name": "sub1", "id": "s1"}])
    @patch("cis_azure_audit.check_user_permissions")
    @patch("cis_azure_audit.az")
    def test_skip_preflight_envvar(
        self,
        mock_az: Any,
        mock_cpu: Any,
        _mock_subs: Any,
        _mock_audit: Any,
        _mock_html: Any,
    ) -> None:
        """SKIP_PREFLIGHT env var prevents check_user_permissions from being called in main()."""
        mock_az.side_effect = [
            (0, {"azure-cli": "2.0"}),
            (0, ["resource-graph"]),
            (0, {"user": "u", "tenant": "t"}),
        ]
        import cis_azure_audit as mod

        os.environ["SKIP_PREFLIGHT"] = "1"
        try:
            with patch("sys.argv", ["prog"]):
                mod.main()
        finally:
            del os.environ["SKIP_PREFLIGHT"]
        mock_cpu.assert_not_called()
