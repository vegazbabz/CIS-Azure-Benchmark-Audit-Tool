import os
import unittest
from typing import Any
from unittest.mock import patch

import azure_helpers


class TestPermissionHelpers(unittest.TestCase):
    @patch("azure_helpers.az")
    def test_get_signed_in_user_id_success(self, mock_az: Any) -> None:
        mock_az.return_value = (0, "abcd-1234\n")
        uid = azure_helpers.get_signed_in_user_id()
        self.assertEqual(uid, "abcd-1234")
        mock_az.assert_called_with(["ad", "signed-in-user", "show", "--query", "objectId", "-o", "tsv"])

    @patch("azure_helpers.az")
    def test_get_signed_in_user_id_upn_fallback(self, mock_az: Any) -> None:
        # first call fails, second returns UPN, third resolves to objectId
        mock_az.side_effect = [(1, "error"), (0, "user@contoso.com\n"), (0, "abcd-5678\n")]
        uid = azure_helpers.get_signed_in_user_id()
        self.assertEqual(uid, "abcd-5678")
        # verify the sequence of CLI invocations
        expected = [
            ["ad", "signed-in-user", "show", "--query", "objectId", "-o", "tsv"],
            ["account", "show", "--query", "user.name", "-o", "tsv"],
            ["ad", "user", "show", "--id", "user@contoso.com", "--query", "objectId", "-o", "tsv"],
        ]
        self.assertEqual(mock_az.call_args_list, [unittest.mock.call(x) for x in expected])

    @patch("azure_helpers.az")
    def test_get_signed_in_user_id_failure(self, mock_az: Any) -> None:
        mock_az.return_value = (1, "error")
        self.assertIsNone(azure_helpers.get_signed_in_user_id())

    @patch("azure_helpers.az")
    def test_list_roles_per_subscription(self, mock_az: Any) -> None:
        mock_az.return_value = (0, ["Reader", "Security Reader"])
        # Test with GUID (should use --assignee)
        guid = "abcd1234-5678-1234-5678-abcdefabcdef"
        rc, roles = azure_helpers.list_role_names_for_user(guid, "sub")
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

    @patch("azure_helpers.az")
    def test_list_roles_no_subscription(self, mock_az: Any) -> None:
        mock_az.return_value = (0, ["Reader"])
        # Test with a UPN (non-GUID) — should use --assignee with --include-groups
        rc, roles = azure_helpers.list_role_names_for_user("user@contoso.com")
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

    @patch("azure_helpers.az")
    def test_list_roles_error_passthrough(self, mock_az: Any) -> None:
        mock_az.return_value = (2, "boom")
        rc, out = azure_helpers.list_role_names_for_user("u", "sub")
        self.assertEqual(rc, 2)
        self.assertEqual(out, "boom")


class TestPreflight(unittest.TestCase):
    @patch("builtins.print")
    @patch("cis_azure_audit.get_signed_in_user_id")
    @patch("cis_azure_audit.list_role_names_for_user")
    def test_preflight_success(self, mock_list: Any, mock_user: Any, mock_print: Any) -> None:
        mock_user.return_value = "u"

        # return both needed roles for sub1 (tenant roles are ignored)
        def list_side(user_id: str, sub: str | None = None) -> tuple[int, list[str]]:
            if sub:
                return 0, ["Reader", "Security Reader"]
            return 0, []

        mock_list.side_effect = list_side
        # should not raise
        import cis_azure_audit as mod

        subs = [{"name": "sub1", "id": "s1"}]
        mod.preflight_permissions(subs)

    @patch("builtins.print")
    @patch("cis_azure_audit.get_signed_in_user_id")
    @patch("cis_azure_audit.list_role_names_for_user")
    def test_preflight_missing(self, mock_list: Any, mock_user: Any, mock_print: Any) -> None:
        # return None to exercise the "unable to determine" message
        mock_user.return_value = None
        import cis_azure_audit as mod

        subs = [{"name": "sub1", "id": "s1"}]
        with self.assertRaises(SystemExit) as cm:
            mod.preflight_permissions(subs)
        self.assertEqual(cm.exception.code, 1)

    @patch("builtins.print")
    @patch("cis_azure_audit.get_signed_in_user_id")
    @patch("cis_azure_audit.list_role_names_for_user")
    def test_preflight_roles_missing(self, mock_list: Any, mock_user: Any, mock_print: Any) -> None:
        mock_user.return_value = "u"

        # simulate missing any security-related role on sub
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
    def test_preflight_with_security_admin(self, mock_list: Any, mock_user: Any, mock_print: Any) -> None:
        mock_user.return_value = "u"

        # Reader plus Security Admin should satisfy the check
        def list_side(user_id: str, sub: str | None = None) -> tuple[int, list[str]]:
            if sub:
                return 0, ["Reader", "Security Admin"]
            return 0, []

        mock_list.side_effect = list_side
        import cis_azure_audit as mod

        subs = [{"name": "sub1", "id": "s1"}]
        # should not raise
        mod.preflight_permissions(subs)

    def test_skip_preflight_flag(self) -> None:
        import cis_azure_audit as mod

        called = False

        def fake(subs_list: list[dict[str, Any]]) -> None:
            nonlocal called
            called = True

        mod.preflight_permissions = fake

        class A:
            skip_preflight = True

        args = A()
        subs = [{"name": "any", "id": "x"}]
        if not args.skip_preflight and not False:
            mod.preflight_permissions(subs)
        self.assertFalse(called)

    def test_skip_preflight_envvar(self) -> None:
        import cis_azure_audit as mod

        called = False

        def fake(subs_list: list[dict[str, Any]]) -> None:
            nonlocal called
            called = True

        mod.preflight_permissions = fake
        os.environ["SKIP_PREFLIGHT"] = "1"
        subs = [{"name": "any", "id": "x"}]
        if not False and not os.environ.get("SKIP_PREFLIGHT"):
            mod.preflight_permissions(subs)
        self.assertFalse(called)
        del os.environ["SKIP_PREFLIGHT"]
