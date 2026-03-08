"""Unit tests for az_client.py.

Covers:
- _first_error_line     — pure string helper
- is_firewall_error     — firewall token matching
- _friendly_error       — error message normalisation
- az                    — JSON parsing, subscription flag, empty output
- az_rest               — REST endpoint wrapper
- graph_query           — pagination (skipToken) and subscription batching
- get_and_reset_rate_limit_retry_count — thread-safe counter reset
"""

import json
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

import azure.client as az_client

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok(stdout: str = "", stderr: str = "") -> tuple[int, str, str]:
    """Simulate a successful _run_cmd_with_retries return."""
    return 0, stdout, stderr


def _fail(stderr: str = "some error", rc: int = 1) -> tuple[int, str, str]:
    """Simulate a failed _run_cmd_with_retries return."""
    return rc, "", stderr


# ---------------------------------------------------------------------------
# _first_error_line
# ---------------------------------------------------------------------------


class TestFirstErrorLine(unittest.TestCase):

    def test_empty_string(self) -> None:
        self.assertEqual(az_client._first_error_line(""), "")

    def test_single_line(self) -> None:
        self.assertEqual(az_client._first_error_line("oops"), "oops")

    def test_multiline_returns_first(self) -> None:
        self.assertEqual(az_client._first_error_line("first\nsecond\nthird"), "first")

    def test_leading_blank_lines_skipped(self) -> None:
        self.assertEqual(az_client._first_error_line("\n\nactual error"), "actual error")

    def test_whitespace_stripped(self) -> None:
        self.assertEqual(az_client._first_error_line("  trimmed  "), "trimmed")

    def test_all_blank_lines(self) -> None:
        # Falls through to the final strip() path
        self.assertEqual(az_client._first_error_line("   \n   "), "")


# ---------------------------------------------------------------------------
# is_firewall_error
# ---------------------------------------------------------------------------


class TestIsFirewallError(unittest.TestCase):

    def test_forbiddenbyfirewall(self) -> None:
        self.assertTrue(az_client.is_firewall_error("ForbiddenByFirewall"))

    def test_public_network_access_disabled(self) -> None:
        self.assertTrue(az_client.is_firewall_error("Public network access is disabled"))

    def test_not_allowed_by_firewall_rules(self) -> None:
        self.assertTrue(az_client.is_firewall_error("not allowed by its firewall rules"))

    def test_callers_ip(self) -> None:
        self.assertTrue(az_client.is_firewall_error("Caller's IP address is not allowed"))

    def test_case_insensitive(self) -> None:
        self.assertTrue(az_client.is_firewall_error("FORBIDDENBYFIREWALL"))

    def test_private_link_not_approved(self) -> None:
        # Real error from storage accounts with PublicNetworkAccess=Disabled
        msg = (
            "ERROR: (Forbidden) Connection is not an approved private link and caller was ignored "
            "because bypass is not set to 'AzureServices' and PublicNetworkAccess is set to 'Disabled'."
        )
        self.assertTrue(az_client.is_firewall_error(msg))

    def test_plain_permission_error_is_not_firewall(self) -> None:
        self.assertFalse(az_client.is_firewall_error("AuthorizationFailed"))

    def test_empty_string(self) -> None:
        self.assertFalse(az_client.is_firewall_error(""))


# ---------------------------------------------------------------------------
# _friendly_error
# ---------------------------------------------------------------------------


class TestFriendlyError(unittest.TestCase):

    def test_empty_returns_unknown(self) -> None:
        self.assertEqual(az_client._friendly_error(""), "Unknown error")

    def test_firewall_error_message(self) -> None:
        result = az_client._friendly_error("ForbiddenByFirewall")
        self.assertIn("Firewall blocked", result)
        self.assertNotIn("vault", result.lower())

    def test_authz_error_collapsed(self) -> None:
        result = az_client._friendly_error("AuthorizationFailed")
        self.assertIn("Audit incomplete", result)
        self.assertIn("data-plane permissions", result)

    def test_not_authorized_collapsed(self) -> None:
        result = az_client._friendly_error("The client is not authorized to perform this action")
        self.assertIn("Audit incomplete", result)
        self.assertIn("data-plane permissions", result)

    def test_plain_error_first_line(self) -> None:
        result = az_client._friendly_error("Resource not found\nDetails follow")
        self.assertEqual(result, "Resource not found")

    def test_long_error_truncated(self) -> None:
        long_msg = "x" * 200
        result = az_client._friendly_error(long_msg)
        self.assertEqual(len(result), 160)


# ---------------------------------------------------------------------------
# az()
# ---------------------------------------------------------------------------


class TestAz(unittest.TestCase):

    def _patch(self, return_value: tuple[int, str, str]) -> Any:
        return patch("azure.client._run_cmd_with_retries", return_value=return_value)

    def test_success_parses_json(self) -> None:
        payload = json.dumps({"key": "value"})
        with self._patch(_ok(stdout=payload)):
            rc, data = az_client.az(["account", "show"])
        self.assertEqual(rc, 0)
        self.assertEqual(data, {"key": "value"})

    def test_success_empty_stdout_returns_none(self) -> None:
        with self._patch(_ok(stdout="   ")):
            rc, data = az_client.az(["account", "show"])
        self.assertEqual(rc, 0)
        self.assertIsNone(data)

    def test_success_non_json_stdout_returned_raw(self) -> None:
        with self._patch(_ok(stdout="not-json")):
            rc, data = az_client.az(["account", "show"])
        self.assertEqual(rc, 0)
        self.assertEqual(data, "not-json")

    def test_failure_returns_stderr(self) -> None:
        with self._patch(_fail(stderr="something went wrong")):
            rc, data = az_client.az(["account", "show"])
        self.assertEqual(rc, 1)
        self.assertEqual(data, "something went wrong")

    def test_subscription_flag_appended(self) -> None:
        payload = json.dumps([])
        with patch("azure.client._run_cmd_with_retries", return_value=_ok(stdout=payload)) as m:
            az_client.az(["vm", "list"], sub="sub-123")
        cmd_used = m.call_args[0][0]
        self.assertIn("--subscription", cmd_used)
        self.assertIn("sub-123", cmd_used)

    def test_no_subscription_flag_when_sub_is_none(self) -> None:
        payload = json.dumps([])
        with patch("azure.client._run_cmd_with_retries", return_value=_ok(stdout=payload)) as m:
            az_client.az(["vm", "list"])
        cmd_used = m.call_args[0][0]
        self.assertNotIn("--subscription", cmd_used)

    def test_output_json_always_in_command(self) -> None:
        payload = json.dumps([])
        with patch("azure.client._run_cmd_with_retries", return_value=_ok(stdout=payload)) as m:
            az_client.az(["vm", "list"])
        cmd_used = m.call_args[0][0]
        self.assertIn("--output", cmd_used)
        self.assertIn("json", cmd_used)


# ---------------------------------------------------------------------------
# az_rest()
# ---------------------------------------------------------------------------


class TestAzRest(unittest.TestCase):

    def _patch(self, return_value: tuple[int, str, str]) -> Any:
        return patch("azure.client._run_cmd_with_retries", return_value=return_value)

    def test_success_parses_json(self) -> None:
        payload = json.dumps({"value": []})
        with self._patch(_ok(stdout=payload)):
            rc, data = az_client.az_rest("https://management.azure.com/foo")
        self.assertEqual(rc, 0)
        self.assertEqual(data, {"value": []})

    def test_success_empty_stdout_returns_none(self) -> None:
        with self._patch(_ok(stdout="")):
            rc, data = az_client.az_rest("https://management.azure.com/foo")
        self.assertEqual(rc, 0)
        self.assertIsNone(data)

    def test_failure_returns_stderr(self) -> None:
        with self._patch(_fail(stderr="REST call failed")):
            rc, data = az_client.az_rest("https://management.azure.com/foo")
        self.assertEqual(rc, 1)
        self.assertEqual(data, "REST call failed")

    def test_command_contains_rest_and_url(self) -> None:
        payload = json.dumps({})
        url = "https://graph.microsoft.com/v1.0/test"
        with patch("azure.client._run_cmd_with_retries", return_value=_ok(stdout=payload)) as m:
            az_client.az_rest(url)
        cmd_used = m.call_args[0][0]
        self.assertIn("rest", cmd_used)
        self.assertIn(url, cmd_used)
        self.assertIn("get", cmd_used)


# ---------------------------------------------------------------------------
# graph_query()
# ---------------------------------------------------------------------------


class TestGraphQuery(unittest.TestCase):

    def _response(self, data: list[Any], skip_token: str | None = None) -> tuple[int, str, str]:
        payload: dict[str, Any] = {"data": data, "count": len(data)}
        if skip_token:
            payload["skipToken"] = skip_token
        return 0, json.dumps(payload), ""

    def test_single_page_single_batch(self) -> None:
        rows = [{"id": "r1"}, {"id": "r2"}]
        with patch("azure.client._run_cmd_with_retries", return_value=self._response(rows)):
            rc, data = az_client.graph_query("Resources | limit 2", ["sub-1"])
        self.assertEqual(rc, 0)
        self.assertEqual(data, rows)

    def test_pagination_follows_skip_token(self) -> None:
        page1 = self._response([{"id": "r1"}], skip_token="tok-abc")
        page2 = self._response([{"id": "r2"}])
        with patch("azure.client._run_cmd_with_retries", side_effect=[page1, page2]) as m:
            rc, data = az_client.graph_query("Resources", ["sub-1"])
        self.assertEqual(rc, 0)
        self.assertEqual(len(data), 2)
        self.assertEqual(m.call_count, 2)
        # Second call must include the skip token
        second_cmd = m.call_args_list[1][0][0]
        self.assertIn("tok-abc", second_cmd)

    def test_subscription_batching(self) -> None:
        """More than 10 subscriptions must be split into batches of 10."""
        sub_ids = [f"sub-{i}" for i in range(13)]
        single_page = self._response([{"id": "r1"}])
        with patch("azure.client._run_cmd_with_retries", return_value=single_page) as m:
            rc, data = az_client.graph_query("Resources", sub_ids)
        self.assertEqual(rc, 0)
        # 13 subs → 2 batches → 2 calls
        self.assertEqual(m.call_count, 2)
        # Combined data: 1 row × 2 batches
        self.assertEqual(len(data), 2)

    def test_subprocess_failure_returns_error(self) -> None:
        with patch("azure.client._run_cmd_with_retries", return_value=_fail(stderr="query failed")):
            rc, data = az_client.graph_query("Resources", ["sub-1"])
        self.assertEqual(rc, 1)

    def test_json_parse_error_returns_error(self) -> None:
        with patch("azure.client._run_cmd_with_retries", return_value=_ok(stdout="not-json")):
            rc, data = az_client.graph_query("Resources", ["sub-1"])
        self.assertEqual(rc, 1)
        self.assertIn("Parse error", data)

    def test_empty_subscription_list_returns_empty(self) -> None:
        with patch("azure.client._run_cmd_with_retries") as m:
            rc, data = az_client.graph_query("Resources", [])
        self.assertEqual(rc, 0)
        self.assertEqual(data, [])
        m.assert_not_called()


# ---------------------------------------------------------------------------
# get_and_reset_rate_limit_retry_count()
# ---------------------------------------------------------------------------


class TestRateLimitCounter(unittest.TestCase):

    def setUp(self) -> None:
        # Reset counter to known state before each test
        az_client.get_and_reset_rate_limit_retry_count()

    def test_starts_at_zero(self) -> None:
        self.assertEqual(az_client.get_and_reset_rate_limit_retry_count(), 0)

    def test_resets_after_read(self) -> None:
        az_client.get_and_reset_rate_limit_retry_count()
        self.assertEqual(az_client.get_and_reset_rate_limit_retry_count(), 0)

    def test_counter_incremented_by_retry(self) -> None:
        """A 429 response from _run_cmd_with_retries increments the counter."""
        # Simulate a transient throttle followed by success
        responses = [
            (1, "", "429 Too Many Requests"),
            (0, json.dumps({}), ""),
        ]
        with patch("azure.client.subprocess.Popen") as mock_popen, patch("azure.client.time.sleep", lambda s: None):

            def _side(cmd: list[str], **kw: Any) -> Any:
                call_num = mock_popen.call_count - 1
                rc_val, out_val, err_val = responses[call_num]
                proc = MagicMock()
                proc.returncode = rc_val
                proc.communicate.return_value = (out_val, err_val)
                return proc

            mock_popen.side_effect = _side
            az_client.az(["account", "show"])
        count = az_client.get_and_reset_rate_limit_retry_count()
        self.assertGreaterEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
