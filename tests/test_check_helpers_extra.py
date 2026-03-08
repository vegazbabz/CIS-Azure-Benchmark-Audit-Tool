"""Unit tests for cis_check_helpers: _idx, _err, _info."""

from __future__ import annotations

import unittest

from cis.check_helpers import _err, _idx, _info
from cis.config import ERROR, INFO


class TestIdx(unittest.TestCase):
    """_idx retrieves per-subscription records from the prefetch dict."""

    def _td(self) -> dict:
        return {
            "nsgs": {
                "sub-abc": [{"name": "nsg1"}, {"name": "nsg2"}],
                "sub-xyz": [{"name": "nsg3"}],
            }
        }

    def test_returns_list_for_known_sub(self) -> None:
        result = _idx(self._td(), "nsgs", "sub-abc")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["name"], "nsg1")

    def test_case_insensitive_sub_id(self) -> None:
        result = _idx(self._td(), "nsgs", "SUB-ABC")
        self.assertEqual(len(result), 2)

    def test_unknown_sub_returns_empty_list(self) -> None:
        result = _idx(self._td(), "nsgs", "sub-missing")
        self.assertEqual(result, [])

    def test_unknown_key_returns_empty_list(self) -> None:
        result = _idx(self._td(), "storage", "sub-abc")
        self.assertEqual(result, [])

    def test_empty_tenant_data_returns_empty_list(self) -> None:
        self.assertEqual(_idx({}, "nsgs", "sub-abc"), [])

    def test_non_dict_value_returns_empty_list(self) -> None:
        # If a key maps to something other than a dict, return []
        self.assertEqual(_idx({"nsgs": "bad"}, "nsgs", "sub-abc"), [])

    def test_non_list_sub_value_returns_empty_list(self) -> None:
        td = {"nsgs": {"sub-abc": "bad"}}
        self.assertEqual(_idx(td, "nsgs", "sub-abc"), [])


class TestErr(unittest.TestCase):
    """_err builds ERROR result objects."""

    def test_returns_error_status(self) -> None:
        r = _err("1.1", "Title", 1, "Sec", "something went wrong")
        self.assertEqual(r.status, ERROR)

    def test_control_id_and_title(self) -> None:
        r = _err("7.3", "My Check", 2, "Section 7", "oops")
        self.assertEqual(r.control_id, "7.3")
        self.assertEqual(r.title, "My Check")

    def test_message_truncated_at_160(self) -> None:
        # _err passes the message through _friendly_error, which truncates
        # unrecognised plain-text messages at 160 characters.
        long_msg = "x" * 300
        r = _err("1.1", "T", 1, "S", long_msg)
        self.assertEqual(len(r.details), 160)

    def test_short_message_not_truncated(self) -> None:
        r = _err("1.1", "T", 1, "S", "short")
        self.assertEqual(r.details, "short")

    def test_optional_sid_sname_resource(self) -> None:
        r = _err("1.1", "T", 1, "S", "err", sid="s1", sname="Sub One", resource="res1")
        self.assertEqual(r.subscription_id, "s1")
        self.assertEqual(r.subscription_name, "Sub One")
        self.assertEqual(r.resource, "res1")

    def test_defaults_empty_strings(self) -> None:
        r = _err("1.1", "T", 1, "S", "err")
        self.assertEqual(r.subscription_id, "")
        self.assertEqual(r.subscription_name, "")
        self.assertEqual(r.resource, "")


class TestInfo(unittest.TestCase):
    """_info builds INFO result objects."""

    def test_returns_info_status(self) -> None:
        r = _info("5.1", "Title", 1, "Sec", "not applicable")
        self.assertEqual(r.status, INFO)

    def test_message_stored_in_details(self) -> None:
        r = _info("5.1", "T", 1, "S", "no resources found")
        self.assertEqual(r.details, "no resources found")

    def test_optional_sid_sname(self) -> None:
        r = _info("5.1", "T", 1, "S", "msg", sid="s1", sname="Sub")
        self.assertEqual(r.subscription_id, "s1")
        self.assertEqual(r.subscription_name, "Sub")

    def test_tenant_level_no_sub(self) -> None:
        r = _info("5.1", "T", 1, "S", "tenant-wide")
        self.assertEqual(r.subscription_id, "")
        self.assertEqual(r.subscription_name, "")

    def test_remediation_empty(self) -> None:
        r = _info("5.1", "T", 1, "S", "msg")
        self.assertEqual(r.remediation, "")


if __name__ == "__main__":
    unittest.main()
