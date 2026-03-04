"""Unit tests for pure helper functions in cis_azure_audit.

Tests here cover functions that contain logic but make no external calls:
  - port_in_range   — NSG port specification matching
  - nsg_bad_rules   — NSG inbound rule filtering
  - _ctrl_sort_key  — CIS control ID numeric sort key
"""

from __future__ import annotations

import unittest

from cis_azure_audit import _ctrl_sort_key, nsg_bad_rules, port_in_range

# ---------------------------------------------------------------------------
# port_in_range
# ---------------------------------------------------------------------------


class TestPortInRange(unittest.TestCase):
    """Validates every branch of the port specification parser."""

    def test_wildcard_star(self) -> None:
        self.assertTrue(port_in_range("*", 22))

    def test_wildcard_empty(self) -> None:
        self.assertTrue(port_in_range("", 22))

    def test_exact_match(self) -> None:
        self.assertTrue(port_in_range("22", 22))

    def test_exact_no_match(self) -> None:
        self.assertFalse(port_in_range("443", 22))

    def test_range_low_boundary(self) -> None:
        self.assertTrue(port_in_range("1024-65535", 1024))

    def test_range_high_boundary(self) -> None:
        self.assertTrue(port_in_range("1024-65535", 65535))

    def test_range_within(self) -> None:
        self.assertTrue(port_in_range("8000-9000", 8080))

    def test_range_below(self) -> None:
        self.assertFalse(port_in_range("1024-65535", 80))

    def test_malformed_range(self) -> None:
        self.assertFalse(port_in_range("abc-def", 22))

    def test_non_numeric_exact(self) -> None:
        self.assertFalse(port_in_range("rdp", 3389))

    def test_whitespace_stripped(self) -> None:
        self.assertTrue(port_in_range(" 22 ", 22))


# ---------------------------------------------------------------------------
# nsg_bad_rules
# ---------------------------------------------------------------------------

_ALLOW_INBOUND_TCP_FROM_ANY = {
    "name": "bad-rule",
    "access": "Allow",
    "direction": "Inbound",
    "protocol": "Tcp",
    "sourceAddressPrefix": "*",
    "destinationPortRange": "22",
    "destinationPortRanges": [],
}


def _rule(**overrides: object) -> dict[str, object]:
    """Return a copy of the canonical bad rule with selective overrides."""
    r: dict[str, object] = dict(_ALLOW_INBOUND_TCP_FROM_ANY)
    r.update(overrides)
    return r


class TestNsgBadRules(unittest.TestCase):
    """Validates nsg_bad_rules filtering logic."""

    def test_detects_bad_rule(self) -> None:
        self.assertEqual(nsg_bad_rules([_rule()], 22), ["bad-rule"])

    def test_deny_rule_ignored(self) -> None:
        self.assertEqual(nsg_bad_rules([_rule(access="Deny")], 22), [])

    def test_outbound_rule_ignored(self) -> None:
        self.assertEqual(nsg_bad_rules([_rule(direction="Outbound")], 22), [])

    def test_wrong_protocol_ignored(self) -> None:
        # Default protos=("tcp","*") so UDP is excluded
        self.assertEqual(nsg_bad_rules([_rule(protocol="Udp")], 22), [])

    def test_asg_source_ignored(self) -> None:
        asg_id = "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/asg"
        self.assertEqual(nsg_bad_rules([_rule(sourceAddressPrefix=asg_id)], 22), [])

    def test_private_source_ignored(self) -> None:
        self.assertEqual(nsg_bad_rules([_rule(sourceAddressPrefix="10.0.0.0/8")], 22), [])

    def test_internet_keyword_flagged(self) -> None:
        self.assertEqual(nsg_bad_rules([_rule(sourceAddressPrefix="Internet")], 22), ["bad-rule"])

    def test_cidr_slash_zero_flagged(self) -> None:
        self.assertEqual(nsg_bad_rules([_rule(sourceAddressPrefix="0.0.0.0/0")], 22), ["bad-rule"])

    def test_port_mismatch_ignored(self) -> None:
        self.assertEqual(nsg_bad_rules([_rule(destinationPortRange="443")], 22), [])

    def test_port_ranges_list(self) -> None:
        r = _rule(destinationPortRange="", destinationPortRanges=["8000-9000", "22"])
        self.assertEqual(nsg_bad_rules([r], 22), ["bad-rule"])

    def test_wildcard_port_flagged(self) -> None:
        self.assertEqual(nsg_bad_rules([_rule(destinationPortRange="*")], 3389), ["bad-rule"])

    def test_properties_wrapper_format(self) -> None:
        """Resource Graph returns fields at top-level; az CLI wraps in 'properties'."""
        wrapped = {"name": "bad-rule", "properties": _rule(name="bad-rule")}
        self.assertEqual(nsg_bad_rules([wrapped], 22), ["bad-rule"])

    def test_empty_rules_list(self) -> None:
        self.assertEqual(nsg_bad_rules([], 22), [])

    def test_none_rules_list(self) -> None:
        self.assertEqual(nsg_bad_rules(None, 22), [])  # type: ignore[arg-type]

    def test_udp_proto_filter(self) -> None:
        udp_rule = _rule(protocol="Udp")
        self.assertEqual(nsg_bad_rules([udp_rule], 22, protos=("udp", "*")), ["bad-rule"])

    def test_multiple_rules_returns_all_bad(self) -> None:
        r1 = _rule(name="r1")
        r2 = _rule(name="r2", destinationPortRange="443")
        r3 = _rule(name="r3")
        result = nsg_bad_rules([r1, r2, r3], 22)
        self.assertEqual(result, ["r1", "r3"])


# ---------------------------------------------------------------------------
# _ctrl_sort_key
# ---------------------------------------------------------------------------


class TestCtrlSortKey(unittest.TestCase):
    """Validates numeric sort key generation for CIS control IDs."""

    def test_simple_two_part(self) -> None:
        self.assertEqual(_ctrl_sort_key("1.1"), (1, 1))

    def test_three_part(self) -> None:
        self.assertEqual(_ctrl_sort_key("9.3.10"), (9, 3, 10))

    def test_sorts_numerically(self) -> None:
        ids = ["9.3.10", "9.3.2", "9.3.9"]
        self.assertEqual(sorted(ids, key=_ctrl_sort_key), ["9.3.2", "9.3.9", "9.3.10"])

    def test_non_numeric_segment_is_zero(self) -> None:
        self.assertEqual(_ctrl_sort_key("1.a.3"), (1, 0, 3))

    def test_single_segment(self) -> None:
        self.assertEqual(_ctrl_sort_key("5"), (5,))


if __name__ == "__main__":
    unittest.main()
