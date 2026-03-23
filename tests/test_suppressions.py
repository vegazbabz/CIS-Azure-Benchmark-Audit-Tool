"""Unit tests for cis/suppressions.py: load_suppressions, apply_suppressions, _find_match."""

from __future__ import annotations

import datetime
import tempfile
import unittest
from pathlib import Path

from cis.config import ERROR, FAIL, INFO, MANUAL, PASS, SUPPRESSED
from cis.models import R
from cis.suppressions import apply_suppressions, load_suppressions


def _r(
    control_id: str = "7.1",
    status: str = FAIL,
    resource: str = "my-nsg",
    subscription_name: str = "Production",
    details: str = "Open SSH port.",
) -> R:
    return R(
        control_id=control_id,
        title="Test control",
        level=1,
        section="Networking",
        status=status,
        details=details,
        subscription_id="00000000-0000-0000-0000-000000000001",
        subscription_name=subscription_name,
        resource=resource,
    )


def _future(days: int = 30) -> str:
    return (datetime.date.today() + datetime.timedelta(days=days)).isoformat()


def _past(days: int = 30) -> str:
    return (datetime.date.today() - datetime.timedelta(days=days)).isoformat()


def _toml_file(content: str) -> tuple[tempfile.TemporaryDirectory, Path]:
    tmp = tempfile.TemporaryDirectory()
    path = Path(tmp.name) / "suppressions.toml"
    path.write_text(content, encoding="utf-8")
    return tmp, path


# ── load_suppressions ─────────────────────────────────────────────────────


class TestLoadSuppressions(unittest.TestCase):
    def test_missing_file_returns_empty(self) -> None:
        result = load_suppressions(Path("/nonexistent/suppressions.toml"))
        self.assertEqual(result, [])

    def test_valid_suppression_loaded(self) -> None:
        toml = f"""\
[[suppressions]]
control_id    = "7.1"
resource      = "jumphost-nsg"
subscription  = "Production"
justification = "Intentional RDP jump host"
expires       = "{_future(30)}"
"""
        tmp, path = _toml_file(toml)
        try:
            result = load_suppressions(path)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["control_id"], "7.1")
            self.assertEqual(result[0]["resource"], "jumphost-nsg")
            self.assertEqual(result[0]["subscription"], "Production")
            self.assertIsInstance(result[0]["expires"], datetime.date)
        finally:
            tmp.cleanup()

    def test_expired_suppression_skipped(self) -> None:
        toml = f"""\
[[suppressions]]
control_id    = "7.1"
justification = "Old risk"
expires       = "{_past(10)}"
"""
        tmp, path = _toml_file(toml)
        try:
            result = load_suppressions(path)
            self.assertEqual(result, [])
        finally:
            tmp.cleanup()

    def test_far_future_expiry_capped(self) -> None:
        far = (datetime.date.today() + datetime.timedelta(days=500)).isoformat()
        toml = f"""\
[[suppressions]]
control_id    = "7.1"
justification = "Long risk"
expires       = "{far}"
"""
        tmp, path = _toml_file(toml)
        try:
            result = load_suppressions(path)
            self.assertEqual(len(result), 1)
            max_date = datetime.date.today() + datetime.timedelta(days=365)
            self.assertEqual(result[0]["expires"], max_date)
        finally:
            tmp.cleanup()

    def test_missing_required_field_exits(self) -> None:
        toml = f"""\
[[suppressions]]
control_id    = "7.1"
expires       = "{_future(30)}"
"""
        tmp, path = _toml_file(toml)
        try:
            with self.assertRaises(SystemExit):
                load_suppressions(path)
        finally:
            tmp.cleanup()

    def test_invalid_date_exits(self) -> None:
        toml = """\
[[suppressions]]
control_id    = "7.1"
justification = "Bad date"
expires       = "not-a-date"
"""
        tmp, path = _toml_file(toml)
        try:
            with self.assertRaises(SystemExit):
                load_suppressions(path)
        finally:
            tmp.cleanup()

    def test_empty_suppressions_array(self) -> None:
        tmp, path = _toml_file("[other_section]\nkey = 'value'\n")
        try:
            result = load_suppressions(path)
            self.assertEqual(result, [])
        finally:
            tmp.cleanup()

    def test_multiple_entries_mixed_validity(self) -> None:
        toml = f"""\
[[suppressions]]
control_id    = "7.1"
justification = "Active"
expires       = "{_future(30)}"

[[suppressions]]
control_id    = "8.1"
justification = "Expired"
expires       = "{_past(10)}"

[[suppressions]]
control_id    = "9.1"
justification = "Also active"
expires       = "{_future(60)}"
"""
        tmp, path = _toml_file(toml)
        try:
            result = load_suppressions(path)
            self.assertEqual(len(result), 2)
            ids = [s["control_id"] for s in result]
            self.assertIn("7.1", ids)
            self.assertIn("9.1", ids)
            self.assertNotIn("8.1", ids)
        finally:
            tmp.cleanup()


# ── apply_suppressions ────────────────────────────────────────────────────


class TestApplySuppressions(unittest.TestCase):
    def _sup(
        self,
        control_id: str = "7.1",
        resource: str | None = None,
        subscription: str | None = None,
        justification: str = "Accepted risk",
        days: int = 30,
    ) -> dict:
        d: dict = {
            "control_id": control_id,
            "justification": justification,
            "expires": datetime.date.today() + datetime.timedelta(days=days),
        }
        if resource is not None:
            d["resource"] = resource
        if subscription is not None:
            d["subscription"] = subscription
        return d

    def test_empty_suppressions_returns_results_unchanged(self) -> None:
        results = [_r(), _r(status=PASS)]
        out = apply_suppressions(results, [])
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0].status, FAIL)
        self.assertEqual(out[1].status, PASS)

    def test_fail_matched_becomes_suppressed(self) -> None:
        results = [_r(control_id="7.1", resource="my-nsg")]
        sups = [self._sup(control_id="7.1")]
        out = apply_suppressions(results, sups)
        self.assertEqual(out[0].status, SUPPRESSED)
        self.assertIn("Accepted risk", out[0].details)

    def test_error_matched_becomes_suppressed(self) -> None:
        results = [_r(control_id="7.1", status=ERROR)]
        sups = [self._sup(control_id="7.1")]
        out = apply_suppressions(results, sups)
        self.assertEqual(out[0].status, SUPPRESSED)

    def test_pass_not_suppressed(self) -> None:
        results = [_r(control_id="7.1", status=PASS)]
        sups = [self._sup(control_id="7.1")]
        out = apply_suppressions(results, sups)
        self.assertEqual(out[0].status, PASS)

    def test_info_not_suppressed(self) -> None:
        results = [_r(control_id="7.1", status=INFO)]
        sups = [self._sup(control_id="7.1")]
        out = apply_suppressions(results, sups)
        self.assertEqual(out[0].status, INFO)

    def test_manual_not_suppressed(self) -> None:
        results = [_r(control_id="7.1", status=MANUAL)]
        sups = [self._sup(control_id="7.1")]
        out = apply_suppressions(results, sups)
        self.assertEqual(out[0].status, MANUAL)

    def test_control_id_mismatch_not_suppressed(self) -> None:
        results = [_r(control_id="7.2")]
        sups = [self._sup(control_id="7.1")]
        out = apply_suppressions(results, sups)
        self.assertEqual(out[0].status, FAIL)

    def test_resource_filter_exact_match(self) -> None:
        results = [
            _r(control_id="7.1", resource="jumphost-nsg"),
            _r(control_id="7.1", resource="other-nsg"),
        ]
        sups = [self._sup(control_id="7.1", resource="jumphost-nsg")]
        out = apply_suppressions(results, sups)
        self.assertEqual(out[0].status, SUPPRESSED)
        self.assertEqual(out[1].status, FAIL)

    def test_resource_filter_case_insensitive(self) -> None:
        results = [_r(control_id="7.1", resource="JumpHost-NSG")]
        sups = [self._sup(control_id="7.1", resource="jumphost-nsg")]
        out = apply_suppressions(results, sups)
        self.assertEqual(out[0].status, SUPPRESSED)

    def test_subscription_filter_exact_match(self) -> None:
        results = [
            _r(control_id="7.1", subscription_name="Production"),
            _r(control_id="7.1", subscription_name="Development"),
        ]
        sups = [self._sup(control_id="7.1", subscription="Production")]
        out = apply_suppressions(results, sups)
        self.assertEqual(out[0].status, SUPPRESSED)
        self.assertEqual(out[1].status, FAIL)

    def test_subscription_filter_case_insensitive(self) -> None:
        results = [_r(control_id="7.1", subscription_name="PRODUCTION")]
        sups = [self._sup(control_id="7.1", subscription="production")]
        out = apply_suppressions(results, sups)
        self.assertEqual(out[0].status, SUPPRESSED)

    def test_no_resource_filter_matches_all_resources(self) -> None:
        results = [
            _r(control_id="7.1", resource="nsg-a"),
            _r(control_id="7.1", resource="nsg-b"),
        ]
        sups = [self._sup(control_id="7.1")]  # no resource filter
        out = apply_suppressions(results, sups)
        self.assertTrue(all(r.status == SUPPRESSED for r in out))

    def test_original_results_not_mutated(self) -> None:
        original = _r(control_id="7.1")
        results = [original]
        sups = [self._sup(control_id="7.1")]
        out = apply_suppressions(results, sups)
        self.assertEqual(original.status, FAIL)  # original unchanged
        self.assertEqual(out[0].status, SUPPRESSED)  # new instance

    def test_details_include_justification_and_expiry(self) -> None:
        results = [_r(control_id="7.1", details="Port 22 open.")]
        sups = [self._sup(control_id="7.1", justification="Jump host OK")]
        out = apply_suppressions(results, sups)
        self.assertIn("Port 22 open.", out[0].details)
        self.assertIn("Jump host OK", out[0].details)
        self.assertIn("expires", out[0].details)

    def test_mixed_results_only_matching_suppressed(self) -> None:
        results = [
            _r(control_id="7.1", status=FAIL),
            _r(control_id="7.2", status=FAIL),
            _r(control_id="7.1", status=PASS),
            _r(control_id="8.1", status=ERROR),
        ]
        sups = [self._sup(control_id="7.1")]
        out = apply_suppressions(results, sups)
        self.assertEqual(out[0].status, SUPPRESSED)  # 7.1 FAIL → SUPPRESSED
        self.assertEqual(out[1].status, FAIL)  # 7.2 unchanged
        self.assertEqual(out[2].status, PASS)  # 7.1 PASS unchanged
        self.assertEqual(out[3].status, ERROR)  # 8.1 unchanged


if __name__ == "__main__":
    unittest.main()
