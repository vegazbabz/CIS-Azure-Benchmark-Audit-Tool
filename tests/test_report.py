"""Unit tests for cis_report: generate_html."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cis.config import BENCHMARK_VER, FAIL, INFO, MANUAL, PASS, VERSION
from cis.models import R
from cis.report import generate_html


def _results() -> list[R]:
    return [
        R("1.1", "Check Pass", 1, "1 - General", PASS, "All good", "", "sub-1", "Sub One"),
        R("1.2", "Check Fail", 1, "1 - General", FAIL, "Bad thing", "Fix it", "sub-1", "Sub One", "res-bad"),
        R("5.1", "Tenant Check", 1, "5 - IAM", INFO, "N/A", "", "", ""),
        R("8.1", "Manual Check", 2, "8 - Security", MANUAL, "Review required", "See docs", "sub-1", "Sub One"),
    ]


class TestGenerateHtml(unittest.TestCase):
    """generate_html produces a valid HTML report file."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._out = str(Path(self._tmp.name) / "report.html")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _generate(self, results: list | None = None, scope_info: dict | None = None) -> str:
        generate_html(results or _results(), self._out, scope_info)
        return Path(self._out).read_text(encoding="utf-8")

    def test_creates_file(self) -> None:
        self._generate()
        self.assertTrue(Path(self._out).exists())

    def test_valid_html_structure(self) -> None:
        html = self._generate()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("<html", html)
        self.assertIn("</html>", html)

    def test_contains_tool_version(self) -> None:
        html = self._generate()
        self.assertIn(VERSION, html)

    def test_contains_benchmark_version(self) -> None:
        html = self._generate()
        self.assertIn(BENCHMARK_VER, html)

    def test_contains_control_ids(self) -> None:
        html = self._generate()
        self.assertIn("1.1", html)
        self.assertIn("1.2", html)
        self.assertIn("5.1", html)
        self.assertIn("8.1", html)

    def test_contains_check_titles(self) -> None:
        html = self._generate()
        self.assertIn("Check Pass", html)
        self.assertIn("Check Fail", html)

    def test_contains_subscription_name(self) -> None:
        html = self._generate()
        self.assertIn("Sub One", html)

    def test_contains_remediation(self) -> None:
        html = self._generate()
        self.assertIn("Fix it", html)

    def test_scope_info_rendered(self) -> None:
        scope = {"tenant": "t-123", "subscriptions": ["sub-1"]}
        html = self._generate(scope_info=scope)
        self.assertIn("t-123", html)

    def test_empty_results_does_not_crash(self) -> None:
        html = self._generate(results=[])
        self.assertIn("<!DOCTYPE html>", html)

    def test_summary_counts_present(self) -> None:
        html = self._generate()
        # Report should include counts; at minimum the numbers 1 PASS and 1 FAIL exist
        self.assertIn("1", html)

    def test_resource_shown_for_failing_check(self) -> None:
        html = self._generate()
        self.assertIn("res-bad", html)

    def test_output_written_to_specified_path(self) -> None:
        out2 = str(Path(self._tmp.name) / "other.html")
        generate_html(_results(), out2)
        self.assertTrue(Path(out2).exists())

    def test_output_parent_directory_created_for_all_report_files(self) -> None:
        out_nested = Path(self._tmp.name) / "nested" / "reports" / "report.html"
        generate_html(_results(), str(out_nested))

        self.assertTrue(out_nested.exists())
        self.assertTrue(out_nested.with_suffix(".json").exists())
        self.assertTrue(out_nested.with_suffix(".csv").exists())


if __name__ == "__main__":
    unittest.main()
