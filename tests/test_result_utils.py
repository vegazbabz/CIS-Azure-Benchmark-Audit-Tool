"""Unit tests for cis.result_utils."""

from __future__ import annotations

import unittest

from cis.config import ERROR, FAIL, INFO, MANUAL, PASS, SUPPRESSED
from cis.models import R
from cis.result_utils import assessed_count, compliance_score, count_statuses, dedup_results


class TestResultUtils(unittest.TestCase):
    def test_count_statuses_returns_all_known_statuses(self) -> None:
        results = [
            R("1.1", "pass", 1, "s", PASS),
            R("1.2", "fail", 1, "s", FAIL),
            R("1.3", "error", 1, "s", ERROR),
            R("1.4", "info", 1, "s", INFO),
            R("1.5", "manual", 1, "s", MANUAL),
            R("1.6", "suppressed", 1, "s", SUPPRESSED),
        ]

        counts = count_statuses(results)

        self.assertEqual(counts[PASS], 1)
        self.assertEqual(counts[FAIL], 1)
        self.assertEqual(counts[ERROR], 1)
        self.assertEqual(counts[INFO], 1)
        self.assertEqual(counts[MANUAL], 1)
        self.assertEqual(counts[SUPPRESSED], 1)

    def test_compliance_score_excludes_non_assessed_statuses(self) -> None:
        counts = {PASS: 2, FAIL: 1, ERROR: 1, INFO: 3, MANUAL: 2, SUPPRESSED: 1}
        total = sum(counts.values())

        self.assertEqual(compliance_score(counts, total), 50.0)

    def test_assessed_count(self) -> None:
        counts = {PASS: 2, FAIL: 1, ERROR: 1, INFO: 3, MANUAL: 2, SUPPRESSED: 1}
        self.assertEqual(assessed_count(counts), 4)

    def test_dedup_results_preserves_first_result_order(self) -> None:
        first = R("7.1", "RDP", 1, "Network", FAIL, "bad", "", "sub", "Sub", "nsg")
        duplicate = R("7.1", "RDP copy", 1, "Network", FAIL, "bad", "", "sub", "Sub", "nsg")
        distinct = R("7.1", "RDP", 1, "Network", PASS, "ok", "", "sub", "Sub", "nsg")

        self.assertEqual(dedup_results([first, duplicate, distinct]), [first, distinct])


if __name__ == "__main__":
    unittest.main()
