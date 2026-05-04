"""Tests for the CIS 5.0.0 control catalog exposed by --preview."""

from __future__ import annotations

import unittest

from cis.config import CONTROL_CATALOG


class TestBenchmarkCatalog(unittest.TestCase):
    def test_catalog_has_cis_5_recommendation_count(self) -> None:
        self.assertEqual(len(CONTROL_CATALOG), 155)

    def test_catalog_includes_manual_recommendations_missing_from_runtime_before_qa(self) -> None:
        ids = {row[0] for row in CONTROL_CATALOG}
        for control_id in ("2.1.3", "5.2.1", "6.1.1.8", "8.1.11", "8.2.1"):
            self.assertIn(control_id, ids)

    def test_catalog_excludes_non_cis_storage_logging_controls(self) -> None:
        ids = {row[0] for row in CONTROL_CATALOG}
        self.assertFalse({"9.2.4", "9.2.5", "9.2.6"} & ids)


if __name__ == "__main__":
    unittest.main()
