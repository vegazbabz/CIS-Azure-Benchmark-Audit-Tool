"""Unit tests for cis.tenant_checks."""

from __future__ import annotations

import unittest
from unittest.mock import patch

import cis.tenant_checks as tenant_checks
from cis.config import PASS
from cis.models import R


class TestRunTenantChecks(unittest.TestCase):
    def test_runs_registered_checks_in_order(self) -> None:
        def first() -> R:
            return R("3.1.1", "first", 1, "tenant", PASS)

        def second() -> list[R]:
            return [R("5.1.1", "second", 1, "tenant", PASS), R("5.1.2", "third", 1, "tenant", PASS)]

        with patch.object(tenant_checks, "TENANT_CHECKS", (first, second)):
            results = tenant_checks.run_tenant_checks(log_each=False)

        self.assertEqual([r.control_id for r in results], ["3.1.1", "5.1.1", "5.1.2"])

    def test_continues_after_check_exception(self) -> None:
        def broken() -> R:
            raise RuntimeError("boom")

        def healthy() -> R:
            return R("5.1.1", "healthy", 1, "tenant", PASS)

        with (
            patch.object(tenant_checks, "TENANT_CHECKS", (broken, healthy)),
            patch.object(tenant_checks, "LOGGER") as logger,
        ):
            results = tenant_checks.run_tenant_checks(log_each=False)

        self.assertEqual([r.control_id for r in results], ["5.1.1"])
        logger.warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
