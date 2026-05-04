"""Tenant/global check registry and runner.

These checks are intentionally executed once per audit run rather than once per
subscription. Keeping the registry in one place prevents report-only and resume
paths from drifting apart.
"""

from __future__ import annotations

from collections.abc import Callable

from checks.s3 import check_3_1_1
from checks.s5 import (
    check_5_1_1,
    check_5_1_2,
    check_5_1_3,
    check_5_2_2,
    check_5_3_2,
    check_5_4,
    check_5_6,
    check_5_14,
    check_5_15,
    check_5_16,
    check_5_28,
)
from checks.manual import check_tenant_identity_manual_controls, check_tenant_logging_manual_controls
from cis.config import ERROR, FAIL, INFO, LOGGER, MANUAL, PASS, SUPPRESSED
from cis.models import R

TenantCheck = Callable[[], R | list[R]]

TENANT_CHECKS: tuple[TenantCheck, ...] = (
    check_3_1_1,
    check_5_1_1,
    check_5_1_2,
    check_5_1_3,
    check_5_2_2,
    check_tenant_identity_manual_controls,
    check_5_28,
    check_5_3_2,
    check_5_4,
    check_5_6,
    check_5_14,
    check_5_15,
    check_5_16,
    check_tenant_logging_manual_controls,
)

_STATUS_ICON: dict[str, str] = {
    PASS: "\u2705",
    FAIL: "\u274c",
    ERROR: "\u26a0\ufe0f",
    INFO: "\u2139\ufe0f",
    MANUAL: "\U0001f4cb",
    SUPPRESSED: "\U0001f507",
}


def run_tenant_checks(log_each: bool = True) -> list[R]:
    """Run each tenant/global check once, isolating unexpected failures."""
    results: list[R] = []
    for check in TENANT_CHECKS:
        try:
            result = check()
        except Exception as exc:  # noqa: BLE001 - one broken check must not stop the audit
            LOGGER.warning("    \u26a0\ufe0f  ERROR in tenant check %s: %s", check.__name__, exc)
            continue

        items = result if isinstance(result, list) else [result]
        results.extend(items)
        if log_each:
            for item in items:
                icon = _STATUS_ICON.get(item.status, "?")
                LOGGER.info("    %-10s %s  %s", item.control_id, icon, item.status)
    return results
