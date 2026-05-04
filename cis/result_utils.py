"""Shared result aggregation helpers for audit orchestration and reporting."""

from __future__ import annotations

from cis.config import ERROR, FAIL, INFO, MANUAL, PASS, SUPPRESSED
from cis.models import R

STATUS_ORDER: tuple[str, ...] = (PASS, FAIL, ERROR, INFO, MANUAL, SUPPRESSED)


def count_statuses(results: list[R]) -> dict[str, int]:
    """Return counts for every known audit status."""
    counts = {status: 0 for status in STATUS_ORDER}
    for result in results:
        if result.status in counts:
            counts[result.status] += 1
    return counts


def compliance_score(counts: dict[str, int], total: int) -> float:
    """Return the report compliance score using the existing scoring rules."""
    denominator = max(total - counts[INFO] - counts[MANUAL] - counts[SUPPRESSED], 1)
    return round(counts[PASS] / denominator * 100, 1)


def assessed_count(counts: dict[str, int]) -> int:
    """Return the number of automatically assessed controls."""
    return counts[PASS] + counts[FAIL] + counts[ERROR]


def dedup_results(results: list[R]) -> list[R]:
    """Remove identical duplicate R instances while preserving order."""
    seen: set[tuple[str, ...]] = set()
    out: list[R] = []
    for result in results:
        key = (result.control_id, result.subscription_id, result.resource, result.status, result.details)
        if key not in seen:
            seen.add(key)
            out.append(result)
    return out
