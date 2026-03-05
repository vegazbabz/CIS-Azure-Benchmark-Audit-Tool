"""
cis_check_helpers.py — Shared result-builder helpers for CIS Azure check functions.

These three small functions are used by every section module to construct
R (Result) instances for error, info, and indexed-lookup cases without
repeating the constructor boilerplate in every check function.
"""

from __future__ import annotations

from typing import Any

from cis.config import ERROR, INFO
from cis.models import R


def _idx(td: dict[str, Any], key: str, sid: str) -> list[Any]:
    """
    Retrieve prefetched Resource Graph records for a specific subscription.

    Parameters
    ──────────
    td  : The tenant data dict returned by prefetch()
    key : Query name, e.g. "nsgs", "storage", "keyvaults"
    sid : Subscription ID (case-insensitive — lowercased internally)

    Returns
    ───────
    List of record dicts for this subscription, or [] if none found.
    Returning an empty list (not None) means callers can always iterate
    safely without an extra None check.
    """
    by_sub = td.get(key, {})
    if not isinstance(by_sub, dict):
        return []
    records = by_sub.get(sid.lower(), [])
    return records if isinstance(records, list) else []


def _err(
    cid: str,
    title: str,
    lvl: int,
    sec: str,
    msg: str,
    sid: str = "",
    sname: str = "",
    resource: str = "",
) -> R:
    """
    Convenience constructor for ERROR results.

    Used when an az CLI call fails and we cannot evaluate the control.
    The error message is truncated at 200 characters to keep the report readable.
    """
    return R(cid, title, lvl, sec, ERROR, msg[:200], "", sid, sname, resource)


def _info(
    cid: str,
    title: str,
    lvl: int,
    sec: str,
    msg: str,
    sid: str = "",
    sname: str = "",
) -> R:
    """
    Convenience constructor for INFO results.

    Used when a control is not applicable — typically because no resources
    of the required type exist in the subscription (e.g. no Databricks
    workspaces, no Application Gateways, no Key Vaults).

    sid/sname are optional so tenant-level checks (Section 5) can call _info()
    without them and correctly appear as "Tenant-wide" in the report.
    Per-subscription checks must pass sid/sname so the subscription column
    shows the correct subscription name rather than "Tenant-wide".
    """
    return R(cid, title, lvl, sec, INFO, msg, "", sid, sname)
