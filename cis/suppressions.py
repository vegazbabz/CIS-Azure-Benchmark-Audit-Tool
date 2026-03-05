"""
cis/suppressions.py — Finding suppression for accepted risks.

Loads suppressions.toml and applies SUPPRESSED status to matching FAIL/ERROR
results at report-generation time. Checkpoints are never modified — the raw
FAIL is always preserved on disk, so removing a suppression and running
--report-only immediately reinstates the finding.

Suppression file format (suppressions.toml):

    [[suppressions]]
    control_id    = "7.1"
    resource      = "jumphost-nsg"   # optional; exact match (case-insensitive)
    subscription  = "Production"     # optional; exact match (case-insensitive)
    justification = "Intentional RDP jump host — restricted by Azure Firewall"
    expires       = "2026-12-31"     # required; ISO date; max 1 year from today

Matching rules:
  - control_id  : required; exact match
  - resource     : optional; if omitted, matches any resource for that control
  - subscription : optional; if omitted, matches across all subscriptions
  - Only FAIL and ERROR results can be suppressed

Expiry rules:
  - expires is required — prevents suppressions from becoming permanent
  - Maximum 1 year from today; anything longer is capped with a warning
  - Expired entries are skipped and logged as warnings
"""

from __future__ import annotations

import datetime
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from cis.config import ERROR, FAIL, LOGGER, SUPPRESSED
from cis.models import R

# Maximum allowed suppression duration in days
_MAX_EXPIRY_DAYS = 365


def _load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML file using tomllib (3.11+) or tomli (3.10)."""
    if sys.version_info >= (3, 11):
        import tomllib

        with open(path, "rb") as f:
            return tomllib.load(f)
    else:
        try:
            import tomli

            with open(path, "rb") as f:
                return tomli.load(f)
        except ImportError:
            LOGGER.warning(
                "⚠️  %s found but tomli is not installed (Python < 3.11 requires 'pip install tomli'). "
                "Suppressions will be ignored.",
                path,
            )
            return {}


def load_suppressions(path: Path) -> list[dict[str, Any]]:
    """
    Load, validate, and return active suppressions from a TOML file.

    Expired entries are skipped with a warning.
    Entries with expiry beyond 1 year are capped at 1 year with a warning.
    Missing required fields or invalid dates cause a hard exit.

    Returns an empty list if the file does not exist.
    """
    if not path.exists():
        return []

    data = _load_toml(path)
    if not data:
        return []

    entries: list[dict[str, Any]] = data.get("suppressions", [])
    if not entries:
        LOGGER.warning("⚠️  %s has no [[suppressions]] entries.", path)
        return []

    today = datetime.date.today()
    max_date = today + datetime.timedelta(days=_MAX_EXPIRY_DAYS)
    valid: list[dict[str, Any]] = []

    for i, entry in enumerate(entries, 1):
        # Validate required fields
        for field in ("control_id", "justification", "expires"):
            if field not in entry:
                LOGGER.error("❌ Suppression #%d in %s is missing required field '%s'.", i, path, field)
                sys.exit(1)

        # Parse and validate expiry date
        try:
            expires = datetime.date.fromisoformat(str(entry["expires"]))
        except ValueError:
            LOGGER.error(
                "❌ Suppression #%d (control %s): invalid expires date '%s' — expected YYYY-MM-DD.",
                i,
                entry["control_id"],
                entry["expires"],
            )
            sys.exit(1)

        if expires < today:
            LOGGER.warning(
                "⚠️  Suppression #%d (control %s, resource '%s') expired %s — finding will show as FAIL/ERROR.",
                i,
                entry["control_id"],
                entry.get("resource", "*"),
                expires,
            )
            continue  # Expired — skip, finding stays as FAIL/ERROR

        if expires > max_date:
            LOGGER.warning(
                "⚠️  Suppression #%d (control %s): expiry %s exceeds 1-year maximum — capped at %s.",
                i,
                entry["control_id"],
                expires,
                max_date,
            )
            expires = max_date

        valid.append({**entry, "expires": expires})

    LOGGER.info("🔇 Loaded %d active suppression(s) from %s", len(valid), path)
    return valid


def apply_suppressions(results: list[R], suppressions: list[dict[str, Any]]) -> list[R]:
    """
    Return a new list of R instances with SUPPRESSED status applied where matched.

    Only FAIL and ERROR results are candidates for suppression.
    The justification and expiry are appended to the details field so they
    appear in the report without requiring a separate UI element.
    Original R instances are never mutated — dataclasses.replace() is used.
    """
    if not suppressions:
        return results

    out: list[R] = []
    for r in results:
        if r.status not in (FAIL, ERROR):
            out.append(r)
            continue

        sup = _find_match(r, suppressions)
        if sup:
            out.append(
                replace(
                    r,
                    status=SUPPRESSED,
                    details=(f"{r.details}  " f"[Accepted risk: {sup['justification']} — expires {sup['expires']}]"),
                )
            )
        else:
            out.append(r)

    return out


def _find_match(r: R, suppressions: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the first suppression that matches this result, or None."""
    for sup in suppressions:
        if r.control_id != sup["control_id"]:
            continue
        if sup.get("resource") and sup["resource"].lower() != r.resource.lower():
            continue
        if sup.get("subscription") and sup["subscription"].lower() != r.subscription_name.lower():
            continue
        return sup
    return None


def list_suppressions(suppressions: list[dict[str, Any]], path: Path) -> None:
    """Print all active suppressions in a readable table."""
    if not suppressions:
        LOGGER.info("No active suppressions in %s.", path)
        return

    today = datetime.date.today()
    LOGGER.info("\nActive suppressions from %s:\n", path)
    LOGGER.info("  %-10s  %-25s  %-20s  %-12s  %s", "Control", "Resource", "Subscription", "Expires", "Justification")
    LOGGER.info("  %s", "-" * 100)
    for sup in suppressions:
        days_left = (sup["expires"] - today).days
        expiry_str = f"{sup['expires']} ({days_left}d left)"
        LOGGER.info(
            "  %-10s  %-25s  %-20s  %-14s  %s",
            sup["control_id"],
            sup.get("resource", "*"),
            sup.get("subscription", "*"),
            expiry_str,
            sup["justification"][:70],
        )
    LOGGER.info("")
