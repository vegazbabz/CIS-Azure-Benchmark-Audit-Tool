"""
cis_checkpoint.py — Checkpoint save/load for the CIS Azure Audit Tool.

Checkpoint files allow a long-running audit to be safely interrupted and
resumed without losing progress. Each completed subscription produces one
JSON file in CHECKPOINT_DIR.

Functions
─────────
save_checkpoint       Write results for one subscription (atomic write).
load_checkpoints      Load all completed checkpoints from disk.
results_from_checkpoint  Deserialise R instances from a checkpoint dict.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import asdict, replace
from typing import Any

from azure.client import _CLEAN_KV_AUTHZ_MSG
import cis.config as _config
from cis.config import BENCHMARK_VER, LOGGER, VERSION
from cis.models import R

# Tokens whose presence in a stored ERROR result's `details` field means the
# result should be downgraded to INFO on load.  This lets --report-only (and
# checkpoint-resume runs) reflect fixes without requiring a full re-audit.
#
# Only FeatureNotSupportedForAccount is reclassified to INFO — it is genuinely
# "not applicable" (the account type has no blob/file service).
#
# KV data-plane permission errors are intentionally kept as ERROR: the control
# DOES apply, the audit just couldn't verify compliance.  That is an audit gap
# and must be visible in the report so the auditor knows to investigate.
# Old checkpoints may have the raw CLI blob in `details` — we replace it with
# the clean actionable message (imported from azure.client).
_RECLASSIFY_NOTAPPLICABLE_TOKENS = frozenset(
    [
        "featurenotsupportedforaccount",
        "feature not supported for this account type",
    ]
)
_KV_AUTHZ_TOKENS = frozenset(
    [
        "requires key vault data plane permissions",
        "insufficient permissions",
    ]
)

# Mapping of section names that were stored incorrectly in old checkpoints.
# Applied on load so --report-only reflects corrections without a full re-audit.
#
# Each entry can be pruned once you are confident no checkpoints older than the
# fixing commit remain in use (i.e. after running --fresh or re-auditing all
# subscriptions at least once with the corrected version).
_SECTION_NAME_FIXES: dict[str, str] = {
    "7 - Networking & Governance": "7 - Networking Services",
}


def _reclassify(r: R) -> R:
    """Downgrade ERROR→INFO only for genuinely not-applicable results.

    FeatureNotSupportedForAccount errors indicate the account type has no
    blob or file service — INFO is correct (the control doesn't apply).

    KV data-plane permission errors are kept as ERROR: the vault exists,
    the control applies, and compliance is unknown.  The error message is
    now a clean, actionable string rather than a raw CLI dump.
    """
    from cis.config import ERROR, INFO  # avoid circular at module level

    # Fix known section name typos stored in old checkpoints.
    if r.section in _SECTION_NAME_FIXES:
        r = replace(r, section=_SECTION_NAME_FIXES[r.section])

    if r.status != ERROR:
        return r
    low = r.details.lower()
    if any(t in low for t in _RECLASSIFY_NOTAPPLICABLE_TOKENS):
        return replace(r, status=INFO, remediation="", resource="")
    # Old checkpoints store the raw CLI dump for KV auth errors — replace with
    # the clean, actionable message so --report-only shows readable output.
    if any(t in low for t in _KV_AUTHZ_TOKENS):
        # Preserve the vault/key/cert prefix (everything before the first " - ")
        prefix = r.details.split(" - ")[0] if " - " in r.details else r.details.split(":")[0]
        return replace(
            r,
            details=f"{prefix}: {_CLEAN_KV_AUTHZ_MSG}",
            remediation="Grant Key Vault data-plane permissions to the audit account",
        )
    return r


def save_checkpoint(sid: str, sname: str, results: list[R], status: str = "completed") -> None:
    """
    Write audit results for one subscription to a JSON checkpoint file.

    Uses an atomic write pattern to prevent corrupt checkpoint files:
      1. Write to <sid>.json.tmp
      2. Rename .tmp → <sid>.json  (atomic on POSIX; near-atomic on Windows NTFS)

    This ensures that if the process crashes during a write, the partially
    written .tmp file is ignored on the next run (only .json files are loaded).
    The previous checkpoint (if any) remains intact until the rename completes.

    Parameters
    ──────────
    sid     : Subscription GUID (used as the filename)
    sname   : Subscription display name (stored for informational purposes)
    results : List of R dataclass instances to serialise
    status  : "completed" (default) or "failed" — only "completed" is resumed
    """
    _config.CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

    data = {
        "tool_version": VERSION,
        "benchmark_version": BENCHMARK_VER,
        "subscription_id": sid,
        "subscription_name": sname,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": status,
        "results": [asdict(r) for r in results],  # Convert dataclasses to dicts
    }

    target = _config.CHECKPOINT_DIR / f"{sid}.json"
    tmp = _config.CHECKPOINT_DIR / f"{sid}.json.tmp"

    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    # Atomic replace — works on both POSIX and Windows (unlike rename)
    tmp.replace(target)


def load_checkpoints() -> dict[str, Any]:
    """
    Load all completed checkpoint files from CHECKPOINT_DIR.

    Defensively handles:
      - Missing directory (returns empty dict — no checkpoints exist yet)
      - Corrupt JSON (logs a warning, skips the file)
      - Failed subscriptions (status != "completed" — skips the file)

    Returns
    ───────
    dict mapping subscription_id → checkpoint_data_dict
    Only subscriptions with status == "completed" are included.
    """
    if not _config.CHECKPOINT_DIR.exists():
        return {}

    loaded = {}
    for p in _config.CHECKPOINT_DIR.glob("*.json"):
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            sid = data.get("subscription_id", "")
            if not sid or sid.startswith("_"):
                continue  # skip special non-subscription files (e.g. _tenant.json)
            cp_ver = data.get("tool_version", "unknown")
            if cp_ver != VERSION:
                LOGGER.warning(
                    "   \u26a0\ufe0f  Checkpoint %s was written by tool v%s (current: v%s) \u2014 "
                    "results may differ if the schema changed. Use --fresh to re-audit.",
                    p.name,
                    cp_ver,
                    VERSION,
                )
            if data.get("status") != "completed":
                continue
            loaded[sid] = data
        except (json.JSONDecodeError, KeyError) as e:
            LOGGER.warning("   \u26a0\ufe0f  Skipping corrupt checkpoint %s: %s", p.name, e)

    return loaded


def results_from_checkpoint(cp: dict[str, Any]) -> list[R]:
    """
    Deserialise a list of R dataclass instances from a checkpoint dict.

    Uses a defensive approach: only fields that exist on the R dataclass
    are passed to the constructor. Extra fields in the checkpoint (from a
    future version of the tool) are ignored. Missing fields fall back to
    the dataclass defaults.

    This allows old checkpoints to load cleanly even when new fields are
    added to the R dataclass in a later version.

    Parameters
    ──────────
    cp : Checkpoint dict loaded by load_checkpoints()

    Returns
    ───────
    List of R instances, one per record in cp["results"]
    """
    # Get the set of valid field names from the dataclass definition
    valid_fields = set(R.__dataclass_fields__.keys())

    results = []
    for r in cp.get("results", []):
        # Only pass fields that the current R dataclass knows about
        filtered = {k: v for k, v in r.items() if k in valid_fields}
        try:
            results.append(_reclassify(R(**filtered)))
        except TypeError as exc:
            LOGGER.warning("   \u26a0\ufe0f  Skipping unrecognisable checkpoint record (control=%s): %s", r.get("control_id", "?"), exc)

    return results


# ── Tenant checkpoint ─────────────────────────────────────────────────────────
# Tenant-level checks (Section 5 Entra ID checks) are not subscription-scoped
# and therefore not stored in per-subscription checkpoint files.  A separate
# _tenant.json checkpoint file saves them so that --report-only does not need
# to make live Graph API calls on the second and subsequent invocations.

_TENANT_CHECKPOINT_ID = "_tenant"


def save_tenant_checkpoint(results: list[R]) -> None:
    """Write tenant-level (Entra ID) check results to a dedicated checkpoint file.

    Uses the same atomic write pattern as save_checkpoint.  The file is stored
    in CHECKPOINT_DIR as _tenant.json and is skipped by load_checkpoints() so
    it does not appear as a subscription entry in the audit summary.
    """
    _config.CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "tool_version": VERSION,
        "benchmark_version": BENCHMARK_VER,
        "subscription_id": _TENANT_CHECKPOINT_ID,
        "subscription_name": "Tenant (Entra ID)",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "completed",
        "results": [asdict(r) for r in results],
    }
    target = _config.CHECKPOINT_DIR / f"{_TENANT_CHECKPOINT_ID}.json"
    tmp = _config.CHECKPOINT_DIR / f"{_TENANT_CHECKPOINT_ID}.json.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp.replace(target)


def load_tenant_checkpoint() -> list[R] | None:
    """Load tenant-level results from checkpoint.

    Returns None (caller should re-run live tenant checks) when:
      - The checkpoint file does not exist yet (first run after a fresh audit)
      - The tool version has changed (schema may differ)
      - The file is corrupt or unreadable

    The caller is responsible for logging a warning when falling back to live
    API calls, so the operator understands why Graph API calls are being made
    in --report-only mode.
    """
    path = _config.CHECKPOINT_DIR / f"{_TENANT_CHECKPOINT_ID}.json"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        LOGGER.warning("   \u26a0\ufe0f  Could not read tenant checkpoint: %s", exc)
        return None
    cp_ver = data.get("tool_version", "unknown")
    if cp_ver != VERSION:
        LOGGER.warning(
            "   \u26a0\ufe0f  Tenant checkpoint was written by tool v%s (current: v%s) — re-running tenant checks.",
            cp_ver,
            VERSION,
        )
        return None
    return results_from_checkpoint(data)
