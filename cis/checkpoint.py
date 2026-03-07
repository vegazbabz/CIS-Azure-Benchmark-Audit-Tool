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
from dataclasses import asdict
from typing import Any

from cis.config import BENCHMARK_VER, CHECKPOINT_DIR, LOGGER, VERSION
from cis.models import R

_CLEAN_KV_AUTHZ_MSG = (
    "Audit incomplete — account lacks Key Vault data-plane permissions. "
    "Grant 'Key Vault Reader' data-plane role (or an access policy) to include this vault."
)

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
# the clean actionable message.
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


def _reclassify(r: R) -> R:
    """Downgrade ERROR→INFO only for genuinely not-applicable results.

    FeatureNotSupportedForAccount errors indicate the account type has no
    blob or file service — INFO is correct (the control doesn't apply).

    KV data-plane permission errors are kept as ERROR: the vault exists,
    the control applies, and compliance is unknown.  The error message is
    now a clean, actionable string rather than a raw CLI dump.
    """
    from cis.config import ERROR, INFO  # avoid circular at module level

    if r.status != ERROR:
        return r
    low = r.details.lower()
    if any(t in low for t in _RECLASSIFY_NOTAPPLICABLE_TOKENS):
        return R(
            r.control_id,
            r.title,
            r.level,
            r.section,
            INFO,
            r.details,
            "",  # no remediation for INFO
            r.subscription_id,
            r.subscription_name,
            "",  # clear resource marker — nothing to flag
        )
    # Old checkpoints store the raw CLI dump for KV auth errors — replace with
    # the clean, actionable message so --report-only shows readable output.
    if any(t in low for t in _KV_AUTHZ_TOKENS):
        # Preserve the vault/key/cert prefix (everything before the first " - ")
        prefix = r.details.split(" - ")[0] if " - " in r.details else r.details.split(":")[0]
        return R(
            r.control_id,
            r.title,
            r.level,
            r.section,
            ERROR,
            f"{prefix}: {_CLEAN_KV_AUTHZ_MSG}",
            "Grant Key Vault data-plane permissions to the audit account",
            r.subscription_id,
            r.subscription_name,
            r.resource,
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
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

    data = {
        "tool_version": VERSION,
        "benchmark_version": BENCHMARK_VER,
        "subscription_id": sid,
        "subscription_name": sname,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": status,
        "results": [asdict(r) for r in results],  # Convert dataclasses to dicts
    }

    target = CHECKPOINT_DIR / f"{sid}.json"
    tmp = CHECKPOINT_DIR / f"{sid}.json.tmp"

    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    # Atomic rename — replaces the target file in a single OS operation
    tmp.rename(target)


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
    if not CHECKPOINT_DIR.exists():
        return {}

    loaded = {}
    for p in CHECKPOINT_DIR.glob("*.json"):
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            # Only load checkpoints that successfully completed
            if data.get("status") != "completed":
                continue
            cp_ver = data.get("tool_version", "unknown")
            if cp_ver != VERSION:
                LOGGER.warning(
                    "   \u26a0\ufe0f  Checkpoint %s was written by tool v%s (current: v%s) \u2014 "
                    "results may differ if the schema changed. Use --fresh to re-audit.",
                    p.name,
                    cp_ver,
                    VERSION,
                )
            loaded[data["subscription_id"]] = data
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
        except TypeError:
            pass  # Skip records that cannot be reconstructed

    return results
