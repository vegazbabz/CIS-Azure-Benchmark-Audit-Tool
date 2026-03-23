"""
cis_config.py — Configuration constants for the CIS Azure Audit Tool.

All tuneable values live here. An optional ``cis_audit.toml`` file next to this
module (or at the path given by the ``CIS_AUDIT_CONFIG`` environment variable)
can override any value in the ``[timeouts]``, ``[audit]``, and ``[report]``
sections. Values not present in the file keep their built-in defaults.

Example cis_audit.toml
─────────────────────────
[audit]
parallel    = 5
executor    = "thread"
checkpoint_dir = "cis_checkpoints"

[timeouts]
default      = 20
storage_list = 30
storage_svc  = 15
activity_log = 25
graph        = 120
"""

from __future__ import annotations

import functools
import logging
import os
import sys
from pathlib import Path
from typing import Any

# TOML parsing: tomllib is stdlib on Python 3.11+; fall back to tomli on 3.10.
# The sys.version_info guard lets mypy resolve the right branch per version.
if sys.version_info >= (3, 11):
    import tomllib as _tomllib
else:
    try:
        import tomli as _tomllib
    except ImportError:
        _tomllib = None  # type: ignore[assignment]

# ── Tool / benchmark identity ──────────────────────────────────────────────────
VERSION = "1.0.1"  # Written into checkpoints for change detection
BENCHMARK_VER = "5.0.0"  # CIS Benchmark version this tool targets


@functools.lru_cache(maxsize=None)
def _git_hash() -> str:
    """Return the short git commit hash, or 'unknown' if git is unavailable."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def version_full() -> str:
    """Return the full version string including git hash (computed on first call)."""
    return f"{VERSION}+{_git_hash()}"


# ── Filesystem ────────────────────────────────────────────────────────────────
CHECKPOINT_DIR = Path("cis_checkpoints")  # Per-subscription result cache

# ── Azure CLI call timeouts (seconds) ─────────────────────────────────────────
TIMEOUTS: dict[str, int] = {
    "default": 20,  # Most az CLI calls (diagnostics, security, keyvault, network)
    "storage_list": 30,  # az storage account list — larger payload per subscription
    "storage_svc": 15,  # Per-account blob/file/table service property queries
    "activity_log": 25,  # Activity log queries with 90-day window
    "graph": 120,  # Resource Graph bulk queries (az graph query)
}

# ── Default parallel execution settings ───────────────────────────────────────
DEFAULT_PARALLEL: int = 3
DEFAULT_EXECUTOR: str = "thread"  # "thread" or "process"

# ── Audit result status values ────────────────────────────────────────────────
PASS = "PASS"  # Control requirement is met
FAIL = "FAIL"  # Control requirement is NOT met — action required
ERROR = "ERROR"  # Could not evaluate — az CLI call failed or timed out
INFO = "INFO"  # Not applicable (e.g. no resources of this type in subscription)
MANUAL = "MANUAL"  # Requires human review — cannot be automated via az CLI
SUPPRESSED = "SUPPRESSED"  # Accepted risk — suppressed via suppressions.toml

# ── Custom log level ──────────────────────────────────────────────────────────
TRACE_LEVEL = 5  # Below DEBUG — very chatty execution traces

# ── Module logger ─────────────────────────────────────────────────────────────
LOGGER = logging.getLogger("cis_audit")

# ── MSAL / Graph auth config ─────────────────────────────────────────────────
# Populated by load_config_file() from [graph_auth] in cis_audit.toml and/or
# CIS_GRAPH_* environment variables.  Used by azure/graph_auth.py for Graph
# endpoints whose required scopes are not available in the az CLI app token.
GRAPH_AUTH: dict[str, str] = {}

# ── Caller identity (set at startup from az account show) ────────────────────
# Either "user" or "servicePrincipal".  Used by checks to tailor error messages
# so remediation guidance matches the authentication method in use.
CALLER_TYPE: str = "user"  # default to user; overwritten in main()

# ── Azure built-in role definition GUIDs (stable, defined by Microsoft) ──────
# These GUIDs are identical in every tenant — safe to hardcode.
ROLE_OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  # Owner
ROLE_UAA = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"  # User Access Administrator

# ── Source addresses meaning "open to the internet" in NSG rules ─────────────
# "0.0.0.0/0" is covered by the endswith("/0") check, not this set.
INTERNET_SRCS: frozenset[str] = frozenset({"*", "0.0.0.0", "internet", "any"})

# ── Platform-managed subnets that Azure prohibits attaching NSGs to ───────────
# check_7_11 skips these to avoid false FAIL results.
EXEMPT_SUBNETS: frozenset[str] = frozenset(
    {
        "gatewaysubnet",  # VPN / ExpressRoute Gateway
        "azurebastionsubnet",  # Azure Bastion
        "azurefirewallsubnet",  # Azure Firewall
        "azurefirewallmanagementsubnet",  # Azure Firewall management traffic
        "routeserversubnet",  # Azure Route Server
    }
)

# ══════════════════════════════════════════════════════════════════════════════
# TOML CONFIG LOADER
# ══════════════════════════════════════════════════════════════════════════════

_DEFAULT_CONFIG_NAME = "cis_audit.toml"


def load_config_file(path: Path | None = None) -> None:
    """Load ``cis_audit.toml`` and override module-level defaults in place.

    Looks for the config file in this order:
    1. *path* argument (if supplied)
    2. ``CIS_AUDIT_CONFIG`` environment variable
    3. ``cis_audit.toml`` next to ``cis_config.py``

    Missing file → silently ignored (all defaults kept).
    Unknown keys → logged as warnings, not errors.
    """
    # TIMEOUTS and GRAPH_AUTH are mutated in-place (dict item assignment) — no global declaration needed.
    # The other three are reassigned, so they require global.
    global DEFAULT_PARALLEL, DEFAULT_EXECUTOR, CHECKPOINT_DIR  # noqa: PLW0603

    # --- resolve config path ---
    if path is None:
        env_path = os.environ.get("CIS_AUDIT_CONFIG")
        if env_path:
            path = Path(env_path)
        else:
            path = Path(__file__).parent / _DEFAULT_CONFIG_NAME

    if not path.exists():
        return  # No config file — use built-in defaults, that's fine

    # --- parse TOML ---
    if _tomllib is None:
        LOGGER.warning(
            "cis_audit.toml found but tomllib/tomli is not available. "
            "Install tomli (pip install tomli) on Python < 3.11 to use config files."
        )
        return

    try:
        with open(path, "rb") as fh:
            data: dict[str, Any] = _tomllib.load(fh)
    except Exception as exc:
        LOGGER.warning("Failed to parse config file %s: %s", path, exc)
        return

    LOGGER.info("Loaded config from %s", path)

    # --- [timeouts] section ---
    _KNOWN_TIMEOUT_KEYS = set(TIMEOUTS)
    for key, val in data.get("timeouts", {}).items():
        if key not in _KNOWN_TIMEOUT_KEYS:
            LOGGER.warning("Unknown [timeouts] key in config: %r (ignored)", key)
            continue
        if not isinstance(val, int) or val <= 0:
            LOGGER.warning("[timeouts].%s must be a positive integer (got %r) — ignored", key, val)
            continue
        TIMEOUTS[key] = val

    # --- [audit] section ---
    audit = data.get("audit", {})

    if "parallel" in audit:
        val = audit["parallel"]
        if isinstance(val, int) and val >= 1:
            DEFAULT_PARALLEL = val
        else:
            LOGGER.warning("[audit].parallel must be a positive integer (got %r) — ignored", val)

    if "executor" in audit:
        val = audit["executor"]
        if val in ("thread", "process"):
            DEFAULT_EXECUTOR = val
        else:
            LOGGER.warning("[audit].executor must be 'thread' or 'process' (got %r) — ignored", val)

    if "checkpoint_dir" in audit:
        val = audit["checkpoint_dir"]
        if isinstance(val, str) and val.strip():
            CHECKPOINT_DIR = Path(val)
        else:
            LOGGER.warning("[audit].checkpoint_dir must be a non-empty string (got %r) — ignored", val)

    # --- [graph_auth] section ---
    _KNOWN_GRAPH_AUTH_KEYS = {"client_id", "tenant_id", "client_secret"}
    for key, val in data.get("graph_auth", {}).items():
        if key not in _KNOWN_GRAPH_AUTH_KEYS:
            LOGGER.warning("Unknown [graph_auth] key in config: %r (ignored)", key)
            continue
        if not isinstance(val, str) or not val.strip():
            LOGGER.warning("[graph_auth].%s must be a non-empty string (got %r) — ignored", key, val)
            continue
        GRAPH_AUTH[key] = val
