"""
cis_helpers.py — Pure helper functions and console/logging utilities.

Contains logic that requires no external calls:
  - setup_logging      — root logging configuration
  - console_init/update/finish — thread-safe single-line progress UI
  - port_in_range      — NSG port specification matching
  - nsg_bad_rules      — NSG inbound rule filtering
  - _ctrl_sort_key     — CIS control ID numeric sort key
"""

from __future__ import annotations

import logging
import sys
import threading
from typing import Any

from cis.config import INTERNET_SRCS, TRACE_LEVEL

# ── Thread-safe console state ─────────────────────────────────────────────────
# A single lock shared by all threads. Without it, parallel workers would
# interleave progress updates and produce garbled console lines.
_lock = threading.Lock()

# Simple console UI state for in-place progress updates
_console: dict[str, int] = {"total": 0, "last_len": 0}


# ══════════════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ══════════════════════════════════════════════════════════════════════════════


def setup_logging(
    log_level: str,
    verbose: bool = False,
    debug: bool = False,
    log_file: str | None = None,
    rich_console: Any = None,
) -> None:
    """Configure root logging for console output and optional log file.

    Precedence: --debug > --verbose > --log-level.

    When rich_console is provided (a rich.console.Console instance that is
    shared with the Rich Progress bar), a RichHandler is used instead of a
    plain StreamHandler.  This lets Rich suspend the progress bar, print the
    log line cleanly above it, and then redraw the bar — eliminating the
    garbled interleaving of progress output and log messages.
    """
    if debug:
        effective_level = TRACE_LEVEL
    elif verbose:
        effective_level = logging.DEBUG
    elif log_level.upper() == "TRACE":
        effective_level = TRACE_LEVEL
    else:
        effective_level = getattr(logging, log_level.upper(), logging.INFO)

    logging.addLevelName(TRACE_LEVEL, "TRACE")

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(effective_level)

    # Force UTF-8 on Windows where the console may default to cp1252.
    # line_buffering=True preserves real-time output (prevents output disappearing).
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:
            pass

    if rich_console is not None:
        try:
            from rich.logging import RichHandler  # noqa: PLC0415

            console_handler: logging.Handler = RichHandler(
                console=rich_console,
                show_time=False,   # keep the same minimal format as the plain handler
                show_level=False,
                show_path=False,
                markup=False,      # don't interpret [ ] in Azure resource names as markup
                highlighter=None,  # no syntax colouring on log messages
            )
        except Exception:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter("%(message)s"))

    console_handler.setLevel(effective_level)
    root_logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(effective_level)
        file_handler.setFormatter(
            logging.Formatter("time=%(asctime)s level=%(levelname)s name=%(name)s msg=%(message)s")
        )
        root_logger.addHandler(file_handler)


# ══════════════════════════════════════════════════════════════════════════════
# CONSOLE PROGRESS UI
# ══════════════════════════════════════════════════════════════════════════════


def console_init(total: int) -> None:
    """Initialize console progress UI.

    Prints an initial progress line and stores total for later updates.
    """
    _console["total"] = total
    _console["last_len"] = 0
    with _lock:
        sys.stdout.write(f"Progress: 0/{total}\n")
        sys.stdout.flush()


def console_update(done: int, total: int, current: str = "") -> None:
    """Update the single-line progress indicator in-place.

    Called by worker threads to show overall progress and the current
    subscription being processed.
    """
    s = f"Progress: [{done}/{total}] {current}"
    with _lock:
        # Overwrite the previous line (pad with spaces to clear)
        pad = max(0, _console.get("last_len", 0) - len(s))
        sys.stdout.write("\r" + s + (" " * pad))
        sys.stdout.flush()
        _console["last_len"] = len(s)


def console_finish() -> None:
    """Finish the progress UI and move to the next line."""
    with _lock:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ══════════════════════════════════════════════════════════════════════════════
# NSG RULE HELPERS
# ══════════════════════════════════════════════════════════════════════════════


def port_in_range(s: str, p: int) -> bool:
    """
    Return True if port number p falls within the NSG port specification s.

    Azure NSG port fields accept three formats:
      "*"          — wildcard, matches any port
      "22"         — exact port number
      "1024-65535" — inclusive range

    Parameters
    ──────────
    s : Port specification string from an NSG rule
    p : Integer port number to test
    """
    s = str(s).strip()
    if s in ("*", ""):
        return True  # Wildcard matches everything
    if "-" in s:
        try:
            lo, hi = s.split("-", 1)
            return int(lo) <= p <= int(hi)
        except ValueError:
            return False  # Malformed range — treat as non-matching
    try:
        return int(s) == p  # Exact match
    except ValueError:
        return False  # Non-numeric — treat as non-matching


def nsg_bad_rules(rules: list[Any], port: int, protos: tuple[str, ...] = ("tcp", "*")) -> list[str]:
    """
    Find NSG inbound rules that allow internet traffic on a given port.

    A rule is considered non-compliant if ALL of the following are true:
      1. access    == Allow      (not a Deny rule)
      2. direction == Inbound    (not an outbound rule)
      3. protocol  is in protos  (TCP, UDP, or wildcard *)
      4. source    is an internet wildcard (*, 0.0.0.0/0, Internet, Any)
         Note: source prefixes starting with "/" are ASG resource IDs,
         not internet wildcards — these are explicitly skipped.
      5. at least one destination port range covers the target port

    Parameters
    ──────────
    rules  : List of NSG security rule objects (from Resource Graph)
    port   : Port number to check (e.g. 22 for SSH, 3389 for RDP)
    protos : Protocols to flag. Default ("tcp", "*") catches TCP + wildcard.
             Use ("udp", "*") for UDP checks like check_7_3.

    Returns
    ───────
    List of rule names that are non-compliant (empty list = all OK).
    """
    bad = []
    for rule in rules or []:
        # Resource Graph returns properties at the top level; az CLI wraps them
        # in a "properties" key. Support both formats with .get("properties", rule).
        pr = rule.get("properties", rule)

        if str(pr.get("access", "")).lower() != "allow":
            continue
        if str(pr.get("direction", "")).lower() != "inbound":
            continue

        proto = str(pr.get("protocol", "*")).lower()
        if proto not in protos:
            continue

        src = str(pr.get("sourceAddressPrefix", "")).lower()
        # Application Security Groups have IDs like "/subscriptions/..."
        # They are not internet wildcards, so skip them to avoid false positives.
        if src.startswith("/"):
            continue

        # Azure NSG rules use EITHER sourceAddressPrefix (singular) OR
        # sourceAddressPrefixes (plural list) — never both.  Combine them so
        # rules that specify multiple sources are not silently skipped.
        srcs_extra = pr.get("sourceAddressPrefixes", [])
        all_srcs = ([src] if src else []) + (srcs_extra if isinstance(srcs_extra, list) else [])

        if not any(s in INTERNET_SRCS or s.endswith("/0") for s in all_srcs):
            continue

        # Collect all destination ports — Azure allows either a single value
        # or a list in destinationPortRanges
        dest = str(pr.get("destinationPortRange", ""))
        dests = pr.get("destinationPortRanges", [])
        ports = ([dest] if dest else []) + (dests if isinstance(dests, list) else [])

        if any(port_in_range(p, port) for p in ports):
            bad.append(rule.get("name", "unknown"))

    return bad


# ══════════════════════════════════════════════════════════════════════════════
# SORT KEY
# ══════════════════════════════════════════════════════════════════════════════


def _ctrl_sort_key(control_id: str) -> tuple[int, ...]:
    """Return a numeric sort key for a CIS control ID.

    Splits the ID on '.' and converts each segment to an integer so that
    e.g. '9.3.10' sorts after '9.3.9' instead of before '9.3.2'.
    Non-numeric segments fall back to 0.
    """
    return tuple(int(p) if p.isdigit() else 0 for p in str(control_id).split("."))
