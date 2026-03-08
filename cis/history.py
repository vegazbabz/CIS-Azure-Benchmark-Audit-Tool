"""
cis/history.py — Run history for compliance trend tracking.

Appends a summary entry to cis_run_history.json after each full audit run.
--report-only does NOT update history (it is not a new measurement).

History file format (JSON array, oldest first, max MAX_HISTORY entries):

    [
      {
        "timestamp": "2026-03-05T14:30:00Z",
        "version":   "1.0.0-beta3",
        "score":     72.3,
        "pass":      850,
        "fail":      120,
        "error":     45,
        "info":      200,
        "manual":    2,
        "suppressed": 5,
        "total":     1222,
        "subscriptions": ["Production", "Staging"],
        "level_filter": null
      },
      ...
    ]
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cis.config import LOGGER

MAX_HISTORY = 30  # Maximum number of run entries to retain


def load_history(path: Path) -> list[dict[str, Any]]:
    """Load run history from disk. Returns an empty list if the file does not exist."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception as exc:
        LOGGER.warning("⚠️  Could not read run history from %s: %s", path, exc)
        return []


def append_history(path: Path, entry: dict[str, Any]) -> None:
    """
    Append a new run entry to the history file, trimming to MAX_HISTORY entries.

    Entries are stored oldest-first so they can be iterated in chronological
    order when drawing a trend chart.  Uses an atomic write-and-rename pattern
    to avoid a truncated history file if the process crashes mid-write.
    """
    history = load_history(path)
    history.append(entry)
    if len(history) > MAX_HISTORY:
        history = history[-MAX_HISTORY:]
    tmp = path.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)  # atomic on both Windows and POSIX; replaces if target exists
    except Exception as exc:
        LOGGER.warning("⚠️  Could not write run history to %s: %s", path, exc)
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def history_path_for(output: str) -> Path:
    """Return the default history file path based on the HTML output path."""
    return Path(output).parent / "cis_run_history.json"
