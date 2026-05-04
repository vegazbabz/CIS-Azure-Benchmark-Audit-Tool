"""Unit tests for cis/history.py: load_history, append_history, history_path_for."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cis.history import MAX_HISTORY, append_history, history_path_for, load_history


def _entry(score: float = 80.0, ts: str = "2026-01-01T00:00:00Z") -> dict:
    return {
        "timestamp": ts,
        "version": "1.0.0-test",
        "score": score,
        "pass": 90,
        "fail": 10,
        "error": 0,
        "info": 5,
        "manual": 1,
        "suppressed": 0,
        "total": 106,
        "subscriptions": ["Sub1"],
        "level_filter": None,
    }


class TestLoadHistory(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._path = Path(self._tmp.name) / "history.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_missing_file_returns_empty_list(self) -> None:
        self.assertEqual(load_history(self._path), [])

    def test_loads_valid_history(self) -> None:
        entries = [_entry(80.0), _entry(85.0)]
        self._path.write_text(json.dumps(entries), encoding="utf-8")
        result = load_history(self._path)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["score"], 80.0)

    def test_corrupt_json_returns_empty_list(self) -> None:
        self._path.write_text("not json", encoding="utf-8")
        result = load_history(self._path)
        self.assertEqual(result, [])

    def test_non_list_json_returns_empty_list(self) -> None:
        self._path.write_text('{"not": "a list"}', encoding="utf-8")
        result = load_history(self._path)
        self.assertEqual(result, [])


class TestAppendHistory(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._path = Path(self._tmp.name) / "history.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_creates_file_on_first_entry(self) -> None:
        append_history(self._path, _entry())
        self.assertTrue(self._path.exists())
        data = json.loads(self._path.read_text(encoding="utf-8"))
        self.assertEqual(len(data), 1)

    def test_appends_to_existing_history(self) -> None:
        append_history(self._path, _entry(80.0))
        append_history(self._path, _entry(85.0))
        data = json.loads(self._path.read_text(encoding="utf-8"))
        self.assertEqual(len(data), 2)
        self.assertEqual(data[1]["score"], 85.0)

    def test_trims_to_max_history(self) -> None:
        # Write MAX_HISTORY + 5 entries and confirm only MAX_HISTORY are kept
        for i in range(MAX_HISTORY + 5):
            append_history(self._path, _entry(float(i)))
        data = json.loads(self._path.read_text(encoding="utf-8"))
        self.assertEqual(len(data), MAX_HISTORY)
        # Oldest entries are dropped — last entry should be at index MAX_HISTORY-1
        self.assertEqual(data[-1]["score"], float(MAX_HISTORY + 4))

    def test_no_tmp_file_left_behind(self) -> None:
        append_history(self._path, _entry())
        tmp = self._path.with_suffix(".json.tmp")
        self.assertFalse(tmp.exists())

    def test_creates_parent_directory(self) -> None:
        nested_path = Path(self._tmp.name) / "nested" / "reports" / "history.json"
        append_history(nested_path, _entry())
        self.assertTrue(nested_path.exists())

    def test_round_trip(self) -> None:
        e = _entry(72.5)
        append_history(self._path, e)
        loaded = load_history(self._path)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["score"], 72.5)
        self.assertEqual(loaded[0]["subscriptions"], ["Sub1"])


class TestHistoryPathFor(unittest.TestCase):
    def test_same_directory_as_output(self) -> None:
        path = history_path_for("/reports/audit.html")
        self.assertEqual(path, Path("/reports/cis_run_history.json"))

    def test_current_dir_output(self) -> None:
        path = history_path_for("report.html")
        self.assertEqual(path, Path("cis_run_history.json"))


if __name__ == "__main__":
    unittest.main()
