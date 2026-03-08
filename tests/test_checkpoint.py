"""Unit tests for cis_checkpoint: save_checkpoint, load_checkpoints, results_from_checkpoint."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cis.checkpoint as cis_checkpoint
from cis.checkpoint import (
    load_checkpoints,
    load_tenant_checkpoint,
    results_from_checkpoint,
    save_checkpoint,
    save_tenant_checkpoint,
)
from cis.config import BENCHMARK_VER, VERSION
from cis.models import R


def _sample_results() -> list[R]:
    return [
        R("1.1", "Check one", 1, "Sec 1", "PASS", "All good", "", "sub-1", "Sub One"),
        R("1.2", "Check two", 2, "Sec 1", "FAIL", "Bad thing", "Fix it", "sub-1", "Sub One", "res-a"),
    ]


class TestSaveCheckpoint(unittest.TestCase):
    """save_checkpoint writes a valid JSON file atomically."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._dir = Path(self._tmp.name)
        self._patch = patch.object(cis_checkpoint, "CHECKPOINT_DIR", self._dir)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def test_creates_json_file(self) -> None:
        save_checkpoint("sub-1", "Sub One", _sample_results())
        self.assertTrue((self._dir / "sub-1.json").exists())

    def test_no_tmp_file_left_behind(self) -> None:
        save_checkpoint("sub-1", "Sub One", _sample_results())
        self.assertFalse((self._dir / "sub-1.json.tmp").exists())

    def test_file_content_is_valid_json(self) -> None:
        save_checkpoint("sub-1", "Sub One", _sample_results())
        data = json.loads((self._dir / "sub-1.json").read_text(encoding="utf-8"))
        self.assertEqual(data["subscription_id"], "sub-1")
        self.assertEqual(data["subscription_name"], "Sub One")
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["tool_version"], VERSION)
        self.assertEqual(data["benchmark_version"], BENCHMARK_VER)
        self.assertEqual(len(data["results"]), 2)

    def test_results_serialised_correctly(self) -> None:
        save_checkpoint("sub-1", "Sub One", _sample_results())
        data = json.loads((self._dir / "sub-1.json").read_text(encoding="utf-8"))
        r0 = data["results"][0]
        self.assertEqual(r0["control_id"], "1.1")
        self.assertEqual(r0["status"], "PASS")

    def test_custom_status_stored(self) -> None:
        save_checkpoint("sub-1", "Sub One", [], status="failed")
        data = json.loads((self._dir / "sub-1.json").read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "failed")

    def test_creates_directory_if_missing(self) -> None:
        nested = self._dir / "nested" / "checkpoints"
        with patch.object(cis_checkpoint, "CHECKPOINT_DIR", nested):
            save_checkpoint("sub-1", "Sub One", [])
        self.assertTrue((nested / "sub-1.json").exists())


class TestLoadCheckpoints(unittest.TestCase):
    """load_checkpoints returns only completed checkpoints."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._dir = Path(self._tmp.name)
        self._patch = patch.object(cis_checkpoint, "CHECKPOINT_DIR", self._dir)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def _write(self, sid: str, status: str = "completed", extra: dict | None = None) -> None:
        data = {
            "tool_version": VERSION,
            "benchmark_version": BENCHMARK_VER,
            "subscription_id": sid,
            "subscription_name": f"Sub {sid}",
            "timestamp": "2025-01-01T00:00:00+00:00",
            "status": status,
            "results": [],
        }
        if extra:
            data.update(extra)
        (self._dir / f"{sid}.json").write_text(json.dumps(data), encoding="utf-8")

    def test_missing_dir_returns_empty(self) -> None:
        with patch.object(cis_checkpoint, "CHECKPOINT_DIR", self._dir / "no-such-dir"):
            result = load_checkpoints()
        self.assertEqual(result, {})

    def test_loads_completed_checkpoint(self) -> None:
        self._write("sub-1")
        result = load_checkpoints()
        self.assertIn("sub-1", result)

    def test_skips_failed_checkpoint(self) -> None:
        self._write("sub-fail", status="failed")
        result = load_checkpoints()
        self.assertNotIn("sub-fail", result)

    def test_skips_corrupt_json(self) -> None:
        (self._dir / "corrupt.json").write_text("not json", encoding="utf-8")
        result = load_checkpoints()
        self.assertNotIn("corrupt", result)

    def test_loads_multiple_checkpoints(self) -> None:
        self._write("sub-1")
        self._write("sub-2")
        self._write("sub-bad", status="failed")
        result = load_checkpoints()
        self.assertIn("sub-1", result)
        self.assertIn("sub-2", result)
        self.assertEqual(len(result), 2)

    def test_version_mismatch_still_loads(self) -> None:
        self._write("sub-1", extra={"tool_version": "0.0.0"})
        result = load_checkpoints()
        self.assertIn("sub-1", result)


class TestResultsFromCheckpoint(unittest.TestCase):
    """results_from_checkpoint deserialises R instances defensively."""

    def _cp(self, results: list[dict]) -> dict:
        return {
            "subscription_id": "sub-1",
            "results": results,
        }

    def test_round_trip(self) -> None:
        originals = _sample_results()
        from dataclasses import asdict

        cp = self._cp([asdict(r) for r in originals])
        restored = results_from_checkpoint(cp)
        self.assertEqual(len(restored), 2)
        self.assertEqual(restored[0].control_id, "1.1")
        self.assertEqual(restored[1].status, "FAIL")

    def test_empty_results(self) -> None:
        self.assertEqual(results_from_checkpoint(self._cp([])), [])

    def test_missing_results_key(self) -> None:
        self.assertEqual(results_from_checkpoint({}), [])

    def test_extra_fields_ignored(self) -> None:
        from dataclasses import asdict

        rec = asdict(_sample_results()[0])
        rec["future_field"] = "ignored"
        restored = results_from_checkpoint(self._cp([rec]))
        self.assertEqual(len(restored), 1)

    def test_bad_record_skipped(self) -> None:
        from dataclasses import asdict

        good = asdict(_sample_results()[0])
        bad = {"not_a_field": "x"}
        restored = results_from_checkpoint(self._cp([good, bad]))
        self.assertEqual(len(restored), 1)


class TestSaveLoadRoundTrip(unittest.TestCase):
    """Integration: save then load returns equivalent results."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._dir = Path(self._tmp.name)
        self._patch = patch.object(cis_checkpoint, "CHECKPOINT_DIR", self._dir)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def test_save_load_roundtrip(self) -> None:
        originals = _sample_results()
        save_checkpoint("sub-rt", "Round-Trip Sub", originals)
        loaded = load_checkpoints()
        self.assertIn("sub-rt", loaded)
        restored = results_from_checkpoint(loaded["sub-rt"])
        self.assertEqual(len(restored), len(originals))
        for orig, rest in zip(originals, restored):
            self.assertEqual(orig.control_id, rest.control_id)
            self.assertEqual(orig.status, rest.status)
            self.assertEqual(orig.details, rest.details)


# =============================================================================
# TENANT CHECKPOINT
# =============================================================================


def _tenant_results() -> list[R]:
    return [
        R("5.1.1", "Security defaults", 1, "5 - Identity Services", "INFO", "CA in use", "", "", ""),
        R("5.1.2", "MFA enabled", 1, "5 - Identity Services", "MANUAL", "Review required", "Check docs", "", ""),
    ]


class TestSaveTenantCheckpoint(unittest.TestCase):
    """save_tenant_checkpoint writes the correct file; load_tenant_checkpoint reads it back."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._dir = Path(self._tmp.name)
        self._patch = patch.object(cis_checkpoint, "CHECKPOINT_DIR", self._dir)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def test_creates_tenant_json_file(self) -> None:
        save_tenant_checkpoint(_tenant_results())
        self.assertTrue((self._dir / "_tenant.json").exists())

    def test_no_tmp_file_left_behind(self) -> None:
        save_tenant_checkpoint(_tenant_results())
        self.assertFalse((self._dir / "_tenant.json.tmp").exists())

    def test_file_content_is_valid_json(self) -> None:
        save_tenant_checkpoint(_tenant_results())
        data = json.loads((self._dir / "_tenant.json").read_text(encoding="utf-8"))
        self.assertEqual(data["subscription_id"], "_tenant")
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["tool_version"], VERSION)
        self.assertEqual(len(data["results"]), 2)

    def test_round_trip(self) -> None:
        originals = _tenant_results()
        save_tenant_checkpoint(originals)
        loaded = load_tenant_checkpoint()
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0].control_id, "5.1.1")
        self.assertEqual(loaded[1].status, "MANUAL")

    def test_empty_results_round_trip(self) -> None:
        save_tenant_checkpoint([])
        loaded = load_tenant_checkpoint()
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded, [])

    def test_creates_directory_if_missing(self) -> None:
        nested = self._dir / "nested" / "checkpoints"
        with patch.object(cis_checkpoint, "CHECKPOINT_DIR", nested):
            save_tenant_checkpoint(_tenant_results())
        self.assertTrue((nested / "_tenant.json").exists())


class TestLoadTenantCheckpoint(unittest.TestCase):
    """load_tenant_checkpoint returns None on missing / corrupt / version-mismatched files."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._dir = Path(self._tmp.name)
        self._patch = patch.object(cis_checkpoint, "CHECKPOINT_DIR", self._dir)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def test_missing_file_returns_none(self) -> None:
        self.assertIsNone(load_tenant_checkpoint())

    def test_corrupt_json_returns_none(self) -> None:
        (self._dir / "_tenant.json").write_text("not json", encoding="utf-8")
        self.assertIsNone(load_tenant_checkpoint())

    def test_version_mismatch_returns_none(self) -> None:
        save_tenant_checkpoint(_tenant_results())
        path = self._dir / "_tenant.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["tool_version"] = "0.0.0-old"
        path.write_text(json.dumps(data), encoding="utf-8")
        self.assertIsNone(load_tenant_checkpoint())

    def test_load_checkpoints_skips_tenant_file(self) -> None:
        """load_checkpoints must not surface _tenant.json as a subscription entry."""
        save_tenant_checkpoint(_tenant_results())
        result = load_checkpoints()
        self.assertNotIn("_tenant", result)
        self.assertEqual(len(result), 0)


if __name__ == "__main__":
    unittest.main()
