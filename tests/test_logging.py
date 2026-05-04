"""Unit tests for logging setup helpers."""

from __future__ import annotations

import logging
import tempfile
import unittest
from pathlib import Path

from cis.helpers import setup_logging


class TestSetupLogging(unittest.TestCase):
    def tearDown(self) -> None:
        _close_root_handlers()

    def test_log_file_parent_directory_is_created(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "nested" / "audit.log"

            setup_logging("INFO", log_file=str(log_path))

            self.assertTrue(log_path.exists())
            _close_root_handlers()


def _close_root_handlers() -> None:
    root = logging.getLogger()
    handlers = list(root.handlers)
    root.handlers.clear()
    for handler in handlers:
        handler.close()


if __name__ == "__main__":
    unittest.main()
