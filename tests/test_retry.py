"""Unit tests for the subprocess retry helper in az_client.

These tests mock ``subprocess.Popen`` so no real Azure CLI calls are made.  The
focus is on verifying retry/backoff behaviour in the face of throttling,
timeouts, and missing binaries.  Mocking ``time.sleep`` avoids slowing the
suite during backoff loops.
"""

import unittest
from typing import Any
from unittest.mock import patch, MagicMock
import azure.client as az_client
import subprocess


def _mock_popen(returncode: int, stdout: str, stderr: str) -> MagicMock:
    """Return a MagicMock that mimics a Popen object with communicate() returning fixed outputs."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate.return_value = (stdout, stderr)
    return proc


class TestRunCmdWithRetries(unittest.TestCase):
    """Validates retry/backoff outcomes for transient and fatal subprocess errors."""

    @patch("azure.client.logger")
    @patch("azure.client.time.sleep", lambda s: None)
    def test_retry_on_429_then_success(self, _mock_logger: Any) -> None:
        # The helper should notice an HTTP 429 message, retry once, and then
        # return the successful result on the second attempt.  We patch
        # ``subprocess.Popen`` to simulate this sequence.
        p1 = _mock_popen(1, "", "HTTP 429 Too Many Requests")
        p2 = _mock_popen(0, '{"ok": true}', "")

        with patch("azure.client.subprocess.Popen", side_effect=[p1, p2]) as popen_mock:
            rc, out, err = az_client._run_cmd_with_retries(["az", "dummy"], timeout=1)
            self.assertEqual(rc, 0)
            self.assertIn('"ok": true', out)
            self.assertEqual(err, "")
            self.assertEqual(popen_mock.call_count, 2)

    @patch("azure.client.time.sleep", lambda s: None)
    def test_timeout_then_fail(self) -> None:
        # If the subprocess call times out repeatedly, the helper should back
        # off a few times and ultimately return an error code with a timeout
        # message.
        def make_timeout_proc(*args: Any, **_: Any) -> MagicMock:
            proc = MagicMock()
            # First communicate() raises TimeoutExpired; second (drain call) returns empty
            proc.communicate.side_effect = [
                subprocess.TimeoutExpired(cmd=args[0], timeout=1),
                ("", ""),
            ]
            proc.kill = MagicMock()
            return proc

        with patch("azure.client.subprocess.Popen", side_effect=make_timeout_proc):
            rc, out, err = az_client._run_cmd_with_retries(["az", "dummy"], timeout=1)
            self.assertEqual(rc, 1)
            self.assertEqual(out, "")
            self.assertTrue(err.startswith("Timed out"))

    def test_file_not_found(self) -> None:
        # When the az CLI binary is missing, ``subprocess.Popen`` raises
        # FileNotFoundError; the helper should propagate a friendly error
        # string instead of crashing.
        def raise_fnf(*args: Any, **_: Any) -> None:
            raise FileNotFoundError()

        with patch("azure.client.subprocess.Popen", side_effect=raise_fnf):
            rc, out, err = az_client._run_cmd_with_retries(["az", "dummy"], timeout=1)
            self.assertEqual(rc, 1)
            self.assertEqual(out, "")
            self.assertEqual(err, "az CLI not found")


if __name__ == "__main__":
    unittest.main()
