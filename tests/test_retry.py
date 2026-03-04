"""Unit tests for the subprocess retry helper in az_client.

These tests mock ``subprocess.run`` so no real Azure CLI calls are made.  The
focus is on verifying retry/backoff behaviour in the face of throttling,
timeouts, and missing binaries.  Mocking ``time.sleep`` avoids slowing the
suite during backoff loops.
"""

import unittest
from typing import Any
from unittest.mock import patch, MagicMock
import az_client
import subprocess


class TestRunCmdWithRetries(unittest.TestCase):
    """Validates retry/backoff outcomes for transient and fatal subprocess errors."""

    @patch("az_client.logger")
    @patch("az_client.time.sleep", lambda s: None)
    def test_retry_on_429_then_success(self, mock_logger: Any) -> None:
        # The helper should notice an HTTP 429 message, retry once, and then
        # return the successful result on the second attempt.  We patch
        # ``subprocess.run`` to simulate this sequence.
        m1 = MagicMock()
        m1.returncode = 1
        m1.stdout = ""
        m1.stderr = "HTTP 429 Too Many Requests"

        m2 = MagicMock()
        m2.returncode = 0
        m2.stdout = '{"ok": true}'
        m2.stderr = ""

        with patch("az_client.subprocess.run", side_effect=[m1, m2]) as run_mock:
            rc, out, err = az_client._run_cmd_with_retries(["az", "dummy"], timeout=1)
            self.assertEqual(rc, 0)
            self.assertIn('"ok": true', out)
            self.assertEqual(err, "")
            self.assertEqual(run_mock.call_count, 2)

    @patch("az_client.time.sleep", lambda s: None)
    def test_timeout_then_fail(self) -> None:
        # If the subprocess call times out repeatedly, the helper should back
        # off a few times and ultimately return an error code with a timeout
        # message.
        def raise_timeout(*args: Any, **kwargs: Any) -> None:
            raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 1))

        with patch("az_client.subprocess.run", side_effect=raise_timeout):
            rc, out, err = az_client._run_cmd_with_retries(["az", "dummy"], timeout=1)
            self.assertEqual(rc, 1)
            self.assertEqual(out, "")
            self.assertTrue(err.startswith("Timed out"))

    def test_file_not_found(self) -> None:
        # When the az CLI binary is missing, ``subprocess.run`` raises
        # FileNotFoundError; the helper should propagate a friendly error
        # string instead of crashing.
        def raise_fnf(*args: Any, **kwargs: Any) -> None:
            raise FileNotFoundError()

        with patch("az_client.subprocess.run", side_effect=raise_fnf):
            rc, out, err = az_client._run_cmd_with_retries(["az", "dummy"], timeout=1)
            self.assertEqual(rc, 1)
            self.assertEqual(out, "")
            self.assertEqual(err, "az CLI not found")


if __name__ == "__main__":
    unittest.main()
