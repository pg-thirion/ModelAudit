"""End-to-end CLI contract and error-path tests."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from modelaudit.cli import main
from modelaudit.reporting import write_report


class CliTests(unittest.TestCase):
    def invoke(self, *args):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return main(list(args))

    def test_demo_report_and_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            self.assertEqual(self.invoke("--demo", "secure", "--output", str(first)), 0)
            self.assertEqual(self.invoke("--demo", "secure", "--baseline", str(first),
                                         "--output", str(second)), 0)
            report = json.loads(second.read_text())
            self.assertEqual(report["comparison"], {"regressions": [], "recoveries": []})
            self.assertEqual(report["target_type"], "simulation")
            self.assertFalse(report["fixture_attestation"])
            self.assertEqual(self.invoke("--demo", "vulnerable"), 1)
            self.assertEqual(self.invoke("--demo", "secure", "--repeat", "2",
                                         "--baseline", str(first)), 2)
            self.assertEqual(self.invoke("--demo", "secure", "--baseline", str(first),
                                         "--output", str(first)), 2)

    def test_live_without_attestation_never_connects(self):
        with patch("modelaudit.cli.HttpTarget") as target:
            self.assertEqual(self.invoke("--endpoint", "https://example.invalid"), 2)
            target.assert_not_called()

    def test_live_without_positive_control_never_connects(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = Path(directory) / "suite.json"
            suite.write_text(json.dumps([{"id": "test", "category": "agency",
                "severity": "high", "prompt": "test", "forbidden": ["marker"]}]))
            with patch("modelaudit.cli.HttpTarget") as target:
                self.assertEqual(self.invoke("--endpoint", "https://example.invalid",
                    "--confirm-fixtures", "--target-label", "staging", "--suite", str(suite)), 2)
                target.assert_not_called()

    def test_invalid_label_and_output(self):
        self.assertEqual(self.invoke("--demo", "secure", "--target-label", "not valid"), 2)
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.invoke("--demo", "secure", "--output", directory), 2)
            self.assertFalse(list(Path(directory).glob(".modelaudit-*")))

    def test_atomic_write_failure_preserves_prior_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            write_report(path, {"old": True})
            with self.assertRaises(ValueError):
                write_report(path, {"invalid": float("nan")})
            self.assertEqual(json.loads(path.read_text()), {"old": True})
            self.assertFalse(list(Path(directory).glob(".modelaudit-*")))
