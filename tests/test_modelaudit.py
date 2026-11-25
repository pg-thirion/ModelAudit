import json
from pathlib import Path
import tempfile
import unittest
from modelaudit.adapters import DemoTarget, HttpTarget
from modelaudit.engine import evaluate, exit_code
from modelaudit.suite import Case, load_suite

class EngineTests(unittest.TestCase):
    def setUp(self):
        self.cases = load_suite(Path(__file__).parents[1] / "modelaudit" / "default_suite.json")

    def test_secure_demo(self):
        report = evaluate(self.cases, DemoTarget(), 3)
        self.assertEqual(exit_code(report), 0)
        self.assertEqual(report["case_pass_rate"], 100)
        self.assertEqual(len(report["results"][0]["trials"]), 3)

    def test_vulnerable_demo(self):
        report = evaluate(self.cases, DemoTarget(True))
        self.assertEqual(exit_code(report), 1)
        self.assertGreater(report["counts"]["fail"], 0)

    def test_error_is_fail_closed(self):
        class Broken:
            def respond(self, case):
                raise RuntimeError("sensitive value")
        report = evaluate(self.cases, Broken())
        self.assertEqual(exit_code(report), 2)
        self.assertNotIn("sensitive value", json.dumps(report))

    def test_casefold_and_no_raw_reply(self):
        case = Case("case", "policy", "high", "secret input", (), ("canary",))
        class Reply:
            def respond(self, case):
                return "CANARY and private reply"
        report = evaluate([case], Reply())
        self.assertEqual(exit_code(report), 1)
        self.assertNotIn("private reply", json.dumps(report))
        self.assertNotIn("secret input", json.dumps(report))

    def test_insecure_url_rejected(self):
        for url in ("http://example.com", "file:///tmp/test", "https://u:p@example.com"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                HttpTarget(url, "generic", None, 10)

    def test_chat_requires_model(self):
        with self.assertRaises(ValueError):
            HttpTarget("https://example.com", "chat", None, 10)

    def test_invalid_suite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "suite.json"
            path.write_text('[{"id":"one"}]')
            with self.assertRaises(ValueError):
                load_suite(path)

if __name__ == "__main__":
    unittest.main()
