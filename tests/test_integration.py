import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from modelaudit.adapters import DemoTarget, HttpTarget, Response
from modelaudit.engine import evaluate, exit_code
from modelaudit.reporting import compare_baseline, write_report
from modelaudit.suite import Case, load_suite

CASE = Case("event", "agency", "high", "synthetic request", (), (),
            forbidden_events=("audit_write",))

class Handler(BaseHTTPRequestHandler):
    requests = []
    def log_message(self, *args):
        pass
    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.requests.append((self.path, payload))
        if self.path == "/redirect":
            self.send_response(307)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        body = {"response": "completed", "events": []}
        if self.path == "/missing":
            body.pop("events")
        elif self.path == "/action":
            body["events"] = ["audit_write"]
        elif self.path == "/chat":
            body = {"choices": [{"finish_reason": "stop", "message": {"content": "okay"}}]}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def target(self, path, adapter="generic", model=None):
        with patch.dict(os.environ, {}, clear=True):
            return HttpTarget(self.url + path, adapter, model, 2)

    def test_event_assertions(self):
        for path, expected in (("/ok", 0), ("/missing", 2), ("/action", 1)):
            with self.subTest(path=path):
                self.assertEqual(exit_code(evaluate([CASE], self.target(path))), expected)

    def test_redirect_is_not_followed(self):
        before = len(Handler.requests)
        self.assertEqual(exit_code(evaluate([CASE], self.target("/redirect"))), 2)
        self.assertEqual(len(Handler.requests), before + 1)

    def test_chat_adapter(self):
        case = Case("chat", "control", "low", "hello", ("okay",), ())
        self.assertEqual(exit_code(evaluate([case], self.target("/chat", "chat", "mock"))), 0)
        self.assertEqual(Handler.requests[-1][1]["messages"][0]["content"], "hello")

    def test_http_token_rejected(self):
        with patch.dict(os.environ, {"MODELAUDIT_TOKEN": "synthetic"}):
            with self.assertRaises(ValueError):
                HttpTarget(self.url + "/ok", "generic", None, 2)

class ReportTests(unittest.TestCase):
    def test_baseline_and_atomic_report(self):
        cases = load_suite(Path(__file__).parents[1] / "modelaudit" / "default_suite.json")
        first = evaluate(cases, DemoTarget())
        second = evaluate(cases, DemoTarget(True))
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "report.json"
            write_report(path, first)
            comparison = compare_baseline(path, second)
            self.assertIn("fictional-secret", comparison["regressions"])
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                compare_baseline(path, evaluate(cases, DemoTarget(), 2))

    def test_missing_event_evidence(self):
        class NoEvidence:
            def respond(self, case):
                return Response("nothing")
        self.assertEqual(exit_code(evaluate([CASE], NoEvidence())), 2)

    def test_demo_not_driven_by_assertions(self):
        case = Case("control-basic", "control", "low", "test", ("impossible",), ())
        self.assertEqual(exit_code(evaluate([case], DemoTarget())), 1)

    def test_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "suite.json"
            path.write_text('[{"id":"one","id":"two"}]')
            with self.assertRaises(ValueError):
                load_suite(path)
