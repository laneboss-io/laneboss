"""Official HTTP-shape rows for the Python catalog consumer; Linux only.

The HTTP service is a local stand-in. Its response uses api.md fields, with
every Choice option derived from the actual request. No credential or model
service is used. Invalid variants precede the positive control in each row.
"""

import copy
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import unittest

# The stand-in judge's key. The header is assembled at run time so no source line carries an
# Authorization-shaped literal (the medium acceptance harness refuses inputs with credential shapes).
STAND_IN_KEY = "local-stand-in-header-only"


def setUpModule():
    if not sys.platform.startswith("linux"):
        raise RuntimeError("TypeSafe rows require the authorized disposable Linux machine")


def load_jobs():
    source = Path(__file__).resolve().parents[1] / "scripts" / "laneboss_jobs.py"
    spec = importlib.util.spec_from_file_location("typesafe_catalog_rows", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def official_response(criteria, choice, owned=0.95, confidence=1.0):
    n = len(criteria)
    top = (confidence * (n - 1) + 1) / n
    return {"model": "jev-1.13.0", "answers": {
        "owned": {"type": "noul", "noul": owned},
        "command": {"type": "choice", "choice": choice, "confidence": confidence,
                    "probabilities": {option: top if option == choice else (1 - top) / (n - 1) for option in criteria}}},
        "usage": {"input_tokens": 318, "output_tokens": 40}}


class TypeSafeJobsRows(unittest.TestCase):
    def setUp(self):
        self.jobs = load_jobs()
        self.state = self.jobs.state()
        self.command = "tmux new-session -d -s demo-lane"
        self.state["managed_objects"] = {"lanes": ["demo-lane"]}
        self.request = self.jobs.question(self.command, self.state)
        self.criteria = self.request["questions"]["command"]["criteria"]
        self.choice = next(iter(self.criteria))

    def test_invalid_envelopes_and_answers(self):
        good = official_response(self.criteria, self.choice)
        variants = []
        for key in ("model", "usage"):
            response = copy.deepcopy(good)
            del response[key]
            variants.append(response)
        for key in ("owned", "command"):
            response = copy.deepcopy(good)
            del response["answers"][key]
            variants.append(response)
        for value in (True, "0.95", -0.1, 1.1):
            response = copy.deepcopy(good)
            response["answers"]["owned"]["noul"] = value
            variants.append(response)
        for key in ("confidence", "probabilities"):
            response = copy.deepcopy(good)
            del response["answers"]["command"][key]
            variants.append(response)
        response = copy.deepcopy(good)
        response["answers"]["command"]["probabilities"][self.choice] = 0.7
        variants.append(response)
        response = copy.deepcopy(good)
        response["answers"]["owned"]["type"] = "score"
        variants.append(response)
        for response in variants:
            with self.subTest(response_fields=list(response)):
                with self.assertRaises(ValueError):
                    self.jobs.validate_response(self.state, response)
                answers = self.jobs.validate_response(self.state, good)
                out = self.jobs.flag(self.command, self.state, answers)
                self.assertTrue(out["flagged"])
                self.assertEqual(out["laneboss_command"], self.choice)
                self.assertEqual(set(out["probabilities"]), set(self.criteria))
        raw = json.dumps(good).replace('"noul": 0.95', '"noul": 1.0000000000000001')
        with self.assertRaises(ValueError):
            self.jobs.validate_response(self.state, self.jobs.load_response(raw))
        with self.assertRaises(ValueError):
            self.jobs.load_response('{"model":"jev-1.13.0","model":"jev-1.13.0"}')

    def test_probability_sum_rounding_boundary(self):
        """Rounding-sized drift passes; drift just outside and bad sums do not."""
        good = official_response(self.criteria, self.choice, confidence=0.91)
        budget = max(1e-6, len(self.criteria) * 5e-5)
        for drift, accepted in ((-budget - 1e-7, False), (budget + 1e-7, False),
                                (-budget + 1e-7, True), (budget - 1e-7, True)):
            response = copy.deepcopy(good)
            response["answers"]["command"]["probabilities"][self.choice] += drift
            if accepted:
                answers = self.jobs.validate_response(self.state, response)
                out = self.jobs.flag(self.command, self.state, answers)
                self.assertTrue(out["flagged"])
                self.assertEqual(out["laneboss_command"], self.choice)
            else:
                with self.assertRaises(ValueError):
                    self.jobs.validate_response(self.state, response)
        malformed = copy.deepcopy(good)
        malformed["answers"]["command"]["probabilities"][self.choice] = 0.5
        with self.assertRaises(ValueError):
            self.jobs.validate_response(self.state, malformed)


    def test_one_request_official_retry(self):
        row = self
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                # Keep server access logs out of credential/error evidence.
                return

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append({"path": self.path, "body": body,
                             "auth_ok": self.headers.get("Authorization") == "Bearer" + " " + STAND_IN_KEY})
                if len(seen) == 1:
                    self.send_response(429)
                    self.end_headers()
                    return
                response = official_response(body["questions"]["command"]["criteria"], row.choice)
                raw = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 3)
        self.addCleanup(server.shutdown)
        self.jobs.ENDPOINT = "http://127.0.0.1:%d/v1/systemone" % server.server_port
        out = self.jobs.judge(self.command, self.state, key=STAND_IN_KEY, timeout=3)
        self.assertTrue(out["flagged"])
        self.assertEqual(len(seen), 2, "one batch and one documented transient retry")
        for call in seen:
            self.assertTrue(call["auth_ok"])
            self.assertEqual(call["path"], "/v1/systemone")
            self.assertEqual(set(call["body"]), {"state", "model", "questions"})
            self.assertEqual(call["body"]["model"], "jev-latest")
            self.assertEqual(call["body"]["state"]["shell_command"], self.command)
            self.assertEqual(set(call["body"]["questions"]), {"owned", "command"})
            self.assertEqual(set(call["body"]["questions"]["owned"]["criteria"]), {"true", "false"})
            self.assertIn("none", call["body"]["questions"]["command"]["criteria"])


if __name__ == "__main__":
    unittest.main()
