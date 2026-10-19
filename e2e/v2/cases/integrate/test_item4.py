import copy
import json
from pathlib import Path
import tempfile
import unittest

import run


class InferenceFixtureTests(unittest.TestCase):
    def test_positive_limit_is_current_an_b550(self):
        policy = {"generation": 3, "context": {"level": 3, "role": "executor"},
                  "judge": {"deployment_sha256": "a" * 64, "tokenizer_sha256": "b" * 64}}
        lane = {"level": 3, "role": "executor", "logical_turn_id": "turn-one", "grant_set_id": "grant-one",
                "workspace": {"logical_cwd": "/work/main"}, "budget_remaining": {"spend_micros": 37}}
        value = {"schema": "laneboss.e2e-judge-budget.v1", "config": "case-integrate",
                 "policy_generation": 3, "deployment_sha256": "a" * 64,
                 "tokenizer_sha256": "b" * 64, "max_cost_micros": 19}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inference-budget.json"
            path.write_text(json.dumps(value))
            self.assertEqual(run.fixture_inference_limit(path, "case-integrate", policy, lane), 19)
            for field, changed in (("config", "foreign"), ("policy_generation", 2),
                                   ("deployment_sha256", "c" * 64), ("tokenizer_sha256", "d" * 64),
                                   ("max_cost_micros", 0), ("max_cost_micros", True), ("max_cost_micros", 38)):
                bad = copy.deepcopy(value)
                bad[field] = changed
                path.write_text(json.dumps(bad))
                with self.assertRaises(run.CaseFailure):
                    run.fixture_inference_limit(path, "case-integrate", policy, lane)
        request = run.preview_request("case-integrate", {"life_id": "life-one", "run": 1},
                                      policy, lane, "e" * 64, 19, b"measured command")
        self.assertEqual(request["rules"], [])
        self.assertEqual(request["task"], "")
        self.assertEqual(request["max_cost_micros"], 19)
        self.assertEqual(request["command"]["raw_sha256"], run.digest(b"measured command"))


if __name__ == "__main__":
    unittest.main()
