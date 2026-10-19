import base64
import json
import unittest

from wd_review import check_request


class ReviewInput(unittest.TestCase):
    def test_capture_selection(self):
        target = {"life_id": "owned-child", "run": 3}
        request = {"child": target, "candidate": {"id": "actual-candidate", "class": "manifest", "bytes": 17},
                   "test_plan": {"id": "actual-plan", "class": "manifest", "bytes": 23}, "budget": {"wall_ms": 60000}}
        value = {"type": "assistant", "message": {"content": [{"type": "text", "text": "WD-CHECK-INPUT " +
                 base64.b64encode(json.dumps(request).encode()).decode()}]}}
        self.assertEqual(check_request([value], target), request)
        for values, selected in (([], target), ([value, value], target), ([value], dict(target, run=2))):
            with self.assertRaisesRegex(ValueError, "no unique"):
                check_request(values, selected)


if __name__ == "__main__":
    unittest.main()
