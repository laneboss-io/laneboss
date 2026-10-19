"""Populated-view and refusal controls; Linux unit scope, no installed claim."""

import copy
import json
import unittest

from view_checks import cli_passed, denied, populated


PIN = "21" * 32
REF = {"id": "fixture-object", "sha256": PIN, "bytes": 5, "class": "record"}


def views():
    target = {"life_id": "fixture-life", "run": 1}
    resource = {"id": "fixture-resource", "sha256": PIN, "source": REF,
                "declared": True, "verified_loaded": True, "kind": "plugin"}
    return {
        "DASH-DECISIONS": {"decisions": [{"id": "decision", "text": "retained decision", "source": REF}]},
        "DASH-RAW": {"records": [{"id": "raw-1", "target": target, "data": REF},
                                 {"id": "raw-2", "target": target, "data": REF}],
                     "gaps": [{"target": target, "reason": "capture gap", "observed_at": "2026-01-01T00:00:00Z"}],
                     "messages": [{"id": "mail", "content": REF}]},
        "DASH-TREE": {"nodes": [{"configured": True, "live": False, "instance_id": "configured"},
                                 {"configured": False, "live": True, "life_id": "live-life"}]},
        "DASH-REFUSALS": {"counts": [{"refused": 1, "unscored": 1}], "receipts": []},
        "DASH-PLUGINS": {"resources": [resource]},
        "DASH-RESOURCES": {"resources": [resource]},
        "DASH-LIFECYCLE": {"lanes": [{"life_id": "fixture-life", "run": 1, "generation": 2}]},
        "DASH-APPROVALS": {
            "changes": [{"id": "change", "manifest_sha256": PIN}],
            "approvals": [{"id": "approval", "change_id": "change", "manifest_sha256": PIN}],
            "applications": [{"id": "application", "change_id": "change", "approval_id": "approval",
                              "manifest_sha256": PIN, "old_generation": 1, "new_generation": 2}]},
    }


class ViewTests(unittest.TestCase):
    def test_eight(self):
        self.assertEqual(len(views()), 8)
        for aid, value in views().items():
            with self.subTest(aid=aid):
                self.assertTrue(populated(aid, value), "real populated shape was rejected")

    def test_empty(self):
        for aid, value in views().items():
            for key, rows in value.items():
                if key == "receipts":
                    continue
                empty = copy.deepcopy(value)
                empty[key] = []
                with self.subTest(aid=aid, key=key):
                    self.assertFalse(populated(aid, empty), "empty dashboard view passed")

    def test_malformed(self):
        for aid, value in views().items():
            for malformed in (None, [], "rows", 1, True, {"error": {"code": "forbidden"}}):
                with self.subTest(aid=aid, malformed=malformed):
                    self.assertFalse(populated(aid, malformed), "malformed dashboard view passed")
            for key in value:
                for malformed in (None, 1, "rows"):
                    changed = copy.deepcopy(value)
                    changed[key] = malformed
                    with self.subTest(aid=aid, key=key, malformed=malformed):
                        self.assertFalse(populated(aid, changed), "malformed dashboard rows passed")

    def test_pins(self):
        for aid in ("DASH-RESOURCES", "DASH-PLUGINS"):
            for field, bad in (("id", ""), ("sha256", ""), ("sha256", "z" * 64), ("source", {}),
                               ("source", {"id": "another", "sha256": "22" * 32})):
                value = copy.deepcopy(views()[aid])
                value["resources"][0][field] = bad
                with self.subTest(aid=aid, field=field, bad=bad):
                    self.assertFalse(populated(aid, value), "unbound resource bytes passed")

    def test_plugin(self):
        for field, value in (("declared", False), ("verified_loaded", False), ("kind", "script")):
            changed = copy.deepcopy(views()["DASH-PLUGINS"])
            changed["resources"][0][field] = value
            self.assertFalse(populated("DASH-PLUGINS", changed), "unverified plugin passed")
        changed = copy.deepcopy(views()["DASH-PLUGINS"])
        changed["resources"][0]["verified_loaded"] = False
        other = copy.deepcopy(changed["resources"][0])
        other.update({"id": "other-plugin", "declared": False, "verified_loaded": True})
        changed["resources"].append(other)
        self.assertFalse(populated("DASH-PLUGINS", changed), "different declared/loaded rows passed")

    def test_approvals(self):
        for collection, field, bad in (
                ("changes", "id", "other"), ("changes", "manifest_sha256", "23" * 32),
                ("approvals", "change_id", "other"), ("approvals", "manifest_sha256", "23" * 32),
                ("applications", "approval_id", "other"), ("applications", "change_id", "other"),
                ("applications", "manifest_sha256", "23" * 32), ("applications", "new_generation", 1),
                ("applications", "new_generation", True), ("applications", "old_generation", -1)):
            changed = copy.deepcopy(views()["DASH-APPROVALS"])
            changed[collection][0][field] = bad
            with self.subTest(collection=collection, field=field):
                self.assertFalse(populated("DASH-APPROVALS", changed), "unrelated approval/application passed")

    def test_raw(self):
        value = copy.deepcopy(views()["DASH-RAW"])
        value["records"][1] = copy.deepcopy(value["records"][0])
        self.assertFalse(populated("DASH-RAW", value), "duplicate raw records passed")
        for collection, field, bad in (("records", "target", {}), ("records", "data", {}),
                                       ("gaps", "reason", ""), ("gaps", "observed_at", ""),
                                       ("messages", "content", {})):
            changed = copy.deepcopy(views()["DASH-RAW"])
            changed[collection][0][field] = bad
            with self.subTest(collection=collection, field=field):
                self.assertFalse(populated("DASH-RAW", changed), "unbound raw record/gap/mail passed")

    def test_cli(self):
        valid = {"exit": 0, "populated": True, "session_proof_sha256": PIN, "stderr": None}
        self.assertTrue(cli_passed(valid))
        for field, value in (("exit", 2), ("populated", False), ("session_proof_sha256", ""),
                             ("stderr", {"code": "forbidden"})):
            changed = dict(valid, **{field: value})
            self.assertFalse(cli_passed(changed), "failed or unauthorized CLI probe passed")

    def test_denials(self):
        body = json.dumps({"error": {"code": "forbidden", "message": "refused"}}).encode()
        self.assertTrue(denied(403, body, (401, 403)))
        for status, raw in ((200, body), (500, body), (403, b""), (403, b"<html>denied</html>"),
                            (403, b'{"error":{"code":"not_implemented","message":"missing"}}'),
                            (403, b'{"result":{"status":"succeeded"}}')):
            with self.subTest(status=status, raw=raw):
                self.assertFalse(denied(status, raw, (401, 403)), "status-only refusal passed")
        missing_receipt = b'{"error":{"code":"not_found","message":"mutation receipt is absent"}}'
        self.assertFalse(denied(404, missing_receipt, (401, 403, 404)), "non-stale missing receipt passed as an authentication refusal")
        self.assertTrue(denied(404, missing_receipt, (401, 403, 404), stale=True))


if __name__ == "__main__":
    unittest.main()
