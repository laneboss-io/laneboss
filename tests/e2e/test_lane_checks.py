"""Fix round 1, findings 7, 11 and 12 (ruling R19) and follow-ups 3, 4 and 5: resume hands over only the verified
rendered brief; a lane.started event names its own configuration's session; classification is bounded; rebuild
checks payloads like append and verify do; a start template passes the brief; resume rechecks the account.
"""

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import time

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class LaneCheckTest(lanesupport.LaneTest):
    def test_resume_verifies_the_brief(self):
        self.start("k-brief", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("k-brief"))
        self.wait_event("lane.ended", "k-brief")
        path = Path(self.wait_event("lane.started", "k-brief")["payload"]["brief"]["path"])
        original = path.read_bytes()
        path.write_bytes(original + b"\nAn edit made after rendering.\n")
        result = self.lane("resume", "--lane", "k-brief", code=3)
        self.assertIn("brief", result.stderr)
        copy = path.with_name("copy.md")
        copy.write_bytes(original)
        path.unlink()
        path.symlink_to(copy)
        self.lane("resume", "--lane", "k-brief", code=3)
        self.assertEqual(self.lane_events("k-brief", "lane.resumed"), [])
        path.unlink()
        copy.unlink()
        path.write_bytes(original)
        self.lane_json("resume", "--lane", "k-brief")
        self.assertEqual(self.wait_event("lane.ended", "k-brief", run=2)["payload"]["reason"], "exit")
        self.assert_sound()

    def test_replayed_start_is_refused(self):
        self.add_config("beta")
        self.start("k-replay", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("k-replay"))
        self.wait_event("lane.ended", "k-replay")
        genuine = self.wait_event("lane.started", "k-replay")
        envelope = {key: genuine[key] for key in ("id", "kind", "lane", "actor", "occurred_at", "payload",
                                                  "protocol_version")}
        result = self.append(envelope, config="beta", code=2)
        self.assertIn("session", result.stderr)
        self.assertEqual(self.events("beta"), [])
        for change in ({"session": dict(genuine["payload"]["session"], name="k-other")},
                       {"log": genuine["payload"]["log"].replace("k-replay", "k-other")}):
            with self.subTest(change=sorted(change)):
                changed = dict(envelope, id=None, lane="k-other", payload=dict(genuine["payload"], **change))
                self.append(changed, config="alpha", code=2)
        self.assertEqual(self.lane_events("k-other"), [])
        self.assert_sound()

    def test_classification_is_bounded(self):
        follower = self.follow()
        began = time.monotonic()
        self.start("k-regex", "--runner", "regex", "--model", "regex-model-1", "--worktree", self.scratch("k-regex"))
        _, ended = follower.wait(self, "lane.ended", "k-regex", timeout=60)
        self.assertLess(time.monotonic() - began, 30)
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"], ended["payload"]["pattern"],
                          ended["payload"]["classification"]), ("exit", 1, None, "timed-out"))
        record = self.record("k-regex", ended=True)
        self.assert_gone([record["pid"]], timeout=5)
        self.assertIs(self.status("k-regex")["live"]["supervisor"]["alive"], False)
        self.assert_sound()

    def legacy_store(self):
        """A store holding lane events in the form the 0.2.0 launcher (97f077a) accepted and kept: payloads it never
        checked, and its smaller lane projection. The rows are written as 0.2.0 wrote them, hash included."""
        self.append(self.event("note.added", payload={"text": "before"}))
        store = Path(self.paths()["store"])
        rows = [("lane.planned", {}), ("lane.started", {}), ("lane.state", {"state": "accepted", "note": "extra"})]
        with closing(sqlite3.connect(str(store))) as connection:
            for seq, (kind, payload) in enumerate(rows, 2):
                event = {"id": "ev-legacy-{}".format(seq), "kind": kind, "lane": "k-old", "actor": "e2e",
                         "occurred_at": "2026-10-08T09:0{}:00Z".format(seq), "payload": payload,
                         "protocol_version": "1.0.0", "recorded_at": "2026-10-08T09:0{}:00.000000Z".format(seq),
                         "seq": seq}
                digest = hashlib.sha256(canonical(event).encode("utf-8")).hexdigest()
                connection.execute("INSERT INTO events (seq, id, kind, lane, actor, occurred_at, payload, "
                                   "protocol_version, recorded_at, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                   (seq, event["id"], kind, "k-old", "e2e", event["occurred_at"], canonical(payload),
                                    "1.0.0", event["recorded_at"], digest))
            projection = {"lane": "k-old", "state": "accepted", "state_at": "2026-10-08T09:04:00Z",
                          "times": {"planned": "2026-10-08T09:02:00Z", "started": "2026-10-08T09:03:00Z",
                                    "ended": None, "timeout": None, "stuck": None},
                          "landing": {"merged": None, "deployed": None, "landed": None}, "events": 3, "last_seq": 4}
            connection.execute("INSERT INTO lanes (lane, projection) VALUES (?, ?)", ("k-old", canonical(projection)))
            connection.commit()

    def test_legacy_events_are_refused_alike(self):
        self.legacy_store()
        events = self.events()
        self.assertEqual([item["kind"] for item in events], ["note.added", "lane.planned", "lane.started",
                                                            "lane.state"])
        lanes = self.run_laneboss("state", "lanes", "--config", "alpha", code=None)
        verify = self.run_laneboss("state", "verify", "--config", "alpha", code=3)
        rebuild = self.run_laneboss("state", "rebuild", "--config", "alpha", code=3)
        append = self.append(self.event("lane.state", lane="k-old", payload={"state": "abandoned"}), code=3)
        for result in (verify, rebuild, append):
            self.assertTrue(result.stderr.startswith("integrity problem:"), result.stderr)
        self.assertIn("seq 3", verify.stderr)
        self.assertIn("seq 3", rebuild.stderr)
        self.assertNotEqual(lanes.returncode, 70)
        self.assertEqual(self.run_laneboss("state", "lanes", "--config", "alpha", code=None).stdout, lanes.stdout)

    def test_start_template_needs_the_brief(self):
        directory = self.home / "configs" / "alpha"
        text = (directory / "config.toml").read_text(encoding="utf-8")
        text += lanesupport.runner("blind", "ok", ["--lane", "{lane}"])
        (directory / "config.toml").write_text(text, encoding="utf-8")
        result = self.run_laneboss("config", "validate", "alpha", code=2)
        self.assertIn("runners.blind.command", result.stderr)
        self.assertIn("{brief}", result.stderr)

    def test_resume_rechecks_the_account(self):
        self.start("web-k5", "--project", "web", "--runner", "limit", "--model", "lim-model-1")
        ended = self.wait_event("lane.ended", "web-k5")
        self.assertEqual(self.wait_event("lane.started", "web-k5")["payload"]["account"], "acc-two")
        self.assertEqual(ended["payload"]["reason"], "limit")
        project = self.home / "configs" / "alpha" / "projects" / "web.toml"
        project.write_text(project.read_text(encoding="utf-8").replace('excluded_accounts = ["acc-one"]',
                                                                        'excluded_accounts = ["acc-one", "acc-two"]'),
                           encoding="utf-8")
        result = self.lane("resume", "--lane", "web-k5", code=2)
        self.assertIn("acc-two", result.stderr)
        self.assertEqual(self.lane_events("web-k5", "lane.resumed"), [])
        resumed = self.lane_json("resume", "--lane", "web-k5", "--account", "acc-three")
        self.assertEqual(resumed["account"], "acc-three")
        self.wait_event("lane.ended", "web-k5", run=2)
        self.assert_sound()
