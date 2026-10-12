"""F. Lanes: a projection of lane events, with landing as three separate facts and a byte-exact rebuild.

Lane events carry the payloads the launcher writes (docs/architecture.md, "Lanes"); these tests append them by hand,
as a supervisor or a replayed spool would.
"""

from contextlib import closing
import json
from pathlib import Path
import sqlite3

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


ended = support.ended_payload


class LaneTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.write_config("alpha")

    def started(self, lane="alpha-lane-1", **options):
        return support.started_payload(self.laneboss_json("config", "path", "alpha"), lane, **options)

    def lane_event(self, kind, at, lane="alpha-lane-1", payload=None):
        return self.event(kind, lane=lane, occurred_at=at, payload=payload or {})

    def lanes(self):
        return self.laneboss_json("state", "lanes", "--config", "alpha")

    def lane(self, name):
        matches = [item for item in self.lanes() if item["lane"] == name]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_projection_and_rebuild(self):
        planned, began, end = "2026-10-08T09:00:00+08:00", "2026-10-08T09:05:00+08:00", "2026-10-08T10:40:00Z"
        self.append(self.lane_event("lane.planned", planned))
        self.append(self.lane_event("lane.started", began, payload=self.started()))
        self.append(self.lane_event("lane.ended", end, payload=ended()))
        self.append(self.event("test.note", lane="alpha-lane-1"))
        lane = self.lane("alpha-lane-1")
        self.assertEqual(lane["state"], "verifying")
        self.assertEqual(lane["state_at"], end)
        self.assertEqual(lane["times"], {"planned": planned, "started": began, "ended": end, "timeout": None,
                                         "stuck": None, "resumed": None, "lost": None, "cleaned": None})
        self.assertEqual(lane["landing"], {"merged": None, "deployed": None, "landed": None})
        self.assertEqual(lane["events"], 3)
        self.assertEqual((lane["run"], lane["running"], lane["runner"], lane["model"], lane["account"],
                          lane["reason"], lane["resumes"], lane["lost"]),
                         (1, False, "local", "example-model-2", "account-two", "exit", 0, 0))
        self.append(self.lane_event("lane.planned", "2026-10-08T11:00:00Z", lane="alpha-lane-2"))
        self.append(self.lane_event("lane.state", "2026-10-08T11:30:00+08:00", payload={"state": "accepted"}))
        self.append(self.lane_event("lane.merged", "2026-10-08T12:00:00+08:00"))
        lane = self.lane("alpha-lane-1")
        self.assertEqual(lane["state"], "accepted")
        self.assertEqual(lane["landing"], {"merged": "2026-10-08T12:00:00+08:00", "deployed": None, "landed": None})
        self.append(self.lane_event("lane.deployed", "2026-10-08T12:30:00+08:00"))
        self.assertEqual(self.lane("alpha-lane-1")["landing"],
                         {"merged": "2026-10-08T12:00:00+08:00", "deployed": "2026-10-08T12:30:00+08:00",
                          "landed": None})
        self.append(self.lane_event("lane.landed", "2026-10-08T13:00:00+08:00"))
        self.append(self.lane_event("lane.state", "2026-10-08T13:05:00+08:00", payload={"state": "merged"}))
        self.append(self.lane_event("lane.started", "2026-10-08T11:05:00Z", lane="alpha-lane-2",
                                    payload=self.started("alpha-lane-2")))
        self.append(self.lane_event("lane.stuck", "2026-10-08T11:10:00Z", lane="alpha-lane-2",
                                    payload={"run": 1, "quiet_seconds": 600, "output_bytes": 12}))
        self.append(self.lane_event("lane.timeout", "2026-10-08T11:20:00Z", lane="alpha-lane-2",
                                    payload={"run": 1, "budget_minutes": 30, "elapsed_seconds": 1800.2}))
        lane = self.lane("alpha-lane-1")
        self.assertEqual(lane["state"], "merged")
        self.assertEqual(lane["landing"], {"merged": "2026-10-08T12:00:00+08:00",
                                           "deployed": "2026-10-08T12:30:00+08:00",
                                           "landed": "2026-10-08T13:00:00+08:00"})
        other = self.lane("alpha-lane-2")
        self.assertEqual((other["state"], other["running"]), ("running", True))
        self.assertEqual((other["times"]["stuck"], other["times"]["timeout"]),
                         ("2026-10-08T11:10:00Z", "2026-10-08T11:20:00Z"))
        self.append(self.lane_event("lane.lost", "2026-10-08T11:30:00Z", lane="alpha-lane-2",
                                    payload={"run": 1, "survivors": 0}))
        self.append(self.lane_event("lane.resumed", "2026-10-08T11:40:00Z", lane="alpha-lane-2",
                                    payload={"run": 2, "after": "lost", "message": None}))
        self.append(self.lane_event("lane.started", "2026-10-08T11:40:01Z", lane="alpha-lane-2",
                                    payload=self.started("alpha-lane-2", run=2, how="resume", account="account-one")))
        other = self.lane("alpha-lane-2")
        self.assertEqual((other["run"], other["running"], other["account"], other["resumes"], other["lost"],
                          other["reason"]), (2, True, "account-one", 1, 1, None))
        listing = self.run_laneboss("state", "lanes", "--config", "alpha").stdout
        self.assertEqual([item["lane"] for item in json.loads(listing)], ["alpha-lane-1", "alpha-lane-2"])
        self.assertEqual(self.run_laneboss("state", "rebuild", "--config", "alpha").stdout, listing)
        self.assertEqual(self.run_laneboss("state", "lanes", "--config", "alpha").stdout, listing)
        self.laneboss_json("state", "verify", "--config", "alpha")

    def test_recorded_time_by_default(self):
        result = json.loads(self.append(self.event("lane.planned", lane="alpha-lane-3")).stdout)
        lane = self.lane("alpha-lane-3")
        self.assertEqual(lane["times"]["planned"], result["recorded_at"])
        self.assertEqual(lane["state"], "queued")

    def test_tampered_projection_rebuilds(self):
        self.append(self.lane_event("lane.planned", "2026-10-08T09:00:00Z"))
        self.append(self.lane_event("lane.started", "2026-10-08T09:01:00Z", payload=self.started()))
        listing = self.run_laneboss("state", "lanes", "--config", "alpha").stdout
        store = Path(self.laneboss_json("config", "path", "alpha")["store"])
        with closing(sqlite3.connect(str(store))) as connection:
            tables = [row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite%'")]
            derived = [name for name in tables if name not in ("events", "meta")]
            self.assertTrue(derived, "the store keeps its lane projection in a table")
            for name in derived:
                connection.execute('DELETE FROM "{}"'.format(name))
            connection.commit()
        self.assertIn("projection", self.run_laneboss("state", "verify", "--config", "alpha", code=3).stderr)
        self.assertEqual(self.run_laneboss("state", "rebuild", "--config", "alpha").stdout, listing)
        self.assertEqual(self.run_laneboss("state", "lanes", "--config", "alpha").stdout, listing)
        self.laneboss_json("state", "verify", "--config", "alpha")
