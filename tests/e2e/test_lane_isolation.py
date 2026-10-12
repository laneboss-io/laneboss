"""H. Lanes stay inside their configuration: events, status and sessions are not shared, another configuration cannot
stop, resume or clean them, and two configurations can run lanes of the same name at the same time."""

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LaneIsolationTest(lanesupport.LaneTest):
    def setUp(self):
        super().setUp()
        self.add_config("beta")

    def test_configurations_do_not_share_lanes(self):
        both = {}
        for config in ("alpha", "beta"):
            both[config] = self.start("web-h1", "--project", "web", "--runner", "forever", "--model", "ever-model-1",
                                      config=config)
        self.start("web-h2", "--project", "web", "--runner", "plain", "--model", "plain-model-1", config="alpha")
        self.wait_event("lane.ended", "web-h2", config="alpha")
        records = {config: self.record("web-h1", config=config) for config in ("alpha", "beta")}
        self.assertNotEqual(records["alpha"]["pid"], records["beta"]["pid"])
        self.assertTrue(both["alpha"]["worktree"].startswith(str(self.repos["alpha"]) + "-"))
        self.assertTrue(both["beta"]["worktree"].startswith(str(self.repos["beta"]) + "-"))
        self.assertNotEqual(both["alpha"]["session"]["socket"], both["beta"]["session"]["socket"])
        alpha_events, beta_events = self.events("alpha"), self.events("beta")
        self.assertEqual({item["id"] for item in alpha_events} & {item["id"] for item in beta_events}, set())
        self.assertEqual(sorted({item["lane"] for item in beta_events}), ["web-h1"])
        self.assertTrue(all(item["payload"].get("worktree", both["beta"]["worktree"]) == both["beta"]["worktree"]
                            for item in beta_events if item["kind"] == "lane.started"))
        self.assertEqual([item["lane"] for item in self.status(config="beta")], ["web-h1"])
        self.assertEqual(sorted(item["lane"] for item in self.status(config="alpha")), ["web-h1", "web-h2"])
        for config in ("alpha", "beta"):
            sessions = self.tmux(both[config]["session"]["socket"], "list-sessions", "-F",
                                 "#{session_name}").stdout.split()
            self.assertEqual(sessions, ["web-h1"], config)
            self.assertIs(self.status("web-h1", config=config)["live"]["session_alive"], True)
        # beta does not know alpha's lane, so it can neither stop, resume nor clean it.
        self.lane_json("mark", "--lane", "web-h2", "--state", "merged", config="alpha")
        for action in ("stop", "resume", "clean", "status"):
            with self.subTest(action):
                self.lane(action, "--lane", "web-h2", config="beta", code=2)
        self.lane("mark", "--lane", "web-h2", "--state", "abandoned", config="beta", code=2)
        self.assertEqual(self.events("beta"), beta_events)
        # Stopping beta's lane leaves alpha's lane of the same name running.
        self.lane_json("stop", "--lane", "web-h1", config="beta")
        self.assertTrue(self.alive(records["alpha"]["pid"]))
        self.assertIs(self.status("web-h1", config="alpha")["running"], True)
        self.assertEqual(self.lane_json("check", config="alpha")["lost"], [])
        self.lane_json("stop", "--lane", "web-h1", config="alpha")
        self.lane_json("clean", "--lane", "web-h2", config="alpha")
        for config in ("alpha", "beta"):
            self.assert_sound(config)
