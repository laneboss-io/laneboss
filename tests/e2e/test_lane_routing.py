"""B. Routing and overrides: the first usable routing entry, explicit choices that win and say so, accounts that are
never picked, and requests refused before anything starts."""

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LaneRoutingTest(lanesupport.LaneTest):
    def started(self, lane):
        return self.wait_event("lane.started", lane)["payload"]

    def test_routing_first_usable_entry(self):
        # routing.hard[0] uses runner solo, whose only account the project excludes, so hard[1] is the first usable.
        self.start("web-b1", "--project", "web", "--difficulty", "hard")
        payload = self.started("web-b1")
        self.assertEqual((payload["runner"], payload["model"], payload["effort"], payload["account"]),
                         ("ok", "hard-model-4", "max", "acc-two"))
        self.assertEqual(payload["chosen_by"], {"runner": "routing", "model": "routing", "effort": "routing",
                                                "account": "default"})
        self.assertEqual(payload["difficulty"], "hard")
        record = self.record("web-b1", ended=True)
        self.assertEqual(record["argv"][record["argv"].index("--model") + 1], "hard-model-4")
        self.assertEqual(record["argv"][record["argv"].index("--effort") + 1], "max")
        self.assertEqual(record["argv"][record["argv"].index("--account") + 1], "acc-two")
        self.wait_event("lane.ended", "web-b1")
        self.assert_sound()

    def test_explicit_choices_win(self):
        self.start("web-b2", "--project", "web", "--difficulty", "hard", "--model", "custom-model-7", "--account",
                   "acc-three")
        payload = self.started("web-b2")
        self.assertEqual((payload["runner"], payload["model"], payload["effort"], payload["account"]),
                         ("ok", "custom-model-7", "max", "acc-three"))
        self.assertEqual(payload["chosen_by"], {"runner": "routing", "model": "supervisor", "effort": "routing",
                                                "account": "supervisor"})
        self.start("web-b3", "--project", "web", "--difficulty", "standard", "--effort", "low")
        payload = self.started("web-b3")
        self.assertEqual((payload["model"], payload["effort"]), ("std-model-2", "low"))
        self.assertEqual(payload["chosen_by"]["effort"], "supervisor")
        self.start("web-b4", "--project", "web", "--runner", "nap", "--model", "nap-model-8")
        payload = self.started("web-b4")
        self.assertEqual((payload["runner"], payload["model"], payload["effort"], payload["account"],
                          payload["difficulty"]), ("nap", "nap-model-8", None, "acc-two", None))
        self.assertEqual(payload["chosen_by"], {"runner": "supervisor", "model": "supervisor", "effort": None,
                                                "account": "default"})
        # Without a project nothing is excluded: the runner's first account is the default.
        self.start("b5", "--runner", "ok", "--model", "plain-model-9", "--effort", "low", "--worktree",
                   self.scratch("b5"))
        self.assertEqual(self.started("b5")["account"], "acc-one")
        for lane in ("web-b2", "web-b3", "web-b4", "b5"):
            self.wait_event("lane.ended", lane)
        self.assert_sound()

    def test_bad_requests_start_nothing(self):
        repo = self.repos["alpha"]
        worktrees = self.git(repo, "worktree", "list", "--porcelain")
        branches = self.git(repo, "branch", "--list")
        cases = [
            ("model alias without a version", ["--difficulty", "standard", "--model", "example"]),
            ("unknown runner", ["--runner", "ghost", "--model", "ghost-model-1"]),
            ("account the runner does not list", ["--difficulty", "standard", "--account", "stranger"]),
            ("account the project excludes", ["--difficulty", "standard", "--account", "acc-one"]),
            ("runner that is not a project worker", ["--runner", "fail", "--model", "fail-model-1"]),
            ("no difficulty and no runner", ["--model", "lone-model-1"]),
            ("no model", ["--runner", "ok"]),
            ("unknown difficulty", ["--difficulty", "urgent"]),
            ("zero budget", ["--difficulty", "standard", "--budget", "0"]),
            ("unknown project", ["--difficulty", "standard", "--project", "absent"]),
            ("worktree and base together", ["--difficulty", "standard", "--worktree", str(self.scratch("both")),
                                            "--base", "trunk"]),
        ]
        for index, (label, arguments) in enumerate(cases):
            with self.subTest(label):
                if "--project" not in arguments:
                    arguments = ["--project", "web"] + arguments
                lane = "web-bad{}".format(index)
                result = self.start(lane, *arguments, code=2)
                self.assertTrue(result.stderr.startswith(("refused:", "usage:")), result.stderr)
                self.assertEqual(result.stdout, "")
        result = self.start("other-b1", "--project", "web", "--difficulty", "standard", code=2)
        self.assertIn("web-", result.stderr)
        self.assertEqual(self.events(), [])
        self.assertEqual(list(self.records["alpha"].iterdir()), [])
        self.assertEqual(self.git(repo, "worktree", "list", "--porcelain"), worktrees)
        self.assertEqual(self.git(repo, "branch", "--list"), branches)
        self.assertEqual(sorted(path.name for path in repo.parent.iterdir() if path.name.startswith("repo-alpha-")),
                         [])
        self.assert_sound()

    def test_one_lane_per_directory(self):
        shared = self.scratch("shared")
        self.start("b-first", "--runner", "plain", "--model", "plain-model-1", "--worktree", shared)
        self.wait_event("lane.ended", "b-first")
        result = self.start("b-second", "--runner", "plain", "--model", "plain-model-1", "--worktree", shared, code=2)
        self.assertIn("b-first", result.stderr)
        self.assertEqual(self.lane_events("b-second"), [])
        inside = self.laneboss_json("config", "path", "alpha")["state_dir"]
        self.start("b-state", "--runner", "plain", "--model", "plain-model-1", "--worktree", inside, code=2)
        self.assertEqual(self.lane_events("b-state"), [])
        self.assert_sound()

    def test_known_lane_is_not_reused_silently(self):
        self.start("web-b6", "--project", "web", "--difficulty", "standard")
        self.wait_event("lane.ended", "web-b6")
        result = self.start("web-b6", "--project", "web", "--difficulty", "standard", code=2)
        self.assertIn("web-b6", result.stderr)
        self.start("web-b6", "--project", "web", "--difficulty", "standard", "--reuse", code=2)
        self.assertEqual(len(self.lane_events("web-b6", "lane.started")), 1)
        self.assert_sound()
