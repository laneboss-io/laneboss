"""The same ladder assertions reject independent deliberate red observations."""

import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "e2e" / "v2"))
import ladder
from prepare_ladder import prepare
from support import evidence, load, regular, sha256
from ladder_fixtures import live_sample, make_pair, make_run, replace_report


def created(seed):
    events = []
    by_name = {}
    for index, node in enumerate(ladder.structure(seed), 1):
        parent = by_name.get(node["parent"])
        life = "life-" + node["name"]
        chain = parent["starter_chain"] + [parent["life_id"]] if parent else []
        root = parent["root_life_id"] if parent else life
        actor = {"kind": "lane", "id": "actor-" + node["parent"],
                 "life_id": parent["life_id"]} if parent else {"kind": "human", "id": "human"}
        lane = {"name": node["name"], "level": node["level"], "life_id": life,
                "starter_chain": chain, "root_life_id": root,
                "session": {"driver": node["driver"]}}
        if parent:
            lane["parent_life_id"] = parent["life_id"]
        event = {"kind": "lane.created", "origin": "service", "run": 1, "seq": index,
                 "life_id": life, "actor": actor, "starter_chain": chain,
                 "root_life_id": root, "starter_event_seq": parent["seq"] if parent else 0,
                 "payload": {"lane": lane}}
        if parent:
            event["parent_life_id"] = parent["life_id"]
        events.append(event)
        by_name[node["name"]] = event
    return events


class LadderControls(unittest.TestCase):
    def assertRed(self, check_id, operation, *args):
        with self.assertRaises(ladder.LadderFailure) as caught:
            operation(*args)
        self.assertEqual(caught.exception.check_id, check_id)

    def test_wrong_token_and_path(self):
        expected = {"child": {"path": "random/file.txt", "token": os.urandom(8).hex()}}
        good = [{"node": "child", **expected["child"]}]
        wrong = copy.deepcopy(good)
        wrong[0]["token"] = os.urandom(8).hex()
        self.assertRed("answers", ladder.answers, expected, wrong)
        wrong = copy.deepcopy(good)
        wrong[0]["path"] = "another/file.txt"
        self.assertRed("answers", ladder.answers, expected, wrong)
        self.assertIsNone(ladder.answers(expected, good))

    def test_other_lane_and_missing_answer(self):
        expected = {"parent": {"path": "p/file", "token": os.urandom(8).hex()},
                    "child": {"path": "c/file", "token": os.urandom(8).hex()}}
        good = [{"node": name, **answer} for name, answer in expected.items()]
        wrong = copy.deepcopy(good)
        wrong[1]["path"] = expected["parent"]["path"]
        self.assertRed("answers", ladder.answers, expected, wrong)
        self.assertRed("answers", ladder.answers, expected, good[:1])
        self.assertIsNone(ladder.answers(expected, good))

    def test_missing_ancestor_and_upward_skip(self):
        events = created(7)
        target = next(event for event in events if event["life_id"] == "life-l3a")
        target["parent_life_id"] = "life-l5a"
        self.assertRed("graph", ladder.graph, events, ladder.structure(7))
        self.assertEqual(len(ladder.graph(created(7), ladder.structure(7))), 10)

    def test_all_claudock_is_not_mixed(self):
        events = created(7)
        for event in events:
            event["payload"]["lane"]["session"]["driver"] = "claudock-cli"
        self.assertRed("graph", ladder.graph, events, ladder.structure(7))

    def test_selected_end_controls(self):
        event = {"kind": "lane.ended", "origin": "service", "life_id": "child",
                 "run": 2, "payload": {"reason": "exit", "observation": {
                     "handle": {"target": {"life_id": "child", "run": 2}},
                     "state": "exited", "exit_code": 0, "survivors": 0,
                     "prompt_status": "completed"}}}
        for change in ({"origin": "observation"}, {"life_id": "sibling"}, {"run": 1}):
            wrong = {**event, **change}
            self.assertRed("selected-end", ladder.selected_end, wrong, "child", 2)
        wrong = copy.deepcopy(event)
        wrong["payload"]["observation"]["survivors"] = 1
        self.assertRed("survivors", ladder.selected_end, wrong, "child", 2)
        wrong["payload"]["observation"].pop("survivors")
        self.assertRed("survivors", ladder.selected_end, wrong, "child", 2)
        self.assertIsNone(ladder.selected_end(event, "child", 2))

    def test_hidden_end_and_latency(self):
        event = {"id": "end", "seq": 9, "kind": "lane.ended", "origin": "service",
                 "life_id": "child", "run": 2, "payload": {"reason": "exit", "observation": {
                     "handle": {"target": {"life_id": "child", "run": 2}},
                     "state": "exited", "exit_code": 0, "survivors": 0,
                     "prompt_status": "completed"}}}
        receipt = {"life_id": "child", "run": 2, "reader_life_id": "parent",
                   "event_id": "end", "event_seq": 9, "visible": False,
                   "commit_ns": 100, "received_ns": 101, "clock_id": "unit-clock"}
        self.assertRed("selected-end", ladder.wait_receipt, receipt, event, "parent")
        receipt.update({"visible": True, "received_ns": 2_000_000_101})
        self.assertRed("end-latency", ladder.wait_receipt, receipt, event, "parent")
        receipt["received_ns"] = 101
        self.assertIsNone(ladder.wait_receipt(receipt, event, "parent"))

    def test_mail_sender_actor(self):
        expected = {"kind": "lane", "id": "parent", "life_id": "parent-life"}
        sender = {"kind": "lane", "id": "sibling", "life_id": "sibling-life"}
        event = {"actor": sender, "requested_by": sender}
        self.assertRed("actor", ladder.actor_matches, event, expected)
        event.update({"actor": expected, "requested_by": expected})
        self.assertIsNone(ladder.actor_matches(event, expected))

    def test_early_pong_and_delivery(self):
        nonce = os.urandom(16).hex()
        queued = {"seq": 1, "payload": {"id": "ping"}}
        delivered = {"seq": 2, "payload": {"mail_id": "ping", "logical_turn_id": "turn2",
                                          "target": {"life_id": "child", "run": 2},
                                          "prompt_status": "completed"}}
        launch = {"seq": 3, "logical_turn_id": "turn2", "life_id": "child", "run": 2,
                  "payload": {"trigger": {"mail_ids": ["ping"]}}}
        pong = {"seq": 1, "payload": {"reply_to": "ping"}}
        self.assertRed("ping-pong", ladder.ping_order, queued, delivered, launch, pong, nonce)
        pong["seq"] = 4
        delivered["payload"]["prompt_status"] = "not_written"
        self.assertRed("ping-pong", ladder.ping_order, queued, delivered, launch, pong, nonce)
        delivered["payload"]["prompt_status"] = "completed"
        self.assertIsNone(ladder.ping_order(queued, delivered, launch, pong, nonce))

    def test_sequential_trees_are_red(self):
        lives = [{(prefix, str(number)) for number in range(10)} for prefix in ("a", "b")]
        sequential = [{"live_refs": [{"config": config, "life_id": life} for config, life in items],
                       "observed_ns": index + 1}
                      for index, items in enumerate(lives)]
        self.assertRed("concurrency", ladder.concurrent_sample, lives, sequential)
        concurrent = [live_sample(lives[0] | lives[1])]
        self.assertIsNone(ladder.concurrent_sample(lives, concurrent))

    def test_missing_immutable_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, kept = root / "source", root / "kept"
            source.write_bytes(os.urandom(24))
            kept.write_bytes(source.read_bytes())
            expected = sha256(source)
            source.unlink()
            self.assertRed("artifacts", ladder.pinned_file, source, kept, expected)
            source.write_bytes(kept.read_bytes())
            self.assertIsNone(ladder.pinned_file(source, kept, expected))

    def test_missing_and_changed_transcript(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events, inventory = [], {}
            for stream in ("stdout", "transcript"):
                path = root / stream
                path.write_bytes(os.urandom(24))
                reference = {"id": stream, "sha256": sha256(path), "bytes": path.stat().st_size}
                inventory[stream] = evidence(root, path)
                events.append({"kind": "capture.appended", "origin": "service", "payload": {
                    "target": {"life_id": "life", "run": 1}, "stream": stream, "offset": 0,
                    "data": reference, "primary": True, "coverage": "complete"}})
            lanes = [{"life_id": "life", "run": 1}]
            self.assertRed("transcript", ladder.captures, events[:1], lanes, root, inventory)
            self.assertIsNone(ladder.captures(events, lanes, root, inventory))
            (root / "transcript").write_bytes(os.urandom(24))
            with self.assertRaisesRegex(Exception, "mismatch"):
                ladder.captures(events, lanes, root, inventory)

    def test_seed_does_not_determine_tokens(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            one = prepare(base / "one", ["tree-a", "tree-b"], 7)
            two = prepare(base / "two", ["tree-a", "tree-b"], 7)
            self.assertEqual(ladder.structure(one["seed"]), ladder.structure(two["seed"]))
            self.assertNotEqual(one["answers"], two["answers"])
            self.assertEqual(sha256(base / "one" / "draw.json"),
                             sha256(base / "two" / "draw.json"))
            for config in ("tree-a", "tree-b"):
                for node, answer in one["answers"][config].items():
                    other = two["answers"][config][node]
                    self.assertNotEqual(answer["token"], other["token"])
                    self.assertNotEqual(answer["path"], other["path"])
                    self.assertNotEqual(one["pings"][config][node],
                                        two["pings"][config][node])
                    path = base / "one" / config / node / answer["path"]
                    self.assertEqual(path.read_text().strip(), answer["token"])


class WholeRunControls(unittest.TestCase):
    """Every mutation enters the same verify_run used by the real live entry."""

    def red(self, check_id, mutate):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, reports = make_run(root)
            mutate(root, run, plan, reports)
            with self.assertRaises(ladder.LadderFailure) as caught:
                ladder.verify_run(run, plan, root)
            self.assertEqual(caught.exception.check_id, check_id)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, _ = make_run(root)
            self.assertEqual(len(ladder.verify_run(run, plan, root)), 10)

    def result_mutation(self, change):
        def mutate(root, run, plan, reports):
            from support import load
            ref = reports["l5a"]
            body = load(root / run["blobs"][ref["id"]]["path"])
            change(body, plan)
            replace_report(root, run, ref, body)
        self.red("answers", mutate)

    def test_wrong_token(self):
        self.result_mutation(lambda body, _plan: body["answers"][0].update(
            token=os.urandom(16).hex()))

    def test_wrong_path(self):
        self.result_mutation(lambda body, _plan: body["answers"][0].update(
            path="wrong/path"))

    def test_other_lane_path(self):
        self.result_mutation(lambda body, plan: body["answers"][0].update(
            path=plan["answers"]["tree-a"]["l5b"]["path"]))

    def test_missing_ancestor_answer(self):
        self.result_mutation(lambda body, _plan: body["answers"].pop())

    def test_upward_skip(self):
        def mutate(_root, run, _plan, _reports):
            event = next(item for item in run["events"] if
                         item["kind"] == "report.submitted" and
                         item["actor"]["life_id"] == "unit-life-l3a")
            event["payload"]["recipient_life_id"] = "unit-life-l6"
        self.red("report-line", mutate)

    def test_all_claude_leaves(self):
        def mutate(_root, run, _plan, _reports):
            for event in run["events"]:
                if event["kind"] == "lane.created":
                    event["payload"]["lane"]["session"]["driver"] = "claudock-cli"
        self.red("graph", mutate)

    def test_early_pong(self):
        def mutate(_root, run, _plan, _reports):
            events = run["events"]
            index = next(index for index, item in enumerate(events)
                         if item["kind"] == "report.submitted")
            pong = events.pop(index)
            queued = next(index for index, item in enumerate(events)
                          if item["kind"] == "mail.queued")
            events.insert(queued, pong)
            for index, item in enumerate(events, 1):
                item["seq"] = index
            for receipt in run["waits"]:
                receipt["event_seq"] = next(item["seq"] for item in events
                                             if item["id"] == receipt["event_id"])
        self.red("ping-pong", mutate)

    def test_hidden_end(self):
        self.red("selected-end", lambda _root, run, _plan, _reports:
                 run["waits"][0].update(visible=False))

    def test_historical_end(self):
        self.red("selected-end", lambda _root, run, _plan, _reports:
                 run["waits"][0].update(run=0))

    def test_fake_end(self):
        def mutate(_root, run, _plan, _reports):
            event = next(item for item in run["events"] if item["kind"] == "lane.ended")
            event["origin"] = "observation"
        self.red("selected-end", mutate)

    def test_parent_receive_late(self):
        def mutate(_root, run, _plan, _reports):
            receipt = run["waits"][0]
            receipt["received_ns"] = receipt["commit_ns"] + 2_000_000_001
        self.red("end-latency", mutate)

    def test_first_mail_sender_actor(self):
        def mutate(_root, run, _plan, _reports):
            request = run["manual_requests"][0]
            event = next(item for item in run["events"] if item["id"] == request["event_id"])
            event["actor"] = request["first_mail_sender"]
            event["requested_by"] = request["first_mail_sender"]
        self.red("actor", mutate)

    def test_missing_transcript(self):
        def mutate(_root, run, _plan, _reports):
            run["events"] = [item for item in run["events"] if not (
                item["kind"] == "capture.appended" and item["payload"]["stream"] == "transcript")]
        self.red("transcript", mutate)

    def test_surviving_child(self):
        self.red("survivors", lambda _root, run, _plan, _reports:
                 run["kernel_final"][1]["processes"].append({"pid": 42}))

    def test_unknown_containment(self):
        self.red("survivors", lambda _root, run, _plan, _reports:
                 run["kernel_final"][1].update(known=False))

    def test_missing_session_mapping(self):
        def mutate(_root, run, _plan, _reports):
            run["events"] = [item for item in run["events"] if not (
                item["kind"] == "runner.session" and item["life_id"] == "unit-life-l3a")]
        self.red("runtime", mutate)

    def test_sibling_privacy(self):
        self.red("privacy", lambda _root, run, _plan, _reports:
                 run["privacy"][0].update(sibling_read=True))

    def test_missing_privacy(self):
        self.red("privacy", lambda _root, run, _plan, _reports: run.update(privacy=[]))

    def test_parent_mark_missing(self):
        def mutate(_root, run, _plan, _reports):
            run["events"] = [item for item in run["events"] if not (
                item["kind"] == "lane.state" and item["payload"]["to"] == "accepted")]
        self.red("cleanup", mutate)

    def test_budget_increase(self):
        def mutate(_root, run, _plan, _reports):
            event = next(item for item in run["events"] if item["kind"] == "lane.ended")
            event["payload"]["budget_remaining"]["wall_ms"] = 20000
        self.red("runtime", mutate)

    def test_archive_bytes_absent(self):
        self.red("cleanup", lambda _root, run, _plan, _reports:
                 run.update(archive_readbacks=[]))


class PairControls(unittest.TestCase):
    def test_required_control_inventory(self):
        rows = load(ROOT / "e2e-rows" / "v2" / "ladder-controls.json")
        self.assertEqual(rows["assertion_id"], "E2E-LADDER")
        self.assertEqual({item["id"] for item in rows["controls"]}, {
            "wrong-token", "wrong-path", "other-lane-path", "missing-ancestor",
            "upward-skip", "early-pong", "hidden-end", "historical-end", "fake-end",
            "mail-sender-actor", "missing-transcript", "absent-executable",
            "surviving-child", "sequential-trees", "all-claude-leaves"})
        self.assertEqual(len(rows["controls"]), 15)
        for row in rows["controls"]:
            cls = globals()[row["class"]]
            self.assertTrue(issubclass(cls, unittest.TestCase))
            self.assertTrue(row["test"].startswith("test_"))
            self.assertTrue(callable(getattr(cls, row["test"])))

    def red(self, check_id, mutate):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runs, plan = make_pair(root)
            mutate(root, runs, plan)
            # Unit fixtures cannot be administrator-installed live artifacts.
            # Only this pure verifier test replaces that external prerequisite.
            with patch("support.immutable", side_effect=regular):
                with self.assertRaises(ladder.LadderFailure) as caught:
                    ladder.verify_pair(runs, plan, root)
            self.assertEqual(caught.exception.check_id, check_id)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runs, plan = make_pair(root)
            with patch("support.immutable", side_effect=regular):
                self.assertIsNone(ladder.verify_pair(runs, plan, root))

    def test_absent_immutable_executable(self):
        def mutate(root, _runs, _plan):
            (root / "source-codex").unlink()
        self.red("artifacts", mutate)

    def test_sequential_pair(self):
        def mutate(_root, runs, plan):
            sample = plan["load_samples"][0]
            plan["load_samples"] = [
                {**sample, "live_refs": [item for item in sample["live_refs"]
                                         if item["config"] == run["config"]]}
                for run in runs]
        self.red("concurrency", mutate)

    def test_nonoverlapping_lifetimes(self):
        def mutate(_root, _runs, plan):
            plan["load_samples"][0]["live_refs"][0]["before_ns"] = 4
        self.red("concurrency", mutate)

    def test_shared_binding(self):
        def mutate(_root, runs, _plan):
            runs[1]["binding"]["socket"] = runs[0]["binding"]["socket"]
        self.red("bindings", mutate)

    def test_fabricated_uid_inventory(self):
        def mutate(_root, runs, _plan):
            runs[1]["binding"]["lane_uids"][0] = 64000
        self.red("bindings", mutate)

    def test_stand_in_process_image(self):
        def mutate(_root, _runs, plan):
            item = plan["load_samples"][0]["live_refs"][0]
            from support import bytes_hash
            digest = bytes_hash(os.urandom(32))
            item.update(executable_before_sha256=digest, executable_after_sha256=digest)
        self.red("artifacts", mutate)
