"""Oracle data/control fixtures; no service, authentication or provider claims."""

import base64
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import guide_turn as guide


def variations():
    # Explicit observation data. These are not fabricated CLI process outputs.
    # At the first clock, both ages clamp to zero. At the later clock, the
    # older choice has decayed below the later choice with unchanged relevance.
    common = {
        "history": {"old": {"effective_at": "2026-10-01T00:00:00Z"},
                    "recent": {"effective_at": "2026-10-03T00:00:00Z"},
                    "unrelated": {"effective_at": "2026-10-01T00:00:00Z"}},
        "half_life": 86400, "cutoff": .5, "judge": {"model": "fixture"},
        "below_cutoff": True,
    }
    first = dict(common, task="task-a", as_of="2026-10-01T00:00:00Z",
                 probabilities={"old": 1, "recent": .6, "unrelated": .1},
                 selected=["old", "recent"])
    changed_task = dict(common, task="task-b", as_of=first["as_of"],
                        probabilities={"old": .1, "recent": .9, "unrelated": .1},
                        selected=["recent"])
    changed_clock = dict(first, as_of="2026-10-03T00:00:00Z",
                         selected=["recent", "old"])
    return [copy.deepcopy(row) for row in (first, changed_task, changed_clock)]


def event_case():
    case = guide.Case.__new__(guide.Case)
    case.context = {"config": "example"}
    case.commands = {"events": ["event", "tail"], "action": ["lane", "start"]}
    case.requests = {"events": {"life_id": "life-a", "run": 2, "since": 0,
                                 "cursor": "", "follow": False, "until": ""}}
    event = {"origin": "service", "config": "example", "life_id": "life-a",
             "run": 2, "logical_turn_id": "turn-a", "seq": 20,
             "kind": "lane.started", "operation_id": "operation-a", "payload": {}}
    case.responses = {"events": {"complete": True, "cursor": "", "events": [event]},
                      "action": {"id": "operation-a", "life_id": "life-a", "run": 2}}
    turn = {"events_step": "events", "action_step": "action", "life_id": "life-a",
            "run": 2, "logical_turn_id": "turn-a", "kind": "initial"}
    return case, turn


def human_candidate():
    return {"id": "decision-a", "binding": True, "text": "seed text",
            "source": {"id": "decision-a", "path": "", "sha256": "a" * 64, "generation": 1},
            "authority": {"kind": "human", "receipt_id": "proof-a", "source_seq": 3, "org_generation": 0},
            "seed_step": "seed", "view_step": "view", "input_file": "candidate.txt",
            "effective_at": "2026-10-01T00:00:00Z", "applies_to": {}}


class VariationTests(unittest.TestCase):
    def test_missing_owner_confirmation_i_945c(self):
        projection = guide.OwnerWait("D6").projection()
        self.assertEqual(projection["code"], "prerequisite_missing")
        self.assertEqual(projection["owner"], "owner-in-person")
        self.assertEqual(projection["gate"], "D6")
        self.assertIn("do not synthesize", projection["instead"])

    def test_zero_cutoff_default_bad_scalars(self):
        self.assertEqual(guide.minimum_relevance(0), .5)
        self.assertEqual(guide.minimum_relevance(.8), .8)
        for value in (-1, 2, True, False, float("nan")):
            with self.subTest(value=value):
                with self.assertRaisesRegex(guide.CheckFailure, "relevance cutoff"):
                    guide.minimum_relevance(value)

    def test_controlled_task_and_clock_pairs(self):
        self.assertIsNone(guide.check_variations(variations()))

    def test_constant_relevance_no_impact(self):
        rows = variations()
        rows[1]["probabilities"] = rows[0]["probabilities"]
        with self.assertRaisesRegex(guide.CheckFailure, "task change"):
            guide.check_variations(rows)

    def test_probs_without_choice_change_fail(self):
        rows = variations()
        rows[1]["selected"] = rows[0]["selected"]
        with self.assertRaisesRegex(guide.CheckFailure, "task change"):
            guide.check_variations(rows)

    def test_confounded_task_pair_fails(self):
        rows = variations()
        rows[1]["as_of"] = "2026-10-02T00:00:00Z"
        with self.assertRaisesRegex(guide.CheckFailure, "task change"):
            guide.check_variations(rows)

    def test_clock_labels_no_order_change(self):
        rows = variations()
        rows[2]["selected"] = rows[0]["selected"]
        with self.assertRaisesRegex(guide.CheckFailure, "clock change"):
            guide.check_variations(rows)

    def test_clock_change_confounded(self):
        rows = variations()
        rows[2]["probabilities"]["recent"] = .7
        with self.assertRaisesRegex(guide.CheckFailure, "clock change"):
            guide.check_variations(rows)

    def test_equal_age_not_recency(self):
        rows = variations()
        for row in rows:
            row["history"]["recent"]["effective_at"] = row["history"]["old"]["effective_at"]
        with self.assertRaisesRegex(guide.CheckFailure, "clock change"):
            guide.check_variations(rows)

    def test_below_cutoff_case_is_mandatory(self):
        rows = variations()
        for row in rows:
            row["below_cutoff"] = False
        with self.assertRaisesRegex(guide.CheckFailure, "below-cutoff"):
            guide.check_variations(rows)


class EventTests(unittest.TestCase):
    def test_prior_run_nonservice_excluded(self):
        case, turn = event_case()
        rows = case.responses["events"]["events"]
        rows[:0] = [dict(rows[0], seq=1, run=1, kind="guidance.selected"),
                    dict(rows[0], seq=2, origin="lane", kind="judge.completed")]
        selected = case.events(turn)
        self.assertEqual([row["seq"] for row in selected], [20])

    def test_prelaunch_duplicate_visible(self):
        case, turn = event_case()
        rows = case.responses["events"]["events"]
        rows.insert(0, dict(rows[0], seq=19, kind="guidance.selected"))
        self.assertEqual([row["kind"] for row in case.events(turn)],
                         ["guidance.selected", "lane.started"])

    def test_event_request_keeps_prelaunch(self):
        for field, value in (("since", 19), ("cursor", "late-page"),
                             ("run", 1), ("life_id", "other-life"),
                             ("until", "lane.started")):
            with self.subTest(field=field):
                case, turn = event_case()
                case.requests["events"][field] = value
                with self.assertRaisesRegex(guide.CheckFailure, "complete authentic run"):
                    case.events(turn)

    def test_empty_unavailable_all_commands(self):
        for kind in ("empty", "unavailable"):
            for verb, event_kind in (("start", "lane.started"), ("resume", "lane.resumed"), ("turn", "lane.turn")):
                with self.subTest(kind=kind, command=verb):
                    case, turn = event_case()
                    turn["kind"] = kind
                    case.commands["action"] = ["lane", verb]
                    case.responses["events"]["events"][0]["kind"] = event_kind
                    _, delivery = case.delivery(turn)
                    self.assertEqual(delivery[-1]["kind"], event_kind)

    def test_forged_delivery_is_not_reached(self):
        case, turn = event_case()
        case.responses["events"]["events"][0]["origin"] = "lane"
        with self.assertRaisesRegex(guide.CheckFailure, "authentic prompt delivery"):
            case.delivery(turn)


class ProvenanceTests(unittest.TestCase):
    def test_human_binding_needs_no_d6_approval(self):
        candidate = human_candidate()
        self.assertIsNone(guide.check_candidate_origin(candidate,
            {"seed": ["decisions", "mutate"]},
            {"seed": {"id": candidate["id"], "actor": {"kind": "human"}}}))

    def test_missing_provenance_proposal_fail(self):
        for defect in ("missing", "proposal"):
            with self.subTest(defect=defect):
                candidate = human_candidate()
                actor = "human"
                if defect == "missing":
                    del candidate["seed_step"]
                else:
                    actor = "lane"
                with self.assertRaises(guide.CheckFailure):
                    guide.check_candidate_origin(candidate,
                        {"seed": ["decisions", "mutate"]},
                        {"seed": {"id": candidate["id"], "actor": {"kind": actor}}})

    def test_d6_needs_apply_generation(self):
        candidate = human_candidate()
        del candidate["seed_step"]
        candidate["approval_step"] = "apply"
        candidate["authority"].update(kind="d6", org_generation=2)
        candidate["source"].update(path="org/decisions.md", generation=2)
        commands = {"apply": ["org", "change", "apply"]}
        receipts = {"apply": {"approval_id": "approval-a", "applied_at": "2026-10-01T00:00:00Z",
                              "old_generation": 1, "new_generation": 2}}
        self.assertIsNone(guide.check_candidate_origin(candidate, commands, receipts))
        receipts["apply"]["new_generation"] = 3
        with self.assertRaisesRegex(guide.CheckFailure, "applied approval"):
            guide.check_candidate_origin(candidate, commands, receipts)


class ReachTests(unittest.TestCase):
    def test_late_missing_input_not_reached(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-guidance-oracle-") as temporary:
            case, turn = event_case()
            case.root = Path(temporary)
            case.root.joinpath("candidate.txt").write_text("seed text")
            case.root.joinpath("task.txt").write_text("task")
            candidate = human_candidate()
            case.responses.update(view={"decisions": []}, seed={}, policy={},
                                  prompt={"offset": 0, "data": base64.b64encode(b"prompt").decode(),
                                          "sha256": hashlib.sha256(b"prompt").hexdigest()})
            case.commands["seed"] = ["decisions", "mutate"]
            turn.update(kind="empty", candidate_ids=[candidate["id"]],
                        task_file="task.txt", as_of="2026-10-01T00:00:00Z",
                        policy_generation=1, half_life_seconds=86400,
                        policy_step="policy", prompt_step="prompt")
            later = dict(turn, task_file="missing.txt")
            with mock.patch.object(case, "oracle") as oracle:
                with self.assertRaises(FileNotFoundError):
                    case.check({"candidates": [candidate], "turns": [turn, later]})
                self.assertFalse(case.reached)
                oracle.assert_not_called()

    def test_setup_errors_clear_reach(self):
        # Classifier injection only: no fake successful CLI/provider output.
        for error in (KeyError("fixture"), OSError("fixture"), TypeError("fixture"),
                      guide.CheckFailure("targeted product observation")):
            with self.subTest(error=type(error).__name__):
                case, _ = event_case()
                with mock.patch.object(case, "preflight"), mock.patch.object(case, "oracle", side_effect=error):
                    with self.assertRaises(type(error)):
                        case.check({})
                self.assertEqual(case.reached, isinstance(error, guide.CheckFailure))


if __name__ == "__main__":
    if sys.platform != "linux":
        raise SystemExit("Linux test box required")
    unittest.main()
