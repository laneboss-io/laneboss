"""Actual boot/binder/prepare prefix; stop before dispatching a lane.

Opaque issued identities and the human ticket are component inputs. No lane
operation, actor observation or installed-service result is manufactured.
"""

import copy
import importlib.util
import json
from pathlib import Path
import sys
import uuid


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("boot_input", HERE / "boot_bundle_input.py")
BOOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOT)
GRANTS = BOOT.GRANTS
SERVER = GRANTS.sibling("run")


class Captured(Exception):
    pass


def prefix(root):
    case = BOOT.BootFixture(root)
    case.config = "grants-prefix"
    approved = GRANTS.boot(case)["bundle"]["root_grants"]
    issued = {name: copy.deepcopy(approved[name]) for name in GRANTS.FAMILIES}
    issued.update(id=uuid.uuid4().hex, generation=1, policy_generation=1,
                  revoked=False, parent_life_id="")
    for family in GRANTS.FAMILIES:
        for member in issued[family]:
            member["id"] = uuid.uuid4().hex
    case.generated_launches = True
    case.grants_enrolled_manifest = approved
    case.initial_receipt = {"generation": 1}
    case.egress_anthropic = False
    case.decode_document = json.loads
    case.lane_inputs = "component launch input"
    case.root_grants = root / "root.input.json"
    case.keep_json("root.input.json", approved)
    case.root_launch_input = lambda _: GRANTS.io.encoded({"codex": {
        "driver": "codex", "grants": {name: [] for name in GRANTS.FAMILIES}}})

    class Human:
        public = {"principal_id": "component-human"}

        def ticket(self, proposal, source):
            GRANTS.io.require(source == case.root_grants, "wrong root input")
            SERVER.Case.bind_root_launch(case, proposal, issued)
            return {"id": "component-ticket", "grant_set_id": issued["id"]}

        def read(self, label, words, request):
            GRANTS.io.require(words == ["grants", "get"] and
                              request == {"grant_set_id": issued["id"]}, "wrong root read")
            return copy.deepcopy(issued)

        def proof(self, *args):
            return root / "component-proof"

    case.human = Human()
    captured = []

    def start(label, words, request, **options):
        GRANTS.io.require(words == ["lane", "start"], "wrong prefix endpoint")
        captured.append(copy.deepcopy(request))
        raise Captured()

    case.checked_cli = start
    for driver in ("claudock-cli", "codex"):
        ordinary = {"driver": driver, "grants": {name: [] for name in GRANTS.FAMILIES}}
        case.human_prefix = "base"
        SERVER.Case.bind_root_launch(case, ordinary, issued)
        actual = next(row for row in issued["profiles"] if row["id"] == ordinary["profile_grant_id"])
        GRANTS.io.require(actual["profile_id"] == "serve-profile-" + driver,
                          "ordinary suite launch changed its baseline seat")
    selectors = copy.deepcopy(getattr(case, "fixture_profile_selectors", {}))
    try:
        GRANTS.prepare(case, GRANTS.io.require, ValueError, RuntimeError)
    except Captured:
        pass
    else:
        raise ValueError("prepare did not reach its actual start endpoint")
    GRANTS.io.require(len(captured) == 1 and
                      getattr(case, "fixture_profile_selectors", {}) == selectors,
                      "prepare changed baseline selectors")
    parent = captured[0]
    members = {row["id"]: row for row in issued["profiles"]}
    # Export exact selections, never repair a producer-selected profile.
    selected = members[parent["profile_grant_id"]]
    delegated = [members[row["parent_grant_id"]] for row in parent["grants"]["profiles"]]
    child = GRANTS.profile_members({"profiles": delegated}, case.grants_boot["profiles"],
                                   GRANTS.io.require)["child"]
    return {"approved": approved, "issued": issued, "parent": selected,
            "delegated": delegated, "child": child, "parent_request": parent,
            "profile_ids": case.grants_boot["profiles"]}


if __name__ == "__main__":
    sys.stdout.buffer.write(GRANTS.io.encoded(prefix(Path(sys.argv[1]))))
