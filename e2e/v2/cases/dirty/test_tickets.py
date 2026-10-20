"""Two dirty-item grant rounds; ceremonies and RPCs are component inputs."""

import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid


source = Path(__file__).resolve().parents[4]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = source / "scripts/v2-serve"
serve = load("ticket_serve", core / "run.py")
dirty = load("ticket_dirty", core / "case_dirty.py")


class DirtyTickets(unittest.TestCase):
    def fixture(self, root):
        case = serve.Case.__new__(serve.Case)
        case.root, case.config = root, "ticket-component"
        case.api_key_canary = None
        case.human_prefix = "itemdirty"
        case.current, case.rows = "item.dirty.run", {}
        case.generated_launches, case.egress_anthropic = True, False
        case.initial_receipt = {"generation": 1}
        case.initial = {"profiles": {"id": "published-profiles"}}
        case.root_grants = root / "source.input"
        case.root_raw = b'{ "manifest": { "id": "published-profiles" }, "budget": {} }\n'
        case.grants_enrolled_manifest = {name: [] for name in (
            "resources", "data", "secrets", "profiles", "network", "channels")}
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        case.grants_enrolled_manifest["profiles"] = [{"profile_id": "component-profile",
            "driver": "claudock-cli", "provider": "serve-fixture", "paid": False,
            "delegate": False, "expires_at": expiry}]
        case.validate_initial_launch = mock.Mock()
        case.starts, case.issued, case.tickets, case.proposals = [], [], [], []
        bind = case.bind_root_launch

        def bind_proposal(launch, grants, **options):
            case.proposals.append(copy.deepcopy(launch))
            return bind(launch, grants, **options)

        case.bind_root_launch = bind_proposal
        human = serve.human.HumanRoot(case, None, {"principal_id": "component-human"},
                                      serve.require, serve.Blocked)
        case.human = human
        # No signer, credential or installed service is used by this unit.
        human.session = mock.Mock()
        human.proof = mock.Mock(return_value=root / "component-proof")

        def rpc(label, words, request, proof=None):
            if words == ["grants", "root"]:
                self.assertEqual(request, json.loads(case.root_raw))
                grants = copy.deepcopy(case.grants_enrolled_manifest)
                grants.update(id=uuid.uuid4().hex, generation=1, policy_generation=1,
                              expires_at=expiry, revoked=False)
                for profile in grants["profiles"]:
                    profile["id"] = uuid.uuid4().hex
                case.issued.append(copy.deepcopy(grants))
                return grants
            self.assertEqual(words, ["ticket", "issue"])
            self.assertEqual(request["grant_set_id"], case.issued[-1]["id"])
            ticket = dict(request, id=uuid.uuid4().hex, principal_id=human.public["principal_id"],
                          config=case.config, redeemed=False, simulated_presence=True)
            case.tickets.append(copy.deepcopy(ticket))
            return ticket

        human.rpc = mock.Mock(side_effect=rpc)

        def cli(label, words, request, **options):
            self.assertEqual(words, ["lane", "start"])
            self.assertEqual(request["root_ticket_id"], case.tickets[-1]["id"])
            self.assertEqual(request["profile_grant_id"], case.issued[-1]["profiles"][0]["id"])
            case.starts.append(copy.deepcopy(request))
            return {"id": uuid.uuid4().hex, "life_id": uuid.uuid4().hex, "run": 1, "status": "succeeded"}

        case.checked_cli = cli
        return case

    def launch(self, case, name):
        request = {"driver": "claudock-cli", "level": 5, "role": "supervisor",
                   "grants": {family: [] for family in case.grants_enrolled_manifest}}
        with mock.patch.object(serve.provision, "read_protected", return_value=case.root_raw), \
                mock.patch.object(dirty, "status", return_value={}), \
                mock.patch.object(dirty.flow, "observe", return_value=({}, {"handle": {"id": "component-handle"}})):
            return dirty.start(case, request, name)

    def test_two_launches(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-g11-") as directory:
            case = self.fixture(Path(directory).resolve())
            first = self.launch(case, "dirty")
            second = self.launch(case, "control")
            self.assertEqual([row["lane"] for row in case.starts], ["g11-dirty", "g11-control"])
            self.assertEqual(case.human.session.call_count, 2, "second grant ceremony was skipped")
            self.assertEqual(len(case.issued), 2, "second grant round was skipped")
            self.assertEqual(len(case.tickets), 2, "second ticket round was skipped")
            self.assertNotEqual(first["request"]["root_ticket_id"], second["request"]["root_ticket_id"])
            roots = sorted(case.root.glob("root-grants.*.input.json"))
            self.assertEqual(len(roots), 2, "a root-grant input was dropped or overwritten")
            for path in roots:
                self.assertEqual(path.read_bytes(), case.root_raw, "input bytes were re-encoded")
            launches = sorted(case.root.glob("launch-*.input"))
            self.assertEqual(len(launches), 2, "a launch binding was dropped or overwritten")
            self.assertEqual({json.loads(path.read_bytes())["profile_grant_id"] for path in launches},
                             {row["profiles"][0]["id"] for row in case.issued})
            # The original exclusive writer still rejects a true name clash.
            before = roots[0].read_bytes()
            with self.assertRaises(FileExistsError):
                case.keep(roots[0].name, b"changed input must not replace evidence\n")
            self.assertEqual(roots[0].read_bytes(), before)

    def test_restore_host(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-g11-") as directory:
            root = Path(directory).resolve()
            case = self.fixture(root)
            first = self.launch(case, "dirty")
            before = copy.deepcopy(first["request"])
            lease = {"phase": "active", "launch_storage": {
                "ready": True, "workspace_native": {"Phase": "published"}}}
            with mock.patch.object(serve.provision, "read_protected", return_value=case.root_raw), \
                    mock.patch.object(dirty, "status", return_value={}), \
                    mock.patch.object(dirty.flow, "observe", return_value=({}, {"handle": {"id": "host-handle"}})), \
                    mock.patch.object(dirty, "workspace_info", return_value=({}, lease, root)), \
                    mock.patch.object(dirty, "restore_into", return_value={}) as restorer, \
                    mock.patch.object(dirty, "stop", return_value={}) as stopper:
                dirty.restore_work(case, first, {}, {}, {}, root, {}, {}, {})
            self.assertEqual([row["lane"] for row in case.starts], ["g11-dirty", "g11-restore"])
            self.assertEqual(len(case.proposals), 2, "a grant-binding guard was skipped")
            for proposal in case.proposals:
                self.assertFalse(proposal.get("profile_grant_id"), "start reused an issued profile")
                self.assertTrue(all(not rows for rows in proposal["grants"].values()),
                                "start reused issued grants")
            self.assertEqual(case.human.session.call_count, 2)
            self.assertEqual(len(case.issued), 2)
            self.assertEqual(len(case.tickets), 2)
            self.assertEqual(first["request"], before, "host start mutated the first request")
            for field in ("profile_grant_id", "root_ticket_id", "grants"):
                self.assertNotEqual(case.starts[0][field], case.starts[1][field],
                                    "host reused the first lane's " + field)
            self.assertEqual(restorer.call_count, 1, "restore was skipped")
            self.assertEqual(stopper.call_count, 1, "host stop was skipped")

    def test_issued_refused(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-g11-") as directory:
            case = self.fixture(Path(directory).resolve())
            proposal = {"driver": "claudock-cli", "level": 5, "role": "supervisor",
                        "profile_grant_id": uuid.uuid4().hex,
                        "grants": {family: [] for family in case.grants_enrolled_manifest}}
            before = copy.deepcopy(proposal)
            with mock.patch.object(serve.provision, "read_protected", return_value=case.root_raw), \
                    self.assertRaisesRegex(serve.Failed, "fixture proposal already contains invented issued selectors"):
                dirty.start(case, proposal, "restore")
            self.assertEqual(proposal, before, "issued selectors were cleared on the shared proposal")
            self.assertEqual(case.proposals, [dict(before, lane="g11-restore")])
            self.assertEqual(case.starts, [], "prefilled proposal reached lane start")
            self.assertEqual(case.tickets, [], "prefilled proposal received a ticket")


if __name__ == "__main__":
    unittest.main(verbosity=2)
