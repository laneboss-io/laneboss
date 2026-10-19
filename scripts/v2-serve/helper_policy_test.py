"""Helper-policy observation controls; run only on the authorized Linux machine."""
import importlib.util
from pathlib import Path
import unittest
import uuid

spec = importlib.util.spec_from_file_location("provision", Path(__file__).with_name("provision.py"))
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


class HelperPolicyControls(unittest.TestCase):
    def inputs(self):
        private = uuid.uuid4().hex
        unit = ("[Service]\nExecStart=/private/" + private + "\nCapabilityBoundingSet=CAP_SETUID CAP_SETGID\n").encode()
        values = {name: "" for name in provision.HELPER_PROPERTIES}
        values.update(CapabilityBoundingSet="cap_setuid cap_setgid", SecureBits="0", User="root", Group="0",
                      PrivateUsers="no", NoNewPrivileges="yes", RestrictSUIDSGID="yes", FragmentPath="/private/" + private)
        return private, unit, values

    def encode(self, values):
        return "".join(name + "=" + value + "\n" for name, value in values.items()).encode()

    def test_real_fields_drive_verdicts(self):
        private, unit, values = self.inputs()
        facts = provision.helper_policy_facts(unit, unit, self.encode(values))
        parsed = {row["name"]: row["verdict"] for row in facts}
        self.assertEqual(parsed["CapabilityBoundingSet.declared"], "match")
        self.assertEqual(parsed["CapabilityBoundingSet.CAP_SETUID"], "present")
        values.update(CapabilityBoundingSet="cap_setgid cap_sys_admin", User=private, PrivateUsers="yes", DropInPaths="/private/" + private)
        changed = provision.helper_policy_facts(unit, unit + b"# changed\n", self.encode(values))
        changed = {row["name"]: row["verdict"] for row in changed}
        self.assertEqual(changed["CapabilityBoundingSet.declared"], "different")
        self.assertEqual(changed["CapabilityBoundingSet.CAP_SETUID"], "absent")
        self.assertEqual(changed["CapabilityBoundingSet.CAP_SETGID"], "present")
        self.assertEqual(changed["fragment.template"], "different")
        self.assertEqual(changed["User.root"], "no")
        self.assertEqual(changed["PrivateUsers"], "enabled")
        self.assertEqual(changed["DropInPaths"], "reported")
        self.assertTrue(private not in str(facts) + str(changed), "private unit values escaped fixed verdicts")
        observed = provision.helper_capability_record({"stage": "helper.before_accounts",
            "observation": "process CAP_SETUID CapEff=present, CapPrm=absent, CapBnd=present"})
        self.assertEqual(observed, {"stage": "helper.before_accounts", "CapEff": "present", "CapPrm": "absent", "CapBnd": "present"})
        unavailable = provision.helper_capability_record({"stage": "helper.after_accounts", "observation": "process CAP_SETUID=unavailable(EPERM)"})
        self.assertEqual(unavailable, {"stage": "helper.after_accounts", "unavailable": "EPERM"})

    def test_incomplete_policy_is_refused(self):
        _, unit, values = self.inputs()
        complete = self.encode(values)
        for altered in (complete + b"User=root\n", complete + b"Unknown=value\n", b"User=root\n", b"\xff"):
            with self.assertRaises(ValueError):
                provision.helper_policy_facts(unit, unit, altered)
        for altered in ({}, {"stage": "helper.before_accounts", "observation": "private text"},
                        {"stage": "helper.after_accounts", "observation": "process CAP_SETUID=unavailable(PRIVATE)"},
                        {"stage": "helper.after_accounts", "observation": "process CAP_SETUID=unavailable(EPERM)", "extra": "private"}):
            with self.assertRaises(ValueError):
                provision.helper_capability_record(altered)

    def test_user_root_default_and_explicit(self):
        private, unit, values = self.inputs()
        for user, expected in (("", "default"), ("root", "yes"), ("0", "yes"), (private, "no")):
            with self.subTest(verdict=expected):
                values["User"] = user
                facts = provision.helper_policy_facts(unit, unit, self.encode(values))
                parsed = {row["name"]: row["verdict"] for row in facts}
                self.assertEqual(parsed["User.root"], expected, "User.root ignored the effective User field")
                self.assertNotIn(private, str(facts), "private User value escaped fixed verdicts")


if __name__ == "__main__":
    unittest.main()
