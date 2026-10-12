"""H. Doctor: one result line per check and a non-zero exit when any check fails."""

import json
import os

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


EXPECTED = ("config", "state.writable", "state.isolated", "store.round_trip", "tool.git", "tool.tmux", "runner.local")


class DoctorTest(support.LauncherTest):
    def doctor(self, code=None, environment=None):
        result = self.run_laneboss("doctor", "--config", "alpha", code=code, environment=environment)
        checks = {}
        for line in result.stdout.splitlines():
            item = json.loads(line)
            self.assertEqual(set(item), {"check", "ok", "detail"})
            checks[item["check"]] = item
        return result, checks

    def test_good_configuration_passes(self):
        self.write_config("alpha")
        result, checks = self.doctor(code=0)
        for name in EXPECTED:
            self.assertIn(name, checks)
            self.assertIs(checks[name]["ok"], True, checks[name])
        self.assertEqual(len(result.stdout.splitlines()), len(checks))
        self.assertEqual(self.events(), [])
        self.laneboss_json("state", "verify", "--config", "alpha")

    def test_unwritable_state_fails(self):
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores directory permissions")
        state = self.directory / "locked-state"
        state.mkdir()
        self.write_config("alpha", state_path=state)
        state.chmod(0o500)
        self.addCleanup(state.chmod, 0o700)
        result, checks = self.doctor()
        self.assertNotEqual(result.returncode, 0)
        self.assertIs(checks["state.writable"]["ok"], False)
        self.assertIs(checks["store.round_trip"]["ok"], False)
        self.assertIs(checks["config"]["ok"], True)
        self.assertIs(checks["runner.local"]["ok"], True)

    def test_missing_runner_fails(self):
        self.write_config("alpha", tail='\n[runners.ghost]\ncommand = ["laneboss-e2e-absent-command", "{brief}"]\n')
        result, checks = self.doctor()
        self.assertNotEqual(result.returncode, 0)
        self.assertIs(checks["runner.ghost"]["ok"], False)
        self.assertIn("laneboss-e2e-absent-command", checks["runner.ghost"]["detail"])
        self.assertIs(checks["runner.local"]["ok"], True)
        self.assertIs(checks["config"]["ok"], True)

    def test_shared_state_fails(self):
        shared = self.directory / "shared-state"
        for beta_state in (shared, shared / "inner"):
            self.write_config("alpha", state_path=shared)
            self.write_config("beta", state_path=beta_state)
            for name, other in (("alpha", "beta"), ("beta", "alpha")):
                result = self.run_laneboss("doctor", "--config", name, code=None)
                self.assertNotEqual(result.returncode, 0)
                checks = {json.loads(line)["check"]: json.loads(line) for line in result.stdout.splitlines()}
                self.assertIs(checks["state.isolated"]["ok"], False)
                self.assertIn(other, checks["state.isolated"]["detail"])
                refused = self.append(self.event(), config=name, code=2)
                self.assertIn(other, refused.stderr)
            self.assertFalse(shared.exists())

    def test_invalid_configuration_fails(self):
        self.write_config("alpha", top='colour = "red"')
        result, checks = self.doctor()
        self.assertNotEqual(result.returncode, 0)
        self.assertIs(checks["config"]["ok"], False)
        self.assertIn("colour", checks["config"]["detail"])

    def test_resource_program_found_and_missing(self):
        # A found and a missing adapter program, after the judge line; the detail names the program, never an argument.
        # The found program is an absolute path to a script that would leave a file behind if it ran, and the variable
        # the entry names is set in the environment: neither doctor's output nor its side effects may show either.
        program = self.directory / "example-adapter"
        marker = self.directory / "example-adapter-ran"
        program.write_text("#!/bin/sh\ntouch {}\n".format(marker), encoding="utf-8")
        program.chmod(0o755)
        variable = "EXAMPLE_ADAPTER_KEY"
        value = "example-value-that-is-not-printed"
        environment = dict(self.environment)
        environment[variable] = value
        self.write_config("alpha", tail=(
            '\n[judges.guard]\ncommand = ["sh", "answer"]\n'
            '\n[resources.present]\ncommand = ["{}", "--config", "adapter.toml"]\nkind = "machine"\n'
            'credential_env = "{}"\nhard_cap_minutes = 60\n'
            '\n[resources.absent]\ncommand = ["laneboss-e2e-absent-adapter", "adapter.toml"]\n'
            'kind = "credential"\nhard_cap_minutes = 5\n'.format(program, variable)))
        result, checks = self.doctor(code=1, environment=environment)
        order = [json.loads(line)["check"] for line in result.stdout.splitlines()]
        self.assertIs(checks["config"]["ok"], True, checks["config"]["detail"])
        self.assertEqual(len(result.stdout.splitlines()), len(checks), "a line is missing or repeated")
        self.assertIs(checks["resource.present"]["ok"], True, checks["resource.present"])
        self.assertIs(checks["resource.absent"]["ok"], False)
        self.assertIn(str(program), checks["resource.present"]["detail"], "the detail does not name the program")
        self.assertNotIn("--config", checks["resource.present"]["detail"], "the detail holds an argument")
        self.assertNotIn("adapter.toml", checks["resource.present"]["detail"], "the detail holds an argument")
        self.assertIn("laneboss-e2e-absent-adapter", checks["resource.absent"]["detail"])
        self.assertNotIn("adapter.toml", checks["resource.absent"]["detail"], "the detail holds an argument")
        self.assertLess(order.index("judge.guard"), order.index("resource.present"),
                        "the resource lines come before the judge lines")
        self.assertFalse(marker.exists(), "doctor ran the adapter")
        self.assertNotIn(value, result.stdout + result.stderr, "the value of the named variable is printed")
        self.assertEqual(self.events(), [])

    def test_resource_org_path_is_refused(self):
        # A configuration that names no organisation and points a resource command into an organisation's directory
        # is valid, and doctor fails its organisation.tools check naming the key path.
        other = str(self.home / "orgs" / "other" / "tools" / "adapter.sh")
        self.write_config("alpha", tail=('\n[resources.example-machine]\ncommand = ["{}", "describe"]\n'
                                         'kind = "machine"\nhard_cap_minutes = 60\n'.format(other)))
        result, checks = self.doctor(code=1)
        self.assertIs(checks["config"]["ok"], True, checks["config"]["detail"])
        self.assertIs(checks["organisation.tools"]["ok"], False)
        self.assertIn("resources.example-machine.command[0]", checks["organisation.tools"]["detail"])
        self.assertNotIn(other, checks["organisation.tools"]["detail"], "the detail repeats the path")
