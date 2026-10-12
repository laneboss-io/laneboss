"""The resource stand-in adapter's own tests, written from the adapter contract alone.

Every test runs the program as its own process ([sys.executable, "-I", PROGRAM, "--config", <toml>]) with an
environment the test supplies and one request on its standard input, in a temporary directory of its own, and compares
what came back with the contract's answer forms (docs/architecture.md, "The adapter contract"). The expected values
are literals here (the environment marker's value is made up afresh for each run), never read from the program.
Nothing of the launcher is needed: no test starts a run, a runner, a cloud account or a variable from outside.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

PROGRAM = Path(__file__).resolve().parent / "resourcestandin.py"

ID = "rs-0123456789abcdef01234567"
UNKNOWN = "rs-" + "f" * 24
LANE = "alpha-lane"
PURPOSE = "e2e-test"
SIZE = "small"
REGION = "eu-west-1"
PRICE = 250000
CURRENCY = "USD"
PRICE_SOURCE = "adapter"
CAP = 60
TIMEOUT = 30
MARKER = "made-up-" + os.urandom(8).hex()
ENVIRONMENT = {"PATH": "/usr/local/bin:/usr/bin:/bin", "E2E_RESOURCE_STANDIN": MARKER}
# The grammar of the envelope's `occurred_at` (src/laneboss/events.py:33-34), as a literal pattern: the form that
# every `started_at` and `ended_at` of the contract has.
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                       r"(?:\.[0-9]{3}(?:[0-9]{3})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})")


class ResourceStandinTest(unittest.TestCase):
    """One temporary directory per test: the configuration, the provider directory and the record file live in it."""

    def setUp(self):
        held = tempfile.TemporaryDirectory(prefix="laneboss-e2e-resstandin-")
        self.addCleanup(held.cleanup)
        self.dir = Path(held.name)
        self.providers = self.dir / "providers"
        self.record_file = self.dir / "record.jsonl"

    def config(self, **overrides):
        """Write this test's adapter configuration, of the literals above with OVERRIDES, and return its path. A
        value of None leaves the key out (so `end_after_seconds` is absent, and a released resource ends at once)."""
        values = {"provider_dir": str(self.providers), "record_file": str(self.record_file),
                  "size": SIZE, "region": REGION, "price_per_hour_micros": PRICE,
                  "currency": CURRENCY, "price_source": PRICE_SOURCE}
        values.update(overrides)
        lines = ["{} = {}".format(name, json.dumps(value) if isinstance(value, str) else value)
                 for name, value in values.items() if value is not None]
        path = self.dir / "adapter.toml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def request(self, operation, **members):
        """One request of the contract's form, for OPERATION, with MEMBERS replaced."""
        value = {"laneboss_resource": 1, "operation": operation, "id": ID, "kind": "machine", "profile": None,
                 "region": REGION, "timeout_seconds": TIMEOUT}
        if operation == "acquire":
            value.update({"lane": LANE, "purpose": PURPOSE, "size": None, "hard_cap_minutes": CAP,
                          "dry_run": False})
        else:
            value["provider_id"] = None
        value.update(members)
        return value

    def run_text(self, config, text, environment=None):
        """Run the program with TEXT, exactly as it is, on its standard input, in a small environment, under this
        test's directory."""
        return subprocess.run(
            [sys.executable, "-I", str(PROGRAM), "--config", str(config)],
            env=ENVIRONMENT if environment is None else environment, cwd=str(self.dir),
            input=text.encode("utf-8"), capture_output=True, timeout=60,
        )

    def run_adapter(self, config, request, environment=None):
        """Run the program with REQUEST, as the one text that `json.dumps` writes for it, on its standard input."""
        return self.run_text(config, json.dumps(request), environment)

    def answer(self, result):
        """The one JSON object a run must have printed, with exit status 0."""
        self.assertEqual(result.returncode, 0, "exit {}; stderr={!r}".format(result.returncode, result.stderr))
        return json.loads(result.stdout.decode("utf-8"))

    def files(self):
        """The provider directory's files, by name; empty when it does not exist."""
        if not self.providers.exists():
            return []
        return sorted(path.name for path in self.providers.iterdir() if path.is_file())

    def assert_timestamp(self, value, name):
        """VALUE is a string in the grammar of the envelope's `occurred_at`."""
        self.assertIsInstance(value, str, "{} is not a string: {!r}".format(name, value))
        self.assertIsNotNone(TIMESTAMP.fullmatch(value),
                             "{}={!r} is outside the envelope's timestamp grammar".format(name, value))

    def test_quote_members_and_no_file(self):
        """fails when the quote writes a provider file, or answers anything but the contract's quoted member set."""
        config = self.config()
        answer = self.answer(self.run_adapter(config, self.request("acquire", dry_run=True, size=None, region=None)))
        self.assertEqual(answer, {"state": "quoted", "size": SIZE, "region": REGION,
                                  "price_per_hour_micros": PRICE, "currency": CURRENCY,
                                  "price_source": PRICE_SOURCE})
        self.assertEqual(self.files(), [])

    def test_acquire_creates_one_file(self):
        """fails when the acquire makes no file or more than one, or answers without provider_id and started_at, or
        with a started_at outside the envelope's timestamp grammar."""
        config = self.config()
        answer = self.answer(self.run_adapter(config, self.request("acquire", dry_run=False)))
        self.assertEqual(set(answer), {"state", "provider_id", "started_at"})
        self.assertEqual(answer["state"], "acquired")
        self.assertIsInstance(answer["provider_id"], str)
        self.assertTrue(answer["provider_id"])
        self.assert_timestamp(answer["started_at"], "started_at")
        self.assertEqual(self.files(), [ID])

    def test_acquire_is_idempotent(self):
        """fails when a second acquire makes a second provider file, or answers another id or start time."""
        config = self.config()
        request = self.request("acquire", dry_run=False)
        first = self.answer(self.run_adapter(config, request))
        after_first = self.files()
        second = self.answer(self.run_adapter(config, request))
        self.assertEqual(after_first, [ID])
        self.assertEqual(second["provider_id"], first["provider_id"])
        self.assertEqual(second["started_at"], first["started_at"])
        self.assertEqual(self.files(), after_first)

    def test_describe_running_unchanged(self):
        """fails when the describe answers other than running, or changes the provider directory."""
        config = self.config()
        started = self.answer(self.run_adapter(config, self.request("acquire", dry_run=False)))
        before = self.files()
        answer = self.answer(self.run_adapter(config, self.request("describe")))
        self.assertEqual(set(answer), {"state", "provider_id", "provider_state", "started_at"})
        self.assertEqual(answer["state"], "running")
        self.assertEqual(answer["provider_id"], started["provider_id"])
        self.assertEqual(answer["started_at"], started["started_at"])
        self.assert_timestamp(answer["started_at"], "started_at")
        self.assertIsInstance(answer["provider_state"], str)
        self.assertEqual(self.files(), before)

    def test_describe_unknown_is_absent(self):
        """fails when a describe of an unknown id answers anything but the bare absent object, with no provider
        directory yet and again with another resource in it, or creates a file, or when the resource that is there
        stops showing as running with its own provider_id (a describe that ignores the id fails here)."""
        config = self.config()
        alone = self.answer(self.run_adapter(config, self.request("describe", id=UNKNOWN)))
        self.assertEqual(alone, {"state": "absent"})
        self.assertEqual(self.files(), [])
        started = self.answer(self.run_adapter(config, self.request("acquire", dry_run=False)))
        answer = self.answer(self.run_adapter(config, self.request("describe", id=UNKNOWN)))
        self.assertEqual(answer, {"state": "absent"})
        self.assertEqual(self.files(), [ID])
        known = self.answer(self.run_adapter(config, self.request("describe")))
        self.assertEqual(known["state"], "running")
        self.assertEqual(known["provider_id"], started["provider_id"])

    def test_release_then_terminated(self):
        """fails when the release is not `releasing`, or the describe after it is not `terminated` with `ended_at`
        in the envelope's timestamp grammar, or when a second release is an error, is not `releasing`, or moves
        `ended_at`."""
        config = self.config()
        started = self.answer(self.run_adapter(config, self.request("acquire", dry_run=False)))
        released = self.answer(self.run_adapter(config, self.request("release")))
        self.assertEqual(released, {"state": "releasing"})
        answer = self.answer(self.run_adapter(config, self.request("describe")))
        self.assertEqual(set(answer), {"state", "provider_id", "provider_state", "started_at", "ended_at"})
        self.assertEqual(answer["state"], "terminated")
        self.assertEqual(answer["provider_id"], started["provider_id"])
        self.assertEqual(answer["started_at"], started["started_at"])
        self.assert_timestamp(answer["started_at"], "started_at")
        self.assert_timestamp(answer["ended_at"], "ended_at")
        released_again = self.answer(self.run_adapter(config, self.request("release")))
        self.assertEqual(released_again, {"state": "releasing"})
        described_again = self.answer(self.run_adapter(config, self.request("describe")))
        self.assertEqual(described_again["ended_at"], answer["ended_at"], "a second release moved ended_at")
        self.assertEqual(described_again, answer)

    def test_release_unknown_is_ok(self):
        """fails when a release of an unknown id, with no provider directory yet and again with another resource in
        it, is an error, or answers anything but `releasing`, or creates a file, or when the resource that is there
        stops showing as running (a release that ends whatever is there fails here)."""
        config = self.config()
        alone = self.answer(self.run_adapter(config, self.request("release", id=UNKNOWN)))
        self.assertEqual(alone, {"state": "releasing"})
        self.assertEqual(self.files(), [])
        started = self.answer(self.run_adapter(config, self.request("acquire", dry_run=False)))
        released = self.answer(self.run_adapter(config, self.request("release", id=UNKNOWN)))
        self.assertEqual(released, {"state": "releasing"})
        self.assertEqual(self.files(), [ID])
        known = self.answer(self.run_adapter(config, self.request("describe")))
        self.assertEqual(known["state"], "running")
        self.assertEqual(known["provider_id"], started["provider_id"])

    def test_record_holds_request_and_env(self):
        """fails when the record is not written, or does not hold the request text exactly as it was sent (an exact
        string comparison, so the member order and the separators count), or holds another request, or not the
        environment it was given, or a name that the test never gave it beyond the interpreter's own LC_CTYPE (with
        a value of C.UTF-8, C.utf8 or UTF-8). The last assertion, that the parent's marker is not in the record, is a
        check of this test's own harness and not of the program: it fails when `run_adapter` (through `run_text`)
        stops passing its own `env=`, because the program sees only the environment it is given."""
        config = self.config()
        request = self.request("acquire", dry_run=False)
        parent_marker_name = "E2E_PARENT_ONLY_MARKER"
        parent_marker_value = "parent-only-made-up-value"
        was_set = os.environ.get(parent_marker_name)
        os.environ[parent_marker_name] = parent_marker_value

        def restore_parent_marker():
            if was_set is None:
                os.environ.pop(parent_marker_name, None)
            else:
                os.environ[parent_marker_name] = was_set

        self.addCleanup(restore_parent_marker)
        self.answer(self.run_adapter(config, request))
        lines = [json.loads(line) for line in self.record_file.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].get("request_text"), json.dumps(request),
                         "the record does not hold the request text exactly as it was sent")
        self.assertEqual(lines[0]["request"], request)
        recorded = lines[0]["environment"]
        for name, value in ENVIRONMENT.items():
            self.assertEqual(recorded.get(name), value,
                             "the record's environment does not hold {}={!r}".format(name, value))
        interpreter_adds = {"LC_CTYPE": ("C.UTF-8", "C.utf8", "UTF-8")}
        for name, value in recorded.items():
            if name in ENVIRONMENT:
                continue
            self.assertIn(name, interpreter_adds,
                          "the record's environment holds {}={!r}, which the test never gave it".format(name, value))
            self.assertIn(value, interpreter_adds[name],
                          "the record's environment holds {}={!r}, a value that the interpreter "
                          "does not give it".format(name, value))
        self.assertNotIn(parent_marker_name, recorded)

    def test_stdout_is_one_object_only(self):
        """fails when stdout holds anything but one JSON object on one line ending in a single newline."""
        config = self.config()
        result = self.run_adapter(config, self.request("describe", id=UNKNOWN))
        self.assertEqual(result.returncode, 0, "exit {}; stderr={!r}".format(result.returncode, result.stderr))
        self.assertEqual(json.loads(result.stdout.decode("utf-8")), {"state": "absent"})
        self.assertEqual(result.stdout.decode("utf-8").count("\n"), 1)
        self.assertTrue(result.stdout.endswith(b"\n"))
        self.assertFalse(result.stdout.endswith(b"\n\n"))

    def test_quote_carries_the_size_asked_for(self):
        """fails when a quote answers the configuration's size, or any size but the one the request asked for."""
        config = self.config()
        asked = "t9.xlarge"
        answer = self.answer(self.run_adapter(config, self.request("acquire", dry_run=True, size=asked, region=None)))
        self.assertEqual(answer, {"state": "quoted", "size": asked, "region": REGION,
                                  "price_per_hour_micros": PRICE, "currency": CURRENCY,
                                  "price_source": PRICE_SOURCE})
        self.assertEqual(self.files(), [])

    def test_quote_follows_its_configuration(self):
        """fails when a quote answers values that are not its own configuration's: this configuration has values that
        no other test uses, so a build that returns the first set (or any set of its own) fails here."""
        config = self.config(size="m7.large", region="ap-south-1", price_per_hour_micros=1750000, currency="EUR",
                             price_source="configured")
        answer = self.answer(self.run_adapter(config, self.request("acquire", dry_run=True, size=None, region=None)))
        self.assertEqual(answer, {"state": "quoted", "size": "m7.large", "region": "ap-south-1",
                                  "price_per_hour_micros": 1750000, "currency": "EUR",
                                  "price_source": "configured"})
        self.assertEqual(self.files(), [])

    def test_unservable_request_is_refused(self):
        """fails when a request for a contract version it does not know, a kind it does not serve or an operation it
        does not have is answered, or ends with exit status 0, or leaves a provider file."""
        config = self.config()
        cases = (
            ("a version it does not know", self.request("acquire", dry_run=False, laneboss_resource=2)),
            ("a kind it does not serve", self.request("acquire", dry_run=False, kind="database")),
            ("an operation it does not have", self.request("terminate")),
        )
        for label, request in cases:
            with self.subTest(label):
                result = self.run_adapter(config, request)
                self.assertNotEqual(result.returncode, 0, "exit 0 for {}; stdout={!r}".format(label, result.stdout))
                self.assertEqual(result.stdout, b"")
        self.assertEqual(self.files(), [])

    def test_unreadable_provider_no_answer(self):
        """fails when a describe or a release answers, or ends with exit status 0, while it cannot look at the
        provider (here the provider directory is a file): `absent` says that it looked and found nothing."""
        config = self.config()
        self.providers.write_text("a file where the provider directory should be\n", encoding="utf-8")
        for operation in ("describe", "release"):
            with self.subTest(operation):
                result = self.run_adapter(config, self.request(operation))
                self.assertNotEqual(result.returncode, 0,
                                    "exit 0 for a {} it could not look into; "
                                    "stdout={!r}".format(operation, result.stdout))
                self.assertEqual(result.stdout, b"")

    def test_record_keeps_the_text_as_received(self):
        """fails when the record holds a re-serialisation of the request and not the text the program was sent: a
        text in compact separators, over several lines with CR LF, with a repeated member and two final line breaks
        is not something that any re-serialisation of the parsed value gives back."""
        config = self.config()
        text = "\r\n".join([
            '{"laneboss_resource":1,',
            ' "operation":"describe",',
            ' "id":"' + ID + '",',
            ' "id":"' + UNKNOWN + '",',
            ' "kind":"machine","profile":null,"region":"' + REGION + '",',
            ' "provider_id":null,"timeout_seconds":' + str(TIMEOUT) + "}",
            "",
            "",
        ])
        self.assertEqual(self.answer(self.run_text(config, text)), {"state": "absent"})
        lines = [json.loads(line) for line in self.record_file.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].get("request_text"), text,
                         "the record does not hold the request text exactly as it was sent")

    def test_write_keeps_other_temp_file(self):
        """fails when a write goes through a name that another writer of the same id may be using: a half file that
        another writer left under `<id>.tmp` must be neither truncated nor renamed into place, and the resource must
        still describe as running. (Two writers of one id at the same moment cannot be placed from outside; this
        puts the other writer's half file in place instead.)"""
        config = self.config()
        self.providers.mkdir()
        other = self.providers / (ID + ".tmp")
        other.write_text("{half a file", encoding="utf-8")
        answer = self.answer(self.run_adapter(config, self.request("acquire", dry_run=False)))
        self.assertEqual(answer["state"], "acquired")
        self.assertTrue(other.exists(), "the write renamed another writer's temporary file into place")
        self.assertEqual(other.read_text(encoding="utf-8"), "{half a file",
                         "the write truncated another writer's temporary file")
        self.assertEqual(self.files(), [ID, ID + ".tmp"])
        described = self.answer(self.run_adapter(config, self.request("describe")))
        self.assertEqual(described["state"], "running")
        self.assertEqual(described["provider_id"], answer["provider_id"])

    def test_version_must_be_the_number_one(self):
        """fails when a request whose `laneboss_resource` is true, 1.0 or "1" (true and 1.0 are equal to 1 in Python,
        and none of the three is the whole number 1 of the contract) is answered or ends with exit status 0."""
        config = self.config()
        for version in (True, 1.0, "1"):
            with self.subTest(version=version):
                result = self.run_adapter(config, self.request("describe", laneboss_resource=version))
                self.assertNotEqual(result.returncode, 0,
                                    "exit 0 for version {!r}; stdout={!r}".format(version, result.stdout))
                self.assertEqual(result.stdout, b"")

    def test_id_outside_grammar_is_refused(self):
        """fails when a request whose id is not `rs-` and 24 lower-case hex digits is answered, or ends with exit
        status 0, or leaves a file: the id is used as a file name, and `../escaped` would reach out of the provider
        directory."""
        config = self.config()
        for identifier in ("../escaped", "rs-0123456789abcdef0123456", "rs-0123456789ABCDEF01234567"):
            for operation in ("acquire", "describe", "release"):
                with self.subTest(operation=operation, identifier=identifier):
                    result = self.run_adapter(config, self.request(operation, id=identifier))
                    self.assertNotEqual(result.returncode, 0,
                                        "exit 0 for a {} of id {!r}; stdout={!r}".format(operation, identifier,
                                                                                         result.stdout))
                    self.assertEqual(result.stdout, b"")
        self.assertEqual(self.files(), [])
        for leftover in ("escaped", "escaped.tmp"):
            self.assertFalse((self.dir / leftover).exists(), "a request reached out of the provider directory")
