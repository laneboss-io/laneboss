"""A. adapters.py (docs/architecture.md, "Resources and cost": "The adapter contract"). The request half: the object
the launcher sends for each of the contract's operations, its members and their order, and the text form it takes. The
call half: the resolution of the program, the environment it is given, the bounded call, the strict reading of its
answer with every refusal of "What is no answer", and the screens for the credential variable's value.

The module has no command of its own yet, so the installed package is asked in a process of its own, as
test_resources_model asks resources.fold(). The call half is driven against a stand-in adapter that the tests write
into their temporary directory: a program that does what a plan file says (print these bytes, exit with this status,
hang, leave a child behind) and records the request it was given and what it was started with. Nothing of the
launcher is replaced, and no third-party service is involved. Every expected value is a literal of the design's tables
("The request", "The answer", "What is no answer"), and nothing is read from the code under test.
"""

import json
import os
from pathlib import Path
import random
import signal
import string
import subprocess
import sys
import time
import uuid

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


RESOURCE = "rs-0123456789abcdef01234567"
LANE = "example-lane"
KIND = "machine"
PROFILE = "example-profile"
PURPOSE = "example-tests"
SIZE = "example-size-2"
REGION = "example-region-1"
PROVIDER_ID = "example-provider-0001"
HARD_CAP_MINUTES = 240
TIMEOUT_SECONDS = 300
# The members of the design's table, in the table's order: one order for both forms of an acquire, another for a
# describe and a release.
ACQUIRE_MEMBERS = ["laneboss_resource", "operation", "id", "lane", "kind", "profile", "purpose", "size", "region",
                   "hard_cap_minutes", "dry_run", "timeout_seconds"]
READ_MEMBERS = ["laneboss_resource", "operation", "id", "kind", "profile", "region", "provider_id", "timeout_seconds"]
# The arguments of each of the four forms, of the design's own values; a test replaces the member it is about.
QUOTE = {"resource": RESOURCE, "kind": KIND, "profile": PROFILE, "lane": LANE, "purpose": PURPOSE, "size": SIZE,
         "hard_cap_minutes": HARD_CAP_MINUTES, "timeout_seconds": TIMEOUT_SECONDS}
ACQUIRE = dict(QUOTE, region=REGION)
DESCRIBE = {"resource": RESOURCE, "kind": KIND, "profile": PROFILE, "region": REGION, "provider_id": PROVIDER_ID,
            "timeout_seconds": TIMEOUT_SECONDS}
RELEASE = dict(DESCRIBE)
FORMS = {"quote_request": QUOTE, "acquire_request": ACQUIRE, "describe_request": DESCRIBE,
         "release_request": RELEASE}
# The text of the describe request of DESCRIBE: its members in the table's order, no space after a separator, one line
# and exactly one final newline.
DESCRIBE_TEXT = ('{"laneboss_resource":1,"operation":"describe","id":"rs-0123456789abcdef01234567","kind":"machine",'
                 '"profile":"example-profile","region":"example-region-1","provider_id":"example-provider-0001",'
                 '"timeout_seconds":300}\n')
# The text of the other three forms, written out by hand from the table like DESCRIBE_TEXT, so that no value in them is
# one the module produced: the quote and the acquire share one member order and differ in `region` (null in the quote)
# and in `dry_run` (the JSON words true and false); the release is the describe with the operation `release`.
QUOTE_TEXT = ('{"laneboss_resource":1,"operation":"acquire","id":"rs-0123456789abcdef01234567","lane":"example-lane",'
              '"kind":"machine","profile":"example-profile","purpose":"example-tests","size":"example-size-2",'
              '"region":null,"hard_cap_minutes":240,"dry_run":true,"timeout_seconds":300}\n')
ACQUIRE_TEXT = ('{"laneboss_resource":1,"operation":"acquire","id":"rs-0123456789abcdef01234567","lane":"example-lane",'
                '"kind":"machine","profile":"example-profile","purpose":"example-tests","size":"example-size-2",'
                '"region":"example-region-1","hard_cap_minutes":240,"dry_run":false,"timeout_seconds":300}\n')
RELEASE_TEXT = ('{"laneboss_resource":1,"operation":"release","id":"rs-0123456789abcdef01234567","kind":"machine",'
                '"profile":"example-profile","region":"example-region-1","provider_id":"example-provider-0001",'
                '"timeout_seconds":300}\n')
# The parameters of each builder, in the table's order and all keyword-only: a positional call would pass members in an
# order that nobody reads, and `lane` comes before `kind` in the table.
PARAMETERS = {
    "quote_request": ["resource", "lane", "kind", "profile", "purpose", "size", "hard_cap_minutes", "timeout_seconds"],
    "acquire_request": ["resource", "lane", "kind", "profile", "purpose", "size", "region", "hard_cap_minutes",
                        "timeout_seconds"],
    "describe_request": ["resource", "kind", "profile", "region", "provider_id", "timeout_seconds"],
    "release_request": ["resource", "kind", "profile", "region", "provider_id", "timeout_seconds"],
}

# The installed package's answer to each call: what it built, or the refusal it made. The module has no command yet, so
# this is the nearest a black-box test comes to it.
PROBE = r"""
import json
import sys

sys.path.insert(0, sys.argv[1])
from laneboss import adapters

with open(sys.argv[2], encoding="utf-8") as handle:
    calls = json.load(handle)
answers = []
for call in calls:
    function = getattr(adapters, call["call"])
    try:
        value = function(*call["args"], **call["kwargs"])
    except Exception as error:
        answers.append({"error": type(error).__name__, "message": str(error)})
        continue
    if isinstance(value, dict):
        answers.append({"keys": list(value), "request": value})
    else:
        answers.append({"text": value})
print(json.dumps({"version": adapters.REQUEST_VERSION, "limit": adapters.MAX_REQUEST_BYTES, "answers": answers}))
"""

# The parameters of each builder named on the command line, as the installed package declares them: [name, kind] each.
SIGNATURE_PROBE = r"""
import inspect
import json
import sys

sys.path.insert(0, sys.argv[1])
from laneboss import adapters

print(json.dumps({name: [[parameter.name, parameter.kind.name]
                         for parameter in inspect.signature(getattr(adapters, name)).parameters.values()]
                  for name in sys.argv[2:]}))
"""

# The launcher's side of the call half: for each case, the request is built by the module's own builder from the case's
# arguments and adapters.call() runs it, in this process, whose environment and working directory are the launcher's.
# The result is what call() returned or, when it raised, the name of the error and its message.
CALL_PROBE = r"""
import json
import sys

sys.path.insert(0, sys.argv[1])
from laneboss import adapters

with open(sys.argv[2], encoding="utf-8") as handle:
    cases = json.load(handle)
results = []
for case in cases:
    try:
        request = getattr(adapters, case["form"])(**case["arguments"])
        result = adapters.call(case["command"], request, case["seconds"], case["credential_env"])
    except Exception as error:
        results.append({"error": type(error).__name__, "message": str(error)})
    else:
        results.append({"reason": result.reason, "answer": result.answer, "detail": result.detail})
print(json.dumps(results))
"""

# The stand-in adapter, written by the tests into their temporary directory and started as `python -I STANDIN PLAN`.
# The plan is one JSON file and the program does what it says and nothing else: it has no branch keyed on a value of
# any test.
#   record          the stem of its two records: STEM.request (the bytes it was given on standard input) and STEM.json
#                   (its process ids and session, its arguments, its working directory, the environment it was started
#                   with, and the first word of its own command line); the record is written after the request was read
#   read            false: it never reads its standard input
#   child           true: it starts a child in its process group that ignores SIGTERM and sleeps
#   stdout, stderr  files whose bytes it writes to those two streams
#   hang            true: after writing, it ignores SIGTERM and sleeps
#   kill            a signal number: after writing, it ends itself with that signal
#   exit            its exit status (default 0)
STANDIN = r"""
import json
import os
import signal
import subprocess
import sys
import time

with open(sys.argv[1], encoding="utf-8") as handle:
    plan = json.load(handle)
stem = plan["record"]
SLEEPER = "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(600)\n"
raw = sys.stdin.buffer.read() if plan.get("read", True) else b""


def started_with():
    # The kernel's copy of the environment the process was started with: Python's own os.environ may hold one more
    # variable than the launcher gave (it sets LC_CTYPE when the locale is the plain C one).
    try:
        with open("/proc/self/environ", "rb") as handle:
            pairs = handle.read().split(b"\0")
    except OSError:
        return dict(os.environ)
    return dict(pair.decode("utf-8", "surrogateescape").split("=", 1) for pair in pairs if pair)


def first_word():
    try:
        with open("/proc/self/cmdline", "rb") as handle:
            return handle.read().split(b"\0")[0].decode("utf-8", "surrogateescape")
    except OSError:
        return None


with open(stem + ".request", "wb") as handle:
    handle.write(raw)
record = {"pid": os.getpid(), "pgid": os.getpgrp(), "sid": os.getsid(0), "argv": sys.argv[1:], "cwd": os.getcwd(),
          "environment": started_with(), "first": first_word(), "child": None}
if plan.get("child"):
    record["child"] = subprocess.Popen([sys.executable, "-I", "-c", SLEEPER]).pid
with open(stem + ".tmp", "w") as handle:
    json.dump(record, handle)
os.replace(stem + ".tmp", stem + ".json")
for name, stream in (("stdout", sys.stdout), ("stderr", sys.stderr)):
    if plan.get(name):
        with open(plan[name], "rb") as handle:
            stream.buffer.write(handle.read())
        stream.buffer.flush()
if plan.get("hang"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(600)
if plan.get("kill"):
    os.kill(os.getpid(), plan["kill"])
    time.sleep(10)
sys.exit(plan.get("exit", 0))
"""


class AdaptersRequestTest(support.LauncherTest):
    def library(self):
        """The `lib` directory of the one installed copy this module built."""
        found = sorted((support._installation.prefix / "share" / support.PROGRAM / "versions").glob("*/lib"))
        self.assertEqual(len(found), 1)
        return found[0]

    def probe(self, calls):
        """The installed package's answer: the contract version, the byte bound, and for each call what it built or the
        refusal it made."""
        path = self.directory / "calls-{}.json".format(uuid.uuid4().hex)
        path.write_text(json.dumps(calls), encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", PROBE, str(self.library()), str(path)],
                                cwd=str(self.directory), env=self.environment, capture_output=True, text=True,
                                encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def ask(self, call, **kwargs):
        """The answer to one call."""
        return self.probe([{"call": call, "args": [], "kwargs": kwargs}])["answers"][0]

    def built(self, call, **kwargs):
        """The call must have built something; its answer is returned."""
        answer = self.ask(call, **kwargs)
        self.assertNotIn("error", answer, answer)
        return answer

    def refused(self, call, **kwargs):
        """The call must have been refused with ValueError; its message is returned."""
        answer = self.ask(call, **kwargs)
        self.assertEqual(answer.get("error"), "ValueError", answer)
        return answer["message"]

    # 1. The four forms: the members of the table, in the table's order, with the design's values.

    def test_quote_members_and_values(self):
        """fails when: the quote is not the acquire's own object (the members of the table's acquire row, in its order,
        with `operation` acquire, `dry_run` true and `region` null, because a quote names no region and does not know it
        yet), or any value is not the one the design gives."""
        answer = self.built("quote_request", **QUOTE)
        self.assertEqual(answer["keys"], ACQUIRE_MEMBERS)
        self.assertEqual(answer["request"], {"laneboss_resource": 1, "operation": "acquire", "id": RESOURCE,
                                             "lane": LANE, "kind": KIND, "profile": PROFILE, "purpose": PURPOSE,
                                             "size": SIZE, "region": None, "hard_cap_minutes": HARD_CAP_MINUTES,
                                             "dry_run": True, "timeout_seconds": TIMEOUT_SECONDS})

    def test_acquire_members_and_values(self):
        """fails when: the acquire does not carry `size` and `region` exactly as the quote answered them (the region is
        sent back, never null), or `dry_run` is not false, or a member is missing or in another position."""
        answer = self.built("acquire_request", **ACQUIRE)
        self.assertEqual(answer["keys"], ACQUIRE_MEMBERS)
        self.assertEqual(answer["request"], {"laneboss_resource": 1, "operation": "acquire", "id": RESOURCE,
                                             "lane": LANE, "kind": KIND, "profile": PROFILE, "purpose": PURPOSE,
                                             "size": SIZE, "region": REGION, "hard_cap_minutes": HARD_CAP_MINUTES,
                                             "dry_run": False, "timeout_seconds": TIMEOUT_SECONDS})

    def test_describe_members_and_values(self):
        """fails when: the describe carries a member of the acquire row (a lane, a purpose, a size, a region's cap, a
        dry_run) or lacks one of its own, or a value is not the design's."""
        answer = self.built("describe_request", **DESCRIBE)
        self.assertEqual(answer["keys"], READ_MEMBERS)
        self.assertEqual(answer["request"], {"laneboss_resource": 1, "operation": "describe", "id": RESOURCE,
                                             "kind": KIND, "profile": PROFILE, "region": REGION,
                                             "provider_id": PROVIDER_ID, "timeout_seconds": TIMEOUT_SECONDS})

    def test_release_members_and_values(self):
        """fails when: the release is not the describe's own object with the operation release, or a value is not the
        design's."""
        answer = self.built("release_request", **RELEASE)
        self.assertEqual(answer["keys"], READ_MEMBERS)
        self.assertEqual(answer["request"], {"laneboss_resource": 1, "operation": "release", "id": RESOURCE,
                                             "kind": KIND, "profile": PROFILE, "region": REGION,
                                             "provider_id": PROVIDER_ID, "timeout_seconds": TIMEOUT_SECONDS})

    def test_null_members_are_present(self):
        """fails when: a member the table allows to be null is left out instead of sent as null (a `profile`, a quote's
        `size` or `region`, a describe's `provider_id` while the resource has none)."""
        described = self.built("describe_request", **dict(DESCRIBE, profile=None, region=None, provider_id=None))
        self.assertEqual(described["keys"], READ_MEMBERS)
        for member in ("profile", "region", "provider_id"):
            with self.subTest(member=member):
                self.assertIn(member, described["request"])
                self.assertIsNone(described["request"][member])
        quoted = self.built("quote_request", **dict(QUOTE, profile=None, size=None))
        self.assertEqual(quoted["keys"], ACQUIRE_MEMBERS)
        for member in ("profile", "size", "region"):
            with self.subTest(member=member):
                self.assertIn(member, quoted["request"])
                self.assertIsNone(quoted["request"][member])
        acquired = self.built("acquire_request", **dict(ACQUIRE, size=None, region=None))
        for member in ("size", "region"):
            with self.subTest(member=member):
                self.assertIsNone(acquired["request"][member])

    # 2. The text.

    def test_text_for_is_one_ascii_line(self):
        """fails when: the text is not exactly the request as ASCII-safe JSON, one line, no space after a separator,
        with exactly one final newline."""
        answer = self.built("text_for", request=self.built("describe_request", **DESCRIBE)["request"])
        self.assertEqual(answer["text"], DESCRIBE_TEXT)
        self.assertEqual(answer["text"].count("\n"), 1)
        self.assertTrue(answer["text"].endswith("\n"))

    def test_text_for_escapes_non_ascii(self):
        """fails when: a character outside ASCII is written raw instead of escaped: the text must hold the escape and
        no character above ASCII."""
        request = dict(self.built("quote_request", **QUOTE)["request"], purpose="café")
        text = self.built("text_for", request=request)["text"]
        self.assertIn('"caf\\u00e9"', text)
        self.assertTrue(all(ord(character) < 128 for character in text))

    def test_text_for_refuses_oversize(self):
        """fails when: a request whose text passes MAX_REQUEST_BYTES (16 KiB) is not refused; the refusal names the
        bound and never a value."""
        request = dict(self.built("quote_request", **QUOTE)["request"], purpose="a" * 20000)
        message = self.refused("text_for", request=request)
        self.assertIn("MAX_REQUEST_BYTES", message)
        self.assertIn("16384", message)

    def test_text_for_size_bound_is_exact(self):
        """fails when: the bound is not on the encoded text itself: a text of exactly MAX_REQUEST_BYTES bytes is
        refused, or the same text with one more byte is accepted."""
        base = dict(self.built("quote_request", **QUOTE)["request"], purpose="")
        room = 16384 - len(self.built("text_for", request=base)["text"])
        text = self.built("text_for", request=dict(base, purpose="a" * room))["text"]
        self.assertEqual(len(text), 16384)
        self.refused("text_for", request=dict(base, purpose="a" * (room + 1)))

    # 3. The version and the contract's words.

    def test_version_and_operation_words(self):
        """fails when: the contract version is not the whole number 1, the byte bound is not 16 KiB, or an operation is
        not one of the contract's three words."""
        answer = self.probe([{"call": "_operation", "args": [], "kwargs": {"value": "acquire"}}])
        self.assertEqual(answer["version"], 1)
        self.assertEqual(answer["limit"], 16384)
        for word in ("acquire", "describe", "release"):
            with self.subTest(word=word):
                self.assertEqual(self.built("_operation", value=word), {"text": word})

    def test_operation_and_dry_run_refused(self):
        """fails when: an operation that is not one of the contract's three words is taken, or a `dry_run` that is not
        a boolean. Each of the four forms fixes both members itself, so the guards the four share are what is asked."""
        for value in ("run", "Acquire", "acquire ", "", None, 1, True):
            with self.subTest(value=value):
                self.assertIn("operation", self.refused("_operation", value=value))
        for value in ("true", "false", 1, 0, None, [], "yes"):
            with self.subTest(value=value):
                self.assertIn("dry_run", self.refused("_dry_run", value=value))

    # 4. Each bound refused.

    def test_timeout_bounds_refused(self):
        """fails when: a time-out outside 1 to 900 is taken (a whole number is what the table asks for, so a boolean and
        a fraction are not one), or a refusal does not name `timeout_seconds`."""
        for value in (0, 901, -1, 1000, True, None, 300.5):
            with self.subTest(value=value):
                self.assertIn("timeout_seconds",
                              self.refused("acquire_request", **dict(ACQUIRE, timeout_seconds=value)))
        for value in (1, 900):
            with self.subTest(value=value):
                self.built("acquire_request", **dict(ACQUIRE, timeout_seconds=value))

    def test_cap_bounds_refused(self):
        """fails when: a hard cap outside 1 to 10080 minutes is taken, or a refusal does not name
        `hard_cap_minutes`."""
        for value in (0, 10081, -1, 20000, True, None, "240"):
            with self.subTest(value=value):
                self.assertIn("hard_cap_minutes",
                              self.refused("acquire_request", **dict(ACQUIRE, hard_cap_minutes=value)))
        for value in (1, 10080):
            with self.subTest(value=value):
                self.built("acquire_request", **dict(ACQUIRE, hard_cap_minutes=value))

    def test_grammar_refusals(self):
        """fails when: an id, a lane, a purpose, a size, a region, a profile, a provider id or a kind outside its
        grammar or its list of words is taken, or a refusal does not name its member, or it repeats the value it
        refused."""
        cases = (
            ("id", "resource", "quote_request", "rs-0123456789abcdef0123456"),
            ("id", "resource", "acquire_request", "rs-0123456789abcdef012345678"),
            ("id", "resource", "describe_request", "RS-0123456789abcdef01234567"),
            ("id", "resource", "release_request", "rs-0123456789ABCDEF01234567"),
            ("id", "resource", "quote_request", "0123456789abcdef01234567"),
            ("id", "resource", "quote_request", None),
            ("lane", "lane", "quote_request", "Example"),
            ("lane", "lane", "acquire_request", "a" * 65),
            ("lane", "lane", "quote_request", "-lane"),
            ("purpose", "purpose", "quote_request", "a purpose"),
            ("purpose", "purpose", "acquire_request", "a" * 65),
            ("size", "size", "quote_request", "a" * 65),
            ("size", "size", "acquire_request", "-size"),
            ("region", "region", "acquire_request", "US-East-1"),
            ("region", "region", "describe_request", "a" * 33),
            ("region", "region", "release_request", "a" * 32 + "-"),
            ("profile", "profile", "quote_request", ".profile"),
            ("profile", "profile", "acquire_request", "a" * 65),
            ("provider_id", "provider_id", "describe_request", "a" * 193),
            ("provider_id", "provider_id", "release_request", "-provider"),
            ("kind", "kind", "quote_request", "service"),
            ("kind", "kind", "describe_request", "Machine"),
            ("kind", "kind", "acquire_request", "machines"),
        )
        for member, parameter, call, value in cases:
            with self.subTest(member=member, value=value):
                arguments = dict(FORMS[call])
                arguments[parameter] = value
                message = self.refused(call, **arguments)
                self.assertIn(member, message)
                self.assertNotIn(str(value), message)

    def test_grammar_edges_are_taken(self):
        """fails when: a value at the very edge of a grammar or a bound is refused: a lane of 64 characters, a purpose
        of 64, a size of 64, a region of 32, a profile of 64, a provider id of 192, at the smallest and the largest
        time-out and cap."""
        arguments = dict(ACQUIRE, lane="a" * 64, purpose="a" * 64, size="a" * 64, region="a" * 32, profile="a" * 64,
                         hard_cap_minutes=1, timeout_seconds=1)
        request = self.built("acquire_request", **arguments)["request"]
        self.assertEqual((request["lane"], request["purpose"], request["size"], request["region"], request["profile"]),
                         ("a" * 64, "a" * 64, "a" * 64, "a" * 32, "a" * 64))
        self.assertEqual((request["hard_cap_minutes"], request["timeout_seconds"]), (1, 1))
        read = self.built("describe_request", **dict(DESCRIBE, provider_id="a" * 192, timeout_seconds=900))["request"]
        self.assertEqual((read["provider_id"], read["timeout_seconds"]), ("a" * 192, 900))

    # 5. The review's four findings. The first three are guards for what the request half already does, each a place
    # where a wrong build was not caught by the tests above; the fourth is the shape of the builders' signatures.

    def test_quote_and_acquire_text(self):
        """fails when: the text of the quote, of the acquire or of the release is not the one written out by hand above
        from the design's table: the members in the table's order, `region` null in the quote, and `dry_run` the JSON
        words true and false and never a number (a build that sends "dry_run":1 fails here: the dictionaries of the
        tests above cannot tell 1 from true, the text can)."""
        for call, text in (("quote_request", QUOTE_TEXT), ("acquire_request", ACQUIRE_TEXT),
                           ("release_request", RELEASE_TEXT)):
            with self.subTest(call=call):
                request = self.built(call, **FORMS[call])["request"]
                self.assertEqual(self.built("text_for", request=request)["text"], text)

    def test_none_refused_for_members(self):
        """fails when: `None` is taken for a member that must be present and is not nullable: a `lane` or a `purpose` of
        the acquire forms, a `kind` of any form; or the refusal does not name the member."""
        cases = (("lane", "quote_request"), ("lane", "acquire_request"), ("purpose", "quote_request"),
                 ("purpose", "acquire_request"), ("kind", "quote_request"), ("kind", "acquire_request"),
                 ("kind", "describe_request"), ("kind", "release_request"))
        for member, call in cases:
            with self.subTest(member=member, call=call):
                self.assertIn(member, self.refused(call, **dict(FORMS[call], **{member: None})))

    def test_timeout_refused_in_every_form(self):
        """fails when: a time-out outside 1 to 900, a boolean, a fraction, an integral float such as 300.0, a string or
        `None` is taken by the quote, the acquire, the describe or the release (and not only by the acquire), or the
        refusal does not name `timeout_seconds`; or an edge, 1 or 900, is refused by one of them."""
        for call in FORMS:
            for value in (0, 901, -1, 1000, True, None, 300.5, 300.0, "300"):
                with self.subTest(call=call, value=value):
                    self.assertIn("timeout_seconds",
                                  self.refused(call, **dict(FORMS[call], timeout_seconds=value)))
            for value in (1, 900):
                with self.subTest(call=call, edge=value):
                    self.built(call, **dict(FORMS[call], timeout_seconds=value))

    def test_integral_float_cap_refused(self):
        """fails when: a hard cap written as an integral float, 240.0, is taken by the quote or by the acquire (the
        table asks for a whole number), or the refusal does not name `hard_cap_minutes`."""
        for call in ("quote_request", "acquire_request"):
            with self.subTest(call=call):
                self.assertIn("hard_cap_minutes", self.refused(call, **dict(FORMS[call], hard_cap_minutes=240.0)))

    def test_builders_are_keyword_only(self):
        """fails when: a builder takes a member positionally: a call that gives every argument in the old order, or in
        the table's order, must raise TypeError for each of the four builders (a build that keeps its parameters
        positional, in either order, builds the request or refuses it with ValueError, and never raises TypeError)."""
        old_order = {"quote_request": [RESOURCE, KIND, PROFILE, LANE, PURPOSE, SIZE, HARD_CAP_MINUTES, TIMEOUT_SECONDS],
                     "acquire_request": [RESOURCE, KIND, PROFILE, LANE, PURPOSE, SIZE, REGION, HARD_CAP_MINUTES,
                                         TIMEOUT_SECONDS],
                     "describe_request": [RESOURCE, KIND, PROFILE, REGION, PROVIDER_ID, TIMEOUT_SECONDS],
                     "release_request": [RESOURCE, KIND, PROFILE, REGION, PROVIDER_ID, TIMEOUT_SECONDS]}
        table_order = {"quote_request": [RESOURCE, LANE, KIND, PROFILE, PURPOSE, SIZE, HARD_CAP_MINUTES,
                                         TIMEOUT_SECONDS],
                       "acquire_request": [RESOURCE, LANE, KIND, PROFILE, PURPOSE, SIZE, REGION, HARD_CAP_MINUTES,
                                           TIMEOUT_SECONDS],
                       "describe_request": old_order["describe_request"],
                       "release_request": old_order["release_request"]}
        for label, orders in (("old order", old_order), ("table order", table_order)):
            for call, arguments in orders.items():
                with self.subTest(order=label, call=call):
                    answer = self.probe([{"call": call, "args": arguments, "kwargs": {}}])["answers"][0]
                    self.assertEqual(answer.get("error"), "TypeError", answer)

    def test_builder_parameters_in_order(self):
        """fails when: the parameters of a builder are not the table's members in the table's order (`lane` before
        `kind`), or one of them can be passed positionally."""
        result = subprocess.run([sys.executable, "-I", "-B", "-c", SIGNATURE_PROBE, str(self.library()), *PARAMETERS],
                                cwd=str(self.directory), env=self.environment, capture_output=True, text=True,
                                encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        found = json.loads(result.stdout)
        for call, names in PARAMETERS.items():
            with self.subTest(call=call):
                self.assertEqual([name for name, _ in found[call]], names)
                self.assertEqual({kind for _, kind in found[call]}, {"KEYWORD_ONLY"})


# The call half. Every answer below is a literal of the design's tables ("The answer"): one for each state of each
# operation, with values that are inside every grammar, and the members each state requires besides `state`.
FIXED_PATH = "/usr/local/bin:/usr/bin:/bin"
VARIABLE = "E2E_ADAPTER_KEY"
VALUE = "e2e-adapter-value-0001"
STARTED = "2026-10-12T08:30:00.123Z"
ENDED = "2026-10-12T09:30:00+00:00"
QUOTED = {"state": "quoted", "size": SIZE, "region": REGION, "price_per_hour_micros": 123456, "currency": "USD",
          "price_source": "adapter"}
FAILED = {"state": "failed", "reason": "no-capacity"}
ACQUIRED = {"state": "acquired", "provider_id": PROVIDER_ID, "started_at": STARTED}
RUNNING = {"state": "running", "provider_id": PROVIDER_ID, "provider_state": "running", "started_at": STARTED}
TERMINATED = {"state": "terminated", "provider_id": PROVIDER_ID, "provider_state": "terminated",
              "started_at": STARTED, "ended_at": ENDED}
ABSENT = {"state": "absent"}
RELEASING = {"state": "releasing"}
# (form, answer) for every state each operation may answer; `failed` is one answer for a quote and for an acquire.
VALID = (("quote_request", QUOTED), ("quote_request", FAILED), ("acquire_request", ACQUIRED),
         ("acquire_request", FAILED), ("describe_request", RUNNING), ("describe_request", TERMINATED),
         ("describe_request", ABSENT), ("release_request", RELEASING))
ANSWER_OF = {(form, answer["state"]): answer for form, answer in VALID}
# What each state requires besides `state`: the design's own table.
REQUIRED = (
    ("quote_request", "quoted", ("size", "region", "price_per_hour_micros", "currency", "price_source")),
    ("quote_request", "failed", ("reason",)),
    ("acquire_request", "acquired", ("provider_id", "started_at")),
    ("acquire_request", "failed", ("reason",)),
    ("describe_request", "running", ("provider_id", "provider_state", "started_at")),
    ("describe_request", "terminated", ("provider_id", "provider_state", "started_at", "ended_at")),
    ("describe_request", "absent", ()),
    ("release_request", "releasing", ()),
)
# A valid value for each member that some state carries, to put a member into a state that does not list it.
SAMPLES = {"size": SIZE, "region": REGION, "price_per_hour_micros": 123456, "currency": "USD",
           "price_source": "adapter", "reason": "no-capacity", "provider_id": PROVIDER_ID,
           "provider_state": "running", "started_at": STARTED, "ended_at": ENDED}
# An answer that is valid for each form.
OF_FORM = {"quote_request": QUOTED, "acquire_request": ACQUIRED, "describe_request": RUNNING,
           "release_request": RELEASING}
# What a call gives when there is no answer, and what it gives for a program that is not found: the reason and the
# judge's words for it (docs/judges.md), and no answer.
NO_ANSWER = {"reason": "output", "answer": None, "detail": "standard output is not one answer object"}
NOT_FOUND = {"reason": "not-found", "answer": None, "detail": "the program was not found or could not be started"}
# The forms of timestamp that the envelope's `occurred_at` has, all of which an answer may use.
TIMES = ("2026-10-12T08:30:00Z", "2026-10-12T08:30:00.123Z", "2026-10-12T08:30:00.123456Z",
         "2026-10-12T16:30:00+08:00", "2026-10-12T08:30:00-05:30")
# Answers at the very edge of a grammar or a bound, which must be taken: (label, form, arguments, answer).
EDGES = (
    ("longest provider id", "acquire_request", None, dict(ACQUIRED, provider_id="a" * 192)),
    ("longest provider id and state", "describe_request", dict(DESCRIBE, provider_id=None),
     dict(RUNNING, provider_id="a" * 192, provider_state="a" * 128)),
    ("longest reason", "quote_request", None, dict(FAILED, reason="a" * 40)),
    ("hyphens in a reason", "acquire_request", None, dict(FAILED, reason="no-more-room")),
    ("longest size and region", "quote_request", None, dict(QUOTED, size="a" * 64, region="a" * 32)),
    ("null size, region and price", "quote_request", None,
     dict(QUOTED, size=None, region=None, price_per_hour_micros=None, currency=None, price_source=None)),
    ("a free price", "quote_request", None, dict(QUOTED, price_per_hour_micros=0)),
    ("the dearest price", "quote_request", None,
     dict(QUOTED, price_per_hour_micros=1000000000, currency="EUR", price_source="configured")),
    ("longest request identifier", "describe_request", None, dict(ABSENT, request="a" * 128)),
    ("no start time", "acquire_request", None, dict(ACQUIRED, started_at=None)),
    ("no times at all", "describe_request", None, dict(TERMINATED, started_at=None, ended_at=None)),
) + tuple(("time " + stamp, "acquire_request", None, dict(ACQUIRED, started_at=stamp)) for stamp in TIMES)
# For each member, the form and the answer that carry it, and then (member, a value outside its grammar or bound).
CARRIER = {"size": ("quote_request", QUOTED), "region": ("quote_request", QUOTED),
           "price_per_hour_micros": ("quote_request", QUOTED), "currency": ("quote_request", QUOTED),
           "price_source": ("quote_request", QUOTED), "reason": ("quote_request", FAILED),
           "provider_id": ("acquire_request", ACQUIRED), "started_at": ("acquire_request", ACQUIRED),
           "provider_state": ("describe_request", TERMINATED), "ended_at": ("describe_request", TERMINATED),
           "request": ("describe_request", ABSENT)}
WRONG_TIMES = (5, True, "", "yesterday", "2026-10-12", "2026-10-12 08:30:00Z", "2026-10-12T08:30:00",
               "2026-10-12T08:30:00.1Z", "2026-13-45T08:30:00Z", "2026-02-30T08:30:00Z", "2026-10-12T08:30:00+0800")
BAD = (
    ("size", 5), ("size", ""), ("size", "-x"), ("size", "a b"), ("size", "a" * 65), ("size", ["a"]),
    ("region", 5), ("region", ""), ("region", "US-East"), ("region", "a" * 33), ("region", "-x"),
    ("price_per_hour_micros", "5"), ("price_per_hour_micros", True), ("price_per_hour_micros", 1000000001),
    ("price_per_hour_micros", -1), ("price_per_hour_micros", [5]), ("price_per_hour_micros", 99999999999999999999),
    ("currency", "usd"), ("currency", "US"), ("currency", "USDD"), ("currency", 5), ("currency", "U$D"),
    ("currency", ""), ("price_source", "other"), ("price_source", "Adapter"), ("price_source", 5),
    ("price_source", True), ("price_source", ""),
    ("reason", None), ("reason", ""), ("reason", "No-capacity"), ("reason", "no capacity"), ("reason", "no_capacity"),
    ("reason", "a1"), ("reason", "-a"), ("reason", "a" * 41), ("reason", 5),
    ("provider_id", None), ("provider_id", 5), ("provider_id", ""), ("provider_id", "-x"), ("provider_id", "a b"),
    ("provider_id", "a" * 193), ("provider_id", ["a"]),
    ("provider_state", None), ("provider_state", 5), ("provider_state", ""), ("provider_state", "-x"),
    ("provider_state", "a/b"), ("provider_state", "a" * 129),
    ("request", 5), ("request", True), ("request", ""), ("request", "-x"), ("request", "a/b"), ("request", "a" * 129),
    ("request", ["r"]),
) + tuple(("started_at", value) for value in WRONG_TIMES) + tuple(("ended_at", value) for value in WRONG_TIMES)
# A state that is none of the contract's words, for the form's first valid answer.
ODD_STATES = ("Quoted", "QUOTED", " quoted", "quoted ", "", None, 5, True, ["quoted"], {"state": "quoted"}, "unknown",
              "Running", "ABSENT", "released")
ALNUM = string.ascii_letters + string.digits
LOWER = string.ascii_lowercase + string.digits
UPPER = string.ascii_uppercase + string.digits


def pick(alphabet, count):
    return "".join(random.choice(alphabet) for _ in range(count))


# Credential-shaped values, built at run time from pieces and different on every call, so that no file of the
# repository holds one and no assertion can be met by remembering one. Each function is one rule of the detector.
def cloud_key_id():
    return "AK" + "IA" + pick(UPPER, 16)


def code_host_token():
    return "gh" + "p_" + pick(ALNUM, 36)


def payment_key():
    return "sk" + "_live_" + pick(ALNUM, 24)


def glpat_token():
    return "glpat" + "-" + pick(LOWER, 20)


def glpat_letters():
    return "glpat" + "-" + pick(string.ascii_lowercase, 20)


def encode(answer):
    """The bytes of an answer object as an adapter prints it: one line of JSON."""
    return (json.dumps(answer) + "\n").encode("utf-8")


def raw_number(answer, member, literal):
    """The bytes of the answer with `member` written as `literal`: a JSON number or word that json.dumps does not."""
    return (json.dumps(dict(answer, **{member: "@NUMBER@"})).replace('"@NUMBER@"', literal) + "\n").encode("utf-8")


def answered(answer):
    """The result of a call that was answered with this object: its members, `request` read as null when it is absent,
    and no detail."""
    return {"reason": "answered", "answer": dict(answer, request=answer.get("request")), "detail": ""}


class AdaptersCallTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.records = self.directory / "records"
        self.records.mkdir()
        self.standin = self.directory / "adapter_standin.py"
        self.standin.write_text(STANDIN, encoding="utf-8")
        self.counter = 0

    def library(self):
        """The `lib` directory of the one installed copy this module built."""
        found = sorted((support._installation.prefix / "share" / support.PROGRAM / "versions").glob("*/lib"))
        self.assertEqual(len(found), 1)
        return found[0]

    def make_case(self, form="describe_request", arguments=None, output=None, error=None, program=None, extra=(),
                  seconds=None, credential_env=None, command=None, **plan):
        """One case for run_cases(), and the stem of the stand-in's records. The command is the stand-in, started by the
        interpreter that runs the suite, unless `command` is given; `program` replaces the interpreter and `extra` goes
        after the plan, where the stand-in ignores it. `output` and `error` are the bytes the stand-in writes to its two
        streams, and the rest of `plan` is its plan (see STANDIN)."""
        self.counter += 1
        stem = self.records / "run-{}".format(self.counter)
        plan["record"] = str(stem)
        for name, data in (("stdout", output), ("stderr", error)):
            if data is not None:
                path = self.records / "{}-{}.bin".format(name, self.counter)
                path.write_bytes(data)
                plan[name] = str(path)
        plan_file = self.records / "plan-{}.json".format(self.counter)
        plan_file.write_text(json.dumps(plan), encoding="utf-8")
        arguments = dict(FORMS[form] if arguments is None else arguments)
        if command is None:
            command = [program or sys.executable, "-I", str(self.standin), str(plan_file), *extra]
        return {"form": form, "arguments": arguments,
                "seconds": arguments["timeout_seconds"] if seconds is None else seconds,
                "credential_env": credential_env, "command": command}, stem

    def run_cases(self, cases, environment=None):
        """The result of adapters.call() for each case, called in a process of its own (see CALL_PROBE) whose
        environment is `environment` or the test's own: `reason`, `answer` and `detail`, or `error` and `message` when
        it raised."""
        path = self.directory / "cases-{}.json".format(uuid.uuid4().hex)
        path.write_text(json.dumps(cases), encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", CALL_PROBE, str(self.library()), str(path)],
                                cwd=str(self.directory), env=self.environment if environment is None else environment,
                                capture_output=True, text=True, encoding="utf-8", timeout=180)
        self.assertEqual(result.returncode, 0, result.stderr)
        results = json.loads(result.stdout)
        self.assertEqual(len(results), len(cases))
        return results

    def record(self, stem):
        """What the stand-in recorded about itself once it had its request."""
        path = Path(str(stem) + ".json")
        self.assertTrue(path.is_file(), "the stand-in adapter did not run")
        return json.loads(path.read_text(encoding="utf-8"))

    def ran(self, stem):
        return Path(str(stem) + ".json").exists()

    def request_bytes(self, stem):
        """The bytes the stand-in was given on its standard input."""
        return Path(str(stem) + ".request").read_bytes()

    def alive(self, pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        status = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
        return status.returncode == 0 and not status.stdout.strip().startswith("Z")

    def assert_gone(self, pids, timeout=10):
        deadline = time.monotonic() + timeout
        while True:
            living = [pid for pid in pids if self.alive(pid)]
            if not living:
                return
            if time.monotonic() > deadline:
                self.fail("processes of the adapter are still alive: {}".format(living))
            time.sleep(0.1)

    def assert_no_answer(self, items, environment=None, credential_env=None):
        """Each item is (label, form, data) or (label, form, data, arguments): the stand-in prints `data` (an answer
        object, or bytes as they are) and exits 0, and every call must give no answer: the reason `output`, nothing of
        the answer and the judge's words for it."""
        cases = []
        for item in items:
            data = item[2]
            cases.append(self.make_case(form=item[1], arguments=item[3] if len(item) > 3 else None,
                                        output=encode(data) if isinstance(data, dict) else data,
                                        credential_env=credential_env)[0])
        for item, result in zip(items, self.run_cases(cases, environment=environment)):
            with self.subTest(case=item[0]):
                self.assertEqual(result, NO_ANSWER)

    # 1. The program: resolved by the launcher, before anything is sent.

    def test_name_found_on_launcher_path(self):
        """fails when: a bare command name is looked up anywhere but on the launcher's own PATH (a build that hands the
        bare name to the new process, which looks it up on the fixed PATH where this name is not, finds nothing), or the
        program is started under a name that is not the absolute path the rule finds: for a PATH entry that is
        relative, `adapter-bin`, the first word of the adapter's own command line is not the absolute path."""
        directory = self.directory / "adapter-bin"
        directory.mkdir()
        name = "e2e-adapter-" + uuid.uuid4().hex[:8]
        os.symlink(sys.executable, str(directory / name))
        for label, entry in (("absolute entry", str(directory)), ("relative entry", "adapter-bin")):
            with self.subTest(entry=label):
                case, stem = self.make_case(output=encode(ABSENT), program=name)
                (result,) = self.run_cases([case], environment=dict(self.environment, PATH=entry))
                self.assertEqual(result, answered(ABSENT))
                self.assertEqual(self.record(stem)["first"], str(directory / name))

    def test_missing_program_sends_nothing(self):
        """fails when: a program that is not found, or cannot be started, is reported as anything but `not-found`, or
        something is run for it: a build that resolves on the wrong PATH, or leaves the lookup to the new process, finds
        `sh` on the fixed PATH (which the launcher's PATH here does not hold) and runs it."""
        marker = self.directory / "ran"
        empty = self.directory / "empty-bin"
        empty.mkdir()
        plain = self.directory / "not-executable"
        plain.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        plain.chmod(0o644)
        unstartable = self.directory / "unstartable"
        unstartable.write_text("#!/no/such/interpreter\n", encoding="utf-8")
        unstartable.chmod(0o755)
        commands = (["laneboss-e2e-absent-adapter", "x"], [str(self.directory / "no-such-directory" / "adapter")],
                    [str(plain)], [str(self.directory)], ["sh", "-c", "touch " + str(marker)], [str(unstartable)])
        cases = [self.make_case(command=command)[0] for command in commands]
        results = self.run_cases(cases, environment=dict(self.environment, PATH=str(empty)))
        for command, result in zip(commands, results):
            with self.subTest(program=command[0]):
                self.assertEqual(result, NOT_FOUND)
        self.assertFalse(marker.exists(), "a program that was not found was run")

    # 2. The environment: exactly two things.

    def test_environment_is_path_and_variable(self):
        """fails when: the adapter gets more or less than `PATH`, set to the fixed value, and the variable that
        credential_env names, with its value: the launcher's own environment handed on, a `HOME`, a `LANEBOSS_`
        variable, an ambient variable that stands for a default profile, another credential, the launcher's PATH, or
        the named variable when no variable is named."""
        launcher = dict(self.environment, E2E_AMBIENT_PROFILE="ambient-default", E2E_OTHER_KEY="other-value",
                        LANEBOSS_LANE="some-lane",
                        PATH=str(self.directory / "launcher-bin") + os.pathsep + self.environment["PATH"])
        launcher[VARIABLE] = VALUE
        self.assertIn("HOME", launcher)
        self.assertTrue(any(name.startswith(support.ENV_PREFIX) for name in launcher))
        named, named_stem = self.make_case(output=encode(ABSENT), credential_env=VARIABLE)
        unnamed, unnamed_stem = self.make_case(output=encode(ABSENT))
        results = self.run_cases([named, unnamed], environment=launcher)
        self.assertEqual(results, [answered(ABSENT), answered(ABSENT)])
        self.assertEqual(self.record(named_stem)["environment"], {"PATH": FIXED_PATH, VARIABLE: VALUE})
        self.assertEqual(self.record(unnamed_stem)["environment"], {"PATH": FIXED_PATH})

    def test_unset_variable_is_not_called(self):
        """fails when: the adapter is called while the variable that credential_env names is unset, or set to nothing,
        in the launcher's environment (the call is refused with Refused before anything is started); or it is not
        called once the variable is set, which is the control."""
        without = {name: value for name, value in self.environment.items() if name != VARIABLE}
        for label, environment in (("unset", without), ("empty", dict(without, **{VARIABLE: ""}))):
            with self.subTest(variable=label):
                case, stem = self.make_case(output=encode(ABSENT), credential_env=VARIABLE)
                (result,) = self.run_cases([case], environment=environment)
                self.assertEqual(result.get("error"), "Refused", result)
                self.assertFalse(self.ran(stem), "the adapter was called")
        case, stem = self.make_case(output=encode(ABSENT), credential_env=VARIABLE)
        (result,) = self.run_cases([case], environment=dict(without, **{VARIABLE: VALUE}))
        self.assertEqual(result, answered(ABSENT))

    def test_variable_name_is_refused(self):
        """fails when: a name that the adapter may not be given is taken as `credential_env`: `PATH` (the adapter's
        fixed PATH would be replaced), a name that starts with LANEBOSS_, a name outside the grammar of the
        configuration key (lower case, a leading digit, more than 64 characters, a space, a hyphen) or an empty one;
        each is a ValueError, and the adapter is not started."""
        names = ("PATH", "LANEBOSS_TOKEN", "lower_case", "1ABC", "A" * 65, "", "TWO WORDS", "A-B")
        environment = dict(self.environment, LANEBOSS_TOKEN=VALUE, lower_case=VALUE)
        environment["1ABC"] = VALUE
        made = [self.make_case(output=encode(ABSENT), credential_env=name) for name in names]
        results = self.run_cases([case for case, _ in made], environment=environment)
        for name, (_, stem), result in zip(names, made, results):
            with self.subTest(name=name):
                self.assertEqual(result.get("error"), "ValueError", result)
                self.assertFalse(self.ran(stem), "the adapter was called")

    def test_call_refusals_run_nothing(self):
        """fails when: call() starts the adapter for a call it must refuse with ValueError: a `seconds` that is not the
        request's own `timeout_seconds` (the deadline the launcher keeps must be the one it told the adapter), or a
        command that is not a list of strings with a program first."""
        mismatch, stem = self.make_case(seconds=5)
        cases = [mismatch, self.make_case(command=[])[0], self.make_case(command=[5])[0],
                 self.make_case(command="adapter")[0]]
        for label, result in zip(("seconds", "empty command", "command of a number", "command as text"),
                                 self.run_cases(cases)):
            with self.subTest(case=label):
                self.assertEqual(result.get("error"), "ValueError", result)
        self.assertFalse(self.ran(stem), "the adapter was called")

    # 3. The call: the request on standard input, a process group of its own, an end at the time-out.

    def test_request_text_reaches_stdin(self):
        """fails when: the adapter is not given, on its standard input, exactly the hand-written text of the request:
        the members in the table's order, one line, one final newline, ASCII, nothing else, and not the value of the
        credential variable (which reaches the adapter only through its environment)."""
        texts = (("quote_request", QUOTE_TEXT), ("acquire_request", ACQUIRE_TEXT),
                 ("describe_request", DESCRIBE_TEXT), ("release_request", RELEASE_TEXT))
        made = [self.make_case(form=form, output=encode(OF_FORM[form]), credential_env=VARIABLE)
                for form, _ in texts]
        results = self.run_cases([case for case, _ in made], environment=dict(self.environment, **{VARIABLE: VALUE}))
        for (form, text), (_, stem), result in zip(texts, made, results):
            with self.subTest(form=form):
                self.assertEqual(result, answered(OF_FORM[form]))
                data = self.request_bytes(stem)
                self.assertEqual(data, text.encode("ascii"))
                self.assertNotIn(VALUE.encode("ascii"), data)

    def test_adapter_runs_apart_without_shell(self):
        """fails when: the adapter is started through a shell (an argument with a shell's metacharacters is run), or in
        the launcher's own session and process group, or not in the launcher's working directory."""
        marker = self.directory / "shell-marker"
        text = "x; touch " + str(marker)
        case, stem = self.make_case(output=encode(ABSENT), extra=[text])
        (result,) = self.run_cases([case])
        self.assertEqual(result, answered(ABSENT))
        record = self.record(stem)
        self.assertEqual(record["argv"][-1], text)
        self.assertFalse(marker.exists(), "the command was run through a shell")
        self.assertEqual((record["pgid"], record["sid"]), (record["pid"], record["pid"]), "its own session")
        self.assertEqual(record["cwd"], str(self.directory))

    def test_adapter_may_ignore_its_input(self):
        """fails when: an adapter that never reads its standard input is treated as an error: it answers, and that is an
        answer."""
        case, _ = self.make_case(output=encode(ABSENT), read=False)
        (result,) = self.run_cases([case])
        self.assertEqual(result, answered(ABSENT))

    def test_nonzero_exit_is_no_answer(self):
        """fails when: a valid object that an adapter printed is read as an answer although it exited with a non-zero
        status or ended by a signal; when silence (a clean exit with nothing printed) is read as anything; or when the
        words are not a judge's: `exit status N`, `ended by a signal`, and the first line of standard error after a
        colon."""
        valid = encode(ABSENT)
        cases = [self.make_case(output=valid, exit=3)[0], self.make_case(output=valid, error=b"boom\n", exit=3)[0],
                 self.make_case(output=valid, kill=int(signal.SIGKILL))[0], self.make_case(exit=1)[0],
                 self.make_case()[0]]
        wanted = [{"reason": "exit", "answer": None, "detail": "exit status 3"},
                  {"reason": "exit", "answer": None, "detail": "exit status 3: boom"},
                  {"reason": "exit", "answer": None, "detail": "ended by a signal"},
                  {"reason": "exit", "answer": None, "detail": "exit status 1"}, NO_ANSWER]
        self.assertEqual(self.run_cases(cases), wanted)

    def test_hang_ends_group_at_timeout(self):
        """fails when: an adapter that does not end is waited for past the operation's time-out, or its output is read
        as an answer, or the reason is not `timeout` with a judge's words, or its process group is not ended whole (a
        build that ends only the adapter leaves the child, which ignores SIGTERM, alive; one that sends only SIGTERM
        leaves both)."""
        case, stem = self.make_case(output=encode(ABSENT), hang=True, child=True,
                                    arguments=dict(DESCRIBE, timeout_seconds=1))
        started = time.monotonic()
        (result,) = self.run_cases([case])
        self.assertLess(time.monotonic() - started, 10, "the time-out and the end of the group take a few seconds")
        self.assertEqual(result, {"reason": "timeout", "answer": None, "detail": "no answer within 1 second(s)"})
        record = self.record(stem)
        self.assert_gone([record["pid"], record["child"]], timeout=5)

    def test_leftover_child_is_ended(self):
        """fails when: a child that the adapter left holding its output pipes is waited for (the call must return as
        soon as the adapter has ended, with what it printed), or is left running."""
        case, stem = self.make_case(output=encode(ABSENT), child=True, arguments=dict(DESCRIBE, timeout_seconds=20))
        started = time.monotonic()
        (result,) = self.run_cases([case])
        self.assertLess(time.monotonic() - started, 10, "the call waited for a child that holds the pipe")
        self.assertEqual(result, answered(ABSENT))
        self.assert_gone([self.record(stem)["child"]], timeout=5)

    # 4. The answer: every state read as the design's table says, and every refusal of "What is no answer".

    def test_every_state_is_read(self):
        """fails when: an answer that the table allows is not read as the state and the members it names: each state of
        each operation, with `request` absent (read as null), null and an identifier; a build that reads another
        operation's table, drops a member, or gives back something else than the members that were printed."""
        cases, wanted = [], []
        for form, answer in VALID:
            for extra in ({}, {"request": None}, {"request": "req-0001:a.b"}):
                body = dict(answer, **extra)
                cases.append(self.make_case(form=form, output=encode(body))[0])
                wanted.append((form, body))
        for (form, body), result in zip(wanted, self.run_cases(cases)):
            with self.subTest(form=form, answer=body):
                self.assertEqual(result, answered(body))

    def test_white_space_around_is_allowed(self):
        """fails when: white space before or after the object (a final newline included) makes the answer no answer."""
        body = encode(ABSENT).strip()
        variants = (b" " + body, body + b"\n\n", b"\n \t\r\n" + body + b" \r\n\t ", b"\r\n" + body)
        cases = [self.make_case(output=data)[0] for data in variants]
        for data, result in zip(variants, self.run_cases(cases)):
            with self.subTest(answer=data):
                self.assertEqual(result, answered(ABSENT))

    def test_bound_edges_are_taken(self):
        """fails when: an answer at the very edge of a grammar or a bound is refused: the longest provider id (192
        characters), provider state (128), reason (40), size (64), region (32) and request identifier (128), the
        smallest and the largest price, null where the table allows it, and each form of timestamp the envelope has."""
        cases = [self.make_case(form=form, arguments=arguments, output=encode(answer))[0]
                 for _, form, arguments, answer in EDGES]
        for (label, _, _, answer), result in zip(EDGES, self.run_cases(cases)):
            with self.subTest(case=label):
                self.assertEqual(result, answered(answer))

    def test_bounds_are_enforced(self):
        """fails when: a member outside its grammar or its bound is taken: a wrong type (a number for a string, a string
        or a boolean for a whole number, a list), a value one past a length or a price bound, a currency not of three
        capital letters, a price source outside its list, a reason that is not a code, `null` for a member that is
        never null, and a timestamp outside the envelope's grammar or that is no date and time."""
        items = []
        for member, value in BAD:
            form, answer = CARRIER[member]
            items.append(("{} {!r}".format(member, value)[:70], form, dict(answer, **{member: value})))
        self.assert_no_answer(items)

    def test_required_member_absent(self):
        """fails when: an answer that lacks a member its state requires, or its `state`, is read as an answer or as
        anything but what an unreadable answer is read as: the same reason, no answer and the same words (a build that
        defaults a member, reads a missing `state` as `absent`, silence as anything or a broken answer as `failed` fails
        here)."""
        items = []
        for form, state, members in REQUIRED:
            answer = ANSWER_OF[(form, state)]
            for member in ("state",) + members:
                items.append(("{} {} lacks {}".format(form, state, member), form,
                              {key: value for key, value in answer.items() if key != member}))
        for form in FORMS:
            items.append((form + " empty object", form, b"{}\n"))
            items.append((form + " nothing", form, b""))
        cases = [self.make_case(form=form, output=encode(data) if isinstance(data, dict) else data)[0]
                 for _, form, data in items]
        cases.append(self.make_case(output=b"this is not json\n")[0])
        results = self.run_cases(cases)
        unreadable = results.pop()
        self.assertEqual(unreadable, NO_ANSWER)
        for (label, _, _), result in zip(items, results):
            with self.subTest(case=label):
                self.assertEqual(result, unreadable)

    def test_unlisted_member_refused(self):
        """fails when: a member that is not listed for the operation and the state is taken: an unknown member, a
        member of another state (a price in a describe, a provider id in a quote, an end time in an acquire), whatever
        its value (`request` is the one member every answer may carry)."""
        items = []
        for form, answer in VALID:
            for member in ("extra", "x_price"):
                items.append(("{} {} {}".format(form, answer["state"], member), form, dict(answer, **{member: 1})))
            for member, sample in SAMPLES.items():
                if member not in answer:
                    items.append(("{} {} also {}".format(form, answer["state"], member), form,
                                  dict(answer, **{member: sample})))
        self.assert_no_answer(items)

    def test_wrong_state_refused(self):
        """fails when: a state that the operation does not allow is taken: `quoted` for an acquire with `dry_run` false,
        `acquired` for a quote, `releasing` for a describe, `running` for a release, `released` for any of them, and a
        word that is none of the contract's states, in other case or with a space, `null`, a number, a list."""
        items = []
        for form in FORMS:
            allowed = [answer["state"] for other, answer in VALID if other == form]
            for other, answer in VALID:
                if answer["state"] not in allowed:
                    items.append(("{} answered {}".format(form, answer["state"]), form, answer))
            items.append((form + " answered released", form, {"state": "released"}))
            first = next(answer for other, answer in VALID if other == form)
            for odd in ODD_STATES:
                items.append(("{} state {!r}".format(form, odd), form, dict(first, state=odd)))
        self.assert_no_answer(items)

    def test_price_members_null_together(self):
        """fails when: three price members of which some are null and some are not are taken (any one null, any two
        null), or a quote with all three null or all three set is refused."""
        names = ("price_per_hour_micros", "currency", "price_source")
        items = []
        for nulled in ((0,), (1,), (2,), (0, 1), (0, 2), (1, 2)):
            body = dict(QUOTED, **{names[index]: None for index in nulled})
            items.append(("null: {}".format(", ".join(names[index] for index in nulled)), "quote_request", body))
        self.assert_no_answer(items)
        every = dict(QUOTED, price_per_hour_micros=None, currency=None, price_source=None)
        cases = [self.make_case(form="quote_request", output=encode(body))[0] for body in (every, QUOTED)]
        self.assertEqual(self.run_cases(cases), [answered(every), answered(QUOTED)])

    def test_describe_provider_id_checked(self):
        """fails when: a describe that answers another provider id than the request's is taken (two resources under one
        id is a fault a person has to see), whatever the state, even an id that differs only in case; or an answer
        with the request's own id is refused, or any id is refused when the request's is null."""
        other = "example-provider-0002"
        self.assert_no_answer([("another id, running", "describe_request", dict(RUNNING, provider_id=other)),
                               ("another id, terminated", "describe_request", dict(TERMINATED, provider_id=other)),
                               ("an id in another case", "describe_request",
                                dict(RUNNING, provider_id=PROVIDER_ID.upper()))])
        null_id = dict(DESCRIBE, provider_id=None)
        wanted = [(DESCRIBE, RUNNING), (DESCRIBE, TERMINATED), (null_id, dict(RUNNING, provider_id=other)),
                  (null_id, ABSENT)]
        cases = [self.make_case(form="describe_request", arguments=arguments, output=encode(body))[0]
                 for arguments, body in wanted]
        for (_, body), result in zip(wanted, self.run_cases(cases)):
            with self.subTest(answer=body):
                self.assertEqual(result, answered(body))

    def test_fractions_and_exponents_refused(self):
        """fails when: a number with a fraction or an exponent is taken for a price, even one that is whole in value
        (5.0, 1e3), or an unreadable number or word (NaN, Infinity, 1e999) is read as anything but no answer."""
        literals = ("5.0", "5.5", "0.5", "1e3", "1E3", "1e+3", "1e-3", "5e0", "1.5e2", "-0.0", "10E-1", "1e999", "NaN",
                    "Infinity", "-Infinity")
        self.assert_no_answer([("price " + literal, "quote_request",
                                raw_number(QUOTED, "price_per_hour_micros", literal)) for literal in literals])

    def test_repeated_member_refused(self):
        """fails when: an object that repeats a member is taken (the last, or the first, value read), even when the two
        values are the same."""
        known = PROVIDER_ID.encode("ascii")
        self.assert_no_answer([
            ("state twice", "describe_request", b'{"state":"absent","state":"absent"}\n'),
            ("request twice", "describe_request", b'{"state":"absent","request":null,"request":null}\n'),
            ("reason twice", "quote_request", b'{"state":"failed","reason":"a","reason":"b"}\n'),
            ("provider id twice", "describe_request",
             b'{"state":"running","provider_id":"' + known + b'","provider_id":"' + known
             + b'","provider_state":"running","started_at":null}\n'),
            ("an unlisted member twice", "release_request", b'{"state":"releasing","x":1,"x":1}\n')])

    def test_text_and_objects_beside_refused(self):
        """fails when: standard output that is not exactly one object is taken: a second object, text before or after
        it, an array or a scalar, nothing, text that is not JSON, JSON with a trailing comma, single quotes or a
        comment, and white space that JSON does not allow."""
        body = encode(ABSENT).strip()
        self.assert_no_answer([
            ("a second object", "describe_request", body + b"\n" + body + b"\n"),
            ("two objects joined", "describe_request", body + body),
            ("text before", "describe_request", b"adapter v1\n" + body + b"\n"),
            ("text after", "describe_request", body + b" done\n"),
            ("a character after", "describe_request", body + b"x"),
            ("an array of it", "describe_request", b"[" + body + b"]"),
            ("a string", "describe_request", b'"absent"'), ("null", "describe_request", b"null"),
            ("a number", "describe_request", b"0"), ("true", "describe_request", b"true"),
            ("nothing", "describe_request", b""), ("a blank line", "describe_request", b"\n"),
            ("not json", "describe_request", b"not json\n"), ("an open brace", "describe_request", b"{"),
            ("a trailing comma", "describe_request", b'{"state":"absent",}'),
            ("single quotes", "describe_request", b"{'state': 'absent'}"),
            ("a comment", "describe_request", body + b" // note\n"),
            ("a form feed first", "describe_request", b"\x0c" + body),
            ("a NUL first", "describe_request", b"\x00" + body)])

    def test_non_utf8_refused(self):
        """fails when: standard output that is not UTF-8 is taken: a byte that is not, in a string or after the
        object, a Latin-1 letter, a byte order mark, UTF-16."""
        failed = encode(FAILED)
        self.assert_no_answer([
            ("a byte in a string", "quote_request", b'{"state":"failed","reason":"x\xff"}\n'),
            ("a byte after the object", "quote_request", failed + b"\xff"),
            ("a Latin-1 letter", "quote_request", b'{"state":"failed","reason":"caf\xe9"}\n'),
            ("a lone continuation byte", "quote_request", b'{"state":"failed","reason":"\x80"}\n'),
            ("a byte order mark", "quote_request", b"\xef\xbb\xbf" + failed),
            ("UTF-16", "quote_request", failed.decode("ascii").encode("utf-16"))])

    def test_oversize_answer_refused(self):
        """fails when: an answer of more than 64 KiB is taken, or cut and read (a valid object followed by white space
        that passes the bound is refused whole), or an answer of exactly 64 KiB is refused."""
        body = encode(ABSENT)
        exact = body[:-1] + b" " * (65536 - len(body)) + b"\n"
        self.assertEqual(len(exact), 65536)
        cases = [self.make_case(output=exact)[0]]
        refused = [("one byte more", "describe_request", exact + b" "),
                   ("a valid object and a flood of spaces", "describe_request", body + b" " * 100000)]
        self.assertEqual(self.run_cases(cases), [answered(ABSENT)])
        self.assert_no_answer(refused)

    # 5. Standard error and the credential: the screens.

    def test_stderr_line_is_cut_and_clean(self):
        """fails when: what is shown of standard error is not its first non-empty line, stripped, cut to 300 characters,
        with each control character replaced by `?`; when more than that line is shown; when anything is shown for an
        adapter that answered; or when the line does not follow the judge's words and a colon."""
        lines = ((b"boom\n", "exit status 3: boom"),
                 (b"\n  \n   padded line  \nsecond line\n", "exit status 3: padded line"),
                 (b"x" * 500 + b"\n", "exit status 3: " + "x" * 300),
                 (b"a\x07b\x1bc\td\n", "exit status 3: a?b?c?d"),
                 (b"\n\n  \n", "exit status 3"), (b"", "exit status 3"))
        cases = [self.make_case(error=data, exit=3)[0] for data, _ in lines]
        cases.append(self.make_case(output=encode(ABSENT), error=b"a warning\n")[0])
        results = self.run_cases(cases)
        for (data, detail), result in zip(lines, results):
            with self.subTest(stderr=data[:40]):
                self.assertEqual(result, {"reason": "exit", "answer": None, "detail": detail})
        self.assertEqual(results[-1], answered(ABSENT))

    def test_stderr_shape_is_withheld(self):
        """fails when: a first line of standard error that looks like a credential is shown, whole or as a line that is
        longer than the 300 characters shown and begins its credential before the cut: the detector screens the line as
        written and as cut, with or without a credential variable named."""
        cases, secrets = [], []
        for make in (cloud_key_id, code_host_token, payment_key, glpat_token):
            secret = make()
            for line in ("boom " + secret, "x" * 289 + " " + secret):
                secrets.append(secret)
                cases.append(self.make_case(error=(line + "\n").encode("ascii"), exit=3)[0])
        for secret, result in zip(secrets, self.run_cases(cases)):
            with self.subTest(shape=secret[:6]):
                self.assertEqual(result, {"reason": "exit", "answer": None, "detail": "exit status 3: [withheld]"})
                self.assertNotIn(secret[:8], result["detail"])

    def test_stderr_value_is_withheld(self):
        """fails when: a first line of standard error that holds the value of the credential variable is shown, whole
        or begun before the 300th character (a build that searches only the text that is shown shows the beginning of a
        value that straddles the cut); when a value of 8 characters is not searched for, or one of 7 is (open point 18);
        or when the line is written to any file."""
        long_value = "k7Qm2xZp9LrT4vBn8Cd3"
        cases = (
            ("a value of 8 characters", "qwertyui", b"boom qwertyui here\n", "exit status 3: [withheld]", True),
            ("a value that straddles the cut", long_value, ("y" * 290 + long_value + "\n").encode("ascii"),
             "exit status 3: [withheld]", True),
            ("a value of 7 characters is not searched for", "qwertyu", b"boom qwertyu here\n",
             "exit status 3: boom qwertyu here", False),
            ("a later line is not shown", "qwertyui", b"fine\nqwertyui\n", "exit status 3: fine", False))
        for label, value, data, detail, withheld in cases:
            with self.subTest(case=label):
                case, _ = self.make_case(error=data, exit=3, credential_env=VARIABLE)
                (result,) = self.run_cases([case], environment=dict(self.environment, **{VARIABLE: value}))
                self.assertEqual(result, {"reason": "exit", "answer": None, "detail": detail})
                if withheld:
                    self.assertNotIn(value[:7], result["detail"])
        for directory in (self.state_home, self.home, self.user_home):
            self.assertEqual(list(directory.iterdir()), [], "a call left a file in " + directory.name)

    def test_answer_holding_value_refused(self):
        """fails when: an answer with a string member that holds the value of the credential variable, whole or inside a
        longer member, is taken (nothing of it is printed: no answer); when a value of 8 characters is not searched for,
        or one of 7 is; or when an answer that does not hold the value is refused because a variable is named."""
        cases = (
            ("8 characters in a reason", "qwertyui", "quote_request", dict(FAILED, reason="no-qwertyui"), False),
            ("8 characters in a provider id", "qwertyui", "acquire_request",
             dict(ACQUIRED, provider_id="vm-qwertyui-1"), False),
            ("8 characters in a provider state", "qwertyui", "describe_request",
             dict(RUNNING, provider_state="state-qwertyui"), False),
            ("8 characters in a request identifier", "qwertyui", "describe_request",
             dict(ABSENT, request="req-qwertyui"), False),
            ("8 characters in a size", "qwertyui", "quote_request", dict(QUOTED, size="size-qwertyui"), False),
            ("7 characters in a reason are not searched for", "qwertyu", "quote_request",
             dict(FAILED, reason="no-qwertyu"), True),
            ("7 characters in a provider id are not searched for", "qwertyu", "acquire_request",
             dict(ACQUIRED, provider_id="vm-qwertyu-1"), True),
            ("a value that is nowhere in the answer", "qwertyui", "describe_request", ABSENT, True))
        for label, value, form, answer, taken in cases:
            with self.subTest(case=label):
                case, _ = self.make_case(form=form, output=encode(answer), credential_env=VARIABLE)
                (result,) = self.run_cases([case], environment=dict(self.environment, **{VARIABLE: value}))
                self.assertEqual(result, answered(answer) if taken else NO_ANSWER)
                if not taken:
                    self.assertNotIn(value, json.dumps(result))

    def test_answer_shape_refused(self):
        """fails when: an answer with a string member that the credential detector refuses is taken, for a member whose
        grammar lets such a value through (a provider id, a provider state, a size, a region, a reason, a request
        identifier), with or without a credential variable named."""
        items = []
        for member, form, answer, make in (("provider_id", "acquire_request", ACQUIRED, cloud_key_id),
                                           ("provider_state", "describe_request", RUNNING, cloud_key_id),
                                           ("size", "quote_request", QUOTED, cloud_key_id),
                                           ("region", "quote_request", QUOTED, glpat_token),
                                           ("reason", "quote_request", FAILED, glpat_letters),
                                           ("request", "describe_request", ABSENT, cloud_key_id)):
            items.append((member, form, dict(answer, **{member: make()})))
        self.assert_no_answer(items)
        self.assert_no_answer(items, environment=dict(self.environment, **{VARIABLE: VALUE}), credential_env=VARIABLE)
