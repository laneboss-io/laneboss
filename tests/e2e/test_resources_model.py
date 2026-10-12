"""A. The resource model (docs/architecture.md, "Resources and cost": "The resource model", "Events" and "The test
plan"): the five resource.* kinds are checked at append whoever appends them, they fold into one record for each
resource, and a stored event that no rule covers is an integrity problem.

Hand-written events go through `event append`, the launcher's interface for them. A refusal is shown by the store being
unchanged afterwards and an acceptance by what `state events` prints. A store that `append` would not let a wrong event
into is made with sqlite3, as test_store and test_mail make theirs. The fold, held_of() and standing() have no command
of their own yet, so the installed package is called in a separate process, as test_judges calls judges.ask(). Every
expected value is a literal of the design text; nothing is read from the code under test.
"""

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
import uuid

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


LANE = "res-lane"
OTHER = "res-other"
EMPTY = "res-empty"
START = "2026-10-08T08:00:00.000000Z"
END = "2026-10-08T08:20:30.500000Z"
RECORDED = "2026-10-08T12:00:00.000000Z"
PRICE = {"per_hour": {"amount_micros": 500000, "currency": "USD"}, "source": "adapter"}
# The first worked case of "Cost": half a unit an hour from 08:00:00.000000 to 08:20:30.500000 is 170,903 micro-units.
COST = {"amount_micros": 170903, "currency": "USD"}
READ_BACK = {"at": "2026-10-08T08:21:00Z", "state": "terminated", "provider_state": "terminated", "ended_at": END,
             "request": None}
RUNNING = {"running": True, "run": 1}
ENDED = {"running": False, "run": 1}
NO_ADAPTERS = {}
ADAPTER = {"resources": {"example-cloud": {"acquire_bound_minutes": 30}}}
ADAPTER_BY_DEFAULT = {"resources": {"example-cloud": {}}}
ADAPTER_FOR_LONG = {"resources": {"example-cloud": {"acquire_bound_minutes": 1440}}}
ANOTHER_ADAPTER = {"resources": {"another-cloud": {"acquire_bound_minutes": 30}}}
RAW = re.compile(r'\{"\$raw": "([^"]*)"\}')

# Calls the installed package's fold, held_of and standing on events that `state events` printed. None of them has a
# command yet, so this is the nearest a black-box test comes to them.
PROBE = r"""
import json
import sys
import types

sys.path.insert(0, sys.argv[1])
from laneboss import resources

with open(sys.argv[2], encoding="utf-8") as handle:
    request = json.load(handle)
records = resources.fold(request["events"])
answer = {"records": {}, "standing": []}
for name, record in records.items():
    answer["records"][name] = {"state": record["state"], "held": resources.held_of(record)}
for item in request["queries"]:
    configuration = types.SimpleNamespace(data=item["data"])
    answer["standing"].append(resources.standing(records[item["resource"]], item["row"], configuration, item["clock"]))
print(json.dumps(answer))
"""


def rid(number):
    """A resource id: rs- and 24 lower-case hexadecimal digits."""
    return "rs-{:024x}".format(number)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def raw(text):
    """A number as the JSON text it is written in (1e3), which json.dumps cannot print for a float; see spelled()."""
    return {"$raw": text}


def spelled(value):
    """The event as JSON text, with each raw() put in as the text it holds."""
    return RAW.sub(r"\1", json.dumps(value, ensure_ascii=False))


def shifted(text, minutes=0, microseconds=0):
    """A UTC timestamp moved by some minutes and microseconds, written as the store writes recorded_at."""
    moment = datetime.fromisoformat(text[:-1] + "+00:00") + timedelta(minutes=minutes, microseconds=microseconds)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def without(value, *names):
    return {key: item for key, item in value.items() if key not in names}


def item(name, state):
    return {"resource": name, "state": state}


def intent(resource, **changes):
    """A resource.intent payload as the design's table gives it; `changes` replace members."""
    value = {"resource": resource, "run": 1, "kind": "machine", "provider": "example-cloud",
             "purpose": "example-tests", "size": "example.small", "region": "region-one", "price": PRICE,
             "hard_cap_minutes": 240}
    value.update(changes)
    return value


def acquired(resource, **changes):
    value = {"resource": resource, "provider_id": "i-0123456789abcdef0", "found_by": "acquire", "started_at": START,
             "request": None}
    value.update(changes)
    return value


def failed(resource, **changes):
    value = {"resource": resource, "how": "adapter", "reason": "no-capacity", "request": None}
    value.update(changes)
    return value


def released(resource, **changes):
    value = {"resource": resource, "how": "release", "read_back": dict(READ_BACK)}
    value.update(changes)
    return value


def costed(resource, **changes):
    value = {"resource": resource, "started_at": START, "ended_at": END, "price": PRICE, "cost": COST}
    value.update(changes)
    return value


def gone(base, *names):
    """One case (label, member, payload) for each member that is left out."""
    return [("{} is absent".format(name), None, without(base, name)) for name in names]


def each(base, member, values):
    """One case (label, member, payload) for each value that `member` must not take."""
    return [("{} is {}".format(member, repr(value)[:40]), member, dict(base, **{member: value})) for value in values]


class ResourceModelTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.write_config("alpha")
        self.cache = {}

    def where(self, config="alpha"):
        if config not in self.cache:
            self.cache[config] = self.laneboss_json("config", "path", config)
        return self.cache[config]

    def put(self, kind, lane, payload, occurred_at="2026-10-08T10:00:00Z", code=0, config="alpha", **fields):
        """Append one event by hand through `event append`; a lane of None leaves the member out."""
        value = self.event(kind, lane=lane, occurred_at=occurred_at, payload=payload, **fields)
        path = self.directory / "event-{}.json".format(uuid.uuid4().hex)
        path.write_text(spelled(value), encoding="utf-8")
        return self.run_laneboss("event", "append", "--config", config, "--file", path, code=code)

    def accept(self, kind, lane, payload, config="alpha", **options):
        """An event that must be stored: `state events` shows it, once, with the payload it was given."""
        before = self.events(config)
        result = json.loads(self.put(kind, lane, payload, config=config, **options).stdout)
        after = self.events(config)
        self.assertEqual(len(after), len(before) + 1, "the event was not stored")
        self.assertEqual(after[:-1], before)
        last = after[-1]
        self.assertEqual((last["id"], last["seq"], last["kind"], last["lane"], last["payload"]),
                         (result["id"], result["seq"], kind, lane, payload))
        self.assertIs(result["duplicate"], False)
        return last

    def refuse(self, kind, lane, payload, config="alpha", **options):
        """An event that must be refused (exit 2), and the store is the same afterwards."""
        before = self.events(config)
        result = self.put(kind, lane, payload, code=2, config=config, **options)
        self.assertEqual(self.events(config), before, "a refused event changed the store")
        return result

    def refuse_all(self, kind, cases, lane=LANE, config="alpha"):
        """Every case (label, member, payload) is refused with exit 2 and names its member, and the store is the same
        after all of them."""
        before = self.events(config)
        for label, member, payload in cases:
            with self.subTest(kind=kind, case=label):
                result = self.put(kind, lane, payload, code=2, config=config)
                self.assertTrue(result.stderr.startswith("refused:"), result.stderr)
                self.assertIn("payload" + ("." + member if member else ""), result.stderr)
        self.assertEqual(self.events(config), before, "a refused event changed the store")

    def start_lane(self, lane=LANE, run=1, config="alpha"):
        how = "start" if run == 1 else "resume"
        payload = support.started_payload(self.where(config), lane=lane, run=run, how=how)
        return self.put("lane.started", lane, payload, occurred_at="2026-10-08T07:{:02d}:00Z".format(run),
                        config=config)

    def end_lane(self, lane=LANE, run=1, config="alpha"):
        return self.put("lane.ended", lane, support.ended_payload(run=run), occurred_at="2026-10-08T07:30:00Z",
                        config=config)

    def mark(self, state, lane=LANE, config="alpha", code=0, **extra):
        return self.put("lane.state", lane, dict({"state": state}, **extra), code=code, config=config)

    def bring(self, number, state, lane=LANE, config="alpha", intent_at="2026-10-08T07:59:00Z", price=PRICE,
              started_at=START, read_back=None, **members):
        """Append the events that take resource `number` to `state` (intent, acquired, failed or released)."""
        name = rid(number)
        self.put("resource.intent", lane, intent(name, price=price, **members), occurred_at=intent_at, config=config)
        if state == "failed":
            self.put("resource.failed", lane, failed(name), occurred_at="2026-10-08T08:00:05Z", config=config)
        if state in ("acquired", "released"):
            self.put("resource.acquired", lane, acquired(name, started_at=started_at),
                     occurred_at="2026-10-08T08:00:05Z", config=config)
        if state == "released":
            self.put("resource.released", lane, released(name, read_back=read_back or dict(READ_BACK)),
                     occurred_at="2026-10-08T08:21:00Z", config=config)
        return name

    def insert(self, rows, config="alpha"):
        """Put events into the store behind the launcher's back, as test_mail does, and return their seq numbers. A
        row is (kind, lane, payload) or (kind, lane, payload, protocol_version); the hash is the one the store makes."""
        seqs = []
        with closing(sqlite3.connect(self.where(config)["store"])) as connection:
            seq = connection.execute("SELECT max(seq) FROM events").fetchone()[0]
            for row in rows:
                kind, lane, payload = row[:3]
                version = row[3] if len(row) > 3 else "1.2.0"
                seq += 1
                event = {"id": "ev-hand-{}".format(seq), "kind": kind, "lane": lane, "actor": "e2e",
                         "occurred_at": "2026-10-08T11:00:00Z", "payload": payload, "protocol_version": version,
                         "recorded_at": RECORDED, "seq": seq}
                digest = hashlib.sha256(canonical(event).encode("utf-8")).hexdigest()
                connection.execute(
                    "INSERT INTO events (seq, id, kind, lane, actor, occurred_at, payload, protocol_version, "
                    "recorded_at, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (seq, event["id"], kind, lane, "e2e", event["occurred_at"], canonical(payload), version, RECORDED,
                     digest))
                seqs.append(seq)
            connection.commit()
        return seqs

    def library(self):
        found = sorted((support._installation.prefix / "share" / support.PROGRAM / "versions").glob("*/lib"))
        self.assertEqual(len(found), 1)
        return found[0]

    def probe(self, queries=(), config="alpha"):
        """The installed package's answer about the stored events: each record's state and held, and the reasons
        standing() gives for each query (resource, clock, row, data)."""
        request = {"events": self.events(config), "queries": [
            {"resource": name, "clock": clock, "row": row, "data": data} for name, clock, row, data in queries]}
        path = self.directory / "probe-{}.json".format(uuid.uuid4().hex)
        path.write_text(json.dumps(request), encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", PROBE, str(self.library()), str(path)],
                                cwd=str(self.directory), env=self.environment, capture_output=True, text=True,
                                encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def stand(self, queries, config="alpha"):
        return self.probe(queries, config)["standing"]

    def lane_row(self, lane=LANE, config="alpha"):
        rows = [row for row in self.laneboss_json("state", "lanes", "--config", config) if row["lane"] == lane]
        self.assertEqual(len(rows), 1)
        return rows[0]

    def assertNamesSeq(self, result, seq):
        self.assertTrue(result.stderr.startswith("integrity problem:"), result.stderr)
        self.assertRegex(result.stderr, r"\bseq {}\b".format(seq))

    def held_world(self):
        """LANE holds A (acquired) and B (intent) and has C released and D failed; OTHER holds E; EMPTY holds none."""
        for lane in (LANE, OTHER, EMPTY):
            self.start_lane(lane)
        first = self.bring(1, "acquired")
        second = self.bring(2, "intent")
        self.bring(3, "released")
        self.bring(4, "failed")
        third = self.bring(5, "intent", lane=OTHER)
        return first, second, third

    # 1. The id.

    def test_id_grammar(self):
        """fails when: the grammar of a resource id (rs- and 24 lower-case hex digits) is not enforced: a build that
        takes 23 or 25 digits, upper-case hex, no prefix or another one, a character outside 0-9a-f, a trailing newline
        (a pattern that ends in $ and is not matched whole), a number or null, in resource.intent or in any other
        kind."""
        self.start_lane()
        good = "rs-0123456789abcdef01234567"
        self.accept("resource.intent", LANE, intent(good))
        wrong = [("23 digits", good[:-1]), ("25 digits", good + "8"), ("upper-case hex", "rs-0123456789ABCDEF01234567"),
                 ("one upper-case digit", "rs-0123456789abcdeF01234567"), ("no prefix", good[3:]),
                 ("prefix rf-", "rf-" + good[3:]), ("prefix rs_", "rs_" + good[3:]), ("prefix RS-", "RS-" + good[3:]),
                 ("a character outside 0-9a-f", good[:-1] + "g"), ("a trailing newline", good + "\n"),
                 ("a leading space", " " + good), ("empty", ""), ("a number", 5), ("null", None)]
        self.refuse_all("resource.intent", [(label, "resource", intent(value)) for label, value in wrong])
        for kind, build in (("resource.acquired", acquired), ("resource.failed", failed),
                            ("resource.released", released), ("resource.cost", costed)):
            self.refuse_all(kind, [(label, "resource", build(value)) for label, value in wrong])
        self.accept("resource.intent", LANE, intent("rs-fedcba9876543210fedcba98"))

    # 2. Each payload form.

    def test_intent_members(self):
        """fails when: a member of resource.intent is not held to its form or bound (absent, a string for a number, a
        fraction, an exponent, true, null where it is not allowed, one past an edge, a character outside its grammar),
        or the payload may carry a member the design does not name, or an edge the design gives is not the edge: kind,
        provider and region 32 characters, purpose and size 64, a cap of 1 to 10080 minutes."""
        self.start_lane()
        self.accept("resource.intent", LANE, intent(rid(1)))
        self.accept("resource.intent", LANE, intent(rid(2), size=None, region=None, price=None))
        self.accept("resource.intent", LANE, intent(
            rid(3), kind="a" + "b" * 31, provider="a" + "b" * 31, purpose="A" + "b" * 63, size="A" + "b" * 63,
            region="a" + "b" * 31, hard_cap_minutes=10080,
            price={"per_hour": {"amount_micros": 9007199254740991, "currency": "ZZZ"}, "source": "configured"}))
        self.accept("resource.intent", LANE, intent(
            rid(4), kind="a", provider="0", purpose="0", size="0", region="0", hard_cap_minutes=1,
            price={"per_hour": {"amount_micros": 0, "currency": "AAA"}, "source": "adapter"}))
        base = intent(rid(9))
        money = {"amount_micros": 500000, "currency": "USD"}
        cases = gone(base, "resource", "run", "kind", "provider", "purpose", "size", "region", "price",
                     "hard_cap_minutes")
        cases += each(base, "run", ["1", 1.5, raw("1e0"), True, None, 0, -1, 1000001])
        cases += each(base, "kind", [None, 5, ["machine"], "", "Machine", "9machine", "machine!", "m" * 33])
        cases += each(base, "provider", [None, 5, "", "Example", "-cloud", "cloud_one", "c" * 33])
        cases += each(base, "purpose", [None, 5, "", "two words", "-tests", "p" * 65])
        cases += each(base, "size", [5, True, "", "two words", "s" * 65])
        cases += each(base, "region", [5, "", "Region-one", "region_one", "-r", "r" * 33])
        cases += each(base, "hard_cap_minutes", ["240", 240.5, raw("2.4e2"), True, None, 0, -1, 10081])
        cases += [
            ("price is a string", "price", dict(base, price="free")),
            ("price lacks source", "price", dict(base, price={"per_hour": money})),
            ("price lacks per_hour", "price", dict(base, price={"source": "adapter"})),
            ("price has a member more", "price", dict(base, price=dict(PRICE, note=1))),
            ("source is another word", "price.source", dict(base, price=dict(PRICE, source="other"))),
            ("source is null", "price.source", dict(base, price=dict(PRICE, source=None))),
            ("per_hour is a number", "price.per_hour", dict(base, price=dict(PRICE, per_hour=5))),
            ("per_hour lacks currency", "price.per_hour", dict(base, price=dict(PRICE, per_hour={"amount_micros": 5}))),
            ("per_hour lacks amount_micros", "price.per_hour",
             dict(base, price=dict(PRICE, per_hour={"currency": "USD"}))),
            ("per_hour has a member more", "price.per_hour",
             dict(base, price=dict(PRICE, per_hour=dict(money, note=1)))),
            ("a member the design does not name", None, dict(base, note="x")),
        ]
        self.refuse_all("resource.intent", cases)
        self.accept("resource.intent", LANE, base)

    def test_run_form_bounds(self):
        """fails when: the run of an intent is not a whole number from 1 to 1000000 in its form. The lane's row is
        changed (deliberate tampering, as test_integrity does) so that the lane has run 2000000: otherwise the rule that
        the run is one of the lane's hides the upper edge, and a build that takes 1000001 would pass."""
        self.start_lane()
        with closing(sqlite3.connect(self.where()["store"])) as connection:
            projection = json.loads(connection.execute(
                "SELECT projection FROM lanes WHERE lane = ?", (LANE,)).fetchone()[0])
            projection["run"] = 2000000
            connection.execute("UPDATE lanes SET projection = ? WHERE lane = ?", (canonical(projection), LANE))
            connection.commit()
        self.accept("resource.intent", LANE, intent(rid(1), run=1000000))
        self.accept("resource.intent", LANE, intent(rid(2), run=1))
        self.refuse_all("resource.intent", each(intent(rid(3)), "run", [1000001, 2000000, 0, -1]))

    def test_acquired_members(self):
        """fails when: a member of resource.acquired is not held to its form or bound (provider_id up to 192 characters
        and no more, found_by acquire or describe, started_at and request null or a timestamp and an identifier), or
        the payload may carry a member the design does not name."""
        self.start_lane()
        for number in (1, 2, 3, 4):
            self.bring(number, "intent")
        self.accept("resource.acquired", LANE, acquired(rid(1)))
        self.accept("resource.acquired", LANE, acquired(
            rid(2), found_by="describe", started_at=None, request="r" * 128, provider_id="vol-1/a+b:c.d"))
        self.accept("resource.acquired", LANE, acquired(rid(4), provider_id="i" + "0" * 191, request="a.b_c:d-e"))
        base = acquired(rid(3))
        cases = gone(base, "resource", "provider_id", "found_by", "started_at", "request")
        cases += each(base, "provider_id", [None, 5, "", "-i-1", "i 1", "i@1", "i#1", "i" + "0" * 192])
        cases += each(base, "found_by", [None, 1, "", "other", "Acquire", "acquire "])
        cases += each(base, "started_at", ["noon", 5, True, "2026-10-08 08:00:00", "2026-10-08T08:00:00",
                                           "2026-13-08T08:00:00Z", "2026-10-08T08:00:00.5Z"])
        cases += each(base, "request", [5, True, "", "a b", "a/b", "a+b", "r" * 129])
        cases.append(("a member the design does not name", None, dict(base, note="x")))
        self.refuse_all("resource.acquired", cases)
        self.accept("resource.acquired", LANE, base)

    def test_failed_members(self):
        """fails when: a member of resource.failed is not held to its form or bound (how adapter or release, reason a
        lower-case code of 1 to 40 letters and hyphens, request null or an identifier), or the payload may carry a
        member the design does not name."""
        self.start_lane()
        for number in (1, 2, 3, 4):
            self.bring(number, "intent")
        self.accept("resource.failed", LANE, failed(rid(1)))
        self.accept("resource.failed", LANE, failed(rid(2), how="release", reason="absent", request="req-2"))
        self.accept("resource.failed", LANE, failed(rid(4), reason="a" * 40))
        base = failed(rid(3))
        cases = gone(base, "resource", "how", "reason", "request")
        cases += each(base, "how", [None, 1, "", "other", "Adapter", "by-itself", "observed"])
        cases += each(base, "reason", [None, 1, "", "Capacity", "no capacity", "1abc", "-abc", "no_capacity", "a" * 41])
        cases += each(base, "request", [5, True, "", "a b", "a/b", "r" * 129])
        cases.append(("a member the design does not name", None, dict(base, note="x")))
        self.refuse_all("resource.failed", cases)
        self.accept("resource.failed", LANE, base)

    def test_released_members(self):
        """fails when: a member of resource.released is not held to its form or bound (how release, by-itself or
        observed; a read_back of exactly at, state, provider_state, ended_at and request, whose state is exactly
        terminated), or the payload or the read_back may carry a member the design does not name."""
        self.start_lane()
        for number in (1, 2, 3, 4):
            self.bring(number, "acquired")
        self.accept("resource.released", LANE, released(rid(1)))
        self.accept("resource.released", LANE, released(rid(2), how="by-itself", read_back=dict(
            READ_BACK, ended_at=None, request="req-3", provider_state="shutting-down")))
        self.accept("resource.released", LANE, released(rid(4), how="observed", read_back=dict(
            READ_BACK, at="2026-10-08T08:21:00.123Z", provider_state="p" * 128)))
        base = released(rid(3))

        def inside(member, values):
            return [("read_back.{} is {}".format(member, repr(value)[:40]), "read_back." + member,
                     dict(base, read_back=dict(READ_BACK, **{member: value}))) for value in values]

        cases = gone(base, "resource", "how", "read_back")
        cases += each(base, "how", [None, 1, "", "other", "Release", "by itself", "adapter"])
        cases += each(base, "read_back", [None, "terminated", 5, [], {}])
        cases += [("read_back lacks " + member, "read_back", dict(base, read_back=without(READ_BACK, member)))
                  for member in READ_BACK]
        cases.append(("read_back has a member more", "read_back", dict(base, read_back=dict(READ_BACK, note=1))))
        cases += inside("at", [None, 5, "", "soon", "2026-10-08T08:21:00"])
        cases += inside("state", [None, 5, "", "running", "Terminated", "terminating", "absent", "released",
                                  "pending", "stopping", "stopped", "shutting-down", "releasing", "unknown"])
        cases += inside("provider_state", [None, 5, "", "has space", "a/b", "a+b", "p" * 129])
        cases += inside("ended_at", [5, True, "", "later", "2026-10-08T08:20:30"])
        cases += inside("request", [5, True, "", "a b", "a/b", "r" * 129])
        cases.append(("a member the design does not name", None, dict(base, note="x")))
        self.refuse_all("resource.released", cases)
        self.accept("resource.released", LANE, base)

    def test_cost_members(self):
        """fails when: a member of resource.cost is not held to its form (the times are timestamps and never null; the
        price is the intent's form; the cost is money or null), or a cost is given without a price or a price without
        a cost, or in another currency than the price, or the payload may carry a member the design does not name."""
        self.start_lane()
        self.bring(1, "released")
        self.bring(2, "released", price=None)
        self.bring(3, "released")
        self.accept("resource.cost", LANE, costed(rid(1)))
        self.accept("resource.cost", LANE, costed(rid(2), price=None, cost=None))
        base = costed(rid(3))
        cases = gone(base, "resource", "started_at", "ended_at", "price", "cost")
        cases += each(base, "started_at", [None, 5, True, "", "noon", "2026-10-08T08:00:00"])
        cases += each(base, "ended_at", [None, 5, True, "", "noon", "2026-10-08T08:20:30"])
        cases += each(base, "price", ["free", 5, {"source": "adapter"}, dict(PRICE, note=1)])
        cases += each(base, "cost", ["170903", 170903, [], {"amount_micros": 170903}, dict(COST, note=1)])
        cases += [
            ("a cost without a price", "cost", dict(base, price=None)),
            ("a price without a cost", "cost", dict(base, cost=None)),
            ("a cost in another currency than the price", "cost",
             dict(base, cost={"amount_micros": 170903, "currency": "EUR"})),
            ("a member the design does not name", None, dict(base, note="x")),
        ]
        self.refuse_all("resource.cost", cases)
        self.accept("resource.cost", LANE, base)

    # 3. Money.

    def test_money_is_whole_micro_units(self):
        """fails when: money is accepted in a form the design forbids: a float (1.0, 0.5), an exponent (1e3), true, a
        string, a negative value or one above 9007199254740991, or a currency that is not three capital letters, in the
        price of an intent or in the cost; or the edges 0 and 9007199254740991 are not taken."""
        self.start_lane()
        edge = {"per_hour": {"amount_micros": 9007199254740991, "currency": "USD"}, "source": "configured"}
        self.accept("resource.intent", LANE, intent(rid(1), price={
            "per_hour": {"amount_micros": 0, "currency": "USD"}, "source": "configured"}))
        stored = self.accept("resource.intent", LANE, intent(rid(2), price=edge))
        self.assertIs(type(stored["payload"]["price"]["per_hour"]["amount_micros"]), int)
        self.assertEqual(stored["payload"]["price"]["per_hour"]["amount_micros"], 9007199254740991)
        base = intent(rid(3))

        def priced(amount, currency="USD"):
            return dict(base, price={"per_hour": {"amount_micros": amount, "currency": currency}, "source": "adapter"})

        cases = [("amount_micros is {}".format(repr(value)[:30]), "price.per_hour.amount_micros", priced(value))
                 for value in (1.0, 0.5, 1.5, raw("1e3"), raw("1E3"), True, False, "1000000", "", None, -1,
                               9007199254740992, [1])]
        cases += [("currency is {}".format(repr(value)[:30]), "price.per_hour.currency", priced(5, value))
                  for value in ("usd", "Usd", "US", "USDD", "U1D", "", 840, None, True)]
        self.refuse_all("resource.intent", cases)
        self.accept("resource.intent", LANE, base)
        self.bring(4, "released")
        good = costed(rid(4))
        cases = [("amount_micros of the cost is {}".format(repr(value)[:30]), "cost.amount_micros",
                  dict(good, cost={"amount_micros": value, "currency": "USD"}))
                 for value in (170903.0, raw("170903.0"), raw("1.70903e5"), True, "170903", -1, 9007199254740992)]
        cases += [("currency of the cost is {}".format(repr(value)[:30]), "cost.currency",
                   dict(good, cost={"amount_micros": 170903, "currency": value})) for value in ("usd", "US", 840, None)]
        self.refuse_all("resource.cost", cases)
        self.accept("resource.cost", LANE, good)

    # 4. The kinds.

    def test_unknown_resource_kinds(self):
        """fails when: a kind that starts with resource. and is not one of the five is stored, whatever payload it
        carries; or the check is made on a kind that merely resembles it (resources.intent, resource_x.intent), which
        is an ordinary kind and is stored; or one of the five is not stored when its payload fits."""
        self.start_lane()
        first, second = rid(1), rid(2)
        steps = [("resource.intent", intent(first), ["resource.intents", "resource.intent.v2", "resource.entry",
                                                     "resource.x"]),
                 ("resource.acquired", acquired(first), ["resource.acquire", "resource.acquireds"]),
                 ("resource.released", released(first), ["resource.release", "resource.release.done"]),
                 ("resource.cost", costed(first), ["resource.costs", "resource.cost2"])]
        for kind, payload, others in steps:
            before = self.events()
            for other in others:
                with self.subTest(kind=other):
                    result = self.put(other, LANE, payload, code=2)
                    self.assertIn("kind", result.stderr)
            self.assertEqual(self.events(), before, "an unknown resource kind was stored")
            self.accept(kind, LANE, payload)
        self.accept("resource.intent", LANE, intent(second))
        before = self.events()
        for other in ("resource.fail", "resource.failures"):
            with self.subTest(kind=other):
                self.put(other, LANE, failed(second), code=2)
        self.assertEqual(self.events(), before, "an unknown resource kind was stored")
        self.accept("resource.failed", LANE, failed(second))
        self.accept("resources.intent", LANE, {"anything": 1})
        self.accept("resource_x.intent", None, {})

    # 5. The lane.

    def test_lane_binding(self):
        """fails when: a resource event can belong to no lane or to two: a build that stores one without a lane, for a
        lane that has no lane event, or that lets an id be used with a lane other than the lane of its intent
        (an intent with an id that is stored, an acquired, failed, released or cost for another lane)."""
        self.start_lane(LANE)
        self.start_lane(OTHER)
        ghost = "res-ghost"
        self.bring(2, "intent")
        self.bring(3, "intent")
        self.bring(4, "acquired")
        self.bring(5, "released")
        # Each of these is stored when it has the lane of its resource: they are refused below only for their lane.
        # An intent with an unused id is stored for OTHER too, so its id is tried for OTHER once it is used.
        steps = [("resource.intent", intent(rid(1)), (None, ghost)),
                 ("resource.acquired", acquired(rid(3)), (None, ghost, OTHER)),
                 ("resource.failed", failed(rid(2)), (None, ghost, OTHER)),
                 ("resource.released", released(rid(4)), (None, ghost, OTHER)),
                 ("resource.cost", costed(rid(5)), (None, ghost, OTHER))]
        for kind, payload, lanes in steps:
            for lane in lanes:
                with self.subTest(kind=kind, lane=lane):
                    self.refuse(kind, lane, payload)
        for kind, payload, _ in steps:
            self.accept(kind, LANE, payload)
        self.refuse("resource.intent", OTHER, intent(rid(1)))
        self.assertEqual([row["lane"] for row in self.laneboss_json("state", "lanes", "--config", "alpha")],
                         [LANE, OTHER])

    # 6. The order of the five kinds.

    def test_intent_is_used_once(self):
        """fails when: a second resource.intent for an id is stored, whatever its payload, whatever became of the
        first (a build that forgets an id once its resource has failed or been released) and whatever lane it names."""
        self.start_lane()
        self.start_lane(EMPTY)
        name = rid(1)
        self.accept("resource.intent", LANE, intent(name))
        self.refuse("resource.intent", LANE, intent(name))
        self.refuse("resource.intent", LANE, intent(name, purpose="other-tests", hard_cap_minutes=5))
        self.accept("resource.intent", LANE, intent(rid(2)))
        self.accept("resource.failed", LANE, failed(name))
        self.refuse("resource.intent", LANE, intent(name))
        done = self.bring(3, "released")
        self.refuse("resource.intent", LANE, intent(done))
        self.refuse("resource.intent", EMPTY, intent(done))
        self.accept("resource.intent", EMPTY, intent(rid(4)))

    def test_acquired_follows_an_intent(self):
        """fails when: resource.acquired is stored without an intent, twice for one intent, or after the resource has
        failed or been released."""
        self.start_lane()
        self.refuse("resource.acquired", LANE, acquired(rid(1)))
        self.bring(1, "intent")
        self.accept("resource.acquired", LANE, acquired(rid(1)))
        self.refuse("resource.acquired", LANE, acquired(rid(1)))
        self.refuse("resource.acquired", LANE, acquired(rid(1), provider_id="i-other", found_by="describe"))
        self.bring(2, "failed")
        self.refuse("resource.acquired", LANE, acquired(rid(2)))
        self.bring(3, "released")
        self.refuse("resource.acquired", LANE, acquired(rid(3)))
        self.bring(4, "intent")
        self.accept("resource.acquired", LANE, acquired(rid(4)))

    def test_failed_follows_an_intent(self):
        """fails when: resource.failed is stored without an intent, after the resource has been acquired or released,
        or twice."""
        self.start_lane()
        self.refuse("resource.failed", LANE, failed(rid(1)))
        self.bring(1, "acquired")
        self.refuse("resource.failed", LANE, failed(rid(1)))
        self.bring(2, "released")
        self.refuse("resource.failed", LANE, failed(rid(2)))
        self.bring(3, "intent")
        self.accept("resource.failed", LANE, failed(rid(3)))
        self.refuse("resource.failed", LANE, failed(rid(3)))
        self.refuse("resource.failed", LANE, failed(rid(3), how="release", reason="absent"))

    def test_released_follows_an_acquire(self):
        """fails when: resource.released is stored for a resource that was never acquired (an intent only, a failed
        one, an unknown id) or twice."""
        self.start_lane()
        self.refuse("resource.released", LANE, released(rid(1)))
        self.bring(1, "intent")
        self.refuse("resource.released", LANE, released(rid(1)))
        self.bring(2, "failed")
        self.refuse("resource.released", LANE, released(rid(2)))
        self.accept("resource.acquired", LANE, acquired(rid(1)))
        self.accept("resource.released", LANE, released(rid(1)))
        self.refuse("resource.released", LANE, released(rid(1)))
        self.refuse("resource.released", LANE, released(rid(1), how="observed"))

    def test_cost_follows_a_release(self):
        """fails when: resource.cost is stored before the release (for an intent, an acquired or a failed resource) or
        twice, or a second cost is let in when its payload differs."""
        self.start_lane()
        self.bring(1, "intent")
        self.bring(2, "acquired")
        self.bring(3, "failed")
        for number in (1, 2, 3):
            self.refuse("resource.cost", LANE, costed(rid(number)))
        self.accept("resource.released", LANE, released(rid(2)))
        self.accept("resource.cost", LANE, costed(rid(2)))
        self.refuse("resource.cost", LANE, costed(rid(2)))
        self.refuse("resource.cost", LANE, costed(rid(2), price=None, cost=None))

    def test_cost_agrees_with_the_fold(self):
        """fails when: resource.cost is stored with a price, started_at, ended_at or cost that is not what the fold
        gives (the intent's price, the start and the end that "Cost" derives, the amount of its arithmetic), or when
        started_at and ended_at are compared as instants and not as the text the fold gives."""
        self.start_lane()
        one = self.bring(1, "released")
        base = costed(one)
        dearer = {"per_hour": {"amount_micros": 500001, "currency": "USD"}, "source": "adapter"}
        euro = {"per_hour": {"amount_micros": 500000, "currency": "EUR"}, "source": "adapter"}
        cases = [
            ("price null and cost null", "price", dict(base, price=None, cost=None)),
            ("another price per hour", "price", dict(base, price=dearer)),
            ("another source", "price", dict(base, price=dict(PRICE, source="configured"))),
            ("another currency", "price", dict(base, price=euro, cost={"amount_micros": 170903, "currency": "EUR"})),
            ("started_at a second later", "started_at", dict(base, started_at="2026-10-08T08:00:01.000000Z")),
            ("started_at, the same instant in other text", "started_at", dict(base, started_at="2026-10-08T08:00:00Z")),
            ("started_at, the same instant at +08:00", "started_at",
             dict(base, started_at="2026-10-08T16:00:00+08:00")),
            ("ended_at a second later", "ended_at", dict(base, ended_at="2026-10-08T08:20:31.500000Z")),
            ("ended_at, the same instant in other text", "ended_at", dict(base, ended_at="2026-10-08T08:20:30.500Z")),
            ("cost one less", "cost", dict(base, cost=dict(COST, amount_micros=170902))),
            ("cost one more", "cost", dict(base, cost=dict(COST, amount_micros=170904))),
            ("cost zero", "cost", dict(base, cost=dict(COST, amount_micros=0))),
        ]
        self.refuse_all("resource.cost", cases)
        self.accept("resource.cost", LANE, base)
        two = self.bring(2, "released", price=None)
        self.refuse_all("resource.cost", [
            ("a price the intent did not have", "price", costed(two)),
            ("an amount without a price", "cost", costed(two, price=None))])
        self.accept("resource.cost", LANE, costed(two, price=None, cost=None))

    def test_cost_worked_cases(self):
        """fails when: the cost of a resource is not the exact product of the price and the held time rounded up to
        the next micro-unit, with integers: a build that truncates (170902 and 500), rounds to the nearest (500),
        adds one to the quotient (1000001), or computes in floats and stores the integer (5004002). The numbers are the
        worked cases of "Cost" and the first case of the test plan of step C."""
        self.start_lane()
        table = [("first", 500000, "2026-10-08T08:20:30.500000Z", 170903, (170902, 170904)),
                 ("second", 1800000, "2026-10-08T08:33:20.000000Z", 1000000, (999999, 1000001)),
                 ("third", 1000000, "2026-10-08T08:00:01.800900Z", 501, (500, 502)),
                 ("fourth", 7, "2108-04-27T01:25:42.857143Z", 5004003, (5004002, 5004004))]
        for number, (label, per_hour, ended_at, amount, wrong) in enumerate(table, 1):
            with self.subTest(label):
                price = {"per_hour": {"amount_micros": per_hour, "currency": "USD"}, "source": "configured"}
                name = self.bring(number, "released", price=price,
                                  read_back=dict(READ_BACK, ended_at=ended_at, at=ended_at))
                base = costed(name, price=price, ended_at=ended_at)
                self.refuse_all("resource.cost", [
                    ("{} micro-units".format(value), "cost",
                     dict(base, cost={"amount_micros": value, "currency": "USD"})) for value in wrong])
                self.accept("resource.cost", LANE, dict(base, cost={"amount_micros": amount, "currency": "USD"}))

    def test_cost_times(self):
        """fails when: the held time of a cost is not read as "Cost" reads it: the start is the provider's started_at
        and else the time of the intent; the end is the read_back's ended_at when it is not null and not before the
        start (as an instant, an offset counted), else the read_back's at, and when even that is before the start it
        is the start."""
        self.start_lane()
        plus8 = "2026-10-08T16:00:00+08:00"
        cases = [
            ("no start from the provider", {"intent_at": "2026-10-08T08:00:00Z", "started_at": None, "read_back": {},
                                            "start": "2026-10-08T08:00:00Z", "end": END, "amount": 170903,
                                            "wrong": {"started_at": "2026-10-08T08:00:05Z"}}),
            ("ended_at is null", {"read_back": {"ended_at": None, "at": END}, "start": START, "end": END,
                                  "amount": 170903, "wrong": {"ended_at": START}}),
            ("ended_at is before the start", {"read_back": {"ended_at": "2026-10-08T07:00:00Z", "at": END},
                                              "start": START, "end": END, "amount": 170903,
                                              "wrong": {"ended_at": "2026-10-08T07:00:00Z"}}),
            ("ended_at is later in text and earlier as an instant",
             {"read_back": {"ended_at": "2026-10-08T10:00:00+08:00", "at": END}, "start": START, "end": END,
              "amount": 170903, "wrong": {"ended_at": "2026-10-08T10:00:00+08:00"}}),
            ("ended_at and at are before the start",
             {"read_back": {"ended_at": "2026-10-08T07:00:00Z", "at": "2026-10-08T07:30:00Z"}, "start": START,
              "end": START, "amount": 0, "wrong": {"ended_at": "2026-10-08T07:30:00Z"}}),
            ("ended_at is the start's instant in other text",
             {"read_back": {"ended_at": "2026-10-08T08:00:00Z", "at": END}, "start": START,
              "end": "2026-10-08T08:00:00Z", "amount": 0, "wrong": {"ended_at": END}}),
            ("a start with an offset", {"started_at": plus8, "read_back": {}, "start": plus8, "end": END,
                                        "amount": 170903, "wrong": {"started_at": START}}),
        ]
        for number, (label, case) in enumerate(cases, 1):
            with self.subTest(label):
                name = self.bring(number, "released", intent_at=case.get("intent_at", "2026-10-08T07:59:00Z"),
                                  started_at=case.get("started_at", START),
                                  read_back=dict(READ_BACK, **case["read_back"]))
                good = costed(name, started_at=case["start"], ended_at=case["end"],
                              cost={"amount_micros": case["amount"], "currency": "USD"})
                wrong = dict(good, **case["wrong"])
                self.refuse_all("resource.cost", [("a wrong " + ", ".join(case["wrong"]), None, wrong)])
                self.accept("resource.cost", LANE, good)

    def test_intent_needs_a_run_of_the_lane(self):
        """fails when: a resource.intent is stored for a run the lane has not begun (run 2 while the lane is at run 1,
        run 3 while it is at run 2), or is refused for a run it has (an earlier one)."""
        self.start_lane()
        self.refuse("resource.intent", LANE, intent(rid(1), run=2))
        self.accept("resource.intent", LANE, intent(rid(1), run=1))
        self.end_lane()
        self.start_lane(run=2)
        self.accept("resource.intent", LANE, intent(rid(2), run=2))
        self.refuse("resource.intent", LANE, intent(rid(3), run=3))
        self.accept("resource.intent", LANE, intent(rid(3), run=1))
        self.mark("queued", lane=EMPTY)
        self.refuse("resource.intent", EMPTY, intent(rid(4), run=1))
        self.start_lane(EMPTY)
        self.accept("resource.intent", EMPTY, intent(rid(4), run=1))

    def test_closed_lane_takes_no_intent(self):
        """fails when: an intent is stored for a lane that is merged or abandoned, or is refused for a lane that is
        accepted; or the acquired, failed, released and cost of a resource that was due are refused because its lane
        was merged or abandoned meanwhile."""
        for lane in (LANE, OTHER, EMPTY):
            self.start_lane(lane)
        held = self.bring(1, "acquired")
        self.accept("lane.state", LANE, {"state": "merged", "held": [item(held, "acquired")]})
        self.refuse("resource.intent", LANE, intent(rid(2)))
        self.accept("resource.intent", EMPTY, intent(rid(2)))
        self.accept("resource.released", LANE, released(held))
        self.accept("resource.cost", LANE, costed(held))
        self.refuse("resource.intent", LANE, intent(rid(3)))
        pending = self.bring(4, "intent", lane=OTHER)
        late = self.bring(5, "intent", lane=OTHER)
        self.accept("lane.state", OTHER, {"state": "abandoned"})
        self.refuse("resource.intent", OTHER, intent(rid(3)))
        self.accept("resource.acquired", OTHER, acquired(pending))
        self.accept("resource.failed", OTHER, failed(late))
        self.accept("lane.state", EMPTY, {"state": "accepted", "held": [item(rid(2), "intent")]})
        self.accept("resource.intent", EMPTY, intent(rid(3)))

    def test_257th_held_resource(self):
        """fails when: a lane may hold a 257th resource (the bound of held in lane.state, so that every lane can be
        accepted), or the bound counts resources that are no longer held (failed ones), or a lane that holds 256 cannot
        be accepted with them listed in held."""
        self.start_lane()
        names = [rid(1000 + number) for number in range(256)]
        self.insert([("resource.intent", LANE, intent(name)) for name in names])
        self.assertIs(self.laneboss_json("state", "verify", "--config", "alpha")["ok"], True)
        self.refuse("resource.intent", LANE, intent(rid(5000)))
        self.accept("lane.state", LANE, {"state": "accepted", "held": [item(name, "intent") for name in names]})
        self.refuse("resource.intent", LANE, intent(rid(5000)))
        self.accept("resource.failed", LANE, failed(names[0]))
        self.accept("resource.intent", LANE, intent(rid(5000)))
        self.refuse("resource.intent", LANE, intent(rid(5001)))
        self.assertIs(self.laneboss_json("state", "verify", "--config", "alpha")["ok"], True)

    # 7. The fold.

    def test_fold_states(self):
        """fails when: the fold derives a state differently from the design (intent, acquired, failed, released; and a
        resource.cost leaves the state released), or writes a resource event into the lanes table."""
        self.start_lane()
        lanes_before = self.run_laneboss("state", "lanes", "--config", "alpha").stdout
        self.bring(1, "intent")
        self.bring(2, "acquired")
        self.bring(3, "failed")
        self.bring(4, "released")
        self.bring(5, "released")
        self.accept("resource.cost", LANE, costed(rid(5)))
        self.assertEqual(self.run_laneboss("state", "lanes", "--config", "alpha").stdout, lanes_before)
        found = self.probe()["records"]
        self.assertEqual({name: (record["state"], record["held"]) for name, record in found.items()},
                         {rid(1): ("intent", True), rid(2): ("acquired", True), rid(3): ("failed", False),
                          rid(4): ("released", False), rid(5): ("released", False)})
        self.assertIs(self.laneboss_json("state", "verify", "--config", "alpha")["ok"], True)

    def test_cap_runs_from_the_start(self):
        """fails when: start is not the provider's started_at and else the time of the intent (so that an intent whose
        provider gave no start has its cap run from the intent), or the intent's time is not its occurred_at and else
        its recorded_at, or cap_at is not start plus hard_cap_minutes, or times are compared as text and not as
        instants."""
        self.start_lane()
        at = "2026-10-08T09:00:00Z"
        self.bring(1, "acquired", intent_at=at, started_at="2026-10-08T09:10:00Z", hard_cap_minutes=60)
        self.bring(2, "acquired", intent_at=at, started_at=None, hard_cap_minutes=60)
        self.bring(3, "intent", intent_at=at, hard_cap_minutes=60)
        self.bring(4, "acquired", intent_at=at, started_at="2026-10-08T17:10:00+08:00", hard_cap_minutes=60)
        self.put("resource.intent", LANE, intent(rid(5), hard_cap_minutes=60), occurred_at=None)
        recorded = self.events()[-1]["recorded_at"]
        queries = [(rid(1), "2026-10-08T10:05:00Z"), (rid(1), "2026-10-08T10:10:00.000000Z"),
                   (rid(1), "2026-10-08T10:10:00.000001Z"), (rid(2), "2026-10-08T10:00:00.000000Z"),
                   (rid(2), "2026-10-08T10:00:00.000001Z"), (rid(2), "2026-10-08T10:05:00Z"),
                   (rid(3), "2026-10-08T10:00:00.000000Z"), (rid(3), "2026-10-08T10:00:00.000001Z"),
                   (rid(4), "2026-10-08T10:10:00.000000Z"), (rid(4), "2026-10-08T10:10:00.000001Z"),
                   (rid(5), shifted(recorded, minutes=60)), (rid(5), shifted(recorded, minutes=60, microseconds=1))]
        expected = [[], [], ["held-beyond-cap"], [], ["held-beyond-cap"], ["held-beyond-cap"], [],
                    ["held-beyond-cap"], [], ["held-beyond-cap"], [], ["held-beyond-cap"]]
        found = self.stand([(name, clock, RUNNING, ADAPTER_FOR_LONG) for name, clock in queries])
        for (name, clock), reasons, wanted in zip(queries, found, expected):
            with self.subTest(resource=name, clock=clock):
                self.assertEqual(reasons, wanted)

    # 8. Held and standing.

    def test_held_of(self):
        """fails when: held_of() is not the one definition: a resource whose state is intent or acquired is held, and
        one that is failed or released is not."""
        self.start_lane()
        self.bring(1, "intent")
        self.bring(2, "acquired")
        self.bring(3, "failed")
        self.bring(4, "released")
        found = self.probe()["records"]
        self.assertEqual({name: record["held"] for name, record in found.items()},
                         {rid(1): True, rid(2): True, rid(3): False, rid(4): False})

    def test_standing_lane_ended(self):
        """fails when: lane-ended is given while a run goes on, or after a lane resume for the resource of an earlier
        run, or when the lane's run is less than the resource's; or is not given once the run that held the resource and
        every run after it have ended."""
        self.start_lane()
        one = self.bring(1, "acquired")
        clock = "2026-10-08T10:00:00Z"
        self.assertEqual(self.stand([(one, clock, self.lane_row(), ADAPTER_FOR_LONG)]), [[]])
        self.end_lane()
        self.assertEqual(self.stand([(one, clock, self.lane_row(), ADAPTER_FOR_LONG)]), [["lane-ended"]])
        self.start_lane(run=2)
        two = self.bring(2, "acquired", run=2)
        self.assertEqual(self.stand([(one, clock, self.lane_row(), ADAPTER_FOR_LONG),
                                     (two, clock, self.lane_row(), ADAPTER_FOR_LONG)]), [[], []])
        self.end_lane(run=2)
        self.assertEqual(self.stand([(one, clock, self.lane_row(), ADAPTER_FOR_LONG),
                                     (two, clock, self.lane_row(), ADAPTER_FOR_LONG)]),
                         [["lane-ended"], ["lane-ended"]])
        self.assertEqual(self.stand([(one, clock, ENDED, ADAPTER_FOR_LONG), (two, clock, ENDED, ADAPTER_FOR_LONG)]),
                         [["lane-ended"], []])

    def test_standing_cap_and_bound(self):
        """fails when: held-beyond-cap is given at or before cap_at or not after it; or unresolved is not given for an
        intent once the clock is after its time plus the adapter's acquire_bound_minutes (15 when the configuration has
        no table for the provider, or the table has no such key), is given at the bound, is given for a resource that
        was acquired, or takes the bound of another provider."""
        self.start_lane()
        at = "2026-10-08T09:00:00Z"
        self.bring(1, "intent", intent_at=at)
        self.bring(2, "acquired", intent_at=at, started_at="2026-10-08T09:01:00Z")
        table = [
            (rid(1), "2026-10-08T09:30:00.000000Z", ADAPTER, []),
            (rid(1), "2026-10-08T09:30:00.000001Z", ADAPTER, ["unresolved"]),
            (rid(1), "2026-10-08T09:15:00.000000Z", ADAPTER_BY_DEFAULT, []),
            (rid(1), "2026-10-08T09:15:00.000001Z", ADAPTER_BY_DEFAULT, ["unresolved"]),
            (rid(1), "2026-10-08T09:15:00.000000Z", NO_ADAPTERS, ["adapter-missing"]),
            (rid(1), "2026-10-08T09:15:00.000001Z", NO_ADAPTERS, ["adapter-missing", "unresolved"]),
            (rid(1), "2026-10-08T09:20:00Z", ANOTHER_ADAPTER, ["adapter-missing", "unresolved"]),
            (rid(1), "2026-10-08T13:00:00.000001Z", ADAPTER, ["held-beyond-cap", "unresolved"]),
            (rid(2), "2026-10-08T09:45:00Z", ADAPTER, []),
            (rid(2), "2026-10-08T13:01:00.000000Z", ADAPTER, []),
            (rid(2), "2026-10-08T13:01:00.000001Z", ADAPTER, ["held-beyond-cap"]),
        ]
        found = self.stand([(name, clock, RUNNING, data) for name, clock, data, _ in table])
        for (name, clock, data, wanted), reasons in zip(table, found):
            with self.subTest(resource=name, clock=clock, data=data):
                self.assertEqual(reasons, wanted)

    def test_standing_adapter_missing(self):
        """fails when: adapter-missing is given although the configuration has the table for the provider, or is not
        given when it has none (no resources at all, an empty table, or the table of another provider)."""
        self.start_lane()
        self.bring(1, "acquired")
        clock = "2026-10-08T10:00:00Z"
        table = [(NO_ADAPTERS, ["adapter-missing"]), ({"resources": {}}, ["adapter-missing"]),
                 (ANOTHER_ADAPTER, ["adapter-missing"]), (ADAPTER, []), (ADAPTER_BY_DEFAULT, [])]
        found = self.stand([(rid(1), clock, RUNNING, data) for data, _ in table])
        for (data, wanted), reasons in zip(table, found):
            with self.subTest(data=data):
                self.assertEqual(reasons, wanted)

    def test_standing_is_for_held_resources(self):
        """fails when: a resource that is not held (failed or released) is given a reason that belongs to a held one
        (lane-ended, held-beyond-cap, unresolved, adapter-missing)."""
        self.start_lane()
        self.bring(1, "failed")
        self.bring(2, "released")
        found = self.stand([(rid(1), "2027-01-01T00:00:00Z", ENDED, NO_ADAPTERS),
                            (rid(2), "2027-01-01T00:00:00Z", ENDED, NO_ADAPTERS)])
        self.assertEqual(found, [[], []])

    # 9. The held key of lane.state.

    def test_held_lists_what_is_held(self):
        """fails when: a lane.state that accepts or merges is stored with a held that is not exactly the lane's held
        resources at that moment, or without a held although the lane holds one, or with one that follows an earlier
        reading of the fold (a resource failed or released since); or a held that is exact is refused."""
        first, second, third = self.held_world()
        exact = [item(first, "acquired"), item(second, "intent")]
        self.accept("lane.state", LANE, {"state": "accepted", "held": exact})
        self.accept("lane.state", LANE, {"state": "merged", "held": exact})
        self.accept("lane.state", EMPTY, {"state": "accepted"})
        self.accept("lane.state", OTHER, {"state": "merged", "held": [item(third, "intent")]})
        self.accept("resource.failed", LANE, failed(second))
        self.refuse("lane.state", LANE, {"state": "accepted", "held": exact})
        self.accept("lane.state", LANE, {"state": "accepted", "held": [item(first, "acquired")]})
        self.accept("resource.released", LANE, released(first))
        self.refuse("lane.state", LANE, {"state": "accepted", "held": [item(first, "acquired")]})
        self.refuse("lane.state", LANE, {"state": "merged", "held": exact})
        self.accept("lane.state", LANE, {"state": "accepted"})

    def test_held_refusals(self):
        """fails when: a lane.state that accepts or merges is stored with a held that lists too few, too many, a
        resource that is not held, a resource of another lane, a wrong state, an unsorted list, a repeat, an item of
        another form, more than 256 items or none, or with none while the lane holds some."""
        first, second, third = self.held_world()
        exact = [item(first, "acquired"), item(second, "intent")]
        cases = [
            ("none listed", None),
            ("too few", [exact[0]]),
            ("a released resource", exact + [item(rid(3), "acquired")]),
            ("a failed resource", exact + [item(rid(4), "intent")]),
            ("the resource of another lane", exact + [item(third, "intent")]),
            ("B as acquired", [exact[0], item(second, "acquired")]),
            ("A as intent", [item(first, "intent"), exact[1]]),
            ("a state that is not a fold state of a held resource", [item(first, "released"), exact[1]]),
            ("unsorted", list(reversed(exact))),
            ("a repeat first", [exact[0], exact[0], exact[1]]),
            ("a repeat last", [exact[0], exact[1], exact[1]]),
            ("an item with a member more", [dict(exact[0], note=1), exact[1]]),
            ("an item without state", [{"resource": first}, exact[1]]),
            ("an item that is not an object", [first, exact[1]]),
            ("an id of another form", [item("RS-" + first[3:], "acquired"), exact[1]]),
            ("held is an object", exact[0]),
            ("held is empty", []),
            ("more than 256 items", [item(rid(number), "intent") for number in range(1, 258)]),
        ]
        for state in ("accepted", "merged"):
            self.refuse_all("lane.state", [
                ("{}: {}".format(state, label), "held",
                 {"state": state} if held is None else {"state": state, "held": held}) for label, held in cases])
        self.accept("lane.state", LANE, {"state": "accepted", "held": exact})

    def test_held_only_when_accepting(self):
        """fails when: a lane.state whose state is not accepted or merged is stored with a held, or a lane that holds
        nothing is given a held (a list of another lane's resources, or an empty one)."""
        first, second, third = self.held_world()
        exact = [item(first, "acquired"), item(second, "intent")]
        self.refuse_all("lane.state", [("{} with held".format(state), "held", {"state": state, "held": exact})
                                       for state in ("queued", "running", "verifying", "abandoned")])
        self.refuse_all("lane.state", [("held lists the resource of another lane", "held",
                                        {"state": "accepted", "held": [item(first, "acquired")]}),
                                       ("held is empty", "held", {"state": "accepted", "held": []})], lane=EMPTY)
        self.accept("lane.state", EMPTY, {"state": "accepted"})
        self.accept("lane.state", LANE, {"state": "abandoned"})

    # 10. replay().

    def test_replay_accepts_a_good_store(self):
        """fails when: a store built from accepted events does not verify and rebuild (a replay that refuses an order
        the checks at append let in, or that rejects a hand-made store whose events are in order)."""
        current = self.laneboss_json("--version")["protocol_version"]
        first, second, third = self.held_world()
        self.accept("resource.cost", LANE, costed(rid(3)))
        held = [item(first, "acquired"), item(second, "intent")]
        self.accept("lane.state", LANE, {"state": "accepted", "held": held}, protocol_version=current)
        self.accept("lane.state", OTHER, {"state": "merged", "held": [item(third, "intent")]},
                    protocol_version=current)
        self.accept("lane.state", EMPTY, {"state": "accepted"}, protocol_version=current)
        lanes = self.run_laneboss("state", "lanes", "--config", "alpha").stdout
        self.laneboss_json("state", "verify", "--config", "alpha")
        self.insert([("resource.intent", LANE, intent(rid(8))), ("resource.acquired", LANE, acquired(rid(8)))])
        self.assertEqual(self.run_laneboss("state", "rebuild", "--config", "alpha").stdout, lanes)
        verified = self.laneboss_json("state", "verify", "--config", "alpha")
        self.assertIs(verified["ok"], True)
        self.assertEqual(verified["events"], len(self.events()))
        self.assertEqual(self.run_laneboss("state", "lanes", "--config", "alpha").stdout, lanes)

    def test_replay_rejects_a_bad_order(self):
        """fails when: a store that holds an event in an order the fold has no rule for (or in a form, a lane or a
        bound that append would refuse) verifies or rebuilds: state verify and state rebuild must end with exit 3
        naming the seq of the event, and rebuild must leave the rows as they were."""

        def lane(config):
            self.start_lane(config=config)

        def with_intent(config):
            lane(config)
            self.bring(1, "intent", config=config)

        def with_acquired(config):
            lane(config)
            self.bring(1, "acquired", config=config)

        def with_released(config):
            lane(config)
            self.bring(1, "released", config=config)

        def with_failed(config):
            lane(config)
            self.bring(1, "failed", config=config)

        def two_lanes(config):
            self.start_lane(LANE, config=config)
            self.start_lane(OTHER, config=config)
            self.bring(1, "intent", config=config)

        def merged(config):
            lane(config)
            self.mark("merged", config=config)

        bad_cost = costed(rid(1), cost=dict(COST, amount_micros=170904))
        cases = [
            ("released before acquired", with_intent, [], [("resource.released", LANE, released(rid(1)))]),
            ("acquired without an intent", lane, [], [("resource.acquired", LANE, acquired(rid(1)))]),
            ("acquired twice", with_acquired, [], [("resource.acquired", LANE, acquired(rid(1)))]),
            ("cost before the release", with_acquired, [], [("resource.cost", LANE, costed(rid(1)))]),
            ("a second intent with the id", with_intent, [], [("resource.intent", LANE, intent(rid(1)))]),
            ("an event after failed", with_failed, [], [("resource.acquired", LANE, acquired(rid(1)))]),
            ("a lane that no lane event made", lane, [], [("resource.intent", "res-ghost", intent(rid(1)))]),
            ("an id used with another lane", two_lanes, [], [("resource.acquired", OTHER, acquired(rid(1)))]),
            ("an intent for a merged lane", merged, [], [("resource.intent", LANE, intent(rid(1)))]),
            ("an intent for a run the lane never had", lane, [], [("resource.intent", LANE, intent(rid(1), run=2))]),
            ("a cost that is not the arithmetic", with_released, [], [("resource.cost", LANE, bad_cost)]),
            ("a look-alike kind", lane, [], [("resource.x", LANE, {})]),
            ("an intent without a member", lane, [], [("resource.intent", LANE, without(intent(rid(1)), "region"))]),
            ("a held resource too many", lane,
             [("resource.intent", LANE, intent(rid(1000 + number))) for number in range(256)],
             [("resource.intent", LANE, intent(rid(2000)))]),
        ]
        for index, (label, build, valid, wrong) in enumerate(cases):
            with self.subTest(label):
                config = "bad{}".format(index)
                self.write_config(config)
                build(config)
                if valid:
                    self.insert(valid, config)
                self.laneboss_json("state", "verify", "--config", config)
                lanes = self.run_laneboss("state", "lanes", "--config", config).stdout
                seq = self.insert(wrong, config)[0]
                for command in ("verify", "rebuild"):
                    self.assertNamesSeq(self.run_laneboss("state", command, "--config", config, code=3), seq)
                self.assertEqual(self.run_laneboss("state", "lanes", "--config", config).stdout, lanes)

    def test_replay_stops_a_resource_command(self):
        """fails when: the store appends a resource event although a stored resource event of the same lane is in an
        order the fold has no rule for, or in a form this version cannot read (exit 3 naming its seq, as every command
        that reads the resources does, and not an internal error from the fold)."""
        self.start_lane()
        self.bring(1, "intent")
        seq = self.insert([("resource.released", LANE, released(rid(1)))])[0]
        result = self.put("resource.acquired", LANE, acquired(rid(1)), code=3)
        self.assertNamesSeq(result, seq)
        self.write_config("unreadable")
        self.start_lane(config="unreadable")
        seq = self.insert([("resource.intent", LANE, without(intent(rid(2)), "region"))], "unreadable")[0]
        result = self.put("resource.intent", LANE, intent(rid(3)), code=3, config="unreadable")
        self.assertNamesSeq(result, seq)

    def test_replay_version_test(self):
        """fails when: the version test of the gate is not the replay's alone: a build that exempts a lane.state of an
        older protocol version at append (it must be refused whatever version it names), or that does not leave one
        alone in state verify and state rebuild (a store in which an older launcher accepted a lane must still verify),
        or compares the versions as text and not as three whole numbers (1.10.0 is newer than 1.9.0), or leaves alone
        a newer one."""
        self.start_lane()
        self.start_lane(OTHER)
        self.bring(1, "acquired")
        self.bring(2, "intent", lane=OTHER)
        current = self.laneboss_json("--version")["protocol_version"]
        for version in ("1.0.0", "1.1.0", current, "9.9.9"):
            self.refuse("lane.state", LANE, {"state": "accepted"}, protocol_version=version)
            self.refuse("lane.state", OTHER, {"state": "merged"}, protocol_version=version)
        self.insert([("lane.state", LANE, {"state": "accepted"}, "1.1.0"),
                     ("lane.state", OTHER, {"state": "merged"}, "1.0.0")])
        rows = json.loads(self.run_laneboss("state", "rebuild", "--config", "alpha").stdout)
        self.assertEqual([(row["lane"], row["state"]) for row in rows], [(LANE, "accepted"), (OTHER, "merged")])
        self.assertIs(self.laneboss_json("state", "verify", "--config", "alpha")["ok"], True)
        for index, version in enumerate(("1.10.0", "9.9.9")):
            with self.subTest(version=version):
                config = "late{}".format(index)
                self.write_config(config)
                self.start_lane(config=config)
                self.bring(1, "acquired", config=config)
                seq = self.insert([("lane.state", LANE, {"state": "accepted"}, version)], config)[0]
                self.assertNamesSeq(self.run_laneboss("state", "rebuild", "--config", config, code=3), seq)

    def test_replay_gate_version(self):
        """fails when: the version test of the replay has a threshold other than step A's own version, 1.3.0: a build
        that takes it from the protocol that ships now (1.2.0, so that a store in which the launcher before step A
        accepted or merged a lane that held a resource stops verifying and rebuilding for good), one that leaves alone
        a lane.state that names 1.3.0 itself (a comparison that is strict, or a threshold above it), or one that
        refuses a lane.state of 1.3.0 whose held is exact."""

        def lane_state(config, state, version, held):
            self.write_config(config)
            self.start_lane(config=config)
            name = self.bring(1, "acquired", config=config)
            payload = {"state": state, "held": [item(name, "acquired")]} if held else {"state": state}
            return self.insert([("lane.state", LANE, payload, version)], config)[0]

        for state in ("accepted", "merged"):
            with self.subTest(state=state, version="1.2.0 is left alone"):
                config = "before-" + state
                lane_state(config, state, "1.2.0", held=False)
                rows = json.loads(self.run_laneboss("state", "rebuild", "--config", config).stdout)
                self.assertEqual([(row["lane"], row["state"]) for row in rows], [(LANE, state)])
                self.assertIs(self.laneboss_json("state", "verify", "--config", config)["ok"], True)
            with self.subTest(state=state, version="1.3.0 is checked"):
                config = "gate-" + state
                seq = lane_state(config, state, "1.3.0", held=False)
                for command in ("verify", "rebuild"):
                    self.assertNamesSeq(self.run_laneboss("state", command, "--config", config, code=3), seq)
            with self.subTest(state=state, version="1.3.0 with its held is taken"):
                config = "exact-" + state
                lane_state(config, state, "1.3.0", held=True)
                self.run_laneboss("state", "rebuild", "--config", config)
                self.assertIs(self.laneboss_json("state", "verify", "--config", config)["ok"], True)
