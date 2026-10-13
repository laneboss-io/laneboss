"""The store: replacement inserts, an erased store, inexact numbers, verification gaps and concurrent first use.

Direct sqlite3 connections and file changes are deliberate tampering; outcomes are asserted through the
installed command.
"""

from contextlib import closing
import fcntl
import json
import os
from pathlib import Path
import queue
import shutil
import sqlite3
import subprocess
import threading
import time

from . import support

# Runs the installed program unchanged under an interpreter whose flock refuses directories, as on a file
# system without directory locks, so the lock-file fallback is taken.


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


COLUMNS = "seq, id, kind, lane, actor, occurred_at, payload, protocol_version, recorded_at, sha256"


class StoreTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.write_config("alpha")
        self.paths = self.laneboss_json("config", "path", "alpha")
        self.store = Path(self.paths["store"])
        self.state = Path(self.paths["state_dir"])

    def raw_append(self, text, code=0):
        path = self.directory / "raw-{}.json".format(time.monotonic_ns())
        path.write_text(text, encoding="utf-8")
        return self.run_laneboss("event", "append", "--config", "alpha", "--file", path, code=code)

    def test_replace_inserts_refused(self):
        self.append(self.event(id="keep-1", payload={"n": 1}))
        self.append(self.event(id="keep-2", payload={"n": 2}))
        statements = [
            "INSERT OR REPLACE INTO events ({0}) SELECT seq, id, kind, lane, actor, occurred_at, '{{}}', "
            "protocol_version, recorded_at, sha256 FROM events WHERE seq = 1".format(COLUMNS),
            "REPLACE INTO events ({0}) SELECT 99, id, kind, lane, actor, occurred_at, payload, protocol_version, "
            "recorded_at, sha256 FROM events WHERE seq = 2".format(COLUMNS),
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('config', 'beta')",
            "REPLACE INTO meta (key, value) VALUES ('format', 'other')",
            "INSERT INTO meta (key, value) VALUES ('extra', 'value')",
        ]
        with closing(sqlite3.connect(str(self.store))) as connection:
            for statement in statements:
                with self.subTest(statement[:40]):
                    with self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(statement)
                    connection.rollback()
        self.laneboss_json("state", "verify", "--config", "alpha")
        self.assertEqual([item["payload"] for item in self.events()], [{"n": 1}, {"n": 2}])

    def test_erased_store_refused(self):
        self.append(self.event(id="erase-1"))
        self.append(self.event(id="erase-2", kind="lane.planned", lane="alpha-lane-1"))
        event_file = self.directory / "next.json"
        event_file.write_text(json.dumps(self.event(id="erase-3")), encoding="utf-8")
        commands = [["state", "verify"], ["event", "append", "--file", event_file], ["event", "tail"],
                    ["state", "lanes"]]
        with open(str(self.store), "r+b") as handle:
            handle.truncate(0)
        for arguments in commands:
            with self.subTest(erased="truncated", command=arguments[:2]):
                self.run_laneboss(*arguments[:2], "--config", "alpha", *arguments[2:], code=3)
        self.assertEqual(self.store.stat().st_size, 0)
        os.remove(str(self.store))
        for arguments in commands:
            with self.subTest(erased="deleted", command=arguments[:2]):
                self.run_laneboss(*arguments[:2], "--config", "alpha", *arguments[2:], code=3)
        self.assertFalse(self.store.exists())
        os.remove(str(self.state / ".laneboss-state"))
        self.append(self.event(id="fresh-1"))
        self.assertEqual([item["seq"] for item in self.events()], [1])

    def test_inexact_numbers_refused(self):
        template = ('{{"id": "{0}", "kind": "test.note", "actor": "e2e", "protocol_version": "1.0.0", '
                    '"payload": {{"n": {1}}}}}')
        first = json.loads(self.raw_append(template.format("num-1", "9007199254740992.0")).stdout)
        self.assertFalse(first["duplicate"])
        result = self.raw_append(template.format("num-1", "9007199254740993.0"), code=2)
        self.assertIn("number", result.stderr)
        self.raw_append(template.format("num-2", "1e400"), code=2)
        self.raw_append(template.format("num-3", "0.1"))
        big = "123456789012345678901234567890123456789"
        self.raw_append(template.format("num-4", big))
        stored = {item["id"]: item["payload"]["n"] for item in self.events()}
        self.assertEqual(stored, {"num-1": 9007199254740992.0, "num-3": 0.1, "num-4": int(big)})
        self.assertIn(big, self.run_laneboss("state", "events", "--config", "alpha").stdout)

    def render(self, name, lane="alpha-lane-1"):
        source = self.directory / (name + ".md")
        source.write_text("# Brief " + name + "\n\nAn invented task.\n", encoding="utf-8")
        result = self.run_laneboss("brief", "render", "--config", "alpha", "--lane", lane, "--in", source,
                              "--out", self.directory / (name + "-rendered.md"))
        return json.loads(result.stdout)

    def test_verify_missing_inputs(self):
        self.render("first")
        event = [item for item in self.events() if item["kind"] == "brief.rendered"][0]
        copy = self.state / event["payload"]["inputs"][0]["copy"]
        data = copy.read_bytes()
        os.remove(str(copy))
        result = self.run_laneboss("state", "verify", "--config", "alpha", code=3)
        self.assertIn(event["payload"]["inputs"][0]["sha256"], result.stderr)
        copy.write_bytes(data)
        self.laneboss_json("state", "verify", "--config", "alpha")
        shutil.rmtree(str(self.state / "lanes"))
        self.run_laneboss("state", "verify", "--config", "alpha", code=3)

    def test_verify_lookalike_objects(self):
        self.append(self.event(id="schema-1"))
        for create, drop in (("CREATE TABLE sqliteXextra (x)", "DROP TABLE sqliteXextra"),
                             ("CREATE TRIGGER sqliteXtrig AFTER INSERT ON lanes BEGIN SELECT 1; END",
                              "DROP TRIGGER sqliteXtrig")):
            with self.subTest(create.split()[1]):
                with closing(sqlite3.connect(str(self.store))) as connection:
                    connection.execute(create)
                    connection.commit()
                self.assertIn("schema", self.run_laneboss("state", "verify", "--config", "alpha", code=3).stderr)
                with closing(sqlite3.connect(str(self.store))) as connection:
                    connection.execute(drop)
                    connection.commit()
                self.laneboss_json("state", "verify", "--config", "alpha")

    def test_verify_lane_key(self):
        self.append(self.event("lane.planned", lane="alpha-lane-1", occurred_at="2026-10-08T09:00:00Z"))
        self.append(self.event("lane.started", lane="alpha-lane-1", occurred_at="2026-10-08T09:01:00Z",
                               payload=support.started_payload(self.paths)))
        with closing(sqlite3.connect(str(self.store))) as connection:
            connection.execute("UPDATE lanes SET lane = 'alpha-lane-9'")
            connection.commit()
        self.assertIn("projection", self.run_laneboss("state", "verify", "--config", "alpha", code=3).stderr)
        self.assertEqual([item["lane"] for item in self.laneboss_json("state", "rebuild", "--config", "alpha")],
                         ["alpha-lane-1"])
        self.append(self.event("lane.ended", lane="alpha-lane-1", occurred_at="2026-10-08T10:00:00Z",
                               payload=support.ended_payload()))
        lanes = self.laneboss_json("state", "lanes", "--config", "alpha")
        self.assertEqual([(item["lane"], item["events"], item["state"]) for item in lanes],
                         [("alpha-lane-1", 3, "verifying")])
        self.laneboss_json("state", "verify", "--config", "alpha")

    def test_concurrent_first_use(self):
        for round_number in range(5):
            name = "conc-{}".format(round_number)
            self.write_config(name)
            follower = subprocess.Popen(
                [str(self.command), "event", "tail", "--config", name, "--follow"], cwd=str(self.directory),
                env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
            lines = queue.Queue()
            threading.Thread(target=lambda source=follower.stdout, sink=lines: [sink.put(line) for line in source],
                             daemon=True).start()
            try:
                files = []
                for index in range(8):
                    path = self.directory / "{}-{}.json".format(name, index)
                    path.write_text(json.dumps(self.event(id="{}-{}".format(name, index))), encoding="utf-8")
                    files.append(path)
                appenders = [subprocess.Popen([str(self.command), "event", "append", "--config", name, "--file", path],
                                              cwd=str(self.directory), env=self.environment, stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, text=True, encoding="utf-8")
                             for path in files]
                outcomes = [(appender.communicate(timeout=60), appender.returncode) for appender in appenders]
                for (stdout, stderr), code in outcomes:
                    self.assertEqual(code, 0, "round {}: {}".format(round_number, stderr))
                events = self.events(name)
                self.assertEqual([item["seq"] for item in events], list(range(1, 9)))
                self.assertEqual({item["id"] for item in events}, {"{}-{}".format(name, i) for i in range(8)})
                seen = []
                deadline = time.monotonic() + 10
                while len(seen) < 8 and time.monotonic() < deadline:
                    try:
                        seen.append(json.loads(lines.get(timeout=0.5))["seq"])
                    except queue.Empty:
                        continue
                self.assertEqual(seen, list(range(1, 9)), follower.stderr.read() if follower.poll() is not None else "")
                self.assertIsNone(follower.poll(), "the follower must survive the store's creation")
                self.laneboss_json("state", "verify", "--config", name)
            finally:
                follower.terminate()
                follower.wait(timeout=10)
                follower.stdout.close()
                follower.stderr.close()

    def doctor_checks(self, code):
        result = self.run_laneboss("doctor", "--config", "alpha", code=code)
        return {json.loads(line)["check"]: json.loads(line) for line in result.stdout.splitlines()}

    def test_doctor_checks_real_store(self):
        self.append(self.event(id="real-1"))
        self.assertIs(self.doctor_checks(0).get("store.recorded", {}).get("ok"), True)
        with open(str(self.store), "r+b") as handle:
            handle.truncate(0)
        self.assertIs(self.doctor_checks(1).get("store.recorded", {}).get("ok"), False)
        os.remove(str(self.store))
        self.assertIs(self.doctor_checks(1).get("store.recorded", {}).get("ok"), False)

    def test_unrecorded_store_with_events(self):
        self.append(self.event(id="kept-1"))
        self.append(self.event(id="kept-2"))
        size = self.store.stat().st_size
        os.remove(str(self.state / ".laneboss-state"))
        event_file = self.directory / "late.json"
        event_file.write_text(json.dumps(self.event(id="late-1")), encoding="utf-8")
        for arguments in (["event", "append", "--file", event_file], ["state", "events"], ["event", "tail"],
                          ["state", "lanes"], ["state", "verify"]):
            with self.subTest(arguments[:2]):
                self.run_laneboss(*arguments[:2], "--config", "alpha", *arguments[2:], code=3)
        self.assertIs(self.doctor_checks(1).get("store.recorded", {}).get("ok"), False)
        self.assertEqual(self.store.stat().st_size, size)
        self.assertFalse((self.state / ".laneboss-state").exists())

    def test_store_without_events_adopted(self):
        output = self.directory / "locked-out"
        output.mkdir()
        source = self.directory / "brief.md"
        source.write_text("# Brief\n\nAn invented task.\n", encoding="utf-8")
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores directory permissions")
        output.chmod(0o500)
        self.addCleanup(output.chmod, 0o700)
        self.run_laneboss("brief", "render", "--config", "alpha", "--lane", "alpha-lane-1", "--in", source,
                     "--out", output / "rendered.md", code=2)
        self.assertTrue(self.store.is_file(), "the failed render created the store before writing its output")
        os.remove(str(self.state / ".laneboss-state"))
        self.assertEqual(self.events(), [])
        appended = json.loads(self.append(self.event(id="adopted-1")).stdout)
        self.assertEqual(appended["seq"], 1)
        self.laneboss_json("state", "verify", "--config", "alpha")

    def test_marker_fields_validated(self):
        token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6Q7r8"
        self.append(self.event(id="marker-1"))
        marker = self.state / ".laneboss-state"
        original = json.loads(marker.read_text(encoding="utf-8"))
        cases = [
            ("credential in created_at", dict(original, store=dict(original["store"], created_at=token))),
            ("malformed store id", dict(original, store=dict(original["store"], id=token))),
            ("extra field", dict(original, note=token)),
        ]
        size = self.store.stat().st_size
        for label, value in cases:
            with self.subTest(label):
                marker.write_text(json.dumps(value), encoding="utf-8")
                for arguments in (["state", "verify"], ["state", "events"]):
                    result = self.run_laneboss(*arguments, "--config", "alpha", code=3)
                    self.assertNotIn(token, result.stdout + result.stderr)
                    self.assertIn("not a valid marker", result.stderr, "the store is healthy: the marker is refused")
                result = self.run_laneboss("doctor", "--config", "alpha", code=1)
                self.assertNotIn(token, result.stdout + result.stderr)
                checks = {json.loads(line)["check"]: json.loads(line) for line in result.stdout.splitlines()}
                self.assertIn("not a valid marker", checks["store.recorded"]["detail"])
        self.assertEqual(self.store.stat().st_size, size)
        marker.write_text(json.dumps(original), encoding="utf-8")
        self.assertEqual([item["id"] for item in self.events()], ["marker-1"])

    def test_marker_owner_not_printed(self):
        token = "glpat-" + "zqwxkvjmnbrtpslhgfdc"
        self.append(self.event(id="owner-1"))
        marker = self.state / ".laneboss-state"
        original = json.loads(marker.read_text(encoding="utf-8"))
        marker.write_text(json.dumps(dict(original, config=token)), encoding="utf-8")
        event_file = self.directory / "owner.json"
        event_file.write_text(json.dumps(self.event(id="owner-2")), encoding="utf-8")
        for arguments in (["state", "events"], ["event", "append", "--file", event_file]):
            with self.subTest(arguments[:2]):
                result = self.run_laneboss(*arguments[:2], "--config", "alpha", *arguments[2:], code=2)
                self.assertNotIn(token, result.stdout + result.stderr)
                self.assertIn("another or an unknown configuration", result.stderr)
        result = self.run_laneboss("doctor", "--config", "alpha", code=1)
        self.assertNotIn(token, result.stdout + result.stderr)
        marker.write_text(json.dumps(original), encoding="utf-8")
        self.assertEqual([item["id"] for item in self.events()], ["owner-1"])

    def render_once(self):
        source = self.directory / "brief.md"
        source.write_text("# Brief\n\nAn invented task.\n", encoding="utf-8")
        self.run_laneboss("brief", "render", "--config", "alpha", "--lane", "alpha-lane-1", "--in", source,
                     "--out", self.directory / "rendered.md")
        return [item for item in self.events() if item["kind"] == "brief.rendered"][0]

    def test_rendered_touches_must_be_names(self):
        genuine = self.render_once()
        count = len(self.events())
        envelope = {field: genuine[field] for field in ("kind", "lane", "actor", "payload", "protocol_version")}
        for label, touches in (("object", [{}]), ("mixed", ["billing", 1])):
            with self.subTest(label):
                value = dict(envelope, id="touches-" + label, payload=dict(genuine["payload"], touches=touches))
                result = self.append(value, code=2)
                self.assertIn("touches", result.stderr)
        self.assertEqual(len(self.events()), count)
        self.laneboss_json("state", "verify", "--config", "alpha")

    def test_refused_kind_creates_nothing(self):
        digest = support.digest("missing")
        forged = self.event("brief.rendered", lane="alpha-lane-1", payload={
            "inputs": [{"role": "brief", "path": "/x.md", "sha256": digest,
                        "copy": "lanes/alpha-lane-1/inputs/" + digest},
                       {"role": "protocol", "version": "1.0.0", "sha256": digest,
                        "copy": "lanes/alpha-lane-1/inputs/" + digest}],
            "output": {"path": "/x-rendered.md", "sha256": digest}, "project": None, "touches": [],
            "launcher_version": "0.2.0"})
        cases = (("bare", self.event("brief.rendered")), ("missing copies", forged))
        self.assertFalse(self.state.exists())
        for label, value in cases:
            with self.subTest(label, state="none"):
                self.run_laneboss("event", "append", "--config", "alpha", "--file", "-", code=2, stdin=json.dumps(value))
                self.assertFalse(self.state.exists(), "a refused event created the state directory")
        self.run_laneboss("doctor", "--config", "alpha", code=0)
        self.assertEqual(os.listdir(str(self.state)), [])
        for label, value in cases:
            with self.subTest(label, state="empty directory"):
                self.run_laneboss("event", "append", "--config", "alpha", "--file", "-", code=2, stdin=json.dumps(value))
                self.assertEqual(os.listdir(str(self.state)), [], "a refused event created a marker or a store")

    def test_doctor_reports_unreadable_inputs(self):
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores directory permissions")
        self.render_once()
        inputs = self.state / "lanes" / "alpha-lane-1" / "inputs"
        inputs.chmod(0o000)
        self.addCleanup(inputs.chmod, 0o700)
        result = self.run_laneboss("doctor", "--config", "alpha", code=1)
        checks = {json.loads(line)["check"]: json.loads(line) for line in result.stdout.splitlines()}
        self.assertIs(checks.get("store.recorded", {}).get("ok"), False, result.stderr)
        for check in ("state.writable", "store.round_trip", "tool.git", "tool.tmux"):
            self.assertIn(check, checks, "doctor stopped before its remaining checks")
        self.assertTrue(any(check.startswith("runner.") for check in checks))
        self.assertNotIn("internal error", result.stderr)

    def test_reader_lock_file_fallback(self):
        environment = dict(self.environment, LANEBOSS_FAULTS=json.dumps({"point": "directory-lock"}))

        def start(*arguments):
            return subprocess.Popen([str(support.faults_binary()), *map(str, arguments)],
                                    cwd=str(self.directory), env=environment, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)

        self.append(self.event(id="fallback-1"))
        lock_file = self.state / ".lock"
        self.assertFalse(lock_file.exists(), "a directory that can be locked needs no lock file")
        reader = start("state", "events", "--config", "alpha")
        stdout, stderr = reader.communicate(timeout=60)
        self.assertEqual(reader.returncode, 0, stderr)
        self.assertEqual([item["id"] for item in json.loads(stdout)], ["fallback-1"])
        self.assertTrue(lock_file.is_file(), "a reader creates the lock file where the directory cannot be locked")
        descriptor = os.open(str(lock_file), os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            reader = start("state", "events", "--config", "alpha")
            time.sleep(1.5)
            self.assertIsNone(reader.poll(), "a reader waits while the lock file is held")
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        stdout, stderr = reader.communicate(timeout=60)
        self.assertEqual(reader.returncode, 0, stderr)
        event_file = self.directory / "fallback.json"
        event_file.write_text(json.dumps(self.event(id="fallback-2")), encoding="utf-8")
        writer = start("event", "append", "--config", "alpha", "--file", event_file)
        stdout, stderr = writer.communicate(timeout=60)
        self.assertEqual(writer.returncode, 0, stderr)
        self.assertEqual([item["id"] for item in self.events()], ["fallback-1", "fallback-2"])
        self.laneboss_json("state", "verify", "--config", "alpha")
        self.run_laneboss("doctor", "--config", "alpha", code=0)

    def test_reserved_kind_validated(self):
        self.run_laneboss("event", "append", "--config", "alpha", "--file", "-", code=2,
                     stdin=json.dumps(self.event("brief.rendered")))
        self.laneboss_json("state", "verify", "--config", "alpha")
        digest = support.digest("missing")
        forged = self.event("brief.rendered", lane="alpha-lane-1", payload={
            "inputs": [{"role": "brief", "path": "/x.md", "sha256": digest,
                        "copy": "lanes/alpha-lane-1/inputs/" + digest}],
            "output": {"path": "/x-rendered.md", "sha256": digest}, "project": None, "touches": [],
            "launcher_version": "0.2.0"})
        self.append(forged, code=2)
        self.laneboss_json("state", "verify", "--config", "alpha")
        self.assertEqual([item for item in self.events() if item["kind"] == "brief.rendered"], [])

    def test_integer_digit_limit(self):
        template = ('{{"id": "{0}", "kind": "test.note", "actor": "e2e", "protocol_version": "1.0.0", '
                    '"payload": {{"n": {1}}}}}')
        allowed = "7" * 4300
        self.raw_append(template.format("int-1", allowed))
        self.assertIn(allowed, self.run_laneboss("state", "events", "--config", "alpha").stdout)
        result = self.raw_append(template.format("int-2", "7" * 5000), code=2)
        self.assertIn("digits", result.stderr)

    def test_reader_waits_for_creation(self):
        self.run_laneboss("doctor", "--config", "alpha", code=0)
        descriptor = os.open(str(self.state), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        lock_fd = descriptor
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError:
            lock_fd = os.open(str(self.state / ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        event_file = self.directory / "first.json"
        event_file.write_text(json.dumps(self.event(id="first-1")), encoding="utf-8")
        reader = subprocess.Popen([str(self.command), "state", "events", "--config", "alpha"], cwd=str(self.directory),
                                  env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        writer = None
        try:
            time.sleep(1.5)
            self.assertIsNone(reader.poll(), "a reader must wait while a writer holds the state directory's lock")
            writer = subprocess.Popen([str(self.command), "event", "append", "--config", "alpha", "--file",
                                       str(event_file)], cwd=str(self.directory), env=self.environment,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(0.5)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            if lock_fd != descriptor:
                os.close(lock_fd)
            os.close(descriptor)
        stdout, stderr = reader.communicate(timeout=60)
        self.assertEqual(reader.returncode, 0, stderr)
        self.assertIn([item["id"] for item in json.loads(stdout)], ([], ["first-1"]))
        if writer is not None:
            stdout, stderr = writer.communicate(timeout=60)
            self.assertEqual(writer.returncode, 0, stderr)
