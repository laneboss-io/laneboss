"""D. Events: append, duplicates, conflicts, tail, follow, credential refusal and allowed shapes."""

import hashlib
import json
from pathlib import Path
import queue
import subprocess
import threading
import time
import uuid

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def credential_cases():
    key_header = "-----" + "BEGIN OPENSSH " + "PRIVATE KEY" + "-----"
    github = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6Q7r8"
    key_id = "AK" + "IA" + "EXAMPLE7Q2W3E4R5"
    slack = "xo" + "xb-" + "1234567890-" + "abcdefghijklmnop"
    bearer = "abc123def456" + "ghi789jkl012"
    web_token = ("ey" + "JhbGciOiJIUzI1NiJ9" + ".ey" + "JzdWIiOiIxMjM0In0" + "."
                 + "dBjftJeZ4CVPmB92K27u" + "hbUJU1p1rwW1gFWFOEjXk")
    url_password = "s3cr3t" + "-pass-77"
    google = "AI" + "za" + "SyA1b2C3d4E5f6G7h8I9" + "j0K1l2M3n4O5p6Q"
    prefixed = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2"
    password = "hunter2-" + "correct-horse"
    api = "Zx81-Qw72" + "-Lm55-Np09"
    return [
        ("private key header", "payload", {"payload": {"notes": "key follows " + key_header}}, key_header),
        ("github token", "payload", {"payload": {"items": ["fine", github]}}, github),
        ("access key id", "actor", {"actor": key_id}, key_id),
        ("chat token", "payload", {"payload": {"nested": {"chat": slack}}}, slack),
        ("bearer header", "payload", {"payload": {"request": "Authorization: Bearer " + bearer}}, bearer),
        ("password assignment", "payload", {"payload": {"log": "password = " + password}}, password),
        ("api key assignment", "payload", {"payload": {"log": "api_key: " + api}}, api),
        ("sensitive key name", "payload", {"payload": {"password": password}}, password),
        ("web token", "payload", {"payload": {"cookie": web_token}}, web_token),
        ("url credentials", "payload",
         {"payload": {"remote": "https://deploy:" + url_password + "@" + "repo.invalid/x.git"}}, url_password),
        ("cloud api key", "payload", {"payload": {"value": google}}, google),
        ("prefixed secret key", "payload", {"payload": {"value": prefixed}}, prefixed),
        ("chat token as a lane name", "lane", {"lane": slack}, slack),
    ]


class EventTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.write_config("alpha")

    def test_append_returns_id_and_seq(self):
        first = json.loads(self.append(self.event(id="evt-1", payload={"text": "first"})).stdout)
        self.assertEqual((first["id"], first["seq"], first["duplicate"]), ("evt-1", 1, False))
        self.assertRegex(first["recorded_at"], support.TIMESTAMP)
        self.assertRegex(first["sha256"], "^[0-9a-f]{64}$")
        second = json.loads(self.append(self.event(payload={"text": "generated id"})).stdout)
        self.assertEqual(second["seq"], 2)
        self.assertRegex(second["id"], r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
        result = self.run_laneboss("event", "append", "--config", "alpha", "--file", "-",
                              stdin=json.dumps(self.event(id="evt-stdin", lane="alpha-lane-1")))
        self.assertEqual(json.loads(result.stdout)["seq"], 3)
        stored = self.events()
        self.assertEqual([item["seq"] for item in stored], [1, 2, 3])
        self.assertEqual([item["id"] for item in stored], ["evt-1", second["id"], "evt-stdin"])
        self.assertEqual(stored[0]["payload"], {"text": "first"})
        self.assertEqual(stored[0]["sha256"], first["sha256"])
        self.assertEqual(stored[0]["recorded_at"], first["recorded_at"])
        self.assertEqual((stored[2]["lane"], stored[2]["actor"], stored[2]["kind"]), ("alpha-lane-1", "e2e", "test.note"))
        self.assertIsNone(stored[0]["lane"])
        self.assertIsNone(stored[0]["occurred_at"])

    def test_duplicates_and_conflicts(self):
        value = self.event(id="evt-dup", lane="alpha-lane-1", occurred_at="2026-10-08T09:00:00+08:00",
                           payload={"list": [1, 2], "text": "same"})
        first = json.loads(self.append(value).stdout)
        again = json.loads(self.append(value).stdout)
        self.assertTrue(again["duplicate"])
        self.assertEqual((again["id"], again["seq"], again["sha256"]), (first["id"], first["seq"], first["sha256"]))
        self.assertEqual(len(self.events()), 1)
        reordered = json.loads(json.dumps(value, sort_keys=True))
        self.assertTrue(json.loads(self.append(reordered).stdout)["duplicate"])
        changed = dict(value, payload={"list": [1, 3], "text": "same"})
        result = self.append(changed, code=3)
        self.assertIn("evt-dup", result.stderr)
        self.append(dict(value, actor="someone-else"), code=3)
        stored = self.events()
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["payload"], {"list": [1, 2], "text": "same"})

    def test_tail_since(self):
        for index in range(1, 6):
            self.append(self.event(id="evt-{}".format(index)))
        lines = self.run_laneboss("event", "tail", "--config", "alpha", "--since", "2").stdout.splitlines()
        self.assertEqual([json.loads(line)["seq"] for line in lines], [3, 4, 5])
        self.assertEqual([json.loads(line)["id"] for line in lines], ["evt-3", "evt-4", "evt-5"])
        self.assertEqual(self.run_laneboss("event", "tail", "--config", "alpha", "--since", "5").stdout, "")
        self.assertEqual(len(self.run_laneboss("event", "tail", "--config", "alpha").stdout.splitlines()), 5)
        self.assertEqual(json.loads(lines[0]), self.events()[2])
        self.run_laneboss("event", "tail", "--config", "alpha", "--since", "-1", code=2)

    def stop(self, process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()

    def test_tail_follow(self):
        self.append(self.event(id="before-follow"))
        process = subprocess.Popen(
            [str(self.command), "event", "tail", "--config", "alpha", "--follow"], cwd=str(self.directory),
            env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
        )
        self.addCleanup(self.stop, process)
        lines = queue.Queue()

        def read():
            for line in process.stdout:
                lines.put(line)

        threading.Thread(target=read, daemon=True).start()
        try:
            self.assertEqual(json.loads(lines.get(timeout=20))["id"], "before-follow")
        except queue.Empty:
            self.fail("tail --follow did not print the existing event")
        for name in ("during-follow-1", "during-follow-2"):
            self.append(self.event(id=name))
            appended = time.monotonic()
            try:
                line = lines.get(timeout=2.0)
            except queue.Empty:
                self.fail("tail --follow did not show an event appended by another process within two seconds")
            self.assertLessEqual(time.monotonic() - appended, 2.0)
            self.assertEqual(json.loads(line)["id"], name)
        self.assertIsNone(process.poll())

    def test_follow_before_first_event(self):
        process = subprocess.Popen(
            [str(self.command), "event", "tail", "--config", "alpha", "--follow"], cwd=str(self.directory),
            env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
        )
        self.addCleanup(self.stop, process)
        lines = queue.Queue()

        def read():
            for line in process.stdout:
                lines.put(line)

        threading.Thread(target=read, daemon=True).start()
        time.sleep(1.0)
        self.assertIsNone(process.poll(), "tail --follow must keep running while the store does not exist")
        self.assertTrue(lines.empty())
        self.append(self.event(id="first-event"))
        appended = time.monotonic()
        try:
            line = lines.get(timeout=2.0)
        except queue.Empty:
            self.fail("tail --follow did not show the first event within two seconds")
        self.assertLessEqual(time.monotonic() - appended, 2.0)
        self.assertEqual(json.loads(line)["seq"], 1)

    def test_credentials_are_refused(self):
        for label, field, change, secret in credential_cases():
            with self.subTest(label):
                value = self.event(id="cred-" + uuid.uuid4().hex[:8])
                value.update(change)
                result = self.append(value, code=2)
                self.assertIn(field, result.stderr)
                self.assertNotIn(field + ".", result.stderr, "no key below the top level is printed")
                self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertEqual(self.events(), [])
        self.assertEqual(self.run_laneboss("event", "tail", "--config", "alpha").stdout, "")
        self.assertFalse(Path(self.laneboss_json("config", "path", "alpha")["store"]).exists())

    def test_allowed_shapes_are_accepted(self):
        sha = hashlib.sha256(b"allowed").hexdigest()
        commit = hashlib.sha1(b"allowed").hexdigest()
        request = str(uuid.uuid4())
        payload = {
            "sha256": sha, "commit": commit, "short_commit": commit[:7], "request": request,
            "upper": sha.upper(), "text": "commit " + commit + " built; sha256: " + sha + "; run " + request,
            "token_secret": "E2E_CHAT_TOKEN", "note": "the token is read from the secret store",
        }
        result = json.loads(self.append(self.event(id=request, payload=payload)).stdout)
        self.assertEqual(result["id"], request)
        second = json.loads(self.append(self.event(id=sha, lane="alpha-" + commit[:12])).stdout)
        self.assertEqual(second["id"], sha)
        stored = self.events()
        self.assertEqual(stored[0]["payload"], payload)
        self.assertEqual(stored[1]["lane"], "alpha-" + commit[:12])

    def test_store_fields_are_refused(self):
        for field, value in (("recorded_at", "2026-10-08T09:00:00Z"), ("seq", 7), ("sha256", "0" * 64)):
            with self.subTest(field):
                result = self.append(self.event(**{field: value}), code=2)
                self.assertIn(field, result.stderr)
        self.assertEqual(self.events(), [])

    def test_envelope_is_validated(self):
        cases = [
            ("unknown field", {"colour": "red"}, "colour"),
            ("missing kind", {"kind": None}, "kind"),
            ("bad kind", {"kind": "Lane.Ended"}, "kind"),
            ("kind without dot", {"kind": "note"}, "kind"),
            ("bad id", {"id": "-bad"}, "id"),
            ("bad lane", {"lane": "Bad Lane"}, "lane"),
            ("bad timestamp", {"occurred_at": "2026-10-08 09:00"}, "occurred_at"),
            ("payload not object", {"payload": [1]}, "payload"),
            ("missing actor", {"actor": None}, "actor"),
            ("missing protocol", {"protocol_version": None}, "protocol_version"),
            ("unknown lane kind", {"kind": "lane.finished", "lane": "alpha-lane-1"}, "kind"),
            ("lane event without lane", {"kind": "lane.started"}, "lane"),
            ("bad lane state", {"kind": "lane.state", "lane": "alpha-lane-1", "payload": {"state": "done"}},
             "payload.state"),
        ]
        for label, change, field in cases:
            with self.subTest(label):
                result = self.append(self.event(**change), code=2)
                self.assertIn(field, result.stderr)
        bad = self.directory / "duplicate-key.json"
        bad.write_text('{"kind": "test.note", "kind": "test.other", "actor": "e2e", "payload": {}, '
                       '"protocol_version": "1.0.0"}', encoding="utf-8")
        self.run_laneboss("event", "append", "--config", "alpha", "--file", bad, code=2)
        self.run_laneboss("event", "append", "--config", "alpha", "--file", self.directory / "absent.json", code=2)
        self.run_laneboss("event", "append", "--config", "alpha", json.dumps(self.event()), code=2)
        self.assertEqual(self.events(), [])
