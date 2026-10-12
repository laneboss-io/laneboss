"""Refusals E. A refused command and a guard message that contain credential shapes are withheld in the event: it carries
their length, their hash and where to find them, never the text, and the value appears in no event, no output and no
error."""

import hashlib
import json

from . import refusalsupport, support
from .refusalsupport import hook, refused_steps, shell_steps


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class SecretRefusalTest(refusalsupport.RefusalTest):
    def check_secret(self, fmt, lane):
        token = "gh" + "p_" + "Q8r7S6t5U4v3W2x1Y0z9" + "A8b7C6d5E4f3G2h1"
        command = "curl -s -H 'Authorization: Bearer {}' https://example.invalid/plan > notes/plan.md".format(token)
        message = hook(token)
        follower = self.follow()
        steps = [{"open": {}}] + refused_steps(fmt, command=command, message=message)
        steps += shell_steps("c2", command) + [{"exit": 0}]
        self.start_session(lane, fmt, steps)
        _, ended = follower.wait(self, "lane.ended", lane)
        refusal = self.kind_events(lane, "lane.refusal")[0]["payload"]
        self.assertEqual(refusal["command"], {"text": None, "withheld": True, "length": len(command),
                                              "sha256": hashlib.sha256(command.encode("utf-8")).hexdigest()})
        self.assertIs(refusal["message"]["withheld"], True)
        self.assertIsNone(refusal["message"]["text"])
        self.assertEqual(refusal["message"]["length"], len(message))
        self.assertEqual(refusal["message"]["sha256"], hashlib.sha256(message.encode("utf-8")).hexdigest())
        # Where to find them: the record and the positions of the call and of the refusal.
        self.assertIn(token, self.read_line(refusal["call"]["record"]))
        self.assertIn(token, self.read_line(refusal["record"]))
        self.assertEqual(refusal["guard"], "doc-guard")
        suspicion = self.suspicion_of(lane, "c2")[0]["payload"]
        self.assertEqual(sorted(suspicion["how"]), ["reworded", "shell-write"])
        self.assertIs(suspicion["command"]["withheld"], True)
        self.assertIn(token, self.read_line(suspicion["call"]["record"]))
        outputs = [json.dumps([event for _, event in follower.seen])]
        for arguments in (("state", "events"), ("state", "lanes"), ("state", "verify")):
            result = self.run_laneboss(*arguments, "--config", "alpha", environment=self.env("alpha"))
            outputs.append(result.stdout + result.stderr)
        for action, arguments in (("refusals", ["--lane", lane]), ("scan", ["--lane", lane]),
                                  ("status", ["--lane", lane]), ("mark", ["--lane", lane, "--state", "accepted"])):
            result = self.lane(action, *arguments, code=None)
            outputs.append(result.stdout + result.stderr)
        result = self.review(lane, refusal["refusal"], suspicion["paths"][0], "workaround")
        outputs.append(json.dumps(result))
        state = self.paths()["state_dir"]
        for name in ("watch.log",):
            with open("{}/lanes/{}/{}".format(state, lane, name), encoding="utf-8") as handle:
                outputs.append(handle.read())
        for item in self.refusals(lane)["coverage"]:
            outputs.append(json.dumps(item))
        for text in outputs:
            self.assertNotIn(token, text)
        self.assert_sound()

    def test_claude_code(self):
        self.check_secret("claude-code", "e-claude")

    def test_note_path_is_never_repeated(self):
        # Decision 9: a --note path that looks like a credential (its file name, or a directory on the way) is never
        # repeated, on either output stream, whether or not the file exists.
        value = "Zx81-Qw72" + "-Lm55-Np09"
        named = self.directory / "password={}.md".format(value)
        parent = self.directory / "token={}".format(value) / "note.md"
        for path in (named, parent):
            with self.subTest(path=path.name):
                result = self.review("e-note", "rf-" + "0" * 24, "/x/notes/plan.md", "clean", "--note", path, code=2)
                self.assertNotIn(value, result.stdout + result.stderr)
        named.write_text("Checked by hand.\n", encoding="utf-8")
        result = self.review("e-note", "rf-" + "0" * 24, "/x/notes/plan.md", "clean", "--note", named, code=2)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_long_credential_is_withheld(self):
        # Decision 10: a credential that begins inside the excerpt withholds it, however far away the detector needs to
        # look to recognise it: here a URL whose password is 800 characters long.
        password = ("Kq7" * 300)[:800]
        command = "curl -s https://deploy:" + password + "@" + "example.invalid/plan > notes/plan.md"
        steps = [{"open": {}}] + refused_steps("claude-code", command=command) + [{"exit": 0}]
        self.start_session("e-long", "claude-code", steps)
        self.wait_event("lane.ended", "e-long")
        refusal = self.kind_events("e-long", "lane.refusal")[0]["payload"]
        self.assertIs(refusal["command"]["withheld"], True)
        everything = self.run_laneboss("state", "events", "--config", "alpha", environment=self.env("alpha")).stdout
        self.assertNotIn(password[:12], everything)
        self.assert_sound()
