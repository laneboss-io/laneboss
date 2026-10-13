"""Owner channels through the installed CLI and a strict localhost Discord REST stub.

Identifiers, secret names and token canaries vary on every run. The fixture
checks authorization, every path and payload, and read-back of stored messages;
it has no catch-all success route. API checks use the same installed library.
"""

import copy
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import subprocess
import sys
import threading
import tomllib
import urllib.error
import urllib.request
import uuid

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def snowflake():
    return str(uuid.uuid4().int % (2 ** 63 - 1) + 1)


class DiscordStub:
    def __init__(self, guild_id, bot_value):
        self.guild_id = guild_id
        self.bot_value = bot_value
        self.bot_id = snowflake()
        self.channels = {}
        self.messages = {}
        self.expected_hellos = {}
        self.expected_create = None
        self.create_status = 201
        self.post_status = 200
        self.read_status = 200
        self.read_patch = {}
        self.channel_patch = {}
        self.reflect_error = False
        self.redirect = False
        self.malformed_status = False
        self.requests = []
        self.protocol_errors = []
        self.active_pid = None
        self.argv_exposure = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *arguments):
                # Never let the server log headers or response bodies.
                return

            def reply(self, status, document, headers=None):
                encoded = json.dumps(document).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(encoded)

            def reject(self, status, reason):
                stub.protocol_errors.append(reason)
                self.reply(status, {"message": reason})

            def authenticated(self):
                if self.headers.get("Authorization") != "Bot " + stub.bot_value:
                    self.reject(401, "wrong bot authorization")
                    return False
                if stub.active_pid is not None:
                    # Parse only this live process's argv in memory. A failed ps
                    # is a fixture failure; neither argv nor its values are shown.
                    result = subprocess.run(["ps", "-p", str(stub.active_pid), "-o", "command="],
                                            capture_output=True, timeout=5)
                    stub.argv_exposure.append(result.returncode != 0 or
                                              stub.bot_value.encode() in result.stdout)
                return True

            def do_POST(self):
                if not self.authenticated():
                    return
                if self.headers.get_content_type() != "application/json":
                    self.reject(415, "expected application/json")
                    return
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 10000:
                        raise ValueError("invalid size")
                    body = json.loads(self.rfile.read(size))
                except (ValueError, UnicodeDecodeError):
                    self.reject(400, "invalid JSON request")
                    return
                stub.requests.append({"method": "POST", "path": self.path, "body": body})
                if self.path == "/api/v10/guilds/" + stub.guild_id + "/channels":
                    if stub.expected_create is None or body != {"name": stub.expected_create[0], "type": 0}:
                        self.reject(422, "wrong channel-create payload")
                        return
                    if stub.create_status != 201:
                        self.reply(stub.create_status, {"message": stub.bot_value if stub.reflect_error else "forbidden"})
                        return
                    identifier = snowflake()
                    channel = {"id": identifier, "guild_id": stub.guild_id, "name": body["name"], "type": 0}
                    stub.channels[identifier] = channel
                    stub.expected_hellos[identifier] = stub.expected_create[1]
                    self.reply(201, {**channel, **stub.channel_patch})
                    return
                matched = re.fullmatch(r"/api/v10/channels/([1-9][0-9]*)/messages", self.path)
                if matched and matched[1] in stub.channels:
                    identifier = matched[1]
                    expected = {"content": stub.expected_hellos[identifier], "allowed_mentions": {"parse": []}}
                    if body != expected:
                        self.reject(422, "wrong message-post payload")
                        return
                    if stub.post_status != 200:
                        self.reply(stub.post_status, {"message": stub.bot_value if stub.reflect_error else "forbidden"})
                        return
                    message_id = snowflake()
                    message = {"id": message_id, "channel_id": identifier, "content": body["content"],
                               "author": {"id": stub.bot_id, "bot": True, "username": "test-bot"}}
                    stub.messages[(identifier, message_id)] = message
                    self.reply(200, message)
                    return
                self.reject(404, "unexpected POST path or channel")

            def do_GET(self):
                if not self.authenticated():
                    return
                stub.requests.append({"method": "GET", "path": self.path})
                if stub.malformed_status:
                    self.wfile.write(("HTTP/1.1 " + stub.bot_value + "\r\n\r\n").encode())
                    return
                if stub.redirect:
                    self.reply(302, {}, {"Location": "/api/v10/redirect-target"})
                    return
                matched = re.fullmatch(r"/api/v10/channels/([1-9][0-9]*)", self.path)
                if matched and matched[1] in stub.channels:
                    self.reply(200, {**stub.channels[matched[1]], **stub.channel_patch})
                    return
                matched = re.fullmatch(r"/api/v10/channels/([1-9][0-9]*)/messages/([1-9][0-9]*)", self.path)
                if matched and (matched[1], matched[2]) in stub.messages:
                    if stub.read_status != 200:
                        self.reply(stub.read_status, {"message": stub.bot_value if stub.reflect_error else "unreadable"})
                        return
                    self.reply(200, {**stub.messages[(matched[1], matched[2])], **stub.read_patch})
                    return
                self.reject(404, "unexpected GET path or message")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:{}/api/v10".format(self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def owner_channel(self, identifier, instance, level, name=None):
        self.channels[identifier] = {"id": identifier, "guild_id": self.guild_id,
                                     "name": name or instance.lower(), "type": 0}
        self.expected_hellos[identifier] = "laneboss: owner channel ready for {} (L{}).".format(instance, level)


class OrgDiscordTests(support.LauncherTest):
    def setUp(self):
        super().setUp()
        # HTTP test-stub routing is absent from the release launcher.
        self.command = support.faults_binary()
        self.guild, self.owner, self.decider, self.informer = [snowflake() for _ in range(4)]
        self.decide_group, self.inform_group, self.stranger = [snowflake() for _ in range(3)]
        self.channel_a, self.channel_b = snowflake(), snowflake()
        self.bot_value = uuid.uuid4().hex + "." + uuid.uuid4().hex
        self.secret_name = "TEST_BOT_" + uuid.uuid4().hex.upper()
        self.org = self.directory / "example-org"
        self.org_home = self.org / ".laneboss"
        (self.org_home / "instances").mkdir(parents=True)
        self.roles_file = self.org_home / "shared/services/discord-roles.toml"
        self.secret_file = self.directory / "private-store.toml"
        self.secret_file.write_text(self.secret_name + " = " + json.dumps(self.bot_value) +
                                    '\nOTHER_BOT_NAME = "' + uuid.uuid4().hex + '"\n', encoding="utf-8")
        self.secret_file.chmod(0o600)
        self.write_org()
        for instance, level in (("L6-root", 6), ("L5-topic", 5), ("L4-review", 4), ("L3-work", 3)):
            self.write_instance(instance, level)
        self.stub = DiscordStub(self.guild, self.bot_value)
        self.addCleanup(self.stub.close)
        self.environment["LANEBOSS_TEST_DISCORD_BASE_URL"] = self.stub.base
        self.stub.owner_channel(self.channel_a, "L5-topic", 5, "owner-topic")
        self.stub.owner_channel(self.channel_b, "L6-root", 6, "owner-root")

    def tearDown(self):
        self.assertEqual(self.stub.protocol_errors, [], "the REST fixture rejected a request")
        self.assertFalse(any(self.stub.argv_exposure), "a live CLI argv was unreadable or contained the bot token")
        super().tearDown()

    def write_org(self, *, owner=True):
        text = '[services.discord]\nguild_id = ' + json.dumps(self.guild) + '\ntoken_secret = ' + json.dumps(self.secret_name)
        if owner:
            text += '\nowner_id = ' + json.dumps(self.owner)
        text += '\n\n[secret_store]\nkind = "file"\npath = ' + json.dumps(str(self.secret_file)) + '\n'
        (self.org_home / "org.toml").write_text(text, encoding="utf-8")

    def write_instance(self, name, level, channel=None):
        path = self.org_home / "instances" / name / "instance.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        text = '# Keep these notes and nested services.\nname = ' + json.dumps(name) + '\nlevel = ' + str(level)
        text += '\nrole = "supervisor"\nnotes = "Unicode notes: 規則"\n'
        if channel is not None:
            text += 'discord_channel_id = ' + json.dumps(channel) + '\n'
        text += '\n[services]\nforms = true\nhistory = ["own", "peer"]\n'
        path.write_text(text, encoding="utf-8")
        return path

    def cli(self, instance="L5-topic", *options, code=0, environment=None):
        argv = [str(self.command), "org", "channel", "add", str(self.org), instance, *map(str, options)]
        self.assertTrue(all(self.bot_value not in argument for argument in argv), "token in test launch argv")
        with subprocess.Popen(argv, cwd=self.directory, env=environment or self.environment,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8") as process:
            self.stub.active_pid = process.pid
            try:
                stdout, stderr = process.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                self.fail("org channel command timed out")
            finally:
                self.stub.active_pid = None
            result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
        self.assertTrue(self.bot_value not in result.stdout + result.stderr, "bot token leaked; output withheld")
        self.assertEqual(result.returncode, code, "unexpected CLI exit: " + result.stderr)
        return result

    def add_a(self, *options):
        return json.loads(self.cli("L5-topic", "--channel-id", self.channel_a, *options).stdout)

    def add_b(self, *options):
        return json.loads(self.cli("L6-root", "--channel-id", self.channel_b, *options).stdout)

    def probe(self, operation, message=None, *, code=0, channel_names=None):
        library = self.command.resolve().parent.parent / "lib"
        argv = [sys.executable, "-I", "-B", str(Path(__file__).with_name("discordprobe.py")),
                str(library), operation, str(self.org)]
        if message is not None:
            path = self.directory / "message.json"
            path.write_text(json.dumps(message, ensure_ascii=False), encoding="utf-8")
            argv.extend(["--message", str(path)])
        if channel_names is not None:
            path = self.directory / "channel-names.json"
            path.write_text(json.dumps(channel_names), encoding="utf-8")
            argv.extend(["--channel-names", str(path)])
        result = subprocess.run(argv, cwd=self.directory, env=self.environment, capture_output=True,
                                text=True, encoding="utf-8", timeout=30)
        self.assertTrue(self.bot_value not in result.stdout + result.stderr, "bot token leaked; output withheld")
        self.assertEqual(result.returncode, code, "Discord API probe failed: " + result.stderr)
        return result

    def roles(self):
        return tomllib.loads(self.roles_file.read_text(encoding="utf-8"))["roles"]

    def snapshot(self):
        return {str(path.relative_to(self.org)): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in self.org.rglob("*") if path.is_file()}

    def write_roles(self, roles):
        # An independent fixture writer, so corruption tests never rely on the
        # product renderer agreeing with its own reader.
        lines = ["schema_version = 1", ""]
        for name, entry in roles.items():
            lines.append("[roles." + json.dumps(name) + "]")
            for key, value in entry.items():
                if key != "members":
                    lines.append(key + " = " + json.dumps(value, ensure_ascii=False))
            if "members" in entry:
                lines.append("members = [")
                for member in entry["members"]:
                    lines.append("  { " + ", ".join(key + " = " + json.dumps(value)
                                                     for key, value in member.items()) + " },")
                lines.append("]")
            lines.append("")
        self.roles_file.parent.mkdir(parents=True, exist_ok=True)
        self.roles_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def message(self, sender=None, channel=None, *, groups=None):
        return {"id": snowflake(), "channel_id": channel or self.channel_a,
                "author": {"id": sender or self.decider, "username": "user-handle", "global_name": "Global name"},
                "member": {"nick": "Channel display 🙂", "roles": groups or []},
                "content": "Keep this verbatim: 規則\nsecond line 🙂",
                "message_reference": {"message_id": snowflake()}}

    def test_l3_and_l4_refusal_precedes_secrets(self):
        self.secret_file.unlink()
        before = self.snapshot()
        for instance in ("L3-work", "L4-review"):
            with self.subTest(instance=instance):
                result = self.cli(instance, "--channel-id", self.channel_a, code=2)
                self.assertIn("L5 or L6", result.stderr)
                self.assertIn("L3/L4", result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.stub.requests, [])

    def test_mode_a_writes_both_files_and(self):
        for instance, level, channel, name in (("L5-topic", 5, self.channel_a, "owner-topic"),
                                              ("L6-root", 6, self.channel_b, "owner-root")):
            with self.subTest(instance=instance):
                path = self.org_home / "instances" / instance / "instance.toml"
                before = path.read_bytes()
                result = json.loads(self.cli(instance, "--channel-id", channel,
                    "--member", self.decider + ":decide", "--member", self.informer + ":inform",
                    "--role-id", self.inform_group + ":inform").stdout)
                self.assertTrue(result["verified"])
                self.assertEqual(result["channel_id"], channel)
                self.assertEqual(result["channel_name"], name)
                self.assertTrue(path.read_bytes().endswith(before), "instance notes or services changed")
                config = tomllib.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(config["discord_channel_id"], channel)
                self.assertEqual(config["services"], {"forms": True, "history": ["own", "peer"]})
                role = self.roles()[instance]
                self.assertEqual(role["instance"], instance)
                self.assertEqual(role["channel_id"], channel)
                self.assertEqual(role["channel_name"], name)
                self.assertEqual(role["state_file"], "owner-discord." + instance + ".state.json")
                self.assertEqual(role["events_file"], "owner-discord.events." + instance + ".jsonl")
                self.assertEqual(role["form_doorbell"], "owner-form." + instance)
                self.assertCountEqual(role["members"], [
                    {"user_id": self.decider, "authority": "decide"}, {"user_id": self.informer, "authority": "inform"},
                    {"role_id": self.inform_group, "authority": "inform"}, {"user_id": self.owner, "authority": "decide"}])
                key = (channel, result["hello_message_id"])
                self.assertIn(key, self.stub.messages)
                expected_paths = [("GET", "/api/v10/channels/" + channel),
                                  ("POST", "/api/v10/channels/" + channel + "/messages"),
                                  ("GET", "/api/v10/channels/" + channel + "/messages/" + key[1])]
                self.assertEqual([(row["method"], row["path"]) for row in self.stub.requests[-3:]], expected_paths)
                self.assertEqual(role["hello_message_id"], key[1])
        self.assertEqual(set(self.roles()), {"L5-topic", "L6-root"})
        self.assertEqual(json.loads(self.probe("validate").stdout), {"valid": True, "failures": []})
        self.assertTrue(self.stub.argv_exposure, "the live process argv check never ran")

    def test_mode_b_creates_with_the_configured(self):
        self.stub.expected_create = ("l5-topic", "laneboss: owner channel ready for L5-topic (L5).")
        first = json.loads(self.cli("L5-topic", "--create").stdout)
        self.assertFalse(first["reused"])
        self.assertTrue(first["verified"])
        self.assertIn(first["channel_id"], self.stub.channels)
        self.assertNotIn(first["channel_id"], (self.channel_a, self.channel_b))
        self.assertEqual(self.stub.requests[0], {"method": "POST", "path": "/api/v10/guilds/" + self.guild + "/channels",
                                                "body": {"name": "l5-topic", "type": 0}})
        before = self.snapshot()
        again = json.loads(self.cli("L5-topic", "--create").stdout)
        self.assertTrue(again["reused"])
        self.assertEqual(again["channel_id"], first["channel_id"])
        self.assertEqual(again["hello_message_id"], first["hello_message_id"])
        self.assertEqual(again["changes"], [])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(sum(row["path"].endswith("/channels") for row in self.stub.requests), 1)
        self.assertEqual(sum(row["method"] == "POST" and row["path"].endswith("/messages")
                             for row in self.stub.requests), 1)

    def test_create_403_is_clear_and_never(self):
        self.stub.expected_create = ("l5-topic", "laneboss: owner channel ready for L5-topic (L5).")
        self.stub.create_status = 403
        self.stub.reflect_error = True
        before = self.snapshot()
        result = self.cli("L5-topic", "--create", code=2)
        self.assertIn("HTTP 403", result.stderr)
        self.assertIn("Manage Channels", result.stderr)
        self.assertIn("--channel-id", result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(len(self.stub.requests), 1)
        self.assertEqual(self.stub.messages, {})

    def test_dry_run_changes_nothing_and_does(self):
        self.secret_file.unlink()
        before = self.snapshot()
        for options in (("--channel-id", self.channel_a), ("--create",)):
            with self.subTest(options=options):
                result = json.loads(self.cli("L5-topic", *options, "--member", self.informer + ":inform", "--dry-run").stdout)
                self.assertTrue(result["dry_run"])
                self.assertEqual({row["file"] for row in result["changes"]},
                                 {".laneboss/shared/services/discord-roles.toml", ".laneboss/instances/L5-topic/instance.toml"})
                after = result["changes"][0]["after"]
                self.assertIn({"user_id": self.informer, "authority": "inform"}, after["members"])
                self.assertEqual(after["hello_message_id"], "<posted-message-id>")
                self.assertEqual([row["method"] for row in result["requests"]],
                                 ["GET", "POST", "GET"] if len(options) == 2 else ["POST", "POST", "GET"])
                self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.stub.requests, [])

    def test_mode_a_rerun_preserves_files_and(self):
        first = self.add_a("--member", self.informer + ":inform")
        before = self.snapshot()
        again = self.add_a("--member", self.informer + ":inform")
        self.assertTrue(again["reused"])
        self.assertEqual(again["hello_message_id"], first["hello_message_id"])
        self.assertEqual(again["changes"], [])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(len(self.stub.messages), 1)
        self.assertEqual([row["method"] for row in self.stub.requests], ["GET", "POST", "GET", "GET", "GET"])
        count = len(self.stub.requests)
        dry = json.loads(self.cli("L5-topic", "--create", "--dry-run").stdout)
        self.assertEqual(dry["changes"], [])
        self.assertEqual([row["method"] for row in dry["requests"]], ["GET", "GET"])
        self.assertEqual(len(self.stub.requests), count)
        self.assertEqual(self.snapshot(), before)

    def test_unchanged_repeat_preserves_roles(self):
        self.add_a()
        content = self.roles_file.read_bytes()
        self.roles_file.write_bytes(b"# Retain the shared service notes.\n\n" + content + b"\n# End of roles.\n")
        before = self.snapshot()
        result = self.add_a()
        self.assertEqual(result["changes"], [])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(len(self.stub.messages), 1)

    def test_failed_read_back_retries_the_same(self):
        self.stub.read_status = 503
        self.cli("L5-topic", "--channel-id", self.channel_a, code=2)
        message_id = self.roles()["L5-topic"]["hello_message_id"]
        self.stub.read_status = 200
        result = self.add_a()
        self.assertTrue(result["verified"])
        self.assertEqual(result["hello_message_id"], message_id)
        self.assertEqual(len(self.stub.messages), 1)
        self.assertEqual(sum(row["method"] == "POST" for row in self.stub.requests), 1)

    def test_partial_instance_binding_is(self):
        path = self.org_home / "instances/L5-topic/instance.toml"
        original = path.read_bytes()
        first = self.add_a()
        path.write_bytes(original)
        self.assertFalse(json.loads(self.probe("validate").stdout)["valid"])
        count = len(self.stub.requests)
        result = json.loads(self.cli("L5-topic", "--create").stdout)
        self.assertTrue(result["reused"])
        self.assertTrue(result["verified"])
        self.assertEqual(result["hello_message_id"], first["hello_message_id"])
        self.assertEqual([row["method"] for row in self.stub.requests[count:]], ["GET", "GET"])
        self.assertEqual(tomllib.loads(path.read_text(encoding="utf-8"))["discord_channel_id"], self.channel_a)
        self.assertTrue(path.read_bytes().endswith(original))

    def test_read_back_checks_message_id(self):
        self.add_a()
        patches = ({"id": snowflake()}, {"channel_id": self.channel_b}, {"content": self.bot_value},
                   {"author": {"id": self.owner, "bot": False}})
        for patch in patches:
            with self.subTest(field=next(iter(patch))):
                self.stub.read_patch = patch
                result = self.cli("L5-topic", "--channel-id", self.channel_a, code=2)
                self.assertIn("hello verification failed", result.stderr)
        self.assertEqual(len(self.stub.messages), 1)

    def test_event_decide_inform_stranger_and(self):
        self.add_a("--member", self.decider + ":decide", "--member", self.informer + ":inform",
                   "--role-id", self.decide_group + ":decide")
        for sender, authority, groups in ((self.decider, "decide", []),
                                           (self.informer, "inform", [self.decide_group]), (self.owner, "decide", [])):
            with self.subTest(authority=authority, sender=sender):
                message = self.message(sender, groups=groups)
                result = json.loads(self.probe("event", message).stdout)
                expected = {"role": "L5-topic", "instance": "L5-topic",
                            "channel": {"id": self.channel_a, "name": "owner-topic"},
                            "author": {"id": sender, "display_name": "Channel display 🙂", "authority": authority},
                            "message_id": message["id"], "text": message["content"],
                            "reply_to": message["message_reference"]["message_id"]}
                self.assertEqual(result, expected)
                line = json.loads(self.probe("line", message).stdout)
                self.assertEqual(line.count("\n"), 1)
                self.assertTrue(line.endswith("\n"))
                self.assertEqual(json.loads(line), expected)
        stranger = self.message(self.stranger)
        probe = self.probe("event", stranger)
        self.assertEqual(json.loads(probe.stdout), "drop")
        self.assertIn("sender is not listed", probe.stderr)
        self.assertNotIn(stranger["content"], probe.stderr)
        self.assertEqual(json.loads(self.probe("line", stranger).stdout), "drop")

    def test_server_roles_and_channel_scoping(self):
        self.add_a("--role-id", self.decide_group + ":decide", "--role-id", self.inform_group + ":inform")
        self.add_b()
        for groups, authority in (([self.decide_group], "decide"), ([self.inform_group], "inform"),
                                  ([self.inform_group, self.decide_group], "decide")):
            with self.subTest(groups=groups):
                message = self.message(self.stranger, groups=groups)
                message["member"].pop("nick")
                event = json.loads(self.probe("event", message, channel_names={self.channel_a: "renamed-topic"}).stdout)
                self.assertEqual(event["author"]["authority"], authority)
                self.assertEqual(event["author"]["display_name"], "Global name")
                self.assertEqual(event["channel"]["name"], "renamed-topic")
        message = self.message(self.stranger, self.channel_b, groups=[self.decide_group])
        self.assertEqual(json.loads(self.probe("event", message).stdout), "drop")
        message = self.message(self.stranger)
        message["content"] = "My role id is " + self.decide_group
        self.assertEqual(json.loads(self.probe("event", message).stdout), "drop")
        message = self.message(self.owner)
        message.pop("message_reference")
        self.assertIsNone(json.loads(self.probe("event", message).stdout)["reply_to"])

    def test_bots_webhooks_unknown_channels_and(self):
        self.add_a()
        cases = []
        for patch in ({"channel_id": snowflake()}, {"webhook_id": snowflake()}, {"content": []},
                      {"message_reference": []}, {"id": "bad-id"}, {"member": None}):
            cases.append({**self.message(self.owner), **patch})
        bot = self.message(self.owner)
        bot["author"]["bot"] = True
        cases.append(bot)
        for message in cases:
            with self.subTest(fields=list(message)):
                result = self.probe("event", message)
                self.assertEqual(json.loads(result.stdout), "drop")
                self.assertIn("drop Discord message", result.stderr)

    def test_validate_requires_complete_l5_l6(self):
        result = json.loads(self.probe("validate").stdout)
        self.assertFalse(result["valid"])
        self.assertEqual(len(result["failures"]), 2)
        self.add_a()
        self.assertFalse(json.loads(self.probe("validate").stdout)["valid"])
        self.add_b()
        self.assertEqual(json.loads(self.probe("validate").stdout), {"valid": True, "failures": []})
        self.secret_file.unlink()
        self.assertEqual(json.loads(self.probe("validate").stdout), {"valid": True, "failures": []})

    def test_validate_rejects_lower_level(self):
        self.add_a()
        self.add_b()
        for name, level in (("L3-work", 3), ("L4-review", 4)):
            with self.subTest(level=level):
                self.write_instance(name, level, snowflake())
                result = json.loads(self.probe("validate").stdout)
                self.assertFalse(result["valid"])
                self.assertIn("L3/L4", " ".join(result["failures"]))
                self.write_instance(name, level)
        self.write_instance("L5-topic", 5, self.channel_b)
        result = json.loads(self.probe("validate").stdout)
        self.assertFalse(result["valid"])
        self.assertIn("disagree", " ".join(result["failures"]))

    def test_reader_and_validate_reject_invalid(self):
        self.add_a()
        self.add_b()
        original = self.roles()
        mutations = []
        for authority in (None, "admin", 5):
            roles = copy.deepcopy(original)
            if authority is None:
                roles["L5-topic"]["members"][0].pop("authority")
            else:
                roles["L5-topic"]["members"][0]["authority"] = authority
            mutations.append(("authority", roles))
        roles = copy.deepcopy(original)
        roles["duplicate"] = copy.deepcopy(roles["L5-topic"])
        mutations.append(("duplicate instance", roles))
        roles = copy.deepcopy(original)
        roles["L6-root"]["channel_id"] = self.channel_a
        mutations.append(("duplicate channel", roles))
        roles = copy.deepcopy(original)
        roles["L5-topic"]["instance"] = "L4-review"
        mutations.append(("lower level role", roles))
        roles = copy.deepcopy(original)
        roles["L5-topic"]["members"] = []
        mutations.append(("empty members", roles))
        roles = copy.deepcopy(original)
        roles["L5-topic"]["events_file"] = "../outside.jsonl"
        mutations.append(("outside events file", roles))
        for label, roles in mutations:
            with self.subTest(rule=label):
                self.write_roles(roles)
                result = json.loads(self.probe("validate").stdout)
                self.assertFalse(result["valid"], label + " was accepted")
                self.assertTrue(result["failures"])
                self.probe("read", code=2)
        self.write_roles(original)
        self.assertTrue(json.loads(self.probe("validate").stdout)["valid"])

    def test_members_can_be_added_without(self):
        first = self.add_a("--member", self.informer + ":inform")
        second = self.add_a("--member", self.decider + ":decide", "--role-id", self.inform_group + ":inform")
        self.assertEqual(second["hello_message_id"], first["hello_message_id"])
        members = self.roles()["L5-topic"]["members"]
        self.assertCountEqual(members, [{"user_id": self.informer, "authority": "inform"},
            {"user_id": self.decider, "authority": "decide"}, {"user_id": self.owner, "authority": "decide"},
            {"role_id": self.inform_group, "authority": "inform"}])
        self.assertEqual(len(self.stub.messages), 1)

    def test_rebinding_duplicate_channels_bad(self):
        self.add_a()
        before = self.snapshot()
        count = len(self.stub.requests)
        cases = (("L5-topic", ("--channel-id", self.channel_b)),
                 ("L6-root", ("--channel-id", self.channel_a)),
                 ("L5-topic", ("--channel-id", self.channel_a, "--member", self.owner + ":inform")),
                 ("L5-topic", ("--channel-id", self.channel_a, "--member", self.decider + ":admin")),
                 ("L5-topic", ("--channel-id", self.channel_a, "--role-id", "bad-id:decide")))
        for instance, options in cases:
            with self.subTest(instance=instance, options=options):
                self.cli(instance, *options, code=2)
                self.assertEqual(self.snapshot(), before)
        self.assertEqual(len(self.stub.requests), count)

    def test_role_only_registration_and_empty(self):
        self.write_org(owner=False)
        result = self.cli("L5-topic", "--channel-id", self.channel_a, code=2)
        self.assertIn("at least one", result.stderr)
        self.assertEqual(self.stub.requests, [])
        self.add_a("--role-id", self.inform_group + ":inform")
        self.assertEqual(self.roles()["L5-topic"]["members"], [{"role_id": self.inform_group, "authority": "inform"}])
        event = json.loads(self.probe("event", self.message(self.stranger, groups=[self.inform_group])).stdout)
        self.assertEqual(event["author"]["authority"], "inform")

    def test_credentials_stay_named_and(self):
        self.secret_file.chmod(0o644)
        result = self.cli("L5-topic", "--channel-id", self.channel_a, code=2)
        self.assertIn("mode 600", result.stderr)
        self.assertEqual(self.stub.requests, [])
        self.secret_file.chmod(0o600)
        self.stub.post_status = 403
        self.stub.reflect_error = True
        self.environment["LANEBOSS_DEBUG"] = "1"
        result = self.cli("L5-topic", "--channel-id", self.channel_a, code=2)
        self.assertIn("HTTP 403", result.stderr)
        self.assertEqual(len(self.stub.messages), 0)
        for path in self.org.rglob("*.toml"):
            self.assertTrue(self.bot_value not in path.read_text(encoding="utf-8"),
                            "token was written into org configuration")
        self.assertIn(self.secret_name, (self.org_home / "org.toml").read_text(encoding="utf-8"))

    def test_reflected_channel_secret_wrong(self):
        before = self.snapshot()
        for patch in ({"name": self.bot_value}, {"guild_id": snowflake()}, {"type": 2}, {"type": False}):
            with self.subTest(field=next(iter(patch))):
                self.stub.channel_patch = patch
                self.cli("L5-topic", "--channel-id", self.channel_a, code=2)
                self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.stub.messages, {})

    def test_unicode_channel_names_round_trip(self):
        self.stub.channel_patch = {"name": "owner-規則-🙂"}
        first = self.add_a()
        self.assertEqual(first["channel_name"], "owner-規則-🙂")
        self.assertEqual(json.loads(self.probe("read").stdout)["L5-topic"]["channel_name"], "owner-規則-🙂")
        before = self.snapshot()
        second = self.add_a()
        self.assertEqual(second["changes"], [])
        self.assertEqual(self.snapshot(), before)

    def test_malformed_http_status_does_not(self):
        self.stub.malformed_status = True
        self.environment["LANEBOSS_DEBUG"] = "1"
        result = self.cli("L5-topic", "--channel-id", self.channel_a, code=2)
        self.assertIn("could not be completed", result.stderr)
        self.assertFalse(self.roles_file.exists())

    def test_test_endpoint_is_loopback_only_and(self):
        for base in ("https://discord.com/api/v10", "http://[2001:db8::1]:8000/api/v10",
                     self.stub.base + "?token=placeholder", self.stub.base.replace("/api/v10", "/wrong")):
            with self.subTest(base=base):
                environment = dict(self.environment)
                environment["LANEBOSS_TEST_DISCORD_BASE_URL"] = base
                result = self.cli("L5-topic", "--channel-id", self.channel_a, code=2, environment=environment)
                self.assertIn("localhost", result.stderr)
        self.assertEqual(self.stub.requests, [])
        self.stub.redirect = True
        result = self.cli("L5-topic", "--channel-id", self.channel_a, code=2)
        self.assertIn("redirects are refused", result.stderr)
        self.assertEqual(len(self.stub.requests), 1)

    def test_stub_refuses_wrong_authorization(self):
        # These negative controls prove this server cannot accept arbitrary calls.
        request = urllib.request.Request(self.stub.base + "/channels/" + self.channel_a)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 401)
        request = urllib.request.Request(self.stub.base + "/channels/" + self.channel_a + "/messages",
            data=json.dumps({"content": "wrong text"}).encode(), method="POST",
            headers={"Authorization": "Bot " + self.bot_value, "Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 422)
        request = urllib.request.Request(self.stub.base + "/channels/" + self.channel_a + "/messages/" + snowflake(),
                                         headers={"Authorization": "Bot " + self.bot_value})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 404)
        self.assertEqual(self.stub.protocol_errors, ["wrong bot authorization", "wrong message-post payload",
                                                   "unexpected GET path or message"])
        self.stub.protocol_errors.clear()


if __name__ == "__main__":
    import unittest
    unittest.main()
