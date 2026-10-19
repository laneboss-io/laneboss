"""Black-box Discord gateway rows, for a disposable Linux box only.

Discord itself cannot be reached from this test. A loopback REST/WebSocket
server checks bot authorization, intents, session, sequence, and heartbeat.
The installed Go launcher reads real org TOML; only Discord is doubled.
Python 3.11+ and Node 22+ suffice; no Python or Node packages are required.

LANEBOSS_GATEWAY_BINARY names the absolute launcher built from this checkout.
LANEBOSS_GATEWAY_SCRIPT can name the absolute installed gateway asset.
LANEBOSS_GATEWAY_EVIDENCE optionally names an absolute evidence directory.
Inputs, source/binary bytes, hashes, exits, logs and state are retained.
Synthetic token and dropped-message canaries live only in memory, never in
saved inputs. The mutant edits an isolated copy, never the checkout.

Rows: python3 e2e-rows/test_discord_gateway.py GatewayRows.test_receive
Mutant: python3 e2e-rows/test_discord_gateway.py GatewayRows.test_bot_mutant
"""

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit
import uuid


ROOT = Path(__file__).resolve().parents[1]
GATEWAY = Path(os.environ.get("LANEBOSS_GATEWAY_SCRIPT", str(ROOT / "integrations/discord/gateway.mjs")))
INTENTS = 1 | 2 | 512 | 32768
BOT_FILTER = "if (author.bot) return drop('bot sender');"


def snowflake():
    return str(secrets.randbelow(8 * 10**17) + 10**17)


def read_exact(stream, count):
    data = stream.read(count)
    if len(data) != count:
        raise EOFError("WebSocket peer ended")
    return data


def frame(payload, opcode=1, masked=False):
    first = bytes([0x80 | opcode])
    size = len(payload)
    flag = 0x80 if masked else 0
    if size < 126:
        header = bytes([flag | size])
    elif size < 65536:
        header = bytes([flag | 126]) + struct.pack("!H", size)
    else:
        header = bytes([flag | 127]) + struct.pack("!Q", size)
    if masked:
        mask = secrets.token_bytes(4)
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        return first + header + mask + payload
    return first + header + payload


def read_frame(stream, require_mask):
    first, second = read_exact(stream, 2)
    if not first & 0x80 or first & 0x70:
        raise ValueError("unexpected fragmented or compressed client frame")
    masked = bool(second & 0x80)
    if masked != require_mask:
        raise ValueError("wrong WebSocket masking")
    size = second & 0x7F
    if size == 126:
        size = struct.unpack("!H", read_exact(stream, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", read_exact(stream, 8))[0]
    if size > 1024 * 1024:
        raise ValueError("oversized WebSocket frame")
    mask = read_exact(stream, 4) if masked else None
    payload = read_exact(stream, size)
    if mask:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return first & 0x0F, payload


class Connection:
    def __init__(self, transport):
        self.transport = transport
        self.lock = threading.Lock()

    def send(self, packet):
        payload = json.dumps(packet, ensure_ascii=False).encode()
        with self.lock:
            self.transport.sendall(frame(payload))

    def close(self, code):
        with self.lock:
            self.transport.sendall(frame(struct.pack("!H", code), opcode=8))


class FakeDiscord:
    def __init__(self, token):
        self.token = token
        self.session = "session-" + uuid.uuid4().hex
        self.sequence = 0
        self.resume_from = None
        self.connection = None
        self.history = []
        self.accepted = []
        self.failures = []
        self.trace = []
        self.condition = threading.Condition()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                # Neither HTTP headers nor gateway payloads enter a log.
                return

            def do_GET(self):
                parsed = urlsplit(self.path)
                if parsed.path == "/api/v10/gateway/bot":
                    good = self.headers.get("Authorization") == "Bot " + fake.token
                    fake.trace.append({"rest_authorized": good})
                    data = {"url": fake.url + "/gateway"} if good else {"error": "bad authorization"}
                    payload = json.dumps(data).encode()
                    self.send_response(200 if good else 403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if parsed.path not in {"/gateway", "/resume"}:
                    self.send_error(404)
                    return
                if (parse_qs(parsed.query) != {"v": ["10"], "encoding": ["json"]} or
                        self.headers.get("Upgrade", "").lower() != "websocket" or
                        self.headers.get("Sec-WebSocket-Version") != "13"):
                    self.send_error(400)
                    return
                key = self.headers.get("Sec-WebSocket-Key", "")
                try:
                    valid_key = len(base64.b64decode(key, validate=True)) == 16
                except ValueError:
                    valid_key = False
                if not valid_key:
                    self.send_error(400)
                    return
                accept = base64.b64encode(hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                ).digest()).decode()
                self.send_response(101)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", accept)
                self.end_headers()
                self.wfile.flush()
                connection = Connection(self.connection)
                try:
                    fake.serve_gateway(connection, self.rfile, parsed.path)
                except (EOFError, ConnectionError, OSError):
                    # Closing a peer is part of the test; protocol errors are not.
                    fake.trace.append({"peer_closed": True})
                except (ValueError, TypeError, KeyError, json.JSONDecodeError):
                    fake.failures.append("malformed client protocol")
                finally:
                    with fake.condition:
                        if fake.connection is connection:
                            fake.connection = None
                        fake.condition.notify_all()
                    self.close_connection = True

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.url = "ws://127.0.0.1:" + str(self.port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def serve_gateway(self, connection, stream, endpoint):
        connection.send({"op": 10, "d": {"heartbeat_interval": 250}})
        authenticated = False
        while True:
            opcode, payload = read_frame(stream, require_mask=True)
            if opcode == 8:
                connection.close(1000)
                return
            if opcode == 9:
                with connection.lock:
                    connection.transport.sendall(frame(payload, opcode=10))
                continue
            if opcode != 1:
                raise ValueError("unexpected opcode")
            packet = json.loads(payload)
            op, data = packet["op"], packet["d"]
            if op == 1:
                if data is not None and (not isinstance(data, int) or data > self.sequence):
                    self.failures.append("invalid heartbeat sequence")
                self.trace.append({"heartbeat": data})
                connection.send({"op": 11, "d": None})
                continue
            if op not in {2, 6} or authenticated or not isinstance(data, dict):
                raise ValueError("unexpected client gateway packet")
            if data.get("token") != self.token:
                connection.close(4004)
                self.trace.append({"refused": "token"})
                return
            if op == 2:
                properties = data.get("properties", {})
                if (endpoint != "/gateway" or data.get("intents") != INTENTS or
                        properties.get("os") != "linux" or
                        properties.get("browser") != "laneboss" or
                        properties.get("device") != "laneboss"):
                    connection.close(4013)
                    self.trace.append({"refused": "identify"})
                    return
            elif (endpoint != "/resume" or data.get("session_id") != self.session or
                  self.resume_from is None or data.get("seq") != self.resume_from):
                connection.close(4007)
                self.trace.append({"refused": "resume"})
                return
            authenticated = True
            with self.condition:
                if op == 2:
                    self.sequence += 1
                    connection.send({"op": 0, "t": "READY", "s": self.sequence,
                                     "d": {"session_id": self.session,
                                           "resume_gateway_url": self.url + "/resume"}})
                else:
                    # Replay the boundary message too: client must not duplicate it.
                    for event in self.history:
                        if event["s"] >= self.resume_from:
                            connection.send(event)
                    self.sequence += 1
                    connection.send({"op": 0, "t": "RESUMED", "s": self.sequence, "d": {}})
                self.connection = connection
                self.accepted.append({"op": op, "seq": data.get("seq"), "path": endpoint})
                self.trace.append(self.accepted[-1])
                self.condition.notify_all()

    def wait_connections(self, count):
        with self.condition:
            return self.condition.wait_for(lambda: len(self.accepted) >= count, timeout=15)

    def dispatch(self, message):
        with self.condition:
            self.sequence += 1
            event = {"op": 0, "t": "MESSAGE_CREATE", "s": self.sequence, "d": message}
            self.history.append(event)
            if self.connection is not None:
                self.connection.send(event)
            return self.sequence

    def disconnect(self):
        with self.condition:
            if self.connection is None:
                raise RuntimeError("no live fake gateway")
            self.resume_from = self.sequence
            self.connection.close(1001)
            self.connection = None

    def stop(self):
        with self.condition:
            if self.connection is not None:
                self.connection.close(1000)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def reject_packet(self, packet, expected_code, endpoint="/gateway"):
        # An independent raw client proves this fake refuses invalid identifies.
        transport = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        stream = transport.makefile("rb")
        try:
            key = base64.b64encode(secrets.token_bytes(16)).decode()
            request = (
                "GET " + endpoint + "?v=10&encoding=json HTTP/1.1\r\n"
                "Host: 127.0.0.1:" + str(self.port) + "\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n\r\n"
            )
            transport.sendall(request.encode())
            status = stream.readline()
            if b" 101 " not in status:
                raise AssertionError("fake rejected a valid WebSocket handshake")
            while True:
                header = stream.readline()
                if header == b"\r\n":
                    break
                if not header:
                    raise AssertionError("fake WebSocket handshake ended early")
            opcode, hello = read_frame(stream, require_mask=False)
            if opcode != 1 or json.loads(hello).get("op") != 10:
                raise AssertionError("fake did not send HELLO")
            transport.sendall(frame(json.dumps(packet).encode(), masked=True))
            opcode, payload = read_frame(stream, require_mask=False)
            if opcode != 8 or struct.unpack("!H", payload[:2])[0] != expected_code:
                raise AssertionError("fake accepted an invalid authentication packet")
        finally:
            stream.close()
            transport.close()

    def negative_controls(self):
        rest = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            rest.request("GET", "/api/v10/gateway/bot", headers={"Authorization": "Bot incorrect"})
            response = rest.getresponse()
            if response.status != 403:
                raise AssertionError("fake REST accepted wrong authorization")
            response.read()
        finally:
            rest.close()
        properties = {"os": "linux", "browser": "laneboss", "device": "laneboss"}
        self.reject_packet({"op": 2, "d": {"token": "incorrect", "intents": INTENTS,
                                           "properties": properties}}, 4004)
        self.reject_packet({"op": 2, "d": {"token": self.token, "intents": 0,
                                           "properties": properties}}, 4013)
        self.reject_packet({"op": 6, "d": {"token": self.token,
                                           "session_id": self.session, "seq": -1}},
                           4007, endpoint="/resume")


class GatewayRows(unittest.TestCase):
    def setUp(self):
        if sys.platform != "linux":
            raise RuntimeError("Discord gateway rows require the designated disposable Linux box")
        evidence = os.environ.get("LANEBOSS_GATEWAY_EVIDENCE")
        if evidence and not Path(evidence).is_absolute():
            raise RuntimeError("LANEBOSS_GATEWAY_EVIDENCE must be absolute")
        if evidence:
            Path(evidence).mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="lb-plug-gateway-row-", dir=evidence))
        self.home = self.root / "home"
        self.home.mkdir()
        self.binary = Path(os.environ["LANEBOSS_GATEWAY_BINARY"])
        if not self.binary.is_absolute() or not os.access(self.binary, os.X_OK):
            raise RuntimeError("LANEBOSS_GATEWAY_BINARY must name an absolute executable")
        if not GATEWAY.is_absolute() or not GATEWAY.is_file():
            raise RuntimeError("LANEBOSS_GATEWAY_SCRIPT must name an absolute gateway file")
        self.node = shutil.which("node")
        self.assertIsNotNone(self.node, "Node 22+ must be installed on the box")
        self.environment = {"HOME": str(self.home), "PATH": os.defpath, "LANG": "C.UTF-8"}
        self.token = "canary." + secrets.token_hex(16)
        self.secret_name = "ORG_BOT_" + secrets.token_hex(4).upper()
        self.guild, self.owner, self.informer, self.stranger = [snowflake() for _ in range(4)]
        self.group_decide, self.group_inform = snowflake(), snowflake()
        self.channels = [snowflake(), snowflake()]
        self.role_names = ["domain-" + uuid.uuid4().hex[:8] for _ in range(2)]
        self.instances = ["L5-top", "L6-super-top"]
        self.processes = []
        self.call_number = 0
        self.org = self.root / "org"
        self.cli("org", "init", self.org, "--levels", "5-6", "--name", "example")
        config = self.org / ".laneboss/org.toml"
        config.write_text(config.read_text() + (
            "\n[services.discord]\nguild_id = " + json.dumps(self.guild) +
            "\ntoken_secret = " + json.dumps(self.secret_name) +
            "\nowner_id = " + json.dumps(self.owner) + "\n"
        ))
        roles = ["schema_version = 1\n"]
        for index, (instance, role) in enumerate(zip(self.instances, self.role_names)):
            target = self.org / ".laneboss/instances" / instance / "instance.toml"
            target.write_text("discord_channel_id = " + json.dumps(self.channels[index]) +
                              "\n" + target.read_text())
            suffix = uuid.uuid4().hex[:8]
            roles.append(
                "\n[roles." + json.dumps(role) + "]\ninstance = " + json.dumps(instance) +
                "\nchannel_id = " + json.dumps(self.channels[index]) +
                "\nchannel_name = " + json.dumps("owner-話題-" + str(index), ensure_ascii=False) +
                "\nstate_file = " + json.dumps("cursor-" + suffix + ".json") +
                "\nevents_file = " + json.dumps("events-" + suffix + ".jsonl") +
                "\nform_doorbell = " + json.dumps("bell-" + suffix) +
                "\nmembers = [\n" +
                "  { user_id = " + json.dumps(self.owner) + ', authority = "decide" },\n' +
                "  { user_id = " + json.dumps(self.informer) + ', authority = "inform" },\n' +
                "  { role_id = " + json.dumps(self.group_inform) + ', authority = "inform" },\n' +
                "  { role_id = " + json.dumps(self.group_decide) + ', authority = "decide" },\n]\n'
            )
        (self.org / ".laneboss/shared/services/discord-roles.toml").write_text("".join(roles))
        self.cli("org", "render", self.org)
        self.cli("org", "validate", self.org, "--format", "json")
        before = self.snapshot(self.org)
        result = self.cli("org", "channel", "read", self.org, "--json")
        self.config = json.loads(result.stdout)
        self.assertEqual(before, self.snapshot(self.org), "configuration reader wrote org files")
        self.assertEqual(self.config["guild_id"], self.guild)
        self.assertEqual(self.config["token_env"], self.secret_name)
        self.assertEqual(set(self.config["roles"]), set(self.role_names))
        self.events = [Path(self.config["roles"][name]["events_file"]) for name in self.role_names]
        self.states = [Path(self.config["roles"][name]["state_file"]) for name in self.role_names]
        self.gateway_state = Path(self.config["gateway_state_file"])
        self.fake = FakeDiscord(self.token)
        self.addCleanup(self.fake.stop)
        self.addCleanup(self.stop_processes)
        self.fake.negative_controls()
        self.assertEqual(self.fake.accepted, [], "fake controls accidentally authenticated")
        self.gateway = GATEWAY
        shutil.copyfile(GATEWAY, self.root / "gateway.original.mjs")
        shutil.copyfile(Path(__file__), self.root / "test.row.py")
        shutil.copyfile(self.binary, self.root / "laneboss.tested")
        self.record_hashes()

    def record_hashes(self):
        records = {}
        for name in ["gateway.original.mjs", "test.row.py", "laneboss.tested"]:
            records[name] = hashlib.sha256((self.root / name).read_bytes()).hexdigest()
        (self.root / "hashes.json").write_text(json.dumps(records) + "\n")

    def snapshot(self, directory):
        return {str(item.relative_to(directory)): item.read_bytes()
                for item in directory.rglob("*") if item.is_file()}

    def cli(self, *args):
        self.call_number += 1
        argv = [str(self.binary), *map(str, args)]
        result = subprocess.run(argv, cwd=self.root, env=self.environment,
                                capture_output=True, timeout=60)
        record = self.root / ("cli-" + str(self.call_number))
        record.with_suffix(".input.json").write_text(json.dumps(argv) + "\n")
        record.with_suffix(".stdout").write_bytes(result.stdout)
        record.with_suffix(".stderr").write_bytes(result.stderr)
        record.with_suffix(".exit").write_text(str(result.returncode) + "\n")
        self.assertEqual(result.returncode, 0, "launcher operation failed; retained CLI evidence")
        return result

    def start(self, name="gateway", environment=None):
        env = dict(self.environment)
        env[self.secret_name] = self.token
        env["LANEBOSS_TEST_DISCORD_BASE_URL"] = "http://127.0.0.1:" + str(self.fake.port)
        if environment:
            env.update(environment)
        argv = [self.node, str(self.gateway), "--org", str(self.org), "--launcher", str(self.binary)]
        (self.root / (name + ".argv.json")).write_text(json.dumps(argv) + "\n")
        output = (self.root / (name + ".log")).open("wb")
        process = subprocess.Popen(argv, cwd=self.root, env=env, stdout=output, stderr=output)
        self.processes.append((process, output, name))
        if name in {"gateway", "restarted"}:
            self.active = process
        return process

    def stop_processes(self):
        failed_shutdown = False
        for process, output, name in self.processes:
            if process.poll() is None:
                process.terminate()  # This exact child PID, never a command-line pattern.
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    failed_shutdown = True
            output.close()
            (self.root / (name + ".exit")).write_text(str(process.returncode) + "\n")
        self.processes = []
        self.assertFalse(failed_shutdown, "gateway did not stop on SIGTERM")

    def wait_cursor(self, sequence):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.gateway_state.exists():
                state = json.loads(self.gateway_state.read_text())
                if state.get("last_sequence") == sequence:
                    return
            self.assertIsNone(self.active.poll(), "gateway ended before processing dispatch")
            time.sleep(0.025)
        self.fail("gateway did not advance through the fake dispatch sequence")

    def lines(self, index=0):
        if not self.events[index].exists():
            return []
        raw = self.events[index].read_bytes()
        self.assertTrue(raw.endswith(b"\n"), "JSONL event lacks final newline")
        return [json.loads(line) for line in raw.splitlines()]

    def message(self, author=None, channel=None, text=None, member_roles=None):
        return {"id": snowflake(), "guild_id": self.guild,
                "channel_id": channel or self.channels[0],
                "author": {"id": author or self.owner, "username": "account-name",
                           "global_name": "Global name", "bot": False},
                "member": {"nick": "Guild name", "roles": member_roles or []},
                "content": text if text is not None else "Keep Unicode: 中文 🧭\nsecond line\n",
                "message_reference": {"message_id": snowflake()}}

    def no_canary_leaks(self, stranger_text=None):
        token = self.token.encode()
        stranger = stranger_text.encode() if stranger_text else None
        for item in self.root.rglob("*"):
            if item.is_file():
                data = item.read_bytes()
                self.assertFalse(token in data, "token leaked to a retained file")
                if stranger:
                    self.assertFalse(stranger in data, "stranger text leaked to a file or log")
        for process, _, _ in self.processes:
            if process.poll() is None:
                argv = Path("/proc") / str(process.pid) / "cmdline"
                self.assertFalse(token in argv.read_bytes(), "token leaked to live process argv")

    def exercise(self):
        for index, endpoint in enumerate([
            "https://127.0.0.1:" + str(self.fake.port),
            "http://localhost:" + str(self.fake.port),
            "ws://example.org:" + str(self.fake.port),
            "http://127.0.0.1:0",
            "http://127.0.0.1:" + str(self.fake.port) + "/api/v10",
            "ws://127.0.0.1:" + str(self.fake.port) + "?token=withheld",
            "http://user:withheld" + "@" + "127.0.0.1:" + str(self.fake.port),
        ]):
            invalid = self.start("unsafe-" + str(index), {"LANEBOSS_TEST_DISCORD_BASE_URL": endpoint})
            self.assertNotEqual(invalid.wait(timeout=10), 0, "unsafe test endpoint was accepted")
            self.assertIn("requires a loopback", (self.root / ("unsafe-" + str(index) + ".log")).read_text())
            self.assertFalse(Path(self.config["lock_file"]).exists(), "unsafe endpoint acquired the org lock")
        self.assertEqual(self.fake.accepted, [], "unsafe endpoint reached the fake gateway")
        self.no_canary_leaks()
        process = self.start()
        self.assertTrue(self.fake.wait_connections(1), "gateway did not identify to fake Discord")
        self.assertEqual(self.fake.accepted[0]["op"], 2)
        owner = self.message(member_roles=[self.group_inform])
        sequence = self.fake.dispatch(owner)
        self.wait_cursor(sequence)
        expected = {"role": self.role_names[0], "instance": self.instances[0],
                    "channel": {"id": self.channels[0], "name": "owner-話題-0"},
                    "author": {"id": self.owner, "display_name": "Guild name", "authority": "decide"},
                    "message_id": owner["id"], "reply_to": owner["message_reference"]["message_id"],
                    "text": owner["content"]}
        self.assertEqual(self.lines(), [expected], "allowed message must append exactly one correct event")
        self.assertEqual(self.lines(1), [], "channel routing wrote another role")
        self.assertEqual(json.loads(self.states[0].read_text())["last_message_id"], owner["id"])

        stranger_text = "private-stranger-" + uuid.uuid4().hex
        cases = {}
        cases["stranger"] = self.message(author=self.stranger, text=stranger_text)
        cases["bot"] = self.message()
        cases["bot"]["author"]["bot"] = True  # Listed owner id defeats a second, incidental filter.
        cases["webhook"] = self.message()
        cases["webhook"]["webhook_id"] = snowflake()
        cases["unknown channel"] = self.message(channel=snowflake())
        cases["wrong guild"] = self.message()
        cases["wrong guild"]["guild_id"] = snowflake()
        cases["malformed content"] = self.message()
        cases["malformed content"]["content"] = {"text": "not Discord content"}
        cases["malformed member"] = self.message()
        cases["malformed member"]["member"]["roles"] = "not an array"
        for reason, message in cases.items():
            sequence = self.fake.dispatch(message)
            self.wait_cursor(sequence)
            self.assertEqual(len(self.lines()), 1, reason + " message must be dropped")
            self.assertEqual(self.lines(1), [], reason + " reached another role")
            self.no_canary_leaks(stranger_text)
        log = (self.root / "gateway.log").read_text()
        for reason in ["unlisted sender", "bot sender", "webhook sender", "unknown channel",
                       "wrong or missing guild", "malformed text", "malformed member"]:
            self.assertIn(reason, log, "drop reason is missing")

        rest_calls = sum("rest_authorized" in row for row in self.fake.trace)
        second = self.start("second")
        self.assertNotEqual(second.wait(timeout=10), 0, "second gateway acquired the same org lock")
        self.assertIn("another gateway is already running", (self.root / "second.log").read_text())
        self.assertEqual(len(self.fake.accepted), 1, "second gateway contacted the gateway")
        self.assertEqual(sum("rest_authorized" in row for row in self.fake.trace), rest_calls,
                         "second gateway made a REST request before refusing the lock")
        self.assertIsNone(process.poll(), "second start stopped the first gateway")
        self.no_canary_leaks(stranger_text)

        # Explicit inform beats a matching decide group, and routes to role two.
        informer = self.message(author=self.informer, channel=self.channels[1],
                                member_roles=[self.group_decide])
        del informer["member"]["nick"]
        informer["message_reference"] = None
        sequence = self.fake.dispatch(informer)
        self.wait_cursor(sequence)
        self.assertEqual(json.loads(self.states[1].read_text())["last_message_id"], informer["id"])
        second_event = self.lines(1)[0]
        self.assertEqual(second_event["role"], self.role_names[1])
        self.assertEqual(second_event["author"]["authority"], "inform")
        self.assertEqual(second_event["author"]["display_name"], "Global name")
        self.assertIsNone(second_event["reply_to"])
        for groups, authority in [([self.group_inform], "inform"),
                                  ([self.group_inform, self.group_decide], "decide")]:
            member = self.message(author=snowflake(), member_roles=groups)
            member["member"].pop("nick")
            member["author"].pop("global_name")
            sequence = self.fake.dispatch(member)
            self.wait_cursor(sequence)
            self.assertEqual(self.lines()[-1]["author"]["authority"], authority)
            self.assertEqual(self.lines()[-1]["author"]["display_name"], "account-name")

        # A repeated id with a NEW dispatch sequence still appends no second line.
        before = [self.lines(), self.lines(1)]
        sequence = self.fake.dispatch(owner)
        self.wait_cursor(sequence)
        self.assertEqual([self.lines(), self.lines(1)], before, "duplicate message id was appended")
        resume_from = sequence
        self.fake.disconnect()
        pending = self.message(text="Sent while disconnected: 再開\n🛰️")
        self.fake.dispatch(pending)  # Queued before RESUMED, as on Discord.
        self.assertTrue(self.fake.wait_connections(2), "gateway did not resume")
        self.assertEqual(self.fake.accepted[1], {"op": 6, "seq": resume_from, "path": "/resume"},
                         "resume must use the saved session, last sequence and resume URL")
        self.wait_cursor(self.fake.sequence)
        self.assertEqual(len(self.lines()), len(before[0]) + 1, "resume lost or doubled a message")
        self.assertEqual(self.lines()[-1]["message_id"], pending["id"])
        self.assertEqual(self.lines()[-1]["text"], pending["content"])
        self.assertEqual(json.loads(self.states[0].read_text())["last_message_id"], pending["id"])
        self.assertEqual(self.lines(1), before[1])
        self.assertEqual(len({item["message_id"] for item in self.lines()}), len(self.lines()))
        self.assertIn("resumed", (self.root / "gateway.log").read_text())
        self.no_canary_leaks(stranger_text)
        self.assertEqual(self.fake.failures, [], "fake rejected gateway protocol")
        for target in [*self.events, *self.states, self.gateway_state, Path(self.config["lock_file"])]:
            self.assertEqual(target.stat().st_mode & 0o777, 0o600, "gateway file must have mode 0600")
        self.assertTrue(any("heartbeat" in row for row in self.fake.trace), "gateway never sent a heartbeat")
        self.stop_processes()
        self.assertEqual(int((self.root / "gateway.exit").read_text()), 0, "gateway graceful shutdown failed")
        self.assertFalse(Path(self.config["lock_file"]).exists(), "gateway retained its live lock")
        # A fresh process uses the fallback token, accepts the ws origin override,
        # and reconstructs deduplication from the real log rather than its cursor.
        restarted = self.start("restarted", {
            self.secret_name: "", "DISCORD_BOT_TOKEN": self.token,
            "LANEBOSS_TEST_DISCORD_BASE_URL": self.fake.url,
        })
        self.assertTrue(self.fake.wait_connections(3), "gateway did not restart after releasing its lock")
        self.assertEqual(self.fake.accepted[2]["op"], 2, "fresh process attempted an unrecorded session resume")
        before = [self.lines(), self.lines(1)]
        self.wait_cursor(self.fake.dispatch(pending))
        self.assertEqual([self.lines(), self.lines(1)], before, "restart forgot delivered message ids")
        fresh = self.message(text="After restart: 接續\n")
        self.wait_cursor(self.fake.dispatch(fresh))
        self.assertEqual(len(self.lines()), len(before[0]) + 1, "restart lost a fresh message")
        self.assertEqual(self.lines()[-1]["message_id"], fresh["id"])
        self.assertEqual(json.loads(self.states[0].read_text())["last_message_id"], fresh["id"])
        self.assertIsNone(restarted.poll())
        self.no_canary_leaks(stranger_text)
        self.stop_processes()
        self.assertEqual(int((self.root / "restarted.exit").read_text()), 0)
        self.assertFalse(Path(self.config["lock_file"]).exists())
        self.assertEqual(self.fake.failures, [], "fake rejected restarted gateway protocol")
        (self.root / "fake.trace.json").write_text(json.dumps(self.fake.trace) + "\n")
        self.no_canary_leaks(stranger_text)

    def test_receive(self):
        """Fails on incorrect events, filters, authority, resume, lock or token exposure."""
        self.exercise()

    def test_bot_mutant(self):
        """Requires the real receive row to fail specifically when the bot filter is removed."""
        source = GATEWAY.read_text()
        self.assertEqual(source.count(BOT_FILTER), 1, "bot mutation target changed")
        mutant = self.root / "gateway.bot-mutant.mjs"
        mutant.write_text(source.replace(BOT_FILTER, "if (false && author.bot) return drop('bot sender');", 1))
        self.gateway = mutant
        with self.assertRaisesRegex(AssertionError, "bot message must be dropped"):
            self.exercise()
        (self.root / "mutant.result.txt").write_text("RED: receive row caught disabled bot filter\n")
        self.no_canary_leaks()
        print("RED: receive row caught disabled bot filter")


if __name__ == "__main__":
    unittest.main(verbosity=2)
