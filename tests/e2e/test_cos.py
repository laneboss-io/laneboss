"""Black-box tests for integrations/claudock/cos.py. A stand-in wrapper replaces Claudock through COS_CLAUDOCK.

The stand-in is written by the tests themselves. It records its arguments and standard input, then replays the lines
of a plan (good and bad ones), can sleep so a request can be interrupted, and can ignore signals. Nothing here calls
a real agent or needs Claudock.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

# A runner started as a background job has SIGINT ignored, and a child would inherit that. The signal state of the
# suite's own process is left alone (the suite imports every test module into it before any test runs): the program
# under test is started through this launcher, which takes the interrupt back in the child and then becomes the
# program, with the same process id.
LAUNCH = ("import os, signal, sys\n"
          "signal.signal(signal.SIGINT, signal.SIG_DFL)\n"
          "os.execv(sys.executable, [sys.executable] + sys.argv[1:])\n")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
COS = os.path.join(ROOT, "integrations", "claudock", "cos.py")
SAMPLE = os.path.join(HERE, "fixtures", "cos-stream.jsonl")
SID = "11111111-2222-4333-8444-555555555555"
MODEL = "claude-haiku-4-5-20251001"

FAKE = r'''#!@PYTHON@
import json, os, signal, subprocess, sys, time
d = os.environ["COS_FAKE_DIR"]
counter = os.path.join(d, "count")
n = int(open(counter).read()) if os.path.exists(counter) else 0
open(counter, "w").write(str(n + 1))
plan = json.load(open(os.path.join(d, "plan.json")))
step = plan[min(n, len(plan) - 1)]
data = b"" if step.get("noread") else sys.stdin.buffer.read()
with open(os.path.join(d, "calls.jsonl"), "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "stdin": data.decode("utf-8", "replace")}) + "\n")
signal.signal(signal.SIGINT, signal.SIG_IGN if step.get("ignore_sigint") else (lambda s, f: os._exit(130)))
if step.get("ignore_sigterm"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if step.get("second"):  # a second process of this group that ignores the interrupt; its pid goes to a file
    child = subprocess.Popen([sys.executable, "-c", "import signal, time\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\ntime.sleep(60)"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    open(os.path.join(d, step["second"]), "w").write(str(child.pid))
if step.get("tool"):  # a shell-tool stand-in: a process in a NEW process group of its own; its pid goes to a file
    tool = subprocess.Popen([sys.executable, "-c", "import time\ntime.sleep(60)"], process_group=0,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    open(os.path.join(d, step["tool"]), "w").write(str(tool.pid))
if step.get("tree"):  # an agent in this group that ignores interrupt and terminate and runs a tool in a new group
    agent = ("import os, signal, subprocess, sys, time\n"
             "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
             "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
             "tool = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], process_group=0,"
             " stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
             "open(os.path.join(sys.argv[1], 'agent.pid'), 'w').write(str(os.getpid()))\n"
             "open(os.path.join(sys.argv[1], 'tool.pid'), 'w').write(str(tool.pid))\n"
             "time.sleep(60)\n")
    subprocess.Popen([sys.executable, "-c", agent, d], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
if step.get("holder"):  # a process in a new session that keeps this wrapper's output pipe open after it has exited
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True,
                              stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    open(os.path.join(d, step["holder"]), "w").write(str(holder.pid))
out = sys.stdout.buffer
for item in step.get("lines", []):
    if isinstance(item, dict) and "sleep" in item:
        time.sleep(item["sleep"])
        continue
    if isinstance(item, dict) and "pid" in item:
        open(os.path.join(d, item["pid"]), "w").write(str(os.getpid()))
        continue
    if isinstance(item, dict) and "marker" in item:
        open(os.path.join(d, item["marker"]), "w").write("x")
        continue
    if isinstance(item, dict) and "hex" in item:
        out.write(bytes.fromhex(item["hex"]) + b"\n")
    elif isinstance(item, str):
        out.write(item.encode() + b"\n")
    else:
        out.write(json.dumps(item).encode() + b"\n")
    out.flush()
sys.exit(step.get("exit", 0))
'''


def step(*lines, **kw):
    d = {"lines": list(lines)}
    d.update(kw)
    return d


INIT = {"type": "system", "subtype": "init", "session_id": SID}


def delta(t, index=0):
    return {"type": "stream_event", "event": {"type": "content_block_delta", "index": index,
                                              "delta": {"type": "text_delta", "text": t}}}


def message_start():
    return {"type": "stream_event", "event": {"type": "message_start", "message": {}}}


def assistant(*blocks):
    return {"type": "assistant", "message": {"content": list(blocks)}}


def text(t):
    return {"type": "text", "text": t}


def tool(name, **inp):
    return {"type": "tool_use", "name": name, "input": inp}


def result(cost=0.01, **kw):
    d = {"type": "result", "subtype": "success", "is_error": False, "total_cost_usd": cost,
         "permission_denials": []}
    d.update(kw)
    return d


OK = step(INIT, delta("ok"), assistant(text("ok")), result())


def cos_command(args):
    """The command line that starts cos.py: through LAUNCH, so that it runs with the default SIGINT."""
    return [sys.executable, "-c", LAUNCH, COS] + list(args)


def load_cos():
    """cos.py as a module, to call stop() directly with lowered waits (the rest of the tests run it as a program).
    readline is kept out of the suite's process: importing it there sets LINES and COLUMNS for every process the suite
    starts later, and ps then cuts long command lines (test_refusal_speed finds a process by the end of its arguments)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("cos_under_test", COS)
    module = importlib.util.module_from_spec(spec)
    held = sys.modules.get("readline", False)
    sys.modules["readline"] = None  # the script's `try: import readline` then takes its ImportError branch
    try:
        spec.loader.exec_module(module)
    finally:
        if held is False:
            del sys.modules["readline"]
        else:
            sys.modules["readline"] = held
    return module


class Fake:
    def __init__(self, plan):
        self.dir = tempfile.mkdtemp(prefix="cos-test-")
        self.cwd = os.path.join(self.dir, "cwd")
        os.mkdir(self.cwd)
        self.path = os.path.join(self.dir, "fake-claudock")
        with open(self.path, "w") as f:
            f.write(FAKE.replace("@PYTHON@", sys.executable))
        os.chmod(self.path, 0o755)
        with open(os.path.join(self.dir, "plan.json"), "w") as f:
            json.dump(plan, f)

    def env(self, extra=None):
        e = dict(os.environ)
        e.pop("COS_MODEL", None)
        e["COS_CLAUDOCK"] = self.path
        e["COS_FAKE_DIR"] = self.dir
        e.update(extra or {})
        return e

    def popen(self, args, extra_env=None):
        return subprocess.Popen(cos_command(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=self.env(extra_env), cwd=self.cwd)

    def run(self, args, stdin="", extra_env=None, timeout=60):
        p = subprocess.run(cos_command(args), input=stdin.encode(), capture_output=True,
                           env=self.env(extra_env), cwd=self.cwd, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")

    def calls(self):
        path = os.path.join(self.dir, "calls.jsonl")
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]


class CosTest(unittest.TestCase):
    def fake(self, *plan):
        f = Fake(list(plan) or [OK])
        self.addCleanup(shutil.rmtree, f.dir, True)
        return f

    def session(self, *plan, args=("acct", MODEL), stdin="hello\n/exit\n", extra_env=None):
        f = self.fake(*plan)
        code, out, err = f.run(list(args), stdin, extra_env)
        return f, code, out, err


class StartTest(CosTest):  # decision 1
    def test_bad_arguments_usage_and_exit_2(self):
        bad = [[], ["-x"], [""], ["a b"], ["acct", "bad model"], ["acct", "m;x"], ["acct", "-m"], ["a;b"],
               ["acct", MODEL, "--resume", "not-a-uuid"], ["acct", "--resume", SID + "0"],
               ["acct", "--mode", "bypassPermissions"], ["acct", "--mode", "dontAsk"], ["acct", "--mode", "x"],
               ["acct", "--bogus"], ["acct", "--mode", "plan", "--bypass-permissions"], ["acct", "m", "extra"]]
        for argv in bad:
            f = self.fake()
            code, out, err = f.run(argv, "hello\n/exit\n")
            self.assertEqual(code, 2, argv)
            self.assertIn("usage", err.lower(), argv)
            self.assertEqual(f.calls(), [], argv)

    def test_command_shape_wrapper_from_env(self):
        f, code, out, err = self.session(args=("acct", "claude-opus-5-5[1m]"), stdin="hi\n/exit\n")
        self.assertEqual(code, 0)
        self.assertEqual(len(f.calls()), 1)
        argv = f.calls()[0]["argv"]
        self.assertEqual(argv[:4], ["run", "acct", "--", "-p"])
        self.assertEqual(argv[4], "--session-id")
        uuid.UUID(argv[5])
        self.assertEqual(argv[6:8], ["--model", "claude-opus-5-5[1m]"])
        self.assertEqual(argv[8:], ["--output-format", "stream-json", "--verbose", "--include-partial-messages"])

    def test_model_default_env_then_builtin(self):
        f, code, *_ = self.session(args=("acct",), extra_env={"COS_MODEL": "model-from-env"})
        self.assertEqual(code, 0)
        self.assertEqual(f.calls()[0]["argv"][f.calls()[0]["argv"].index("--model") + 1], "model-from-env")
        f, code, *_ = self.session(args=("acct",))
        argv = f.calls()[0]["argv"]
        self.assertEqual(argv[argv.index("--model") + 1], "claude-sonnet-5-5")
        f = self.fake()
        code, out, err = f.run(["acct"], "hi\n", {"COS_MODEL": "bad model"})
        self.assertEqual(code, 2)
        self.assertIn("usage", err.lower())

    def test_explicit_model_beats_environment(self):
        f, code, *_ = self.session(args=("acct", "explicit.model:1"), extra_env={"COS_MODEL": "model-from-env"})
        argv = f.calls()[0]["argv"]
        self.assertEqual(argv[argv.index("--model") + 1], "explicit.model:1")

    WRAPPER_LINE = ("cos: the account wrapper was not found at %s: Claudock is required "
                    "(set COS_CLAUDOCK to its claudock program)\n")

    def assert_wrapper_refused(self, f, path):
        """No wrapper at that path: one line on standard error, exit 2, no banner, no prompt, no request."""
        code, out, err = f.run(["acct", MODEL], "hello\n/exit\n", {"COS_CLAUDOCK": path})
        self.assertEqual(code, 2)
        self.assertEqual(err, self.WRAPPER_LINE % path)
        self.assertEqual(out, "")
        self.assertEqual(f.calls(), [])

    def test_missing_wrapper_one_line_exit_2(self):
        f = self.fake()
        self.assert_wrapper_refused(f, os.path.join(f.dir, "absent", "claudock"))

    def test_not_executable_wrapper_exit_2(self):
        f = self.fake()
        plain = os.path.join(f.dir, "plain-claudock")
        with open(plain, "w") as handle:
            handle.write("#!/bin/sh\nexit 0\n")
        os.chmod(plain, 0o644)
        self.assert_wrapper_refused(f, plain)


class RequestTest(CosTest):  # decision 2
    def test_one_request_per_message_stdin(self):
        nasty = "$(touch pwned); \"q\" 'x' --permission-mode bypassPermissions `id`"
        f, code, out, err = self.session(stdin="hello world\n" + nasty + "\n/exit\n")
        calls = f.calls()
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["stdin"], "hello world\n")
        self.assertEqual(calls[1]["stdin"], nasty + "\n")
        for c in calls:
            self.assertNotIn("bypassPermissions", c["argv"])
            self.assertFalse(any("hello" in a or "touch" in a for a in c["argv"]))
        self.assertEqual(os.listdir(f.cwd), [])

    def test_new_session_resume_after_init(self):
        f, code, out, err = self.session(stdin="one\ntwo\nthree\n/exit\n")
        argvs = [c["argv"] for c in f.calls()]
        sid = argvs[0][argvs[0].index("--session-id") + 1]
        uuid.UUID(sid)
        self.assertNotIn("--resume", argvs[0])
        for a in argvs[1:]:
            self.assertEqual(a[a.index("--resume") + 1], sid)
            self.assertNotIn("--session-id", a)
        self.assertIn("session %s  (continue later with: --resume %s)" % (sid, sid), out)

    def test_resume_at_start_every_request(self):
        f, code, out, err = self.session(stdin="one\ntwo\n/exit\n", args=("acct", MODEL, "--resume", SID))
        for c in f.calls():
            self.assertEqual(c["argv"][c["argv"].index("--resume") + 1], SID)
            self.assertNotIn("--session-id", c["argv"])
        self.assertIn("session %s  (continue later with: --resume %s)" % (SID, SID), out)

    def test_failed_no_init_keeps_session_id(self):
        f, code, out, err = self.session(step(exit=1), step(exit=1), OK, stdin="a\nb\nc\nd\n/exit\n")
        argvs = [c["argv"] for c in f.calls()]
        self.assertEqual(len(argvs), 4)
        self.assertTrue(all("--session-id" in a for a in argvs[:3]))
        self.assertEqual(len({a[a.index("--session-id") + 1] for a in argvs[:3]}), 1)
        self.assertIn("--resume", argvs[3])
        self.assertIn("[turn 1 | no result | exit 1]", out)

    def test_failed_after_init_then_resume(self):
        bad = step(INIT, result(0.02, is_error=True, result="boom"), exit=1)
        f, code, out, err = self.session(bad, OK, stdin="a\nb\n/exit\n")
        argvs = [c["argv"] for c in f.calls()]
        self.assertIn("--session-id", argvs[0])
        self.assertIn("--resume", argvs[1])
        self.assertNotIn("--session-id", argvs[1])

    def test_blank_lines_send_nothing(self):
        f, code, out, err = self.session(stdin="\n   \nreal\n/exit\n")
        self.assertEqual([c["stdin"] for c in f.calls()], ["real\n"])


class StreamTest(CosTest):  # decision 3
    def test_deltas_print_once_no_repeat(self):
        f, code, out, err = self.session(step(INIT, message_start(), delta("Hel"), delta("lo"),
                                               assistant(text("Hello")), result()))
        self.assertEqual(out.count("Hello"), 1)
        self.assertIn("Hello\n[turn 1 |", out)

    def test_text_appears_while_running(self):
        f = self.fake(step(INIT, delta("FIRST"), {"sleep": 1.5}, delta("LAST"), result()))
        p = f.popen(["acct", MODEL])
        seen = {}

        def reader():
            buf = b""
            while True:
                chunk = os.read(p.stdout.fileno(), 4096)
                if not chunk:
                    break
                buf += chunk
                for word in (b"FIRST", b"LAST"):
                    if word in buf and word not in seen:
                        seen[word] = time.monotonic()

        t = threading.Thread(target=reader)
        t.start()
        p.stdin.write(b"hi\n/exit\n")
        p.stdin.close()
        t.join(30)
        p.wait(30)
        p.stderr.close()
        self.assertGreater(seen[b"LAST"] - seen[b"FIRST"], 1.0)

    def test_no_deltas_prints_whole_text(self):
        f, code, out, err = self.session(step(INIT, assistant(text("Whole answer")), result()))
        self.assertEqual(out.count("Whole answer"), 1)
        self.assertIn("Whole answer\n[turn 1 |", out)

    def test_answer_ends_with_one_newline(self):
        for pieces in (["A"], ["A\n"], ["A\n\n\n"], ["A", "\n", "\n"]):
            f, code, out, err = self.session(step(INIT, *[delta(p) for p in pieces], result()))
            self.assertIn("A\n[turn 1 |", out, pieces)

    def test_text_tool_text_across_messages(self):
        f, code, out, err = self.session(step(
            INIT, message_start(), delta("One"), assistant(text("One")),
            assistant(tool("Bash", command="ls -la")), message_start(), delta("Two"), assistant(text("Two")),
            result()))
        self.assertIn("One\n  [tool Bash] ls -la\nTwo\n[turn 1 |", out)

    def test_blocks_by_text_not_position(self):
        f, code, out, err = self.session(step(
            INIT, message_start(), delta("Alpha", 0), assistant(text("Alpha")), delta("Beta", 1),
            assistant(text("Beta")), result()))
        self.assertEqual(out.count("Alpha"), 1)
        self.assertEqual(out.count("Beta"), 1)

    def test_stream_sample_replay(self):  # the sample is made up: tests/e2e/fixtures/cos-stream.jsonl
        with open(SAMPLE, encoding="utf-8") as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]
        parsed = [json.loads(l) for l in lines]
        answer = [b["text"] for e in parsed if e.get("type") == "assistant" for b in e["message"]["content"]
                  if b.get("type") == "text"][0]
        cost = [e for e in parsed if e.get("type") == "result"][0]["total_cost_usd"]
        f, code, out, err = self.session(step(*lines), OK, stdin="hello\nagain\n/exit\n")
        self.assertEqual(code, 0)
        self.assertEqual(out.count(answer), 1)
        self.assertNotIn("Traceback", err)
        self.assertIn("session $%.4f" % cost, out)
        self.assertNotIn("[raw]", out)
        self.assertIn("--resume", f.calls()[1]["argv"])  # the init line was not the first line, still seen


class ToolTest(CosTest):  # decision 4
    def test_tool_lines_cut_at_100_one_line(self):
        cmd = "echo " + "x" * 200 + "\nsecond line"
        f, code, out, err = self.session(step(
            INIT, assistant(tool("Bash", command=cmd)), assistant(tool("Read", file_path="/tmp/a/b.txt")),
            assistant(tool("Grep", pattern="foo.*bar", path="/x")), assistant(tool("Weird", command="\x1b[31mred")),
            result()))
        self.assertIn("  [tool Bash] " + cmd.replace("\n", " ")[:100] + "\n", out)
        self.assertNotIn("x" * 101, out)
        self.assertIn("  [tool Read] /tmp/a/b.txt\n", out)
        self.assertIn("  [tool Grep] foo.*bar\n", out)
        self.assertNotIn("\x1b", out)

    def test_denials_listed_hint_once(self):
        denied = result(0.01, permission_denials=[{"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/x"}},
                                                  {"tool_name": "Write", "tool_input": {"file_path": "/tmp/y"}}])
        f, code, out, err = self.session(step(INIT, denied), step(INIT, denied), stdin="a\nb\n/exit\n")
        self.assertEqual(out.count("  [denied Bash] rm -rf /tmp/x\n"), 2)
        self.assertEqual(out.count("  [denied Write] /tmp/y\n"), 2)
        self.assertEqual(out.count("  (denied: this request ran without approval rights; see /mode)\n"), 1)

    def test_no_denials_no_hint(self):
        f, code, out, err = self.session()
        self.assertEqual(code, 0)
        self.assertIn("[turn 1 |", out)
        self.assertNotIn("denied", out)


class CostTest(CosTest):  # decision 5
    TURN = re.compile(r"\[turn (\d+) \| this turn (\$[0-9.]+|\?) \| session (\$[0-9.]+|\?) \| (\d+(?:\.\d+)?) s\]")

    def test_cost_difference_and_four_digits(self):
        f, code, out, err = self.session(step(INIT, result(0.0100)), step(INIT, result(0.012345)),
                                         stdin="a\nb\n/exit\n")
        got = self.TURN.findall(out)
        self.assertEqual([g[:3] for g in got], [("1", "$0.0100", "$0.0100"), ("2", "$0.0023", "$0.0123")])

    def test_resumed_first_turn_unknown(self):
        f, code, out, err = self.session(step(INIT, result(0.5)), step(INIT, result(0.52)),
                                         args=("acct", MODEL, "--resume", SID), stdin="a\nb\n/exit\n")
        got = self.TURN.findall(out)
        self.assertEqual([g[:3] for g in got], [("1", "?", "$0.5000"), ("2", "$0.0200", "$0.5200")])

    def test_no_result_line(self):
        f, code, out, err = self.session(step(INIT, delta("partial"), exit=3))
        self.assertIn("[turn 1 | no result | exit 3]", out)
        self.assertIn("partial\n[turn", out)

    def test_cost_command_shows_session_total(self):
        f, code, out, err = self.session(step(INIT, result(0.0371)), stdin="/cost\na\n/cost\n/exit\n")
        self.assertIn("unknown", out.split("[turn 1")[0])
        self.assertIn("$0.0371", out.split("[turn 1")[1].split("\n", 1)[1])

    def test_weird_costs_show_question_marks(self):
        raws = ['{"type":"result","total_cost_usd":NaN}', '{"type":"result","total_cost_usd":1e999}',
                '{"type":"result","total_cost_usd":true}', '{"type":"result","total_cost_usd":"1.5"}',
                '{"type":"result","total_cost_usd":1' + "0" * 400 + "}", '{"type":"result"}']
        for raw in raws:
            f, code, out, err = self.session(step(INIT, raw))
            self.assertEqual(code, 0, raw[:40])
            self.assertIn("| this turn ? | session ? |", out, raw[:40])
            self.assertNotIn("Traceback", err)

    def test_error_result_without_text_is_shown(self):
        f, code, out, err = self.session(step(INIT, result(0.0, is_error=True, result="Credit balance is too low"),
                                               exit=1))
        self.assertIn("Credit balance is too low", out)


class InterruptTest(CosTest):  # decision 6
    def interrupt(self, first_step, low, high):
        f = self.fake(first_step, OK)
        p = f.popen(["acct", MODEL])
        p.stdin.write(b"first\n")
        p.stdin.flush()
        marker = os.path.join(f.dir, "started")
        deadline = time.time() + 15
        while not os.path.exists(marker) and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(os.path.exists(marker))
        t0 = time.monotonic()
        p.send_signal(signal.SIGINT)
        out, err = p.communicate(b"second\n/exit\n", timeout=40)
        elapsed = time.monotonic() - t0
        out = out.decode("utf-8", "replace")
        self.assertEqual(p.returncode, 0, err)
        self.assertGreaterEqual(elapsed, low)
        self.assertLess(elapsed, high)
        self.assertIn("[interrupted]", out)
        self.assertIn("[turn 2 |", out)
        self.assertEqual(len(f.calls()), 2)
        self.assertIn("--resume", f.calls()[1]["argv"])  # init had been seen: the session goes on
        self.assertIn("(continue later with: --resume ", out)

    def test_interrupt_stops_obedient_child(self):
        self.interrupt(step(INIT, {"marker": "started"}, {"sleep": 60}), 0, 2.5)

    def test_ignores_interrupt_term_after_6s(self):  # fix round 3: waits 6, 4, 2
        self.interrupt(step(INIT, {"marker": "started"}, {"sleep": 60}, ignore_sigint=True), 5.5, 10)

    def test_ignores_interrupt_and_term_kill(self):
        self.interrupt(step(INIT, {"marker": "started"}, {"sleep": 60}, ignore_sigint=True, ignore_sigterm=True),
                       9.5, 16)

    def test_ctrl_c_at_prompt_stays(self):
        f = self.fake()
        p = f.popen(["acct", MODEL])
        first = b""
        while b"> " not in first:
            chunk = os.read(p.stdout.fileno(), 4096)
            self.assertTrue(chunk)
            first += chunk
        p.send_signal(signal.SIGINT)
        time.sleep(0.4)
        out, err = p.communicate(b"/exit\n", timeout=20)
        out = (first + out).decode("utf-8", "replace")
        self.assertEqual(p.returncode, 0, err)
        self.assertIn("(type /exit or press Ctrl-D to leave)", out)
        self.assertEqual(f.calls(), [])

    def test_runner_ignoring_ctrl_c_is_undone(self):  # a runner started as a background job ignores SIGINT
        f = self.fake()
        p = subprocess.Popen(["sh", "-c", 'trap "" INT; exec "$@"', "sh"] + cos_command(["acct", MODEL]),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=f.env(),
                             cwd=f.cwd)
        first = b""
        while b"> " not in first:
            chunk = os.read(p.stdout.fileno(), 4096)
            self.assertTrue(chunk)
            first += chunk
        p.send_signal(signal.SIGINT)
        time.sleep(0.4)
        out, err = p.communicate(b"/exit\n", timeout=20)
        out = (first + out).decode("utf-8", "replace")
        self.assertEqual(p.returncode, 0, err)
        self.assertIn("(type /exit or press Ctrl-D to leave)", out)  # the interrupt reached the program

    def test_ctrl_d_leaves_with_resume_line(self):
        f, code, out, err = self.session(stdin="hi\n")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"session ([0-9a-f-]{36})  \(continue later with: --resume \1\)\n$")


class PermissionTest(CosTest):  # decision 7
    WARN = "WARNING: approvals are bypassed: the agent may run any command and change any file it can reach."

    def test_default_no_permission_option(self):
        f, code, out, err = self.session(stdin="a\n/mode\nb\n/exit\n")
        self.assertEqual(len(f.calls()), 2)
        for c in f.calls():
            self.assertFalse([a for a in c["argv"] if "ermission" in a or "angerous" in a or "bypass" in a.lower()])
        self.assertIn("mode: none passed", out)
        self.assertNotIn("WARNING", out)

    def test_mode_option_on_every_request(self):
        for mode in ("default", "acceptEdits", "plan"):
            f, code, out, err = self.session(args=("acct", MODEL, "--mode", mode), stdin="a\nb\n/exit\n")
            self.assertEqual(len(f.calls()), 2)
            for c in f.calls():
                self.assertEqual(c["argv"][c["argv"].index("--permission-mode") + 1], mode)
            self.assertNotIn("WARNING", out)

    def test_bypass_flag_warns_start_and_mode(self):
        f, code, out, err = self.session(args=("acct", MODEL, "--bypass-permissions"),
                                         stdin="a\n/mode\n/mode bypassPermissions\n/mode nonsense\n/exit\n")
        argv = f.calls()[0]["argv"]
        self.assertEqual(argv[argv.index("--permission-mode") + 1], "bypassPermissions")
        self.assertEqual(out.count(self.WARN), 4)  # start, /mode, refused /mode bypassPermissions, refused nonsense

    def test_mode_command_three_never_bypass(self):
        f, code, out, err = self.session(stdin="/mode\n/mode plan\na\n/mode bypassPermissions\n/mode acceptEdits\nb\n"
                                               "/mode nonsense\nc\n/mode default\nd\n/exit\n")
        modes = [c["argv"][c["argv"].index("--permission-mode") + 1] if "--permission-mode" in c["argv"] else None
                 for c in f.calls()]
        self.assertEqual(modes, ["plan", "acceptEdits", "acceptEdits", "default"])
        self.assertNotIn("bypassPermissions", [m for m in modes])
        self.assertNotIn("WARNING", out)

    def test_leaving_bypass_drops_warning(self):
        f, code, out, err = self.session(args=("acct", MODEL, "--bypass-permissions"),
                                         stdin="/mode plan\na\n/mode bypassPermissions\nb\n/exit\n")
        modes = [c["argv"][c["argv"].index("--permission-mode") + 1] for c in f.calls()]
        self.assertEqual(modes, ["plan", "plan"])
        self.assertEqual(out.count(self.WARN), 1)

    START1 = ("permission mode: the account's own default (not chosen here). "
              "On this Mac that is usually bypassPermissions:")
    START2 = ("the agent may then run any command and change any file. "
              "To narrow it: --mode default|acceptEdits|plan, or /mode.")
    BYPASS_INIT = dict(INIT, permissionMode="bypassPermissions")

    def test_start_says_no_mode_was_chosen(self):  # round 2, change 1
        f, code, out, err = self.session(stdin="/exit\n")
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("cos: "), lines[0])
        self.assertEqual(lines[1:3], [self.START1, self.START2])

    def test_no_start_lines_with_a_mode(self):  # round 2, change 1
        for extra in (["--mode", "plan"], ["--mode", "default"], ["--mode", "acceptEdits"], ["--bypass-permissions"]):
            f, code, out, err = self.session(args=["acct", MODEL] + extra, stdin="/exit\n")
            self.assertNotIn("not chosen here", out, extra)

    def test_init_bypass_warns_once_per_run(self):  # round 2, change 2
        f, code, out, err = self.session(step(self.BYPASS_INIT, result()), step(self.BYPASS_INIT, result()),
                                         stdin="a\nb\n/exit\n")
        self.assertEqual(out.count(self.WARN), 1)
        self.assertNotIn("account default permission mode", out)
        self.assertGreater(out.index(self.WARN), out.index(self.START2))  # after the start lines
        self.assertLess(out.index(self.WARN), out.index("[turn 1 |"))  # where the bracket note used to be

    def test_other_modes_keep_bracket_note(self):  # round 2, change 2
        init = dict(INIT, permissionMode="acceptEdits")
        f, code, out, err = self.session(step(init, result()), step(init, result()), stdin="a\nb\n/exit\n")
        self.assertEqual(out.count("  [account default permission mode: acceptEdits]\n"), 1)
        self.assertNotIn("WARNING", out)
        f, code, out, err = self.session(step(dict(INIT, permissionMode="default"), result()))
        self.assertNotIn("account default permission mode", out)
        self.assertNotIn("WARNING", out)

    def test_reported_mode_checked_when_chosen(self):  # fix round 2, decision 3
        for mode in ("default", "acceptEdits", "plan"):
            f, code, out, err = self.session(step(self.BYPASS_INIT, result()), step(self.BYPASS_INIT, result()),
                                             args=("acct", MODEL, "--mode", mode), stdin="a\nb\n/exit\n")
            line = "WARNING: the agent reports bypassPermissions although --mode %s was passed." % mode
            self.assertEqual(out.count(line + "\n"), 1, mode)
            self.assertEqual(out.count(self.WARN), 1, mode)
            self.assertIn(line + "\n" + self.WARN + "\n", out)  # the extra line comes right before the WARNING line
            self.assertNotIn("account default permission mode", out)
        f, code, out, err = self.session(step(self.BYPASS_INIT, result()), stdin="/mode plan\na\n/exit\n")
        self.assertIn("although --mode plan was passed.\n" + self.WARN + "\n", out)  # a mode set with /mode is chosen too
        f, code, out, err = self.session(step(self.BYPASS_INIT, result()), stdin="a\n/exit\n")
        self.assertNotIn("although", out)  # no mode chosen: the WARNING line alone
        self.assertEqual(out.count(self.WARN), 1)
        f, code, out, err = self.session(step(self.BYPASS_INIT, result()), args=("acct", MODEL, "--bypass-permissions"))
        self.assertNotIn("although", out)  # bypass chosen and reported: nothing to add to the start warning
        self.assertEqual(out.count(self.WARN), 1)

    def test_mode_warning_keyed_on_the_pair(self):  # fix round 3, decision 3: reported mode and chosen mode
        f, code, out, err = self.session(step(self.BYPASS_INIT, result()), step(self.BYPASS_INIT, result()),
                                         step(self.BYPASS_INIT, result()), stdin="a\n/mode plan\nb\nc\n/exit\n")
        mismatch = "WARNING: the agent reports bypassPermissions although --mode plan was passed.\n"
        self.assertEqual(out.count(self.WARN + "\n"), 2)  # none chosen, then plan: two different pairs
        self.assertEqual(out.count(mismatch), 1)  # the third request repeats the pair: no third warning
        self.assertLess(out.index(self.WARN), out.index("mode: plan\n"))
        self.assertGreater(out.index(mismatch), out.index("mode: plan\n"))

    def test_mode_shows_last_reported_mode(self):  # round 2, change 3
        f, code, out, err = self.session(step(self.BYPASS_INIT, result()), stdin="/mode\na\n/mode\n/mode plan\n/exit\n")
        first = out.index("mode: none passed (the account's own default applies)\n")
        second = out.index("mode: none passed (the account's own default applies: bypassPermissions)\n")
        self.assertLess(first, second)
        self.assertIn("mode: plan\n", out)
        self.assertEqual(out.count("applies: bypassPermissions)"), 1)

    def test_start_and_warning_not_dim_in_tty(self):  # round 2, changes 1 and 2
        import pty
        import select
        f = self.fake(step(self.BYPASS_INIT, delta("hi"), result()))
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.chdir(f.cwd)
                os.execve(sys.executable, [sys.executable, COS, "acct", MODEL], f.env())
            finally:
                os._exit(127)
        out = b""

        def pump(seconds):
            nonlocal out
            end = time.time() + seconds
            while time.time() < end:
                if select.select([fd], [], [], 0.1)[0]:
                    try:
                        data = os.read(fd, 4096)
                    except OSError:
                        return
                    if not data:
                        return
                    out += data

        pump(1.5)
        for keys in (b"hello\r", b"/exit\r"):
            os.write(fd, keys)
            pump(2.0)
        for _ in range(100):
            if os.waitpid(pid, os.WNOHANG)[0]:
                break
            time.sleep(0.05)
        else:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            self.fail("cos.py did not exit")
        os.close(fd)
        text = out.decode("utf-8", "replace")
        for line in (self.START1, self.START2, self.WARN):
            self.assertIn(line + "\r\n", text)
            self.assertNotIn("\x1b[2m" + line, text)
        self.assertIn("\x1b[2m[turn 1 |", text)  # the bracket line is still dim


class SessionLineTest(CosTest):  # fix round 2, decision 4
    NONE = "no session was started"

    def test_no_resume_line_without_init(self):
        for plan, stdin in (([], "/exit\n"), ([step(exit=1)], "hello\n/exit\n"),
                            ([step("not json", exit=1)], "a\n/session\n/exit\n")):
            f, code, out, err = self.session(*plan, stdin=stdin)
            self.assertEqual(out.splitlines()[-1], self.NONE, stdin)
            self.assertNotIn("continue later with", out, stdin)

    def test_resume_line_after_init_or_resume(self):
        f, code, out, err = self.session(stdin="hello\n/exit\n")
        self.assertRegex(out.splitlines()[-1], r"^session ([0-9a-f-]{36})  \(continue later with: --resume \1\)$")
        f, code, out, err = self.session(args=("acct", MODEL, "--resume", SID), stdin="/exit\n")
        self.assertEqual(out.splitlines()[-1], "session %s  (continue later with: --resume %s)" % (SID, SID))
        f, code, out, err = self.session(step(INIT, result(0.0, is_error=True, result="boom"), exit=1),
                                         stdin="a\n/exit\n")
        self.assertIn("continue later with: --resume", out.splitlines()[-1])


class HangupTest(CosTest):  # fix round 2, decisions 1 and 2
    def wait_for(self, path, seconds=15):
        end = time.time() + seconds
        while not os.path.exists(path) and time.time() < end:
            time.sleep(0.05)
        self.assertTrue(os.path.exists(path), path)

    def pid_from(self, path):
        with open(path) as f:
            pid = int(f.read())

        def kill():  # clean up when a test fails and the process lives on
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

        self.addCleanup(kill)
        return pid

    def gone(self, pid, seconds=3):
        end = time.time() + seconds
        while time.time() < end:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            time.sleep(0.05)
        return False

    def hangup_case(self, signum):
        f = self.fake(step(INIT, {"pid": "leader.pid"}, {"marker": "started"}, {"sleep": 60}))
        p = f.popen(["acct", MODEL])
        p.stdin.write(b"first\n")
        p.stdin.flush()
        self.wait_for(os.path.join(f.dir, "started"))
        pid = self.pid_from(os.path.join(f.dir, "leader.pid"))
        p.send_signal(signum)
        out, err = p.communicate(timeout=30)
        self.assertTrue(self.gone(pid), "the request is still running after cos.py ended")  # the pid, not the time
        self.assertEqual(p.returncode, 128 + signum)

    def test_hangup_leaves_nothing_running(self):
        self.hangup_case(signal.SIGHUP)

    def test_terminate_leaves_nothing_running(self):
        self.hangup_case(signal.SIGTERM)

    def test_second_process_gone_after_ctrl_c(self):
        f = self.fake(step(INIT, {"marker": "started"}, {"sleep": 60}, second="second.pid"), OK)
        p = f.popen(["acct", MODEL])
        p.stdin.write(b"first\n")
        p.stdin.flush()
        self.wait_for(os.path.join(f.dir, "started"))
        second = self.pid_from(os.path.join(f.dir, "second.pid"))
        p.send_signal(signal.SIGINT)  # the leader exits at once; the second process ignores the interrupt
        out, err = p.communicate(b"again\n/exit\n", timeout=40)
        self.assertTrue(self.gone(second), "a second process of the request's group is still running")
        out = out.decode("utf-8", "replace")
        self.assertIn("[interrupted]", out)
        self.assertNotIn("may still be running", out)
        self.assertEqual(p.returncode, 0)

    def test_second_ctrl_c_child_not_alive(self):
        f = self.fake(step(INIT, {"pid": "leader.pid"}, {"marker": "started"}, {"sleep": 60}, ignore_sigint=True,
                           ignore_sigterm=True), OK)
        p = f.popen(["acct", MODEL])
        p.stdin.write(b"first\n")
        p.stdin.flush()
        self.wait_for(os.path.join(f.dir, "started"))
        pid = self.pid_from(os.path.join(f.dir, "leader.pid"))
        p.send_signal(signal.SIGINT)
        time.sleep(0.7)
        p.send_signal(signal.SIGINT)  # during stop: it goes on with the next step, it does not leave
        out, err = p.communicate(b"again\n/exit\n", timeout=40)
        self.assertTrue(self.gone(pid), "the request is still running")
        self.assertIn("[interrupted]", out.decode("utf-8", "replace"))

    def test_new_group_child_killed_at_kill(self):  # fix round 3, decision 1
        cos = load_cos()
        cos.WAITS = (0.3, 0.3, 1.5)  # the test lowers the module constants to keep the run short
        f = self.fake(step(INIT, {"pid": "leader.pid"}, {"marker": "started"}, {"sleep": 60}, ignore_sigint=True,
                           ignore_sigterm=True, tool="tool.pid"))
        proc = subprocess.Popen([f.path, "run", "acct", "--", "-p"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                env=f.env(), cwd=f.cwd, start_new_session=True)
        self.addCleanup(proc.stdout.close)
        proc.stdin.write(b"x\n")
        proc.stdin.close()
        self.wait_for(os.path.join(f.dir, "started"))
        leader = self.pid_from(os.path.join(f.dir, "leader.pid"))
        tool = self.pid_from(os.path.join(f.dir, "tool.pid"))
        self.assertNotEqual(os.getpgid(tool), os.getpgid(leader))  # the tool is in a group of its own
        left = cos.stop(proc)
        self.assertTrue(self.gone(tool), "the shell-tool stand-in (own process group) is still running")
        self.assertTrue(self.gone(leader))
        self.assertEqual(left, [])

    def test_no_false_still_running_line(self):  # fix round 3, decisions 2 and 5
        f = self.fake(step(INIT, {"pid": "leader.pid"}, {"marker": "started"}, {"sleep": 60}, ignore_sigint=True,
                           ignore_sigterm=True), OK)
        p = f.popen(["acct", MODEL])
        p.stdin.write(b"first\n")
        p.stdin.flush()
        self.wait_for(os.path.join(f.dir, "started"))
        pid = self.pid_from(os.path.join(f.dir, "leader.pid"))
        for _ in range(4):  # the first starts the stop, each further one moves on to the next step
            p.send_signal(signal.SIGINT)
            time.sleep(0.25)
        out, err = p.communicate(b"again\n/exit\n", timeout=40)
        out = out.decode("utf-8", "replace")
        self.assertTrue(self.gone(pid))
        self.assertIn("[stopping the request: wait a few seconds, do not press Ctrl-C again]\n", out)
        self.assertNotIn("may still be running", out)
        self.assertIn("[interrupted]", out)

    def start_request(self, f):
        proc = subprocess.Popen([f.path, "run", "acct", "--", "-p"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                env=f.env(), cwd=f.cwd, start_new_session=True)
        self.addCleanup(proc.stdout.close)
        proc.stdin.write(b"x\n")
        proc.stdin.close()
        self.wait_for(os.path.join(f.dir, "started"))
        return proc

    def test_wrapper_gone_agent_and_tool_gone(self):  # fix round 4, decision 2
        cos = load_cos()
        cos.WAITS = (0.3, 0.3, 1.5)
        f = self.fake(step(INIT, {"pid": "leader.pid"}, {"marker": "started"}, {"sleep": 60}, tree=True))
        proc = self.start_request(f)
        self.wait_for(os.path.join(f.dir, "tool.pid"))
        leader = self.pid_from(os.path.join(f.dir, "leader.pid"))
        agent = self.pid_from(os.path.join(f.dir, "agent.pid"))
        tool = self.pid_from(os.path.join(f.dir, "tool.pid"))
        self.assertEqual(os.getpgid(agent), os.getpgid(leader))  # the agent is in the wrapper's group
        self.assertNotEqual(os.getpgid(tool), os.getpgid(leader))  # the tool is in a group of its own
        left = cos.stop(proc)  # the wrapper exits at the interrupt; the agent ignores interrupt and terminate
        for pid in (tool, agent, leader):
            self.assertTrue(self.gone(pid), "process %d is still running" % pid)
        self.assertEqual(left, [])

    def test_missing_ps_said_in_one_line(self):  # fix round 4, decisions 1 and 3
        import contextlib
        import io
        cos = load_cos()
        cos.WAITS = (0.2, 0.2, 1.0)
        cos.PS_PATHS = ()  # no ps anywhere: the listing fails
        f = self.fake(step(INIT, {"pid": "leader.pid"}, {"marker": "started"}, {"sleep": 60}, ignore_sigint=True,
                           ignore_sigterm=True))
        proc = self.start_request(f)
        leader = self.pid_from(os.path.join(f.dir, "leader.pid"))
        shown = io.StringIO()
        with contextlib.redirect_stdout(shown):
            cos.Session("acct", MODEL, SID, False, None, False).stopped(proc)
        text = shown.getvalue()
        self.assertEqual(text.count("[could not list the request's processes: some of its tools may still run]\n"), 1)
        self.assertTrue(self.gone(leader))  # the wrapper's own group is still stopped
        self.assertNotIn("WARNING", text)

    def test_late_ctrl_c_no_stopping_line(self):  # fix round 4, decision 4
        f = self.fake(step(INIT, {"marker": "started"}, holder="holder.pid"), OK)
        p = f.popen(["acct", MODEL])
        p.stdin.write(b"first\n")
        p.stdin.flush()
        self.wait_for(os.path.join(f.dir, "started"))
        self.pid_from(os.path.join(f.dir, "holder.pid"))  # the holder is killed when the test ends
        time.sleep(0.5)  # the wrapper has exited; the holder keeps its output pipe open, so cos.py is still reading
        p.send_signal(signal.SIGINT)
        out, err = p.communicate(b"/exit\n", timeout=30)
        self.assertNotIn("[stopping the request", out.decode("utf-8", "replace"))
        self.assertEqual(p.returncode, 0)


class LocalCommandTest(CosTest):  # decisions 8 and 9
    def test_help_lists_every_command(self):
        f, code, out, err = self.session(stdin="/help\n/exit\n")
        for c in ("/exit", "/help", "/cost", "/session", "/model", "/mode"):
            self.assertIn(c, out)
        self.assertEqual(f.calls(), [])

    def test_session_command(self):
        f, code, out, err = self.session(stdin="/session\n/exit\n", args=("acct", MODEL, "--resume", SID))
        self.assertEqual(out.count("session %s  (continue later with: --resume %s)" % (SID, SID)), 2)

    def test_model_command_next_and_valid(self):
        f, code, out, err = self.session(stdin="a\n/model claude-opus-5-5[1m]\nb\n/model bad name!\n/model -x\nc\n/exit\n")
        models = [c["argv"][c["argv"].index("--model") + 1] for c in f.calls()]
        self.assertEqual(models, [MODEL, "claude-opus-5-5[1m]", "claude-opus-5-5[1m]"])

    def test_other_slash_lines_go_to_the_agent(self):
        f, code, out, err = self.session(stdin="/compact now\n/exit now\n/help me\n/foo\n/exit\n")
        self.assertEqual([c["stdin"] for c in f.calls()], ["/compact now\n", "/exit now\n", "/help me\n", "/foo\n"])

    def test_backslash_continues_the_message(self):
        f, code, out, err = self.session(stdin="first line\\\nsecond\\\n\nthird\n/exit\n")
        self.assertEqual([c["stdin"] for c in f.calls()], ["first line\nsecond\n\n", "third\n"])
        self.assertIn(". ", out)


class RobustTest(CosTest):  # decision 10
    def test_garbage_and_odd_shapes_never_crash(self):
        weird = ["not json at all", "[1,2,3]", "42", "null", '"str"', "", "   ",
                 {"type": "assistant", "message": "x"}, {"type": "assistant", "message": [1]},
                 {"type": "assistant", "message": None}, {"type": "assistant", "message": {"content": None}},
                 {"type": "assistant", "message": {"content": 5}}, {"type": "assistant", "message": {"content": "s"}},
                 {"type": "assistant", "message": {"content": {"a": 1}}},
                 {"type": "assistant", "message": {"content": [1, "x", None, {"type": "text", "text": 5},
                                                                {"type": "tool_use", "name": 5, "input": [1]},
                                                                {"type": "tool_use", "input": {"command": 7}}]}},
                 {"type": "assistant"}, {"type": "stream_event"}, {"type": "stream_event", "event": "panel.refresh"},
                 {"type": "stream_event", "event": {"type": "content_block_delta", "delta": "x"}},
                 {"type": "stream_event", "event": {"type": "content_block_delta", "index": [1], "delta":
                                                    {"type": "text_delta", "text": 7}}},
                 {"type": "stream_event", "event": {"type": "content_block_delta", "index": {"a": 1}, "delta":
                                                    {"type": "text_delta", "text": "ok-delta"}}},
                 {"type": "system", "subtype": "init"}, {"type": "system", "event": "panel.refresh"}, {"type": 7},
                 result(0.02, permission_denials="x"), result(0.02, permission_denials=[1, None, {"tool_name": 3},
                                                                                         {"tool_input": []}]),
                 result(0.03, permission_denials=None)]
        f, code, out, err = self.session(step(*weird))
        self.assertEqual(code, 0)
        self.assertNotIn("Traceback", err)
        self.assertIn("[raw] not json at all", out)
        self.assertIn("ok-delta", out)
        self.assertIn("session $0.0300 |", out)

    def test_deeply_nested_json_is_not_a_crash(self):
        f, code, out, err = self.session(step("[" * 100000, OK["lines"][3]))
        self.assertEqual(code, 0)
        self.assertNotIn("Traceback", err)
        self.assertIn("[turn 1 |", out)

    def test_invalid_utf8_is_replaced(self):
        bad_json = (b'{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":'
                    b'{"type":"text_delta","text":"ab\xffcd"}}}').hex()
        f, code, out, err = self.session(step(INIT, {"hex": bad_json}, {"hex": "fffe41"}, result()))
        self.assertEqual(code, 0)
        self.assertIn("ab�cd", out)
        self.assertIn("[raw] ��A", out)

    def test_wrapper_cannot_start_one_line(self):  # past the start check a request can still fail to start
        f = self.fake()
        broken = os.path.join(f.dir, "broken-claudock")
        with open(broken, "w") as handle:
            handle.write("#!/nonexistent/interpreter\n")  # executable, but the program it names is not there
        os.chmod(broken, 0o755)
        code, out, err = f.run(["acct", MODEL], "a\nb\n/exit\n", {"COS_CLAUDOCK": broken})
        self.assertEqual(code, 0)
        lines = [l for l in err.splitlines() if l.strip()]
        self.assertEqual(len(lines), 2, err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(out.count("> "), 3)
        self.assertNotIn("[turn", out)

    def test_broken_pipe_is_a_failed_request(self):
        f = self.fake(step(noread=True, exit=4), OK)
        big = "x" * 3000000
        code, out, err = f.run(["acct", MODEL], big + "\nsmall\n/exit\n")
        self.assertEqual(code, 0, err)
        self.assertNotIn("Traceback", err)
        self.assertIn("[turn 1 | no result | exit 4]", out)
        self.assertIn("[turn 2 |", out)


class OutputTest(CosTest):  # decision 11 and the file rules
    def test_no_escape_codes_no_files_written(self):
        f, code, out, err = self.session(step(INIT, delta("hi"), assistant(tool("Bash", command="ls")), result(),
                                              ), stdin="a\n/help\n/cost\n/exit\n")
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", out)
        self.assertEqual(os.listdir(f.cwd), [])

    def test_source_stays_small_and_plain(self):
        with open(COS, encoding="utf-8") as f:
            src = f.read()
        self.assertLessEqual(len(src.splitlines()), 560)  # was 400, then 460, then 520; the kill sweep grew the file
        for banned in ("shell=True", "os.system", "socket", "urllib", "http.client", "import requests", "logging", "pickle"):
            self.assertNotIn(banned, src)
        for call in ("open", "eval", "exec"):  # the bare builtins, not Popen( and the like
            self.assertIsNone(re.search(r"(?<![A-Za-z0-9_.])%s\(" % call, src), call)


class SuiteProcessTest(CosTest):  # the suite imports every module into one process: this one must leave it as it was
    def state(self):
        """What the processes that the suite starts later will inherit and what a program in this process sees."""
        environment = subprocess.run(["env"], stdin=subprocess.DEVNULL, capture_output=True, text=True).stdout
        return sorted(environment.splitlines()), signal.getsignal(signal.SIGINT), "readline" in sys.modules

    def test_loading_the_script_is_harmless(self):
        before = self.state()
        load_cos()
        self.assertEqual(self.state(), before)


if __name__ == "__main__":
    unittest.main()
