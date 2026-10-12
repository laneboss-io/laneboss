#!/usr/bin/env python3
"""cos.py: an interactive terminal front for turn-by-turn agent sessions.

Every typed message is one headless request to the account wrapper (the message goes on standard input, never in
an argument). A session id ties the requests into one conversation. See docs/claudock.md.
"""
import argparse
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

try:
    import readline  # noqa: F401  line editing for input(); history stays in memory
except ImportError:
    pass

WRAPPER = "/Applications/Claudock.app/Contents/MacOS/claudock"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:\[\]-]*")
UUID = re.compile(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
MODES = ("default", "acceptEdits", "plan")
BYPASS = "bypassPermissions"
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
USAGE = ("usage: cos.py ACCOUNT [MODEL] [--resume SESSION] [--mode default|acceptEdits|plan] "
         "[--bypass-permissions]")
WARNING = "WARNING: approvals are bypassed: the agent may run any command and change any file it can reach."
NO_MODE = ("permission mode: the account's own default (not chosen here). On this Mac that is usually "
           "bypassPermissions:",
           "the agent may then run any command and change any file. To narrow it: --mode default|acceptEdits|plan, "
           "or /mode.")
HINT = "  (denied: this request ran without approval rights; see /mode)"
HELP = ("/exit          leave (Ctrl-D does the same); the session can be resumed later",
        "/help          this list",
        "/cost          the session's total cost so far",
        "/session       the session id and how to resume it",
        "/model NAME    use another model from the next request",
        "/mode [NAME]   show or set the permission mode: default, acceptEdits or plan",
        "A line ending in a backslash continues on the next line. Any other line goes to the agent.")


def number(value):
    """A finite number from a JSON value, else None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        value = float(value)
    except OverflowError:
        return None
    return value if math.isfinite(value) else None


def label(word, name, tool_input):
    """`  [word NAME] <first 100 characters of its command, file path or pattern>`."""
    detail = ""
    if isinstance(tool_input, dict):
        for key in ("command", "file_path", "pattern", "path", "url"):
            if isinstance(tool_input.get(key), str):
                detail = tool_input[key][:100]
                break
    return "  [%s %s]" % (word, name if isinstance(name, str) else "?") + (" " + detail if detail else "")


def leave(signum, frame):
    raise SystemExit(128 + signum)  # a closed terminal or a kill goes the same way out as an exit


def gone(proc):
    """True when no process of the request's group is left."""
    proc.poll()  # reaps the leader once it has exited: a zombie would still count as a member
    try:
        os.killpg(proc.pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


STEPS = (signal.SIGINT, signal.SIGTERM, signal.SIGKILL)
WAITS = (6, 4, 2)  # seconds to wait after the interrupt, after the terminate and after the kill


PS_PATHS = ("/bin/ps", "/usr/bin/ps")  # ps is never looked up through PATH


def cint(field):
    """The value of a field of ASCII digits that fits a positive C int, else None."""
    if field.isascii() and field.isdigit() and len(field) <= 10 and 0 < int(field) <= 2**31 - 1:
        return int(field)
    return None


def family(proc):
    """The process groups led by descendants of the request: the agent's shell tools run in groups of their own.
    The walk starts at the child and at every process of its group (the wrapper may be gone, the agent re-parented).
    Chosen by pid and ancestry only, from one listing; never group 0 or 1, the child's own or this program's.
    None when the listing failed."""
    ps = next((path for path in PS_PATHS if os.path.isfile(path) and os.access(path, os.X_OK)), None)
    if ps is None:
        return None
    try:
        done = subprocess.run([ps, "-axo", "pid=,ppid=,pgid="], stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=2, start_new_session=True)  # own session: a Ctrl-C cannot kill it
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    rows = []
    for row in done.stdout.splitlines():
        fields = [cint(field) for field in row.split()]
        if len(fields) == 3 and None not in fields:
            rows.append(tuple(fields))
    if done.returncode != 0 or not rows:
        return None
    children = {}
    for pid, ppid, pgid in rows:
        children.setdefault(ppid, []).append((pid, pgid))
    todo = [proc.pid] + [pid for pid, ppid, pgid in rows if pgid == proc.pid]
    seen, leaders = set(todo), set()
    while todo:
        for pid, pgid in children.get(todo.pop(), []):
            if pid not in seen:
                seen.add(pid)
                todo.append(pid)
                if pgid == pid and pgid not in (0, 1, proc.pid, os.getpgrp()):  # a descendant that leads its own group
                    leaders.add(pgid)
    return sorted(leaders)


def alive(proc, groups):
    """The groups that still answer: the child's own (its leader reaped first) and the extra ones."""
    left = [] if gone(proc) else [proc.pid]
    for pgid in groups:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            continue
        except OSError:
            pass
        left.append(pgid)
    return left


def stop(proc, notify=None):
    """End the request's whole group: interrupt, terminate, kill, waiting WAITS seconds after each step while any of it
    answers. At the kill the groups of the child's descendants go too (notify gets a line when they cannot be listed).
    A Ctrl-C meanwhile skips to the next step; a hangup or terminate is raised once it is done. Returns the groups that
    may still be running."""
    state = {"skip": False, "exit": None}

    def note(signum, frame):
        if signum == signal.SIGINT:
            state["skip"] = True
        else:
            state["exit"] = SystemExit(128 + signum)

    saved = {sig: signal.signal(sig, note) for sig in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)}
    groups = []
    try:
        for sig, wait in zip(STEPS, WAITS):
            state["skip"] = False
            if sig == signal.SIGKILL:
                groups = family(proc)  # taken before the kill: afterwards the tools are reparented and cannot be found
                if groups is None:
                    groups = []
                    if notify:
                        notify("[could not list the request's processes: some of its tools may still run]")
            for pgid in [proc.pid] + (groups if sig == signal.SIGKILL else []):
                try:
                    os.killpg(pgid, sig)
                except OSError:
                    pass
            end = time.monotonic() + wait
            while alive(proc, groups) and not state["skip"] and time.monotonic() < end:
                time.sleep(0.05)
            if not alive(proc, groups):
                break
        end = time.monotonic() + 0.5  # a Ctrl-C may have cut the last wait short: look again before reporting
        while alive(proc, groups) and time.monotonic() < end:
            time.sleep(0.05)
        left = alive(proc, groups)
    finally:
        for sig, handler in saved.items():
            signal.signal(sig, handler)
    if state["exit"]:
        raise state["exit"]
    return left


def close(stream):
    try:
        stream.close()
    except OSError:
        pass


class Session:
    def __init__(self, account, model, sid, resumed, mode, bypass):
        self.wrapper = os.environ.get("COS_CLAUDOCK") or WRAPPER
        self.account, self.model, self.sid = account, model, sid
        self.mode = BYPASS if bypass else mode  # None: no permission option is passed at all
        self.confirmed = resumed  # the agent has shown this session's init line (or it existed before)
        self.turn, self.total = 0, None
        self.prev = None if resumed else 0.0  # the session total before the current request
        self.hinted, self.noted, self.reported = False, set(), None  # reported: the mode of the last init line
        self.tty = sys.stdout.isatty()
        self.col0, self.held, self.shown = True, 0, False
        self.streamed, self.tools, self.result = {}, set(), None

    # ---- output
    def write(self, text):
        sys.stdout.write(text)
        sys.stdout.flush()

    def end_line(self):
        """Leave the cursor at the start of a line; of the answer's trailing newlines exactly one is printed."""
        if self.held or not self.col0:
            self.write("\n")
        self.held, self.col0 = 0, True

    def say(self, text, dim=True):
        self.end_line()
        text = CONTROL.sub(" ", text)
        self.write("\x1b[2m%s\x1b[0m\n" % text if self.tty and dim else text + "\n")

    def answer(self, text):
        """The agent's text, printed at once; trailing newlines wait until more text or the end of the turn."""
        text = UNSAFE.sub("", text)
        body = text.rstrip("\n")
        if body:
            self.write("\n" * self.held + body)
            self.held, self.col0, self.shown = len(text) - len(body), False, True
        else:
            self.held += len(text)

    # ---- the stream
    def handle(self, line):
        if not line.strip():
            return
        try:
            event = json.loads(line)
        except (ValueError, RecursionError):
            self.say("[raw] " + line, dim=False)
            return
        if not isinstance(event, dict):
            return
        kind = event.get("type")
        if kind == "system" and event.get("subtype") == "init":
            self.confirmed = True
            mode = event.get("permissionMode")
            if isinstance(mode, str):
                self.reported = mode
                key = (mode, self.mode)  # a warning is spent per pair: the reported mode and the mode in force here
                if mode == BYPASS and self.mode != BYPASS and key not in self.noted:
                    self.noted.add(key)
                    if self.mode:  # a mode was chosen, and the agent says otherwise
                        self.say("WARNING: the agent reports bypassPermissions although --mode %s was passed."
                                 % self.mode, dim=False)
                    self.say(WARNING, dim=False)
                elif self.mode is None and mode not in ("default", BYPASS) and key not in self.noted:
                    self.noted.add(key)
                    self.say("  [account default permission mode: %s]" % mode)
        elif kind == "stream_event":
            self.on_event(event.get("event"))
        elif kind == "assistant":
            self.on_assistant(event.get("message"))
        elif kind == "result":
            self.result = event

    def on_event(self, event):
        if not isinstance(event, dict):
            return
        if event.get("type") == "message_start":
            self.streamed = {}
            self.end_line()
        elif event.get("type") == "content_block_delta":
            delta = event.get("delta")
            if isinstance(delta, dict) and delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
                index = event.get("index")
                key = index if isinstance(index, int) else 0
                self.streamed[key] = self.streamed.get(key, "") + delta["text"]
                self.answer(delta["text"])

    def on_assistant(self, message):
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            return
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and isinstance(block.get("text"), str) and block["text"]:
                for key, printed in self.streamed.items():
                    if printed == block["text"]:  # already shown as deltas
                        del self.streamed[key]
                        break
                else:
                    self.end_line()
                    self.answer(block["text"])
            elif block.get("type") == "tool_use":
                ident = block.get("id")
                if isinstance(ident, str):
                    if ident in self.tools:
                        continue
                    self.tools.add(ident)
                self.say(label("tool", block.get("name"), block.get("input")))

    def finish(self, n, started, code):
        self.end_line()
        res = self.result
        if res is None:
            self.say("[turn %d | no result | exit %d]" % (n, code))
            return
        denials = res.get("permission_denials")
        lines = [label("denied", d.get("tool_name"), d.get("tool_input"))
                 for d in (denials if isinstance(denials, list) else []) if isinstance(d, dict)]
        for text in lines:
            self.say(text)
        if lines and not self.hinted:
            self.hinted = True
            self.say(HINT)
        if res.get("is_error") is True and not self.shown and isinstance(res.get("result"), str):
            self.say("  [error] " + res["result"][:200])
        cost = number(res.get("total_cost_usd"))
        if cost is None:
            this = total = "?"
        else:
            this = "?" if self.prev is None else "$%.4f" % (cost - self.prev + 0.0)
            total = "$%.4f" % cost
            self.prev = self.total = cost
        self.say("[turn %d | this turn %s | session %s | %.1f s]" % (n, this, total, time.monotonic() - started))

    # ---- one request
    def command(self):
        cmd = [self.wrapper, "run", self.account, "--", "-p", "--resume" if self.confirmed else "--session-id",
               self.sid, "--model", self.model, "--output-format", "stream-json", "--verbose",
               "--include-partial-messages"]
        if self.mode:
            cmd += ["--permission-mode", self.mode]
        return cmd

    def ask(self, message):
        try:
            proc = subprocess.Popen(self.command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    start_new_session=True)
        except (OSError, ValueError) as err:
            print("cos: cannot start %s: %s" % (self.wrapper, getattr(err, "strerror", None) or err), file=sys.stderr)
            return
        self.turn += 1
        n, started = self.turn, time.monotonic()
        self.result, self.shown, self.streamed, self.held = None, False, {}, 0
        finished = False
        try:
            try:
                proc.stdin.write(message.encode("utf-8", "replace") + b"\n")
            except OSError:  # a broken pipe: the request fails like any other
                pass
            close(proc.stdin)
            for raw in proc.stdout:
                self.handle(raw.decode("utf-8", "replace").rstrip("\r\n"))
            code = proc.wait()
            finished = True
        except KeyboardInterrupt:
            if self.stopped(proc):  # a Ctrl-C after the request has ended prints nothing and stops nothing
                self.say("[interrupted]")
            return
        finally:
            if not finished and not gone(proc):  # any other way out (an exception, a hangup, a kill) must leave nothing
                self.stopped(proc)
            close(proc.stdin)
            close(proc.stdout)
        self.finish(n, started, code)

    def stopped(self, proc):
        """Stop what still runs of the request, saying so; False (and silent) when nothing runs any more."""
        def plain(text):
            try:
                self.say(text, dim=False)
            except OSError:
                pass

        if gone(proc):
            return False
        plain("[stopping the request: wait a few seconds, do not press Ctrl-C again]")
        left = stop(proc, plain)
        if left:
            plain("WARNING: processes of this request may still be running (group %s)"
                  % ", ".join(str(pgid) for pgid in left))
        return True

    # ---- local commands and the prompt
    def resume_line(self):
        if not self.confirmed:  # no init line was seen and the run did not start with --resume
            return "no session was started"
        return "session %s  (continue later with: --resume %s)" % (self.sid, self.sid)

    def local(self, line):
        """Run a local command: None if the line is not one, "exit" to leave, else True."""
        words = line.split()
        if not words or "\n" in line:
            return None
        cmd, rest = words[0], words[1:]
        if cmd == "/exit" and not rest:
            return "exit"
        elif cmd == "/help" and not rest:
            for text in HELP:
                self.say(text, dim=False)
        elif cmd == "/cost" and not rest:
            if self.total is None:
                self.say("session total: unknown (no request has finished yet)", dim=False)
            else:
                self.say("session total so far: $%.4f over %d request(s) in this run" % (self.total, self.turn),
                         dim=False)
        elif cmd == "/session" and not rest:
            self.say(self.resume_line(), dim=False)
        elif cmd == "/model":
            if not rest:
                self.say("model: " + self.model, dim=False)
            elif len(rest) == 1 and NAME.fullmatch(rest[0]):
                self.model = rest[0]
                self.say("model: %s (from the next request)" % self.model, dim=False)
            else:
                self.say("usage: /model NAME  (letters, digits and . _ : [ ] -)", dim=False)
        elif cmd == "/mode":
            if rest == [BYPASS]:
                self.say("bypass can only be chosen at the start (--bypass-permissions)", dim=False)
            elif len(rest) == 1 and rest[0] in MODES:
                self.mode = rest[0]
            elif rest:
                self.say("usage: /mode [default|acceptEdits|plan]", dim=False)
            self.say("mode: " + (self.mode or "none passed (the account's own default applies%s)"
                                 % (": " + self.reported if self.reported else "")), dim=False)
            if self.mode == BYPASS:
                self.say(WARNING, dim=False)
        else:
            return None
        return True

    def read(self):
        """One message (backslash lines joined), or None at end of input."""
        parts = []
        while True:
            try:
                line = input(". " if parts else "> ")
            except EOFError:
                return None
            except KeyboardInterrupt:
                parts = []
                print("\n(type /exit or press Ctrl-D to leave)")
                continue
            self.col0 = sys.stdin.isatty()  # a typed Enter ends the prompt's line; piped input leaves it open
            if not line.endswith("\\"):
                return "\n".join(parts + [line])
            parts.append(line[:-1])

    def loop(self):
        if not shutil.which(self.wrapper):
            print("cos: the account wrapper was not found at %s: Claudock is required "
                  "(set COS_CLAUDOCK to its claudock program)" % self.wrapper, file=sys.stderr)
            return 2
        self.say("cos: account %s, model %s, session %s  (type /help for commands)"
                 % (self.account, self.model, self.sid), dim=False)
        if self.mode == BYPASS:
            self.say(WARNING, dim=False)
        elif self.mode is None:
            for text in NO_MODE:
                self.say(text, dim=False)
        while True:
            message = self.read()
            if message is None:
                if sys.stdin.isatty():
                    print()
                break
            if not message.strip():
                continue
            try:
                handled = self.local(message.strip())
                if handled is None:
                    self.ask(message)
            except KeyboardInterrupt:  # a Ctrl-C that lands between two steps of a request
                self.say("[interrupted]")
                continue
            if handled == "exit":
                break
        self.say(self.resume_line(), dim=False)
        return 0


class Parser(argparse.ArgumentParser):
    def error(self, message):
        print(USAGE, file=sys.stderr)
        print("cos.py: error: " + message, file=sys.stderr)
        sys.exit(2)


def name(text):
    if not NAME.fullmatch(text):
        raise argparse.ArgumentTypeError("%r must match [A-Za-z0-9][A-Za-z0-9._:[]-]*" % text)
    return text


def session(text):
    if not UUID.fullmatch(text):
        raise argparse.ArgumentTypeError("%r is not a UUID" % text)
    return text.lower()


def main(argv=None):
    parser = Parser(prog="cos.py", usage=USAGE, allow_abbrev=False)
    parser.add_argument("account", type=name)
    parser.add_argument("model", type=name, nargs="?")
    parser.add_argument("--resume", type=session, metavar="SESSION")
    parser.add_argument("--mode", choices=MODES)
    parser.add_argument("--bypass-permissions", action="store_true", dest="bypass")
    args = parser.parse_intermixed_args(argv)
    model = args.model or os.environ.get("COS_MODEL") or "claude-sonnet-5-5"
    if not NAME.fullmatch(model):
        parser.error("COS_MODEL %r must match [A-Za-z0-9][A-Za-z0-9._:[]-]*" % model)
    if args.bypass and args.mode:
        parser.error("--mode and --bypass-permissions exclude each other")
    for sig in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(sig, leave)
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    return Session(args.account, model, args.resume or str(uuid.uuid4()), args.resume is not None, args.mode,
                   args.bypass).loop()


if __name__ == "__main__":
    sys.exit(main())
