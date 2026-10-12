"""A stand-in agent program that writes a session record while it runs, for the refusal tests.

A real agent program cannot reach a test machine, so the refusal tests name this program as their runners' command. Its
first argument is the record format it writes: claude-code or text. It plays the scenario the test wrote to
$E2E_RECORD_DIR/<lane>.<run>.scenario.json (or <lane>.scenario.json): tool calls, their results and hook messages
written as lines of a session record in that format (for text, printed to its output, which is the lane's log), raw
lines and lines of other types, pauses, a wait for <lane>.go, a flood of lines, a change of a record's mode and its
exit status. The line shapes are the ones docs/architecture.md describes under "Refusals"; the content is invented.

Like standin.py it keeps a record of itself at $E2E_RECORD_DIR/<lane>.<run>.json: its process id, the record files it
wrote and the wall-clock moments the scenario marked.

Scenario steps, one key each:
  open    {"cwd", "time", "dir", "first"}  start a new claude-code record file below $HOME; "cwd" names another
                                      working directory, "time" a fixed timestamp, "dir" the record's directory below
                                      $HOME, "first" the length of a first user line written at once
  shell   {"id", "command"}           a shell call
  write   {"id", "path", "content"}   a file-tool write
  call    {"id", "tool", "input"}     any other tool call
  result  {"id", "text", "error"}     the result of an earlier call
  hook    {"id", "kind", "text", "event", "name"}  a hook's message about a call: kind blocking or non-blocking
  block   {"role", "type"}            an assistant or user line holding one content block of that type
  line    {"type", "body"}            a line of that type with the usual envelope and the body's keys
  raw     "text"                      a line written to the current record as it is
  say     "text"                      a line printed to the output (the lane's log)
  truncate {"path", "size"}           cut a file (the lane's log) to that many bytes
  mark    "name"                      remember the moment under that name
  sleep   seconds
  wait    "go"                        wait for <lane>.go in the record directory
  chmod   mode                        change the current record's mode
  flood   {"seconds", "rate"}         write shell calls and results at that many lines a second
  exit    status
"""

import datetime
import json
import os
import sys
import time
import uuid


def stamp():
    value = datetime.datetime.now(datetime.timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + "{:03d}Z".format(value.microsecond // 1000)


def option(arguments, name):
    return arguments[arguments.index(name) + 1] if name in arguments else None


class Session:
    """One claude-code record file."""

    def __init__(self, cwd, home, when=None, directory=None):
        self.cwd = cwd
        self.when = when
        self.id = str(uuid.uuid4())
        slug = "".join(character if character.isalnum() else "-" for character in cwd)
        folder = os.path.join(home, directory) if directory else os.path.join(home, ".claude", "projects", slug)
        self.path = os.path.join(folder, self.id + ".jsonl")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)

    def time(self):
        return self.when or stamp()

    def raw(self, text):
        os.write(self.fd, (text + "\n").encode("utf-8"))

    def line(self, value):
        self.raw(json.dumps(value))

    def envelope(self, kind, extra):
        return dict({"type": kind, "timestamp": self.time(), "cwd": self.cwd, "sessionId": self.id,
                     "uuid": str(uuid.uuid4())}, **extra)

    def message(self, kind, block):
        return self.envelope(kind, {"message": {"role": kind, "content": [block]}})

    def call(self, call_id, tool, arguments):
        self.line(self.message("assistant", {"type": "tool_use", "id": call_id, "name": tool, "input": arguments}))

    def shell(self, call_id, command):
        self.call(call_id, "Bash", {"command": command, "description": "a shell command"})

    def write(self, call_id, path, content):
        self.call(call_id, "Write", {"file_path": os.path.join(self.cwd, path), "content": content})

    def result(self, call_id, text, error):
        content = [{"type": "text", "text": text}] if error else text
        block = {"type": "tool_result", "tool_use_id": call_id, "content": content}
        if error:
            block["is_error"] = True
        self.line(self.message("user", block))

    def hook(self, call_id, kind, text, event, name):
        """A hook's message about a call, the way the program records it: an attachment line."""
        if kind == "blocking":
            attachment = {"type": "hook_blocking_error", "hookName": name, "toolUseID": call_id, "hookEvent": event,
                          "blockingError": {"blockingError": text, "command": "/opt/guards/doc-guard.sh"}}
        else:
            attachment = {"type": "hook_non_blocking_error", "hookName": name, "toolUseID": call_id,
                          "hookEvent": event, "stderr": text, "stdout": "", "exitCode": 1, "command": "guard"}
        self.line(self.envelope("attachment", {"attachment": attachment}))

    def block(self, role, kind):
        self.line(self.message(role, {"type": kind, "data": "invented"}))

    def flood(self, seconds, rate):
        """Benign shell calls and their results, written in batches every 10 milliseconds."""
        deadline = time.monotonic() + seconds
        per_batch = max(2, rate // 100)
        number = 0
        while time.monotonic() < deadline:
            began = time.monotonic()
            lines = []
            for _ in range(per_batch // 2):
                number += 1
                call_id = "flood-{}".format(number)
                lines.append(json.dumps(self.message("assistant", {
                    "type": "tool_use", "id": call_id, "name": "Bash",
                    "input": {"command": "ls -la src/module-{}".format(number)}})))
                lines.append(json.dumps(self.message("user", {
                    "type": "tool_result", "tool_use_id": call_id, "content": "total 0"})))
            os.write(self.fd, ("\n".join(lines) + "\n").encode("utf-8"))
            time.sleep(max(0.0, 0.01 - (time.monotonic() - began)))


def main():
    fmt = sys.argv[1]
    arguments = sys.argv[2:]
    lane = os.environ.get("LANEBOSS_LANE", "no-lane")
    run = os.environ.get("LANEBOSS_RUN", "0")
    records = os.environ["E2E_RECORD_DIR"]
    home = os.path.expanduser("~")
    path = os.path.join(records, "{}.{}.json".format(lane, run))
    record = {"mode": "session", "format": fmt, "argv": sys.argv[1:], "cwd": os.getcwd(), "pid": os.getpid(),
              "pgid": os.getpgrp(), "started": time.time(), "ended": None, "children": [], "records": [], "marks": {}}
    target = option(arguments, "--brief")
    if target is not None:
        with open(target, "rb") as handle:
            record["brief"] = {"path": target, "text": handle.read().decode("utf-8")}

    def save():
        temporary = path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(record, handle)
        os.replace(temporary, path)

    def finish(code):
        record["ended"] = time.time()
        save()
        sys.stdout.flush()
        sys.exit(code)

    save()
    scenario = os.path.join(records, "{}.{}.scenario.json".format(lane, run))
    if not os.path.exists(scenario):
        scenario = os.path.join(records, "{}.scenario.json".format(lane))
    with open(scenario, encoding="utf-8") as handle:
        steps = json.load(handle)["steps"]
    print("sessionstandin: {} {} run {}".format(fmt, lane, run), flush=True)
    session = None
    for step in steps:
        (action, value), = step.items()
        if action == "open":
            session = Session(value.get("cwd", os.getcwd()), home, value.get("time"), value.get("dir"))
            if value.get("first"):
                session.line(session.envelope("user", {"message": {"role": "user", "content": "x" * value["first"]}}))
            record["records"].append(session.path)
            save()
        elif action == "shell":
            session.shell(value["id"], value["command"])
        elif action == "write":
            session.write(value["id"], value["path"], value["content"])
        elif action == "call":
            session.call(value["id"], value["tool"], value["input"])
        elif action == "result":
            session.result(value["id"], value["text"], value.get("error", False))
        elif action == "hook":
            session.hook(value["id"], value["kind"], value["text"], value.get("event", "PreToolUse"),
                         value.get("name", "PreToolUse:Bash"))
        elif action == "block":
            session.block(value["role"], value["type"])
        elif action == "line":
            session.line(session.envelope(value["type"], value["body"]))
        elif action == "raw":
            session.raw(value)
        elif action == "say":
            print(value, flush=True)
        elif action == "truncate":
            os.truncate(value["path"], value["size"])
        elif action == "mark":
            record["marks"][value] = time.time()
            save()
        elif action == "sleep":
            time.sleep(value)
        elif action == "wait":
            go = os.path.join(records, lane + "." + value)
            while not os.path.exists(go):
                time.sleep(0.05)
        elif action == "chmod":
            os.chmod(session.path, value)
        elif action == "flood":
            session.flood(value["seconds"], value["rate"])
        elif action == "exit":
            finish(value)
        else:
            print("sessionstandin: unknown step " + action, flush=True)
            finish(64)
    finish(0)


if __name__ == "__main__":
    main()
