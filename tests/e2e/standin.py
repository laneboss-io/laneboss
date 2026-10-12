"""A stand-in runner program for the lane tests.

A real agent program and its accounts cannot reach a test machine, so the lane tests name this program as their
runners' command instead. The first argument picks a behaviour. Every run writes a record to
$E2E_RECORD_DIR/<lane>.<run>.json (written whole through a temporary name, updated when the run ends): the
argument vector, the working directory, its process ids and those of its children, a few environment variables,
the bytes of the brief and message files it was given, and the wall-clock times it started and ended.

Behaviours: ok (prints a line, exits 0), nap (prints, sleeps two seconds, exits 0), fail (exits 3), forever (starts a
child and runs until stopped), stubborn (ignores SIGTERM and starts two children that ignore it too, one of them in a
session of its own), quiet (prints one line, then nothing), limit and dropped (print the line a configuration's
patterns recognise, exit 1), writer (writes work.txt in its working directory, exits 0), secret (prints a value
that looks like a credential on a limit line, exits 1), leaver (starts a child, waits for the file <lane>.go in the
record directory, then exits 7 and leaves the child behind), waiter (waits for <lane>.go, then exits 0), detacher
(starts a helper that makes a session of its own, forks a worker, records both in <lane>.<run>.helper.json and exits
after two seconds, while the runner goes on), late (does what detacher does once <lane>.go appears), reaped (starts a
child that ends after two seconds, collects it and goes on), regex (prints forty a's and an exclamation mark, exits
1), limitdrop and droplimit (print a limit line and a dropped line, in that order or the other, exit 1), slowend
(prints what regex prints, starts a child that ignores SIGTERM in its own process group and exits 1 at once),
setsider (starts a child that, once <lane>.go appears, makes a session of its own and goes on; then exits 0), deaf
(what forever does, but it never reads its standard input), shut (closes its standard input without reading it and
exits 0), limit0 (prints the line a configuration's limit pattern recognises and exits 0, which limit does not),
idle-open (holds its standard input open for one second without reading it, then exits 0), envcheck (says by a fixed
word, and in its record as `environment_seen`, whether the variable named by --env-name holds a value whose SHA-256 is
--env-sha256, and exits 0; the value itself is never printed or kept) and streamer (plays the steps of the file
<lane>.<run>.script in the record directory, a JSON list, and exits 0 at its end: {"print": TEXT} prints a line,
{"bytes": BASE64} writes bytes as they are, {"wait": NAME} waits for the file <lane>.NAME, {"sleep": SECONDS} sleeps,
{"forever": true} runs until stopped and {"exit": CODE} exits; with no script file it prints one line. It prints
nothing of its own, so a log of invented stream lines holds only those).

Every behaviour except deaf, shut and idle-open also reads its standard input to its end before it does anything else,
and keeps the bytes in the record as "stdin" (length, sha256, the bytes in base64, and whether standard input is
/dev/null itself): empty and /dev/null when the launcher gave it nothing, the prompt when the runner is configured with
prompt = "stdin".
"""

import base64
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

ENVIRONMENT = ("LANEBOSS_CONFIG", "LANEBOSS_LANE", "LANEBOSS_RUN", "TMUX", "TMUX_PANE", "E2E_MARKER")
SLEEPER = "import signal, time\n{}time.sleep(600)\n"
HELPER = """import json, os, sys, time
os.setsid()
worker = os.fork()
if worker == 0:
    time.sleep(600)
    os._exit(0)
temporary = sys.argv[1] + ".tmp"
with open(temporary, "w", encoding="utf-8") as handle:
    json.dump({"helper": os.getpid(), "worker": worker}, handle)
os.replace(temporary, sys.argv[1])
time.sleep(2)
os._exit(0)
"""
SETSID = """import os, sys, time
go = sys.argv[1]
while not os.path.exists(go):
    time.sleep(0.05)
os.setsid()
open(go + ".done", "w").close()
time.sleep(600)
"""


def wait_for(path):
    while not os.path.exists(path):
        time.sleep(0.05)


def option(arguments, name):
    return arguments[arguments.index(name) + 1] if name in arguments else None


def is_devnull():
    """True when standard input is /dev/null itself (not an empty pipe or a closed descriptor), None when it cannot be
    told."""
    try:
        return os.path.samestat(os.fstat(0), os.stat(os.devnull))
    except OSError:
        return None


def standard_input():
    """What the launcher gave the run on standard input, read to its end: nothing for /dev/null."""
    devnull = is_devnull()
    data = b"" if sys.stdin is None or sys.stdin.isatty() else sys.stdin.buffer.read()
    return {"length": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "base64": base64.b64encode(data).decode("ascii"), "devnull": devnull}


def play(steps, directory, lane, finish):
    """The steps of a streamer's script, one after the other; the run ends at the last one (exit 0) or at an exit."""
    for step in steps:
        if "print" in step:
            print(step["print"], flush=True)
        elif "bytes" in step:
            sys.stdout.flush()
            sys.stdout.buffer.write(base64.b64decode(step["bytes"]))
            sys.stdout.buffer.flush()
        elif "wait" in step:
            wait_for(os.path.join(directory, "{}.{}".format(lane, step["wait"])))
        elif "sleep" in step:
            time.sleep(step["sleep"])
        elif "forever" in step:
            while True:
                time.sleep(600)
        elif "exit" in step:
            finish(step["exit"])
    finish(0)


def main():
    mode = sys.argv[1]
    arguments = sys.argv[2:]
    lane = os.environ.get("LANEBOSS_LANE", "no-lane")
    run = os.environ.get("LANEBOSS_RUN", "0")
    path = os.path.join(os.environ["E2E_RECORD_DIR"], "{}.{}.json".format(lane, run))
    record = {"mode": mode, "argv": sys.argv[1:], "cwd": os.getcwd(), "pid": os.getpid(), "pgid": os.getpgrp(),
              "started": time.time(), "ended": None, "children": [],
              "environment": {name: os.environ.get(name) for name in ENVIRONMENT}}
    if mode not in ("deaf", "shut", "idle-open"):
        record["stdin"] = standard_input()
    for name in ("--brief", "--message"):
        target = option(arguments, name)
        if target is not None:
            with open(target, "rb") as handle:
                record[name[2:]] = {"path": target, "text": handle.read().decode("utf-8")}

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

    if mode == "streamer":
        save()
        script = os.path.join(os.environ["E2E_RECORD_DIR"], "{}.{}.script".format(lane, run))
        steps = [{"print": "standin: streamer {} run {}".format(lane, run)}]
        if os.path.exists(script):
            with open(script, encoding="utf-8") as handle:
                steps = json.load(handle)
        play(steps, os.environ["E2E_RECORD_DIR"], lane, finish)
    print("standin: {} {} run {}".format(mode, lane, run), flush=True)
    if mode == "shut":
        os.close(0)
        finish(0)
    if mode == "idle-open":
        # Standard input stays open, and unread, while the launcher writes a prompt that fits the pipe: written is not read.
        save()
        time.sleep(1)
        finish(0)
    if mode == "ok":
        finish(0)
    if mode == "nap":
        save()
        time.sleep(2)
        print("standin: nap over", flush=True)
        finish(0)
    if mode == "fail":
        print("standin: failing on purpose", flush=True)
        finish(3)
    if mode == "limit":
        print("standin: usage limit reached for this account", flush=True)
        finish(1)
    if mode == "limit0":
        print("standin: usage limit reached for this account", flush=True)
        finish(0)
    if mode == "dropped":
        print("standin: stream disconnected before the response completed", flush=True)
        finish(1)
    if mode == "envcheck":
        name, wanted = option(arguments, "--env-name"), option(arguments, "--env-sha256")
        value = os.environ.get(name)
        record["environment_seen"] = value is not None and hashlib.sha256(value.encode("utf-8")).hexdigest() == wanted
        print("standin: environment {}".format("seen" if record["environment_seen"] else "missing"), flush=True)
        finish(0)
    if mode == "writer":
        with open("work.txt", "w", encoding="utf-8") as handle:
            handle.write("uncommitted work\n")
        finish(0)
    if mode == "secret":
        token = "gh" + "p_" + "Z9y8X7w6V5u4T3s2R1q0" + "P9o8N7m6L5k4J3i2"
        record["secret"] = token
        print("standin: usage limit reached for key " + token, flush=True)
        finish(1)
    if mode in ("forever", "deaf"):
        child = subprocess.Popen([sys.executable, "-c", SLEEPER.format("")])
        record["children"].append(child.pid)
        save()
        while True:
            time.sleep(600)
    if mode == "stubborn":
        ignore = "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = subprocess.Popen([sys.executable, "-c", SLEEPER.format(ignore)])
        escaped = subprocess.Popen([sys.executable, "-c", SLEEPER.format(ignore)], start_new_session=True)
        record["children"] += [child.pid, escaped.pid]
        save()
        while True:
            time.sleep(600)
    if mode == "quiet":
        save()
        while True:
            time.sleep(600)
    go = os.path.join(os.environ["E2E_RECORD_DIR"], lane + ".go")
    if mode == "leaver":
        child = subprocess.Popen([sys.executable, "-c", SLEEPER.format("")])
        record["children"].append(child.pid)
        save()
        wait_for(go)
        print("standin: leaving a child behind", flush=True)
        finish(7)
    if mode == "waiter":
        save()
        wait_for(go)
        finish(0)
    if mode in ("detacher", "late"):
        if mode == "late":
            save()
            wait_for(go)
        helper_record = os.path.join(os.environ["E2E_RECORD_DIR"], "{}.{}.helper.json".format(lane, run))
        helper = subprocess.Popen([sys.executable, "-c", HELPER, helper_record])
        record["children"].append(helper.pid)
        save()
        helper.wait()
        while True:
            time.sleep(600)
    if mode == "setsider":
        child = subprocess.Popen([sys.executable, "-c", SETSID, go])
        record["children"].append(child.pid)
        save()
        wait_for(go + ".done")
        finish(0)
    if mode == "reaped":
        helper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
        record["children"].append(helper.pid)
        save()
        helper.wait()
        record["reaped"] = time.time()
        save()
        while True:
            time.sleep(600)
    if mode == "regex":
        print("a" * 40 + "!", flush=True)
        finish(1)
    if mode == "slowend":
        ignore = "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        child = subprocess.Popen([sys.executable, "-c", SLEEPER.format(ignore)])
        record["children"].append(child.pid)
        print("a" * 40 + "!", flush=True)
        finish(1)
    if mode in ("limitdrop", "droplimit"):
        lines = ["standin: usage limit reached for this account",
                 "standin: stream disconnected before the response completed"]
        for line in lines if mode == "limitdrop" else lines[::-1]:
            print(line, flush=True)
        finish(1)
    print("standin: unknown mode", flush=True)
    finish(64)


if __name__ == "__main__":
    main()
