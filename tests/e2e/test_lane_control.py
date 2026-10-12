"""F. lane stop, lane status and lane check: a stop leaves no process, status only reads, and check turns a vanished
session into exactly one lane.lost. The tmux server a run lives in keeps none of the caller's environment beyond the
fixed set of names the launcher gives every tmux command."""

import os
import shutil
import subprocess
import sys
import time
import uuid

from . import lanesupport, support

PROBE = "LB_H1_PROBE"
# The names that every tmux command of the launcher is given, with the caller's values (multiplexer.ENVIRONMENT), and
# the one name that tmux puts into the global environment of a server by itself, from its working directory.
FIVE = ("PATH", "HOME", "LANG", "TMPDIR", "USER")
BY_TMUX = "PWD"
# The probe test starts its session through the multiplexer module of the installed copy, in a process of its own whose
# environment it chooses. The session's pane only waits: the server ends with its last session.
SESSION = """import sys
sys.path.insert(0, sys.argv[1])
from laneboss import multiplexer
socket, name, directory, hold = sys.argv[2:]
multiplexer.new_session(socket, name, directory, [sys.executable, "-I", "-c", hold])
"""
HOLD = "import time; time.sleep(120)"


def installed_library():
    """The `lib` directory of the one installed copy that this module built."""
    found = sorted((support._installation.prefix / "share" / support.PROGRAM / "versions").glob("*/lib"))
    assert len(found) == 1, "expected one installed version, found %r" % (found,)
    return found[0]


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LaneControlTest(lanesupport.LaneTest):
    def test_stop_and_status(self):
        self.start("f-stop", "--runner", "forever", "--model", "ever-model-1", "--worktree", self.scratch("f-stop"),
                   "--budget", "20")
        record = self.record("f-stop")
        pids = [record["pid"]] + record["children"]
        time.sleep(1.0)
        count = len(self.events())
        lane = self.status("f-stop")
        everything = self.status()
        self.assertEqual(len(self.events()), count, "lane status appends nothing")
        self.assertEqual([item["lane"] for item in everything], ["f-stop"])
        self.assertEqual((lane["state"], lane["running"], lane["run"]), ("running", True, 1))
        live = lane["live"]
        self.assertIs(live["session_alive"], True)
        self.assertGreaterEqual(live["running_seconds"], 1.0)
        self.assertLessEqual(live["running_seconds"], 120.0)
        self.assertGreater(live["budget_left_seconds"], 0)
        self.assertLessEqual(live["budget_left_seconds"], 20 * 60)
        self.assertGreaterEqual(live["quiet_seconds"], 0)
        self.assertEqual(live["session"]["name"], "f-stop")
        stopped = self.lane_json("stop", "--lane", "f-stop")
        self.assertEqual((stopped["lane"], stopped["run"], stopped["reason"]), ("f-stop", 1, "stopped"))
        self.assert_gone(pids, timeout=5)
        ended = self.wait_event("lane.ended", "f-stop")
        self.assertEqual(ended["payload"]["reason"], "stopped")
        lane = self.status("f-stop")
        self.assertEqual((lane["state"], lane["running"], lane["reason"], lane["live"]["session_alive"]),
                         ("verifying", False, "stopped", False))
        self.lane("stop", "--lane", "f-stop", code=2)
        self.lane("status", "--lane", "f-absent", code=2)
        self.assert_sound()

    def test_check_reports_lost_once(self):
        for lane in ("f-lost-1", "f-lost-2"):
            self.start(lane, "--runner", "forever", "--model", "ever-model-1", "--worktree", self.scratch(lane))
        self.start("f-done", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("f-done"))
        self.wait_event("lane.ended", "f-done")
        pids = []
        for lane in ("f-lost-1", "f-lost-2"):
            record = self.record(lane)
            pids += [record["pid"]] + record["children"]
        checked = self.lane_json("check")
        self.assertEqual(checked["lost"], [])
        self.assertEqual(sorted(checked["alive"]), ["f-lost-1", "f-lost-2"])
        socket = self.status("f-lost-1")["live"]["session"]["socket"]
        count = len(self.events())
        # The multiplexer server dies behind the launcher's back; its supervising processes stop their runs and end.
        self.tmux(socket, "kill-server")
        deadline = time.monotonic() + 20
        while any(self.status(lane)["live"]["supervisor"]["alive"] for lane in ("f-lost-1", "f-lost-2")):
            self.assertLess(time.monotonic(), deadline, "the supervising processes outlived their session")
            time.sleep(0.2)
        checked = self.lane_json("check")
        self.assertEqual(sorted(item["lane"] for item in checked["lost"]), ["f-lost-1", "f-lost-2"])
        new = self.events()[count:]
        self.assertEqual(sorted((item["kind"], item["lane"]) for item in new),
                         [("lane.lost", "f-lost-1"), ("lane.lost", "f-lost-2")])
        self.assertEqual([(item["payload"]["run"], item["payload"]["survivors"]) for item in new], [(1, 0), (1, 0)])
        self.assertEqual(self.lane_json("check")["lost"], [])
        self.assertEqual(len(self.events()), count + 2)
        for lane in ("f-lost-1", "f-lost-2"):
            row = self.status(lane)
            self.assertEqual((row["running"], row["reason"], row["lost"], row["state"]),
                             (False, "lost", 1, "verifying"))
        self.assert_gone(pids)
        self.assert_sound()

    def stop_server(self, socket, pids):
        """The clean-up of the probe test, run in every path of it: the server at this socket is stopped when there is
        one, the socket's directory is removed, and neither the server nor its pane's process may be left."""
        subprocess.run(["tmux", "-S", socket, "kill-server"], env=self.environment, capture_output=True, timeout=30)
        shutil.rmtree(os.path.dirname(socket), ignore_errors=True)
        self.assertFalse(os.path.lexists(os.path.dirname(socket)), "the probe's socket directory is still there")
        self.assert_gone(pids)

    def test_tmux_server_keeps_no_caller_env(self):
        # The first command that reaches a tmux socket starts the server, and the server keeps that command's
        # environment as its global environment: `show-environment -g` shows it to every process that can reach the
        # socket, and every pane inherits it. A run receives its environment through a FIFO, never through tmux, so no
        # tmux command of the launcher may carry it: every tmux command of the launcher is given the names of FIVE that
        # the caller has, with the caller's values, and nothing else. The starter, the process that starts the server
        # through the product's own path, holds two probes, one under the module's literal name PROBE and one under a
        # name made up at run time, both with values made up at run time (the values, and the second name, appear
        # nowhere in the repository, and nothing can be keyed to them), a name that a wider set would let through
        # (SSH_AUTH_SOCK), the five names (PATH and TMPDIR with values of its own, LANG and USER with the test's values
        # or, when the test has none, values of its own, and HOME with the test's value), and the rest of the
        # environment of this test. The server's answer is read by a process with the test's own environment: that
        # process holds neither probe and none of the starter's own values of SSH_AUTH_SOCK, PATH and TMPDIR. Every name
        # of the starter outside the five (PWD, which tmux sets itself, apart) must be absent from the answer; every one
        # of the five must be there, with the starter's value; and no line of the answer may contain a probe's value.
        token = uuid.uuid4().hex
        value = "lb-h1-probe-" + token
        other = "LB_H1_" + token[:12].upper()
        socket = str(self.tmux_dir / "probe" / "server")
        pids = []
        self.addCleanup(self.stop_server, socket, pids)
        starter = dict(self.environment)
        starter.update({PROBE: value, other: "lb-h1-other-" + token, "SSH_AUTH_SOCK": "/tmp/lb-h1-agent-" + token,
                        "PATH": starter["PATH"] + os.pathsep + "/lb-h1-nowhere-" + token,
                        "TMPDIR": str(self.directory)})
        starter.setdefault("LANG", "C.UTF-8")
        starter.setdefault("USER", "lb-h1")
        started = subprocess.run([sys.executable, "-I", "-B", "-c", SESSION, str(installed_library()), socket,
                                  "lb-h1-probe", str(self.directory), HOLD], env=starter, capture_output=True,
                                 text=True, encoding="utf-8", timeout=60)
        self.assertEqual(started.returncode, 0, "the session was not started: {!r}".format(started.stderr))
        pids += map(int, self.tmux(socket, "list-panes", "-a", "-F", "#{pid} #{pane_pid}").stdout.split())
        lines = self.tmux(socket, "show-environment", "-g").stdout.splitlines()
        self.assertTrue(lines, "the answer is not a server's environment: it is empty")
        names = {line.partition("=")[0] for line in lines}
        with self.subTest("no other variable of the starter"):
            leaked = sorted(name for name in starter if name in names and name not in FIVE and name != BY_TMUX)
            self.assertEqual(leaked, [], "the tmux server's global environment holds variables of its starter")
        with self.subTest("the five names, with the starter's values"):
            wrong = [name for name in FIVE if "{}={}".format(name, starter[name]) not in lines]
            self.assertEqual(wrong, [], "the tmux server's global environment lacks these, or holds other values")
        with self.subTest("no value of the probes"):
            found = [item for item in (value, starter[other]) if any(item in line for line in lines)]
            self.assertEqual(found, [], "the tmux server's global environment holds a value of its starter")
