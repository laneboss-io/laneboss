"""Fix round 2, findings 3 and 4 (ruling R25): the supervising process follows a remembered process only while its
identity (process id and start time) is verified alive, and knows the runner's process group from the moment it
creates the runner.
"""

import json
import shutil
import subprocess
import sys
import time

from . import lanesupport, support

PARENT = ("import subprocess, sys, time\n"
          "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])\n"
          "print(child.pid, flush=True)\n"
          "time.sleep(600)\n")


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LaneDiscoveryTest(lanesupport.LaneTest):
    def unrelated(self, pid=None):
        """An unrelated process with a child: (process, child pid). With pid, the process gets exactly that id, by
        steering the kernel's next id (Linux, root through sudo); None when ids cannot be steered here."""
        if pid is not None:
            if not sys.platform.startswith("linux") or shutil.which("sudo") is None or subprocess.run(
                    ["sudo", "-n", "true"], capture_output=True).returncode != 0:
                return None
        for attempt in range(200):
            if pid is not None:
                subprocess.run(["sudo", "-n", "sh", "-c", "echo {} > /proc/sys/kernel/ns_last_pid".format(pid - 1)],
                               capture_output=True)
            process = subprocess.Popen([sys.executable, "-c", PARENT], stdout=subprocess.PIPE, text=True)
            if pid is None or process.pid == pid:
                child = int(process.stdout.readline())
                self.sentinels.append(child)

                def end():
                    process.kill()
                    process.wait()
                    process.stdout.close()

                self.addCleanup(end)
                return process, child
            process.kill()
            process.wait()
            process.stdout.close()
        return None

    def sampled(self, lane, pid, timeout=15):
        path = self.run_record_path(lane)
        deadline = time.monotonic() + timeout
        while pid not in [item["pid"] for item in json.loads(path.read_text(encoding="utf-8"))["processes"]]:
            self.assertLess(time.monotonic(), deadline, "the supervising process never sampled process {}".format(pid))
            time.sleep(0.1)
        return path

    def test_reused_pid_is_not_followed(self):
        self.start("u-reuse", "--runner", "reaped", "--model", "reaped-model-1", "--worktree",
                   self.scratch("u-reuse"))
        record = self.record("u-reuse")
        helper = record["children"][0]
        path = self.sampled("u-reuse", helper)
        self.assert_gone([helper], timeout=10)
        steered = self.unrelated(helper)
        if steered is not None:
            # The helper's process id now belongs to an unrelated process with a child of its own: the supervising
            # process remembers the helper, whose identity has ended, and must not follow its id to that child.
            process, child = steered
            time.sleep(2.0)
            recorded = [item["pid"] for item in json.loads(path.read_text(encoding="utf-8"))["processes"]]
            self.assertNotIn(child, recorded)
            self.lane_json("stop", "--lane", "u-reuse")
            self.assert_gone([record["pid"]], timeout=5)
        else:
            # Process ids cannot be steered here: the run record names the helper's ended identity under the id of an
            # unrelated process with a child, as a reused id would look, and a lost run is stopped.
            process, child = self.unrelated()
            self.kill_supervisor("u-reuse")
            self.lane_json("check")
            run_record = json.loads(path.read_text(encoding="utf-8"))
            ended = next(item for item in run_record["processes"] if item["pid"] == helper)
            run_record["processes"].append(dict(ended, pid=process.pid))
            path.write_text(json.dumps(run_record), encoding="utf-8")
            stopped = self.lane_json("stop", "--lane", "u-reuse")
            self.assertEqual(stopped["removed"], 1)
            self.assert_gone([record["pid"]], timeout=5)
        time.sleep(1.0)
        self.assertIsNone(process.poll(), "an unrelated process under a reused id was signalled")
        self.assertTrue(self.alive(child), "the child of an unrelated process under a reused id was signalled")
        self.assert_sound()

    def test_runner_leaving_at_once(self):
        # Outside Linux nothing adopts a run's orphans; LANEBOSS_PROCESSES=portable gives Linux the same path.
        self.environment["LANEBOSS_PROCESSES"] = "portable"
        directory = self.home / "configs" / "alpha"
        text = (directory / "config.toml").read_text(encoding="utf-8")
        script = 'sleep 600 & echo $! > "$E2E_RECORD_DIR/$LANEBOSS_LANE.child"'
        text += "[runners.quickfork]\ncommand = {}\n".format(lanesupport.toml(["/bin/sh", "-c", script, "quickfork",
                                                                                "{brief}"]))
        (directory / "config.toml").write_text(text, encoding="utf-8")
        for attempt in range(3):
            lane = "u-quick{}".format(attempt)
            self.start(lane, "--runner", "quickfork", "--model", "quick-model-1", "--worktree", self.scratch(lane))
            ended = self.wait_event("lane.ended", lane)
            child = self.records["alpha"] / (lane + ".child")
            pid = int(child.read_text(encoding="utf-8"))
            self.sentinels.append(pid)
            # The runner exited at once and left a child in its process group: the run is not over until it is gone.
            self.assert_gone([pid], timeout=5)
            self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"],
                              ended["payload"]["survivors"]), ("exit", 0, 0))
        self.assert_sound()
