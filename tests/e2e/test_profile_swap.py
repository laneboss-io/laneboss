"""Black-box profile-swap checks; the only vendor executable is a private PATH stub.

Run the behavioral suite on a disposable machine with Python 3.11 or newer:
    python3 -m unittest tests.e2e.test_profile_swap -v
The --static-checks mode also exercises CLI help, so it runs on the disposable machine.
The product is never imported. Mutants execute copies through the same CLI rows.
"""
import json

from .support import helper_binary
import py_compile
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "integrations" / "claudock" / "profile_swap" / "main.go"
REAL_SHAPE = Path(__file__).resolve().parent / "fixtures" / "claudock-usage.tsv"
HEADER = "PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\n"
FUTURE = "2099-01-01T01:00:00Z"
LATER = "2099-01-01T05:00:00Z"
PAST = "2000-01-01T00:00:00Z"
SID = "11111111-2222-4333-8444-555555555555"
PROMPT = "Continue the same session from where it stopped."

# This fixture implements the vendor boundary, not any profile-swap behavior.
# Its outputs come from files written by each row, and every invocation is recorded.
STUB = r'''import json
import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
with (root / "calls.jsonl").open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"argv": sys.argv[1:], "cwd": os.getcwd()}) + "\n")
control = json.loads((root / "control.json").read_text(encoding="utf-8"))
if sys.argv[1:2] == ["usage"]:
    sys.stdout.write((root / "usage.tsv").read_text(encoding="utf-8"))
    sys.stderr.write(control.get("usage_stderr", ""))
    sys.exit(control.get("usage_exit", 0))
if sys.argv[1:2] == ["run"]:
    sys.stdout.write(control.get("run_stdout", ""))
    sys.stderr.write(control.get("run_stderr", ""))
    sys.exit(control.get("run_exit", 0))
sys.stderr.write("stub: unexpected command\n")
sys.exit(2)
'''


def tsv(*rows):
    """Rows are (profile, used, reset[, window[, plan]]); names come from the caller."""
    lines = [HEADER]
    for row in rows:
        name, used, reset = row[:3]
        window = row[3] if len(row) >= 4 else "5-hour session"
        plan = row[4] if len(row) >= 5 else "Max 99×"
        lines.append(f"{name}\t{plan}\t{window}\t{used}\t{reset}\n")
    return "".join(lines)


class Stub:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.cwd = self.root / "session room"
        self.cwd.mkdir()
        self.executable = self.bin / "claudock"
        self.executable.write_text(f"#!{sys.executable}\n" + STUB, encoding="utf-8")
        self.executable.chmod(0o755)
        self.configure(HEADER)

    def configure(self, usage, **control):
        (self.root / "usage.tsv").write_text(usage, encoding="utf-8")
        (self.root / "control.json").write_text(json.dumps(control), encoding="utf-8")

    def call(self, args, script=SCRIPT):
        # No inherited environment, credentials, network service, or real vendor on PATH.
        # A mutant is one standalone Go source file outside the checkout. Build
        # exactly that file, rather than its directory or the original package.
        program = helper_binary(script, standalone=Path(script).resolve() != SCRIPT.resolve())
        return subprocess.run([str(program), *args],
                              cwd=self.root, env={"PATH": str(self.bin), "LANG": "C.UTF-8"},
                              capture_output=True, encoding="utf-8", timeout=20)

    def calls(self):
        path = self.root / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


HELP_ROWS = (
    ([], ("pick", "resume", "limited")),
    (["pick"], ("--exclude", "--settings", "--max-used", "--max-age", "--include-console")),
    (["resume"], ("--session", "--continue", "--from", "--cwd", "--exclude", "--settings",
                  "--max-used", "--max-age", "--include-console", "--prompt", "--dry-run",
                  "CLAUDE_ARGS", "one session per directory")),
    (["limited"], ("LOG",)),
)


class ProfileSwapTest(unittest.TestCase):
    script = SCRIPT

    def setUp(self):
        held = tempfile.TemporaryDirectory(prefix="lb-claudock-swap-")
        self.addCleanup(held.cleanup)
        self.stub = Stub(held.name)
        suffix = uuid.uuid4().hex[:8]
        self.names = tuple(f"{word}-{suffix}" for word in ("wren", "birch", "cedar", "maple"))

    def call(self, *args):
        return self.stub.call(list(args), self.script)

    def configure(self, *rows, **control):
        self.stub.configure(tsv(*rows), **control)

    def real_shape(self):
        """Keep the reported column shapes, while renaming every invented profile for each test."""
        document = REAL_SHAPE.read_text(encoding="utf-8")
        labels = ("orchard-max", "orchard-unknown", "orchard-team", "orchard-console")
        for label, name in zip(labels, self.names):
            document = document.replace(label + "\t", name + "\t")
        return document

    def console_rows(self):
        a, b = self.names[:2]
        return ((a, "40.00", "-", "Credit · $120.00 of $200.00 left", "Console API"),
                (b, "5.00", "-", "Credit · $9.50 of $10.00 left", "Console API"))

    def settings(self, text):
        path = self.stub.root / "settings.toml"
        path.write_text(text, encoding="utf-8")
        return str(path)

    def expect_pick(self, result, name):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, name + "\n")
        self.assertEqual(result.stderr, "")

    def run_call(self):
        calls = self.stub.calls()
        self.assertEqual(len(calls), 2, "one usage reading and one Claude run are required")
        self.assertEqual(calls[0]["argv"][0], "usage")
        self.assertEqual(calls[1]["argv"][0], "run")
        return calls[1]

    def test_pick_threshold_is_strict(self):
        """Fails when equality to the default 85% threshold is accepted."""
        a, b = self.names[:2]
        self.configure((a, 85, FUTURE), (b, 99, LATER))
        result = self.call("pick")
        self.assertEqual(result.returncode, 3, "strict threshold rejects equality")
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, f"no profile under 85%: next to free up is {a} at {FUTURE}\n")

    def test_pick_below_threshold(self):
        """Fails when a profile immediately below the threshold is rejected."""
        a, b = self.names[:2]
        self.configure((a, 84.99, FUTURE), (b, 85, FUTURE))
        self.expect_pick(self.call("pick"), a)

    def test_pick_custom_threshold(self):
        """Fails when --max-used is ignored or its boundary is inclusive."""
        a, b = self.names[:2]
        self.configure((a, 70, FUTURE), (b, 80, LATER))
        result = self.call("pick", "--max-used", "70")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stderr, f"no profile under 70%: next to free up is {a} at {FUTURE}\n")

    def test_pick_tightest_window(self):
        """Fails when the first window or an average wins instead of the tightest window."""
        a, b, c = self.names[:3]
        self.configure((a, 1, FUTURE), (a, 90, LATER, "Weekly · all models"),
                       (b, 5, FUTURE), (b, 80, LATER, "Weekly · all models"),
                       (c, 60, FUTURE), (c, 55, LATER, "Weekly · all models"))
        self.expect_pick(self.call("pick"), c)

    def test_pick_past_reset(self):
        """Fails when a past-reset window retains its reported usage."""
        a, b = self.names[:2]
        self.configure((a, 100, PAST), (b, 10, FUTURE))
        self.expect_pick(self.call("pick"), a)

    def test_pick_other_window_stays_full(self):
        """Fails when one expired window empties the whole profile."""
        a, b = self.names[:2]
        self.configure((a, 100, PAST), (a, 90, LATER, "Weekly · all models"), (b, 60, FUTURE))
        self.expect_pick(self.call("pick"), b)

    def test_pick_repeated_exclusions(self):
        """Fails when either repeated --exclude is dropped."""
        a, b, c = self.names[:3]
        self.configure((a, 1, FUTURE), (b, 2, FUTURE), (c, 30, FUTURE))
        self.expect_pick(self.call("pick", "--exclude", a, "--exclude", b), c)

    def test_pick_settings_and_cli(self):
        """Fails when settings exclusions replace CLI exclusions, or settings override the CLI threshold."""
        a, b, c = self.names[:3]
        self.configure((a, 1, FUTURE), (b, 2, FUTURE), (c, 72, FUTURE))
        path = self.settings(f'exclude = ["{a}"]\nmax_used_percent = 70\n')
        self.expect_pick(self.call("pick", "--settings", path, "--exclude", b, "--max-used", "80"), c)

    def test_pick_settings_threshold(self):
        """Fails when max_used_percent is not read from the user's TOML file."""
        a = self.names[0]
        self.configure((a, 71, FUTURE))
        path = self.settings("max_used_percent = 70\n")
        result = self.call("pick", "--settings", path)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stderr, f"no profile under 70%: next to free up is {a} at {FUTURE}\n")

    def test_pick_ties_alphabetical(self):
        """Fails when TSV order decides equal headroom without a preference."""
        a, b = self.names[:2]
        self.configure((a, 20, FUTURE), (b, 20, FUTURE))
        self.expect_pick(self.call("pick"), min(a, b))

    def test_pick_ordered_preferences(self):
        """Fails when equal headroom ignores the preference list's order."""
        a, b, c = self.names[:3]
        self.configure((a, 20, FUTURE), (b, 20, FUTURE), (c, 20, FUTURE))
        path = self.settings(f'prefer = ["{c}", "{b}"]\n')
        self.expect_pick(self.call("pick", "--settings", path), c)

    def test_pick_prefer_only_breaks_ties(self):
        """Fails when a preferred profile overrides another profile with more room."""
        a, b = self.names[:2]
        self.configure((a, 20, FUTURE), (b, 10, FUTURE))
        path = self.settings(f'prefer = ["{a}"]\n')
        self.expect_pick(self.call("pick", "--settings", path), b)

    def test_pick_next_full_profile_reset(self):
        """Fails when the first reset is reported before all blocking windows reset, or exclusions are ignored."""
        a, b, c = self.names[:3]
        next_time = "2099-01-01T02:00:00Z"
        self.configure((a, 90, FUTURE), (a, 95, LATER, "Weekly · all models"),
                       (b, 86, next_time), (b, 40, FUTURE, "Weekly · all models"), (c, 100, FUTURE))
        result = self.call("pick", "--exclude", c)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, f"no profile under 85%: next to free up is {b} at {next_time}\n")

    def test_pick_all_excluded(self):
        """Fails when exclusions leave a misleading candidate in the no-profile diagnostic."""
        a = self.names[0]
        self.configure((a, 1, FUTURE))
        result = self.call("pick", "--exclude", a)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr,
                         "no profile under 85%: next to free up is none at unknown (no eligible profiles)\n")

    def test_pick_unknown_reset(self):
        """Fails when a missing reset is treated as expired or a reset time is invented."""
        a = self.names[0]
        self.configure((a, 90, ""))
        result = self.call("pick")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stderr, f"no profile under 85%: next to free up is {a} at unknown\n")

    def test_pick_real_shape_unknown(self):
        """Fails when literal unknown is invalid, empties its window, or real plan/window labels cannot be read."""
        self.stub.configure(self.real_shape())
        result = self.call("pick")
        self.assertEqual(result.returncode, 0, "literal unknown must be a valid reset")
        self.assertEqual(result.stdout, self.names[2] + "\n",
                         "unknown usage must stay full and Console must stay excluded")
        self.assertEqual(result.stderr, "")

    def test_pick_unknown_keeps_usage(self):
        """Fails when an unknown reset makes 99.99% usage empty or produces a made-up timestamp."""
        a = self.names[0]
        self.configure((a, "99.99", "unknown", "9-hour session", "Max 99×"))
        result = self.call("pick")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stderr, f"no profile under 85%: next to free up is {a} at unknown\n")

    def test_pick_console_requires_opt_in(self):
        """Fails when a paid Console profile is chosen by default or its billing exclusion is hidden."""
        self.stub.configure(self.real_shape())
        args = ["pick"]
        for name in self.names[:3]:
            args += ["--exclude", name]
        result = self.call(*args)
        self.assertEqual(result.returncode, 3, "Console requires explicit billing opt-in")
        self.assertEqual(result.stdout, "")
        self.assertEqual(len(result.stderr.splitlines()), 1)
        self.assertIn("Console API profiles excluded", result.stderr)
        self.assertIn("per-token billing", result.stderr)
        self.assertIn("--include-console", result.stderr)
        self.assertIn("include_console = true", result.stderr)

    def test_pick_include_console_flag(self):
        """Fails when the CLI billing opt-in does not make the Console credit row eligible."""
        self.stub.configure(self.real_shape())
        args = ["pick", "--include-console"]
        for name in self.names[:3]:
            args += ["--exclude", name]
        self.expect_pick(self.call(*args), self.names[3])

    def test_pick_console_settings(self):
        """Fails when TOML true does not opt in, or CLI true cannot override TOML false."""
        self.stub.configure(self.real_shape())
        excluded = json.dumps(list(self.names[:3]))
        path = self.settings(f"exclude = {excluded}\ninclude_console = true\n")
        self.expect_pick(self.call("pick", "--settings", path), self.names[3])
        path = self.settings(f"exclude = {excluded}\ninclude_console = false\n")
        result = self.call("pick", "--settings", path)
        self.assertEqual(result.returncode, 3)
        self.expect_pick(self.call("pick", "--settings", path, "--include-console"), self.names[3])

    def test_pick_subscription_first(self):
        """Fails when opted-in Console credit headroom or a preference overrides an available subscription."""
        self.stub.configure(self.real_shape())
        path = self.settings(f'include_console = true\nprefer = ["{self.names[3]}"]\n')
        self.expect_pick(self.call("pick", "--settings", path), self.names[2])

    def test_pick_console_credit_share(self):
        """Fails when Console ordering uses absolute dollars, input order, or preferences over credit share."""
        self.configure(*self.console_rows())
        path = self.settings(f'prefer = ["{self.names[0]}"]\n')
        self.expect_pick(self.call("pick", "--include-console", "--settings", path), self.names[1])

    def test_pick_console_threshold(self):
        """Fails when opting in exempts Console credit usage from the explicit strict threshold."""
        self.configure(*self.console_rows())
        result = self.call("pick", "--include-console", "--max-used", "5")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("Console API profiles excluded", result.stderr)

    def test_pick_shape_values_can_vary(self):
        """Fails when real-shape parsing special-cases the sample's numeric values or plan/window strings."""
        document = self.real_shape().replace("Max 99×", "Max 20×").replace("9-hour session", "5-hour session")
        document = document.replace("71.25", "14.25").replace("49.50", "19.50").replace("44.75", "18.75")
        self.stub.configure(document)
        self.expect_pick(self.call("pick", "--include-console"), self.names[0])

    def test_pick_max_age_argv(self):
        """Fails when --max-age is omitted, changed, or passed to the wrong vendor command."""
        a = self.names[0]
        self.configure((a, 1, FUTURE))
        self.expect_pick(self.call("pick", "--max-age", "30"), a)
        self.assertEqual(self.stub.calls(), [{"argv": ["usage", "--max-age", "30"],
                                             "cwd": str(self.stub.root)}])

    def test_pick_vendor_error(self):
        """Fails when a failing usage command's partial reading is accepted."""
        self.configure((self.names[0], 1, FUTURE), usage_exit=7, usage_stderr="private vendor diagnostic\n")
        result = self.call("pick")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("claudock usage failed (exit 7)", result.stderr)
        self.assertNotIn("private vendor diagnostic", result.stderr)

    def test_pick_bad_usage(self):
        """Fails when malformed columns, numbers, reset times, or conflicting plan metadata become usable."""
        a = self.names[0]
        documents = ("wrong header\n", HEADER + "too\tfew\tcolumns\n",
                     tsv((a, "nan", FUTURE)), tsv((a, "inf", FUTURE)), tsv((a, -1, FUTURE)),
                     tsv((a, 1, "not-a-time")), tsv((a, 1, "2099-01-01T01:00:00")),
                     tsv((a, 1, FUTURE, "5-hour session", "Max 99×"),
                         (a, 2, "-", "Credit · $98.00 of $100.00 left", "Console API")))
        for document in documents:
            with self.subTest(document=document):
                self.stub.configure(document)
                result = self.call("pick")
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")

    def test_settings_invalid_before_usage(self):
        """Fails when invalid settings are accepted or vendor usage is queried before validation."""
        documents = ('exclude = "bad"\n', 'prefer = [1]\n', 'prefer = ["same", "same"]\n',
                     'max_used_percent = true\n', 'max_used_percent = nan\n', 'max_used_percent = 101\n',
                     'max_used_percent = "80"\n', 'include_console = 1\n', 'include_console = "true"\n',
                     'include_console = []\n', 'unknown_key = 1\n', 'not toml\n')
        for document in documents:
            with self.subTest(document=document):
                result = self.call("pick", "--settings", self.settings(document))
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertEqual(self.stub.calls(), [])
        result = self.call("pick", "--settings", str(self.stub.root / "missing.toml"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.stub.calls(), [])

    def test_resume_excludes_from(self):
        """Fails when the source profile can be picked again, even if it reports the most room."""
        a, b = self.names[:2]
        self.configure((a, 0, FUTURE), (b, 70, FUTURE))
        result = self.call("resume", "--session", SID, "--from", a)
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.run_call()
        self.assertEqual(call["argv"][1], b, "source profile must be excluded")
        self.assertIn(b, result.stderr)
        self.assertIn("70%", result.stderr)
        self.assertIn("most room left", result.stderr)

    def test_resume_session_argv(self):
        """Fails when the session id, prompt, argument order, or child output is changed."""
        a, b = self.names[:2]
        prompt = "Continue; preserve the current task."
        tail = ["--model", "claude-sonnet-4-6", "--output-format", "stream-json", "--verbose"]
        self.configure((a, 100, FUTURE), (b, 20, FUTURE), run_stdout="child output\n")
        result = self.call("resume", "--session", SID, "--from", a, "--prompt", prompt, "--", *tail)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.run_call()["argv"], ["run", b, "--", "-p", "--resume", SID, prompt, *tail])
        self.assertEqual(result.stdout, "child output\n")

    def test_resume_continue_argv(self):
        """Fails when --continue is forwarded instead of -c, or a new session is started."""
        a, b = self.names[:2]
        self.configure((a, 99, FUTURE), (b, 10, FUTURE))
        result = self.call("resume", "--continue", "--from", a, "--", "--verbose")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.run_call()["argv"], ["run", b, "--", "-p", "-c", PROMPT, "--verbose"])

    def test_resume_exit_passthrough(self):
        """Fails when the wrapper's actual exit code or stderr is swallowed or rewritten."""
        a, b = self.names[:2]
        for code in (0, 2, 3, 7, 23):
            with self.subTest(code=code):
                self.configure((a, 99, FUTURE), (b, 10, FUTURE), run_exit=code,
                               run_stderr="child diagnostic\n")
                result = self.call("resume", "--session", SID, "--from", a)
                self.assertEqual(result.returncode, code)
                self.assertTrue(result.stderr.endswith("child diagnostic\n"))
        self.assertEqual(sum(call["argv"][0] == "run" for call in self.stub.calls()), 5)

    def test_resume_cwd(self):
        """Fails when --cwd is ignored or whitespace in the directory is split."""
        a, b = self.names[:2]
        self.configure((a, 99, FUTURE), (b, 10, FUTURE))
        result = self.call("resume", "--continue", "--from", a, "--cwd", str(self.stub.cwd))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.run_call()["cwd"], str(self.stub.cwd))

    def test_resume_real_shape_max_age(self):
        """Fails when resume cannot read the real-shaped TSV, loses --max-age, or chooses the source/Console."""
        self.stub.configure(self.real_shape())
        result = self.call("resume", "--continue", "--from", self.names[2], "--max-age", "3600")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.run_call()["argv"], ["run", self.names[0], "--", "-p", "-c", PROMPT])
        self.assertEqual(self.stub.calls()[0]["argv"], ["usage", "--max-age", "3600"])

    def test_resume_console_default(self):
        """Fails when resume launches a Console profile without billing opt-in or hides the exclusion reason."""
        self.stub.configure(self.real_shape())
        result = self.call("resume", "--session", SID, "--from", self.names[0],
                           "--exclude", self.names[1], "--exclude", self.names[2])
        self.assertEqual(result.returncode, 3)
        self.assertEqual(len(self.stub.calls()), 1)
        self.assertIn("Console API profiles excluded", result.stderr)

    def test_resume_console_opt_in(self):
        """Fails when explicit billing opt-in cannot resume the same session on the remaining Console profile."""
        self.stub.configure(self.real_shape())
        result = self.call("resume", "--session", SID, "--from", self.names[0], "--include-console",
                           "--exclude", self.names[1], "--exclude", self.names[2])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.run_call()["argv"], ["run", self.names[3], "--", "-p", "--resume", SID, PROMPT])
        self.assertIn("Console API opt-in", result.stderr)
        self.assertIn("credit left", result.stderr)

    def test_resume_console_credit_share(self):
        """Fails when resume ignores TOML billing opt-in or ranks Console balances by absolute dollars."""
        self.configure(*self.console_rows())
        path = self.settings("include_console = true\n")
        result = self.call("resume", "--continue", "--from", self.names[2], "--settings", path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.run_call()["argv"][1], self.names[1])

    def test_resume_settings_exclusions(self):
        """Fails when resume omits settings exclusions, CLI exclusions, or their union with --from."""
        a, b, c, d = self.names
        self.configure((a, 0, FUTURE), (b, 1, FUTURE), (c, 2, FUTURE), (d, 75, FUTURE))
        path = self.settings(f'exclude = ["{b}"]\nmax_used_percent = 70\n')
        result = self.call("resume", "--session", SID, "--from", a, "--exclude", c,
                           "--settings", path, "--max-used", "80")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.run_call()["argv"][1], d)

    def test_resume_dry_run(self):
        """Fails when dry-run starts Claude, loses quoting, or reports a different directory or argv."""
        a, b = self.names[:2]
        prompt = 'Continue with "quoted text"; $(literal) stays text.'
        tail = ["--model", "claude-sonnet-4-6"]
        self.configure((a, 99, FUTURE), (b, 10, FUTURE), run_exit=23)
        result = self.call("resume", "--session", SID, "--from", a, "--cwd", str(self.stub.cwd),
                           "--prompt", prompt, "--dry-run", "--", *tail)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout),
                         {"argv": [str(self.stub.executable), "run", b, "--", "-p", "--resume", SID,
                                   prompt, *tail], "cwd": str(self.stub.cwd)})
        calls = self.stub.calls()
        self.assertEqual(len(calls), 1, "dry-run may read usage but must never start Claude")
        self.assertEqual(calls[0]["argv"], ["usage"])

    def test_resume_no_cross_provider_flag(self):
        """Fails when the wrapper is told to bypass its cross-provider resume refusal."""
        a, b = self.names[:2]
        self.configure((a, 99, FUTURE), (b, 10, FUTURE))
        result = self.call("resume", "--session", SID, "--from", a)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--allow-cross-provider-resume", self.run_call()["argv"],
                         "cross-provider refusal must stay enabled")

    def test_resume_no_alternative(self):
        """Fails when lack of another profile starts Claude or loses the no-profile exit code."""
        a = self.names[0]
        self.configure((a, 0, FUTURE))
        result = self.call("resume", "--session", SID, "--from", a)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(len(self.stub.calls()), 1)
        self.assertEqual(result.stdout, "")

    def test_resume_invalid_arguments(self):
        """Fails when invalid CLI/cwd input reaches Claudock or a wrapper-only flag is accepted."""
        a = self.names[0]
        cases = (("resume", "--from", a),
                 ("resume", "--session", SID, "--continue", "--from", a),
                 ("resume", "--session", SID),
                 ("resume", "--session", SID, "--from", a, "--allow-cross-provider-resume"),
                 ("resume", "--continue", "--from", a, "--cwd", str(self.stub.root / "missing")),
                 ("pick", "--max-used", "nan"), ("pick", "--max-used", "101"),
                 ("pick", "--max-age", "-1"),
                 ("resume", "--continue", "--from", a, "--max-age", "-1"))
        for args in cases:
            with self.subTest(args=args):
                result = self.call(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(self.stub.calls(), [])

    def limited(self, text):
        path = self.stub.root / "claude.log"
        path.write_text(text, encoding="utf-8")
        return self.call("limited", str(path))

    def test_limited_each_pattern(self):
        """Fails when any documented message family or window label is not detected."""
        labels = ("limit", "usage limit", "session limit", "weekly limit", "Opus limit", "Sonnet limit")
        messages = [f"You've hit your {label}" for label in labels]
        messages += ["You've hit your limit · resets 9pm (UTC)",
                     "You've hit your session limit · resets 9pm (UTC) · progress saved",
                     "You’ve hit your weekly limit.",
                     "Usage limit reached", "Usage limit reached · limit resets 9pm (UTC)",
                     "\x1b[31mYou've hit your limit · resets 9pm (UTC)\x1b[0m"]
        for message in messages:
            with self.subTest(message=message):
                result = self.limited("ordinary output\n" + message + "\n")
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")
        self.assertEqual(self.stub.calls(), [])

    def test_limited_error_json(self):
        """Fails when headless result/error JSON or a rate-limit assistant record loses its actual message."""
        message = "You've hit your limit · resets 9pm (UTC)"
        records = ({"type": "result", "is_error": True, "result": message},
                   {"type": "result", "is_error": True, "errors": [message]},
                   {"type": "assistant", "error": "rate_limit", "message": {
                       "content": [{"type": "text", "text": message}]}})
        for record in records:
            with self.subTest(record=record):
                result = self.limited(json.dumps(record) + "\n")
                self.assertEqual(result.returncode, 0)

    def test_limited_near_misses(self):
        """Fails when ordinary limit discussion, non-quota errors, or quoted JSON input triggers a swap."""
        message = "You've hit your limit · resets 9pm (UTC)"
        lines = ("Set the session limit to 5 for this test.", "No usage limit reached during this run.",
                 "The documentation says: " + message, "You've hit your limit for the request size",
                 "You've hit your fast limit · resets in 3 minutes", "Usage limit reached? No.",
                 "Your usage limit has reset", "Error: max turns reached", "Error: context window exceeded",
                 "[Usage limit reached — grace window active. Checkpoint now.]", "", "{malformed JSON",
                 json.dumps({"type": "user", "message": message}),
                 json.dumps({"type": "result", "is_error": False, "result": message}),
                 json.dumps({"type": "assistant", "message": {
                     "content": [{"type": "tool_use", "input": {"prompt": message}}]}}))
        for line in lines:
            with self.subTest(line=line):
                result = self.limited(line + "\n")
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")

    def test_limited_unreadable(self):
        """Fails when a missing file, directory, or permission-denied file is called a non-limit (exit 1)."""
        missing = self.stub.root / "missing.log"
        denied = self.stub.root / "denied.log"
        denied.write_text("ordinary output\n", encoding="utf-8")
        denied.chmod(0)
        self.addCleanup(denied.chmod, 0o600)
        for path in (missing, self.stub.cwd, denied):
            with self.subTest(path=path.name):
                result = self.call("limited", str(path))
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("cannot read log", result.stderr)
        self.assertEqual(self.stub.calls(), [])

    def test_limited_invalid_utf8(self):
        """Fails when undecodable log bytes are silently replaced and treated as a readable log."""
        path = self.stub.root / "invalid.log"
        path.write_bytes(b"ordinary output\n\xff\n")
        result = self.call("limited", str(path))
        self.assertEqual(result.returncode, 2)

    def test_help_matches_cli(self):
        """Fails when a documented option is absent from actual help or help invokes Claudock."""
        for prefix, tokens in HELP_ROWS:
            with self.subTest(command=prefix):
                result = self.call(*prefix, "--help")
                self.assertEqual(result.returncode, 0, result.stderr)
                text = " ".join(result.stdout.split())
                for token in tokens:
                    self.assertIn(token, text)
                self.assertEqual(self.stub.calls(), [])


# Each transformation must kill its named public CLI row with the stated assertion,
# not with an import failure, missing file, invalid mutant, or broken test setup.
MUTANTS = (
    ("threshold_off_by_one", "p.tightest() < s.maxUsed",
     "p.tightest() <= s.maxUsed", "test_pick_threshold_is_strict",
     "strict threshold rejects equality"),
    ("from_not_excluded", 'excluded[values["--from"]] = true', 'delete(excluded, values["--from"])',
     "test_resume_excludes_from", "source profile must be excluded"),
    ("cross_provider_flag_added", 'runArgv := []string{wrapper, "run", chosen.name, "--", "-p"}',
     'runArgv := []string{wrapper, "run", chosen.name, "--allow-cross-provider-resume", "--", "-p"}',
     "test_resume_no_cross_provider_flag", "cross-provider refusal must stay enabled"),
    ("unknown_reset_rejected", 'case "", "-", "—", "unknown":',
     'case "", "-", "—":', "test_pick_real_shape_unknown", "literal unknown must be a valid reset"),
    ("console_without_opt_in", "!s.includeConsole && p.console()", "false && p.console()",
     "test_pick_console_requires_opt_in", "Console requires explicit billing opt-in"),
)


class MutantTest(unittest.TestCase):
    def test_mutants_fail_named_rows(self):
        """Fails when any specified mutant survives, or fails for a reason other than its intended CLI defect."""
        source = SCRIPT.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="lb-claudock-swap-mutants-") as directory:
            for name, before, after, row, assertion in MUTANTS:
                with self.subTest(mutant=name, row=row):
                    baseline = ProfileSwapTest(row)
                    green = unittest.TestResult()
                    baseline.run(green)
                    self.assertEqual(green.testsRun, 1)
                    self.assertEqual(green.errors, [])
                    self.assertEqual(green.failures, [], "the named row must pass against the original tool")
                    self.assertEqual(source.count(before), 1, "mutant anchor must identify exactly one operation")
                    mutant = Path(directory) / f"{name}.go"
                    mutant.write_text(source.replace(before, after, 1), encoding="utf-8")
                    case = ProfileSwapTest(row)
                    case.script = mutant
                    red = unittest.TestResult()
                    case.run(red)
                    self.assertEqual(red.testsRun, 1)
                    self.assertEqual(red.errors, [], "a setup error does not prove a mutant was detected")
                    self.assertEqual(len(red.failures), 1, "the named row must reject this mutant")
                    self.assertIn(assertion, red.failures[0][1])


def static_checks():
    """Compile and exercise --help with the private stub on the disposable machine."""
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or newer is required")
    with tempfile.TemporaryDirectory(prefix="lb-claudock-swap-static-") as directory:
        root = Path(directory)
        for index, path in enumerate((Path(__file__).resolve(),)):
            py_compile.compile(str(path), cfile=str(root / f"compile-{index}.pyc"), doraise=True)
            print(f"compile {path.name}: PASS", flush=True)
        helper_binary(SCRIPT)
        compile(STUB, "<claudock stub>", "exec")
        print("compile claudock stub: PASS", flush=True)
        stub = Stub(root)
        for prefix, tokens in HELP_ROWS:
            result = stub.call([*prefix, "--help"])
            if result.returncode != 0 or result.stderr:
                raise AssertionError(f"help {' '.join(prefix) or 'root'} failed: {result.stderr}")
            help_text = " ".join(result.stdout.split())
            for token in tokens:
                if token not in help_text:
                    raise AssertionError(f"help is missing {token}")
            if stub.calls():
                raise AssertionError("help unexpectedly invoked Claudock")
            print(f"help {' '.join(prefix) or 'root'} through stub PATH: PASS", flush=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--static-checks"]:
        static_checks()
    else:
        unittest.main()
