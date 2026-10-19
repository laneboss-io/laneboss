"""Org fixture for the rows that start lanes on the combined release tree.

Lane start, adoption, resume and turn enforce the org's role templates and driver
lists, and every configuration load checks the named org and its runners. A row
configuration that starts a lane therefore names an org that carries the built-in
role library, starts its lanes with a role, and lets each role run the fixture's
stand-in runner. The helper runs the supplied binary's own `org init`; it imports
no product package and builds nothing. Run only on the disposable test box.
"""

import json
from pathlib import Path
import re
import stat
import subprocess
import sys

# The role a lane is started with at each level: the library's default role for the level, the one `org init`
# gives its example instance. The lane's level is --level (L3 when absent); --role always names the org's role
# template at that level, never a [supervisors] entry.
ROLES = {3: "executor", 4: "supervisor", 5: "top", 6: "supervisor"}
# The library has a `supervisor` role at L4, L5 and L6: a supervisor lane starts as `--level N --role supervisor`.
SUPERVISOR = "supervisor"

DETACH_REASON = (
    "refused: lanes may not detach their process identity with setsid or nohup\n"
    "Instead: report up with laneboss report, or use lane send for a permitted peer."
)


def assert_hook_deprecation(test, result):
    """Require the single compatibility warning from a real render/validate."""
    stdout = result["stdout"] if isinstance(result, dict) else result.stdout
    stderr = result["stderr"] if isinstance(result, dict) else result.stderr
    output = json.loads(stdout)
    warnings = [json.dumps(item) for item in output.get("warnings", [])]
    warnings.extend(stderr.splitlines())
    # The product's one notice (internal/orgtree/hook_deprecation.go); it names no "deprecated" word.
    deprecated = [line for line in warnings if "strict mode and tool allowlists were removed in 1.0.0" in line]
    test.assertEqual(len(deprecated), 1,
                     "legacy hook sources must emit one deprecation warning per render/validate")
    test.assertIn("blacklist", deprecated[0].lower(),
                  "the warning must explain the blacklist-only behavior")


def set_hook_mode(test, source, mode):
    """Edit only the hooks table, preserving the other source tables."""
    text = source.read_text(encoding="utf-8")
    section = re.search(r"(?m)^\[hooks\][ \t]*(?:#.*)?$", text)
    if section is None:
        text += '\n[hooks]\nmode = ' + json.dumps(mode) + '\n'
    else:
        tail = text[section.end():]
        next_table = re.search(r"(?m)^\[", tail)
        end = section.end() + (next_table.start() if next_table else len(tail))
        body, count = re.subn(r'(?m)^mode\s*=.*$', 'mode = ' + json.dumps(mode),
                              text[section.end():end])
        test.assertLessEqual(count, 1, "one mode belongs to the hooks source table")
        if count == 0:
            body = '\nmode = ' + json.dumps(mode) + body
        text = text[:section.end()] + body + text[end:]
    write_rule_source(test, source, text)


def write_rule_source(test, path, text):
    """Edit one fixture-owned policy source and restore its protected mode."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.chmod(0o444)
        test.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444,
                         "a new fixture rule source must be read-only")
        return
    original_mode = stat.S_IMODE(path.stat().st_mode)
    try:
        path.chmod(original_mode | stat.S_IWUSR)
        path.write_text(text, encoding="utf-8")
    finally:
        path.chmod(original_mode)
        test.assertEqual(stat.S_IMODE(path.stat().st_mode), original_mode,
                         "the fixture rule source must regain its original mode")


def check_incomplete_hook(test, event, runner, **options):
    """Require a fresh real callback for an allowed inspection gap."""
    instance = test.instances["alpha"]
    path = instance / "hooks" / "callbacks.jsonl"
    before = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    reason = test.check_decision(event, runner, "allow",
                                pinned=str(instance / "instance.toml"), **options)
    test.assertEqual(reason, "org policy permits this tool call")
    after = path.read_text(encoding="utf-8").splitlines()
    test.assertEqual(len(after), len(before) + 1, "each inspected call must append one callback")
    test.assertEqual(after[:-1], before, "existing callbacks must remain intact")
    receipt = json.loads(after[-1])
    test.assertEqual((receipt["event"], receipt["runner"], receipt["decision"]),
                     ("PreToolUse", runner, "allow"))
    test.assertIs(receipt["inspection_complete"], False,
                  "a wrapper gap must never claim complete inspection")
    test.assertEqual(receipt["inspection_notice"],
                     "file effects were not fully inspected; blacklist mode allowed the call")
    return reason


def init_org(binary, environment, directory, home, name):
    """Create the org NAME under the configuration home, where `organisation = NAME` finds it.

    `org roles init` installs editable role sources for L3-L6. Its driver files list the agent programs, so each one is
    rewritten, as an org owner edits them, to list the program of the stand-in runner (the interpreter that
    runs the row), which is the first word of every runner command the rows configure.
    """
    org = Path(home) / "orgs" / name
    org.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([str(binary), "org", "init", str(org), "--name", name], cwd=directory, env=environment,
                            capture_output=True, text=True, encoding="utf-8", timeout=90)
    if result.returncode != 0:
        raise RuntimeError("the org fixture could not be created: " + result.stderr)
    if json.loads(result.stdout).get("ok") is not True:
        raise RuntimeError("the org fixture was not created: " + result.stdout)
    result = subprocess.run([str(binary), "org", "roles", "init", str(org)], cwd=directory, env=environment,
                            capture_output=True, text=True, encoding="utf-8", timeout=90)
    if result.returncode != 0 or json.loads(result.stdout).get("ok") is not True:
        raise RuntimeError("the org fixture role sources could not be installed: " + result.stderr)
    drivers = sorted((org / ".laneboss").glob("L*/roles/*.toml"))
    if not drivers:
        raise RuntimeError("the org fixture holds no role driver file")
    for path in drivers:
        path.write_text("drivers = " + json.dumps([Path(sys.executable).name]) + "\n", encoding="utf-8")
    return org
