#!/usr/bin/env python3
"""The laneboss job catalog and the TypeSafe judge's state and output.

An agent that runs a raw shell command for a job that a laneboss command already does (tmux to start or stop a lane,
git worktree to make or remove its directory, sqlite3 on the event store, kill of a lane's process, curl to the
dashboard port) bypasses the launcher's records and checks. The judge decides, for one shell command, whether it does
such a job and which laneboss command should have been used.

The judge's STATE carries the complete catalog of jobs the laneboss command line owns. It is GENERATED from
internal/cli/syntax.json (every command path with its one-line purpose and its argument names), the root commands the
program adds in code after it reads that file (the dashboard, internal/cli/version.go) and the org's levels and roles,
never written by hand: a command that lands in syntax.json appears in the state, in the Choice options and in the
question without anyone editing this file. The judge's OUTPUT is {flagged, laneboss_command, reason, owned,
confidence}: the laneboss command is one of the generated options (anything else is refused), and the reason is built
from the catalog's own purpose text, never from model text.

usage:
  laneboss_jobs.py state [--syntax FILE] [--org ORG]      print the generated state
  laneboss_jobs.py question COMMAND [--syntax F] [--org O] print the TypeSafe request body for one shell command
  laneboss_jobs.py flag COMMAND ANSWERS.json              turn a response's answers into the output
  laneboss_jobs.py judge COMMAND [--syntax F] [--org O]   ask the TypeSafe service (needs the key; prints no secret)
"""
import hashlib
import json
import math
import os
import re
import sys
import time
import tomllib
import urllib.error
import urllib.request
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SYNTAX = ROOT / "internal" / "cli" / "syntax.json"
# The program adds a few root commands in code, after it reads syntax.json (the dashboard): the catalog reads them from there.
CODE_ROOT = ROOT / "internal" / "cli" / "version.go"
CODE_COMMAND = re.compile(r'root\.Commands = append\(root\.Commands, commandSyntax\{Name: "([^"]+)", Help: "((?:[^"\\]|\\.)*)"\}\)')
ENDPOINT = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"
NONE = "none"
MAX_OPTIONS = 255      # a Choice accepts at most 255 options
OWNED_AT = 0.5         # the Noul probability at which a shell command counts as doing a laneboss job
CONFIDENCE_AT = 0.5    # advisory Choice routing floor; calibrate on domain data before changing it
KEY_NAME = "TYPESAFE_API_KEY"
KEY_FILE = Path.home() / ".config" / "typesafe" / "env"


def load_syntax(path=SYNTAX):
    data = Path(path).read_bytes()
    return json.loads(data), hashlib.sha256(data).hexdigest()


def _purpose(node):
    return " ".join((node.get("description") or node.get("help") or "").split())


def _arguments(node):
    return [a["name"] for a in node.get("args", []) if a.get("name") not in ("--help", "-h")]


def code_commands(path=CODE_ROOT):
    """The root commands the program adds in code, as (name, help); none when the source file is not there."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return []
    found = []
    for name, help_text in CODE_COMMAND.findall(text):
        try:
            help_text = json.loads('"' + help_text + '"')    # a Go string literal of plain text is a JSON string
        except ValueError:
            pass
        found.append((name, help_text))
    return found


def jobs(syntax, extra=()):
    """Every command path below the root. A node that needs a subcommand is a group, not a job."""
    found, groups = [], []

    def walk(node, prefix):
        for child in node.get("commands", []):
            path = prefix + [child["name"]]
            row = {"path": " ".join(path), "purpose": _purpose(child), "arguments": _arguments(child)}
            (groups if child.get("subcommand_required") else found).append(row)
            walk(child, path)

    walk(syntax, [])
    known = {row["path"] for row in found + groups}
    for name, help_text in extra:
        if name not in known:
            found.append({"path": name, "purpose": " ".join(help_text.split()), "arguments": []})
    return found, groups


def org_state(org):
    """The org's levels and roles from org.toml; roles are passed through as recorded (names and lists of words)."""
    if org is None:
        return {"levels": [], "roles": {}}
    home = Path(org)
    if home.name != ".laneboss":
        home = home / ".laneboss"
    data = tomllib.loads((home / "org.toml").read_text(encoding="utf-8"))
    roles = data.get("roles", {})
    clean = {}
    if isinstance(roles, dict):
        for name, value in roles.items():
            clean[str(name)] = value if isinstance(value, (list, dict, str, int, bool)) else str(value)
    result = {"name": data.get("name", ""), "levels": data.get("levels", []), "roles": clean}
    if "lane_roles" in data:
        result["lane_roles"] = data["lane_roles"]
    library = sorted({(int(path.parts[-3][1:]), path.stem)
                      for path in home.glob("L[3-6]/roles/*") if path.suffix in (".md", ".toml")})
    if library:
        result["role_library"] = [{"level": level, "role": role} for level, role in library]
    return result


def _canonical_bytes(value):
    # Match Go's canonical map encoding, including its default HTML escaping.
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    for literal, escaped in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"),
                             ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        text = text.replace(literal, escaped)
    return text.encode("utf-8")


def source_hashes(org, found, groups):
    home = Path(org) if org is not None else None
    if home is not None and home.name != ".laneboss":
        home = home / ".laneboss"
    role_hashes = {}
    if home is not None:
        for path in sorted(home.glob("L[3-6]/roles/*")):
            if path.suffix in (".md", ".toml"):
                role_hashes[path.relative_to(home).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "org_sha256": hashlib.sha256((home / "org.toml").read_bytes() if home else b"").hexdigest(),
        "roles_sha256": hashlib.sha256(_canonical_bytes(role_hashes)).hexdigest(),
        "rows_sha256": hashlib.sha256(_canonical_bytes({"laneboss_jobs": found, "laneboss_groups": groups})).hexdigest(),
    }


def state(syntax_path=SYNTAX, org=None, code_path=CODE_ROOT):
    syntax, digest = load_syntax(syntax_path)
    extra = code_commands(code_path)
    found, groups = jobs(syntax, extra)
    hashes = source_hashes(org, found, groups)
    fingerprint = hashlib.sha256("\n".join([digest, hashes["org_sha256"], hashes["roles_sha256"],
                                            hashes["rows_sha256"]]).encode("utf-8")).hexdigest()
    return {"schema": 1,
            "source": {"file": "internal/cli/syntax.json", "sha256": digest, "jobs": len(found), "groups": len(groups),
                       "added_in_code": [name for name, _ in extra], **hashes, "fingerprint": fingerprint},
            "laneboss_jobs": found, "laneboss_groups": groups, "org": org_state(org)}


def options(st):
    return [row["path"] for row in st["laneboss_jobs"]] + [NONE]


def question(shell_command, st):
    """The TypeSafe request body for one shell command: a Noul and a Choice over the same state."""
    paths = options(st)
    if len(paths) > MAX_OPTIONS:
        raise ValueError("more than %d options: ask for the command group first, then for the command in it" % MAX_OPTIONS)
    criteria = {row["path"]: row["purpose"] or "laneboss " + row["path"] for row in st["laneboss_jobs"]}
    criteria[NONE] = "the shell command does no job that any laneboss command in `laneboss_jobs` already does"
    return {
        "state": {**st, "shell_command": shell_command, "managed_objects": st.get("managed_objects", {})},
        "model": MODEL,
        "questions": {
            "owned": {"type": "noul", "instructions":
                      "Does `shell_command` perform a job listed in `laneboss_jobs` on a Laneboss-managed object "
                      "identified by `managed_objects`?", "criteria": {
                          "true": "The shell command performs a catalog job on a Laneboss-managed object supported by the supplied context.",
                          "false": "The shell command performs ordinary unrelated work, or its target is not supported as Laneboss-managed; command resemblance alone is insufficient."}},
            "command": {"type": "choice", "instructions":
                        "Which laneboss command in `laneboss_jobs` should have been used for what `shell_command` does? "
                        "Answer none for ordinary unrelated shell work; command similarity alone is insufficient.",
                        "criteria": criteria},
        },
    }


def _probability(value):
    finite = value.is_finite() if isinstance(value, Decimal) else type(value) in (int, float) and math.isfinite(value)
    if not finite or not 0 <= value <= 1:
        raise ValueError("judge values must be JSON numbers from 0 to 1")
    return float(value)


def _answers(st, answers):
    if not isinstance(answers, dict) or set(answers) != {"owned", "command"}:
        raise ValueError("judge response needs every requested answer")
    owned, command = answers["owned"], answers["command"]
    if not isinstance(owned, dict) or not isinstance(command, dict) or owned.get("type") != "noul" or command.get("type") != "choice":
        raise ValueError("judge answer types do not match the questions")
    p = _probability(owned.get("noul"))
    confidence = _probability(command.get("confidence"))
    choice, distribution = command.get("choice"), command.get("probabilities")
    if not isinstance(choice, str) or choice not in options(st):
        raise ValueError("judge choice is outside the generated catalog")
    if not isinstance(distribution, dict) or set(distribution) != set(options(st)):
        raise ValueError("Choice needs a probability for every catalog option")
    probabilities = {name: _probability(value) for name, value in distribution.items()}
    # api.md:255 and primitives_choice.md:346 require sum=1 but give no
    # precision. Budget half a 4-decimal-place rounding unit per option.
    tolerance = max(1e-6, len(probabilities) * 5e-5)
    if abs(sum(probabilities.values()) - 1) > tolerance or probabilities[choice] < max(probabilities.values()):
        raise ValueError("Choice distribution must sum to one and select a maximum")
    return p, choice, confidence, probabilities


def validate_response(st, response):
    if not isinstance(response, dict) or not isinstance(response.get("model"), str) or not response["model"].strip():
        raise ValueError("judge response needs the documented model")
    usage = response.get("usage")
    if not isinstance(usage, dict) or any(name in usage and (type(usage[name]) is not int or usage[name] < 0) for name in ("input_tokens", "output_tokens")):
        raise ValueError("judge response needs documented token usage")
    _answers(st, response.get("answers"))
    return response["answers"]


def load_response(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate judge response member")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("judge response contains a non-JSON number")

    return json.loads(raw, object_pairs_hook=pairs, parse_float=Decimal, parse_constant=invalid_constant)


def flag(shell_command, st, answers):
    """The output for one shell command, from the answers of a TypeSafe response."""
    owned, choice, confidence, probabilities = _answers(st, answers)
    uncertain = choice != NONE and owned >= OWNED_AT and confidence < CONFIDENCE_AT
    flagged = choice != NONE and owned >= OWNED_AT and not uncertain
    reason = ""
    if flagged:
        purpose = {row["path"]: row["purpose"] for row in st["laneboss_jobs"]}[choice].rstrip(".")
        reason = "laneboss %s (%s) does this job; use it instead of the raw shell command" % (choice, purpose)
    elif uncertain:
        reason = "the catalog route is uncertain; review the generated catalog before choosing a command"
    return {"flagged": flagged, "laneboss_command": choice if flagged else None, "reason": reason,
            "owned": owned, "confidence": confidence, "probabilities": probabilities, "uncertain": uncertain}


def api_key():
    """The key from the environment or the key file; the value is never printed."""
    value = os.environ.get(KEY_NAME, "")
    if not value and KEY_FILE.is_file():
        for line in KEY_FILE.read_text(encoding="utf-8").splitlines():
            name, _, text = line.partition("=")
            if name.strip() == KEY_NAME:
                value = text.strip().strip("'\"")
    return value


def judge(shell_command, st, key=None, timeout=20):
    key = key or api_key()
    if not key:
        raise RuntimeError("no %s in the environment or %s" % (KEY_NAME, KEY_FILE))
    body = json.dumps(question(shell_command, st), allow_nan=False).encode("utf-8")
    request = urllib.request.Request(ENDPOINT, data=body, method="POST", headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + key})
    deadline = time.monotonic() + timeout
    for attempt in range(3):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("TypeSafe overall request deadline expired")
        try:
            with urllib.request.urlopen(request, timeout=remaining) as response:
                raw = response.read((1 << 20) + 1)
            if len(raw) > 1 << 20:
                raise ValueError("TypeSafe response exceeds 1 MiB")
            answers = validate_response(st, load_response(raw.decode("utf-8")))
            return flag(shell_command, st, answers)
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            if status not in (429, 529) or attempt == 2:
                raise RuntimeError("TypeSafe returned HTTP %d" % status) from None
            delay = 0.1 * (2 ** attempt)
            if time.monotonic() + delay >= deadline:
                raise RuntimeError("TypeSafe overall request deadline expired") from None
            time.sleep(delay)
        except urllib.error.URLError:
            raise RuntimeError("TypeSafe could not be reached before the request deadline") from None


def main(argv):
    if not argv or argv[0] not in ("state", "question", "flag", "judge"):
        sys.stderr.write(__doc__)
        return 2
    command, rest = argv[0], argv[1:]
    syntax, org, words = SYNTAX, None, []
    while rest:
        if rest[0] == "--syntax" and len(rest) > 1:
            syntax, rest = rest[1], rest[2:]
        elif rest[0] == "--org" and len(rest) > 1:
            org, rest = rest[1], rest[2:]
        else:
            words.append(rest[0])
            rest = rest[1:]
    st = state(syntax, org)
    if command == "state":
        print(json.dumps(st, indent=1))
    elif command == "question" and len(words) == 1:
        print(json.dumps(question(words[0], st), indent=1))
    elif command == "flag" and len(words) == 2:
        response = load_response(Path(words[1]).read_text(encoding="utf-8"))
        print(json.dumps(flag(words[0], st, validate_response(st, response)), indent=1))
    elif command == "judge" and len(words) == 1:
        print(json.dumps(judge(words[0], st), indent=1))
    else:
        sys.stderr.write(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
