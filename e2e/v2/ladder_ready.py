"""Validate the row/instance handoff; this never reports runtime acceptance."""

import re

from ladder import SCENARIO, structure
from support import Failure, ROOT, beneath, exact_keys, integer, load, require


PLAN = SCENARIO.parent / "cases" / "ladder" / "plan.json"
DECLARATIONS = (
    (re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"),
     re.compile(r"^func\s+\(\s*\w+\s+\*?([A-Za-z_]\w*)")),
    (re.compile(r"^type\s+([A-Za-z_]\w*)"), None),
    (re.compile(r"^(?:var|const)\s+([A-Za-z_]\w*)"), None),
)
IDENTIFIER = re.compile(r"^[A-Za-z_]\w*$")
METHOD = re.compile(r"^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$")
REQUIRED_ROWS = {
    "READY-HEALTH", "READY-SESSION", "READY-PRESENCE", "READY-POLICY",
    "READY-DASHBOARD", "READY-MIGRATION", "LADDER-GRAPH", "LADDER-BIND",
    "LADDER-DATA", "LADDER-DRIVERS", "LADDER-CAPTURE", "LADDER-MAIL",
    "LADDER-PRIVACY", "LADDER-GUIDANCE", "LADDER-JUDGE", "LADDER-POLICY",
    "LADDER-TEMPLATE", "LADDER-USAGE", "LADDER-REVIEW", "LADDER-COLLECT",
    "LADDER-CONCURRENT", "LADDER-AGGREGATE",
}


def declarations(lines):
    """Top-level Go declarations as (name, receiver type, line)."""
    found = []
    for number, text in enumerate(lines, 1):
        for pattern, receiver in DECLARATIONS:
            if text.startswith(("func ", "type ", "var ", "const ")):
                match = pattern.match(text)
                if match:
                    typed = receiver.match(text) if receiver else None
                    found.append((match.group(1), typed.group(1) if typed else "", number))
                    break
    return found


def source_line(name, symbol, cache):
    """Resolve a file + symbol pin to its current line.

    A Go declaration name resolves against the file's top-level funcs, methods,
    types, vars and consts (``Type.Name`` names one method). Any other string
    is an anchor that must occur exactly once in the file. A missing file, a
    symbol with no match, or a symbol with several matches fails the check.
    """
    if name not in cache:
        try:
            path = beneath(ROOT, name)
        except Failure:
            raise Failure("source evidence file is missing: " + name)
        cache[name] = path.read_text().splitlines()
    lines = cache[name]
    found = declarations(lines)
    receivers = METHOD.match(symbol)
    plain = IDENTIFIER.match(symbol)
    if receivers or plain:
        if receivers:
            matches = [item for item in found
                       if item[0] == receivers.group(2) and item[1] == receivers.group(1)]
        else:
            matches = [item for item in found if item[0] == symbol]
        require(len(matches) <= 1,
                "ambiguous source symbol: " + name + " declares " + symbol +
                " " + str(len(matches)) + " times")
        if matches:
            return matches[0][2]
    text = "\n".join(lines)
    count = text.count(symbol)
    require(count > 0, "missing source symbol: " + name + " has no " + repr(symbol))
    require(count == 1, "ambiguous source symbol: " + name + " contains " + repr(symbol) +
            " " + str(count) + " times")
    return text.count("\n", 0, text.index(symbol)) + 1


def ready_plan(path=PLAN):
    value = load(path)
    exact_keys(value, ("schema", "as_of", "contract_revision", "contract_fixes", "lanes", "instances", "rows"))
    require(value["schema"] == "laneboss.ladder-ready.v2" and value["contract_revision"] == "v2.0-draft.4" and
            value["contract_fixes"] == [10, 11], "readiness plan has another contract")
    expected = {node["name"]: node for node in structure(0)}
    instances = value["instances"]
    require(len(instances) == 10 and {item["name"] for item in instances} == set(expected),
            "readiness plan must retain ten distinct instances")
    for node in instances:
        exact_keys(node, ("name", "level", "parent", "driver"))
        source = expected[node["name"]]
        require(node["level"] == source["level"] and node["parent"] == source["parent"] and
                node["driver"] == ("draw" if node["level"] == 3 else source["driver"]),
                "readiness instance changed its level, parent or driver")
    lanes = value["lanes"]
    require(lanes and all(name.startswith("lb-v2-") and type(landed) is bool for name, landed in lanes.items()),
            "every dependency needs an explicit landed status")
    seen, covered, owners = set(), set(), set()
    source_lines, implemented = {}, set()
    for row in value["rows"]:
        exact_keys(row, ("id", "phase", "instances", "seconds", "check", "commands", "depends", "landed"))
        require(row["id"] not in seen and row["phase"] in ("service", "launch") and
                bool(row["check"]) and row["commands"], "row lacks a phase, check or public command")
        seen.add(row["id"])
        names = row["instances"]
        require(names and len(names) == len(set(names)) and (names == ["*"] or set(names) <= set(expected)),
                "row names an unknown or repeated instance")
        covered.update(expected if names == ["*"] else names)
        seconds = row["seconds"]
        require(len(seconds) == 2 and integer(seconds[0], 1) and integer(seconds[1], seconds[0], 7200),
                "row has no bounded expected wall-clock")
        require(row["depends"], "row has no owning port dependency")
        dependencies = set()
        for item in row["depends"]:
            exact_keys(item, ("lane", "port", "landed", "status", "evidence", "note"))
            key = (item["lane"], item["port"])
            require(item["lane"] in lanes and item["port"].strip() and key not in dependencies,
                    "row dependency is unnamed, unknown or repeated")
            require(item["status"] in ("implemented", "stub", "missing") and
                    type(item["landed"]) is bool and item["landed"] == (item["status"] == "implemented"),
                    "port landed flag disagrees with implementation status")
            require(isinstance(item["note"], str) and isinstance(item["evidence"], list) and item["evidence"],
                    "port needs file+symbol source evidence")
            for reference in item["evidence"]:
                exact_keys(reference, ("file", "symbol"), ("directory",))
                name, symbol = reference["file"], reference["symbol"]
                if "directory" in reference:
                    directory = reference["directory"]
                    require(isinstance(directory, str) and directory and
                            isinstance(name, str) and name not in ("", ".", "..") and "/" not in name,
                            "invalid source evidence directory")
                    name = directory + "/" + name
                require(isinstance(name, str) and name.startswith(("internal/v2/", "scripts/v2-admin/")) and
                        isinstance(symbol, str) and symbol.strip(), "invalid source evidence")
                source_line(name, symbol, source_lines)
            if item["landed"]:
                implemented.add(item["lane"])
            dependencies.add(key)
            owners.add(item["lane"])
        require(type(row["landed"]) is bool and row["landed"] == all(item["landed"] for item in row["depends"]),
                "row landed flag disagrees with its ports")
    require(seen == REQUIRED_ROWS, "readiness catalog has missing or unknown rows")
    require(covered == set(expected) and owners == set(lanes), "readiness inventory has uncovered instances or lanes")
    require(all(landed == (lane in implemented) for lane, landed in lanes.items()),
            "lane inventory differs from its implemented ports")
    return value


def instance_rows(plan, name):
    return [row for row in plan["rows"] if row["instances"] == ["*"] or name in row["instances"]]


def blockers(plan, row):
    return [item for item in row["depends"] if not item["landed"]]


def require_ports(plan):
    for row in plan["rows"]:
        for item in blockers(plan, row):
            raise Failure("8E: " + row.get("id", "source") + " still waits for " + item["port"],
                          "prerequisite_missing", item["lane"])
    return plan
