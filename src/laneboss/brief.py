"""Brief rendering: the input brief's bytes unchanged, then a delimited launcher block.

The block carries the shared protocol (with its version and the refusal rule) and the bound
configuration's standing-rules files. Every input is read once and the same bytes are validated,
rendered and kept: the brief through its checked directory, the rules as the configuration loader
validated them. Rendering keeps a copy of every consumed input under the lane's directory in the state
directory, named by hash, writes the output through a temporary name so it appears only complete, and
appends a `brief.rendered` event with the hash of every input and of the output. A failed render removes
the output and every copy it created that no event names.
"""

import os
import re

from . import config, credentials, events, fsguard
from .errors import IntegrityProblem, Refused
from .identity import PROGRAM, VERSION
from .jsonutil import sha256_hex
from .protocol import load_protocol
from .statedir import StateDir

TOUCHES = ("billing", "deploy")
SECTIONS = {
    "billing": ("Cost", re.compile(r"\bcosts?\b", re.IGNORECASE), (
        ("unit price", r"unit[\s-]+prices?"), ("per-run cap", r"per[\s-]*run[\s-]+caps?"),
        ("daily cap", r"daily[\s-]+caps?"), ("worst case", r"worst[\s-]+cases?"))),
    "deploy": ("Preflight", re.compile(r"\bpre[\s-]?flight\b", re.IGNORECASE), (
        ("calls", r"calls?"), ("permission", r"permissions?"),
        ("where granted", r"(?:where[\s-]+)?granted(?:[\s-]+(?:in|at|by))?"), ("read-back", r"read[\s-]?backs?"))),
}
HEADING = re.compile(r"(#{1,6})[ \t]+(.*?)[ \t]*#*[ \t]*$")
FENCE = re.compile(r"[ ]{0,3}(`{3,}|~{3,})")
SEPARATOR = re.compile(r"\s*:?-{3,}:?\s*")
BEGIN_MARKER = "<!-- {} launcher block: begin".format(PROGRAM)
MAX_BRIEF_BYTES = 4 * 1024 * 1024


def fenced_lines(lines):
    """Which lines belong to fenced code, by the Markdown rule: a fence opens with three or more backticks or
    tildes (up to three spaces of indentation); it closes only with the same character, at least as many of
    them, and nothing after them but spaces; a fence that is never closed runs to the end."""
    fenced = []
    fence = None
    for line in lines:
        if fence is None:
            opening = FENCE.match(line)
            if opening:
                fence = opening.group(1)
            fenced.append(fence is not None)
            continue
        closing = re.fullmatch(r"[ ]{0,3}(`{3,}|~{3,})[ \t]*", line)
        if closing and closing.group(1)[0] == fence[0] and len(closing.group(1)) >= len(fence):
            fence = None
        fenced.append(True)
    return fenced


def sections(text):
    """Markdown sections as (heading text, body lines outside fenced code). Lines end at LF, CRLF or CR, as
    in Markdown."""
    lines = re.split(r"\r\n|\r|\n", text)
    fenced = fenced_lines(lines)
    headings = [(index, len(match.group(1)), match.group(2)) for index, line in enumerate(lines)
                if not fenced[index] for match in [HEADING.match(line)] if match]
    found = []
    for position, (index, level, title) in enumerate(headings):
        end = len(lines)
        for later, later_level, _ in headings[position + 1:]:
            if later_level <= level:
                end = later
                break
        found.append((title, [lines[number] for number in range(index + 1, end) if not fenced[number]]))
    return found


def cells(line):
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return [cell.strip() for cell in stripped.split("|")]


def meaningful(value):
    return value.strip().strip("*_`").strip() not in ("", "-", "--", "—", "n/a", "N/A", "tbd", "TBD")


def has_value(lines, label):
    """A label followed by a value: 'Label: value' on a line, or a table column headed by the label with a
    value in at least one row."""
    line_form = re.compile(r"\s*(?:[-*+]\s+|[0-9]+[.)]\s+)?[*_]*(?:" + label + r")[*_]*\s*[:=]\s*(?P<value>.*)$",
                           re.IGNORECASE)
    for line in lines:
        match = line_form.match(line)
        if match and meaningful(match.group("value")):
            return True
    table = []
    for line in lines + [""]:
        if line.strip().startswith("|"):
            table.append(cells(line))
            continue
        if len(table) >= 3 and all(SEPARATOR.fullmatch(cell) for cell in table[1] if cell):
            for column, header in enumerate(table[0]):
                if re.fullmatch(r"[*_]*(?:" + label + r")[*_]*", header, re.IGNORECASE):
                    if any(column < len(row) and meaningful(row[column]) for row in table[2:]):
                        return True
        table = []
    return False


def check_sections(text, touches):
    """--touches billing needs a cost section and --touches deploy a preflight section, each with a value
    for every label in its body (outside fenced code)."""
    found = sections(text)
    for touch in touches:
        name, heading, labels = SECTIONS[touch]
        bodies = [body for title, body in found if heading.search(title)]
        if not bodies:
            raise Refused('--touches {} needs a "{}" section (a heading containing "{}") that states: {}'.format(
                touch, name, name.lower(), ", ".join(label for label, _ in labels)))
        lines = [line for body in bodies for line in body]
        missing = [label for label, pattern in labels if not has_value(lines, pattern)]
        if missing:
            raise Refused("the {} section has no value for: {}; write 'Label: value' lines or a table with one "
                          "column per label and a row of values".format(name.lower(), ", ".join(missing)))


def ended(data):
    return data if data.endswith(b"\n") else data + b"\n"


def compose(configuration, lane, project, brief, protocol, protocol_version, rules):
    header = "\n".join([
        "",
        "{} (protocol {}) -->".format(BEGIN_MARKER, protocol_version),
        "",
        "---",
        "",
        "# Launcher block",
        "",
        "Everything above this block is the brief exactly as written. {} {} appended this block.".format(
            PROGRAM, VERSION),
        "",
        "- Configuration: " + configuration.name,
        "- Project: " + (project or "none"),
        "- Lane: " + lane,
        "- Protocol version: " + protocol_version,
        "- Brief sha256: " + sha256_hex(brief),
        "",
        "",
    ]).encode("utf-8")
    parts = [ended(brief) if brief else brief, header, ended(protocol)]
    for relative, data in rules:
        parts.append("\n## Standing rules: {} (sha256 {})\n\n".format(relative, sha256_hex(data)).encode("utf-8"))
        parts.append(ended(data))
    parts.append("\n<!-- {} launcher block: end -->\n".format(PROGRAM).encode("utf-8"))
    return b"".join(parts)


def render(configuration, zones, lane, source, target, project=None, touches=()):
    events.check_grammar(lane, events.LANE, "--lane")
    if project is not None and project not in configuration.projects:
        raise Refused("--project: configuration {} has no project file projects/{}.toml".format(
            configuration.name, project if config.NAME.fullmatch(project or "") else "<name>"))
    touches = sorted(set(touches))
    brief = config.read_external(zones, source, "--in", MAX_BRIEF_BYTES)
    try:
        text = brief.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("--in: the brief must be UTF-8 text") from None
    if BEGIN_MARKER in text:
        raise Refused("--in: the brief already contains a launcher block; render the original brief")
    found = credentials.find_in_text(text)
    if found:
        raise Refused("brief line {}: looks like a credential ({}); nothing was written".format(found[1], found[0]))
    check_sections(text, touches)
    protocol, protocol_version = load_protocol()
    rules = configuration.rules(project)
    output = compose(configuration, lane, project, brief, protocol, protocol_version, rules)
    output_dir, output_name = config.open_output(zones, target, "--out")
    try:
        state = StateDir.open(configuration, zones, create=True)
        try:
            with state.lock():
                return write_rendered(state, output_dir, output_name, lane, project, touches, protocol_version,
                                      brief, protocol, rules, output, os.path.join(
                                          os.path.realpath(os.path.dirname(os.path.abspath(str(target)))),
                                          output_name), source)
        finally:
            state.close()
    finally:
        os.close(output_dir)


def check_text(data, label, noun="brief"):
    """The refusals every brief and every message gets before anything is rendered or stored: UTF-8 text, no launcher
    block of its own, no credential shape (the error names the line and never repeats it). Returns the text."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("{}: the {} must be UTF-8 text".format(label, noun)) from None
    if BEGIN_MARKER in text:
        raise Refused("{}: the {} already contains a launcher block; give the original {}".format(label, noun, noun))
    found = credentials.find_in_text(text)
    if found:
        raise Refused("{} line {}: looks like a credential ({}); nothing was written".format(label, found[1], found[0]))
    return text


def compose_for_lane(configuration, lane, project, touches, data, label):
    """The checks brief render makes, for a lane's brief or follow-up message given as bytes, and the composed
    output: (output, protocol, protocol version, rules). Nothing is written."""
    text = check_text(data, label)
    check_sections(text, touches)
    protocol, protocol_version = load_protocol()
    rules = configuration.rules(project)
    return compose(configuration, lane, project, data, protocol, protocol_version, rules), protocol, protocol_version, rules


def render_for_lane(state, lane, project, touches, source, data, composed):
    """Write a composed brief to STATE_DIR/lanes/LANE/rendered/SHA256.md (equal bytes are kept once), keep the inputs
    and append brief.rendered, as brief render does. Returns (absolute path, sha256 of the output)."""
    output, protocol, protocol_version, rules = composed
    name = sha256_hex(output) + ".md"
    directory = state.open_lane(lane, "rendered", create=True)
    try:
        with state.lock():
            write_rendered(state, directory, name, lane, project, sorted(set(touches)), protocol_version, data,
                           protocol, rules, output, state.lane_path(lane, "rendered", name), source, reuse=True)
    finally:
        os.close(directory)
    return state.lane_path(lane, "rendered", name), sha256_hex(output)


def write_rendered(state, output_dir, output_name, lane, project, touches, protocol_version, brief, protocol,
                   rules, output, output_path, source, reuse=False):
    store = events.open_for_write(state)
    created = []
    written = False
    try:
        consumed = [("brief", {"path": os.path.realpath(str(source))}, brief),
                    ("protocol", {"version": protocol_version}, protocol)]
        consumed += [("rules", {"path": relative}, data) for relative, data in rules]
        inputs = []
        for role, details, data in consumed:
            copy, digest, was_created = state.keep_input(lane, data)
            if was_created:
                created.append(digest)
            inputs.append(dict(details, role=role, sha256=digest, copy=copy))
        if reuse and fsguard.file_info(output_dir, output_name) is not None:
            kept = fsguard.read_descriptor(fsguard.open_child(output_dir, output_name, output_path), len(output) + 1,
                                           output_path)
            if kept != output:
                raise IntegrityProblem("{} does not hold the bytes its name promises".format(output_path))
        else:
            try:
                fsguard.write_new(output_dir, output_name, output, mode=0o644)
            except FileExistsError:
                raise Refused("--out {} already exists; a rendered brief is never replaced".format(
                    output_path)) from None
            except OSError as error:
                raise Refused("--out: cannot write {}: {}".format(output_path, error.strerror or "error")) from None
            written = True
        output_digest = sha256_hex(output)
        payload = {"inputs": inputs, "output": {"path": output_path, "sha256": output_digest},
                   "project": project, "touches": touches, "launcher_version": VERSION}
        appended = store.append({"kind": "brief.rendered", "lane": lane, "actor": PROGRAM, "payload": payload,
                                 "protocol_version": protocol_version})
    except BaseException:
        if written:
            try:
                os.unlink(output_name, dir_fd=output_dir)
            except OSError:
                pass
        for digest in created:
            if not store.references(lane, digest):
                state.remove_input(lane, digest)
        raise
    finally:
        store.close()
    return {"event": {"id": appended["id"], "seq": appended["seq"]}, "out": output_path,
            "sha256": {"output": output_digest, "inputs": [{"role": item["role"], "sha256": item["sha256"]}
                                                           for item in inputs]}}
