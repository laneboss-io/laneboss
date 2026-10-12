"""Session records: the raw records agent programs keep of every tool call and its result, read for the refusal scan
(docs/architecture.md, "Refusals"). Two formats are read; the shapes of the first were checked against real records:

- claude-code: one JSON object per line, with "timestamp" and "cwd". A line with "type" "assistant" holds tool calls in
  message.content ({"type": "tool_use", "id", "name", "input"}); a later line with "type" "user" holds their results
  ({"type": "tool_result", "tool_use_id", "content": text or a list of blocks, "is_error"}). Only results marked as
  errors are offered to the guards. A hook's message about a call is a line with "type" "attachment": attachment.type
  "hook_blocking_error" with the text in attachment.blockingError.blockingError, or "hook_non_blocking_error" with the
  text in "stderr" or "content", both with "toolUseID", "hookEvent" and "hookName". Those are always offered to the
  guards, whatever the call's result says. Content blocks of a type not seen in real records make the record partly
  read: assistant lines hold text, thinking and tool_use blocks, user lines tool_result and text blocks, and a result's
  content list text and tool_reference blocks. A record is recognised once an assistant or user line was read whole.
- text: the run's own log (the lane's output.log), within the byte range the supervising process recorded for the run.
  Every line is offered; there are no calls, so no command and no targets.

A line that is not JSON, not an object or not of a described shape is skipped and counted as unknown; an object of
another type is skipped and counted as other. Nothing in a record is ever fatal.

A text offered to the guards is bounded: one longer than 128 KiB is matched on its first 64 KiB and on the lines that
begin in its last 64 KiB (`cut`: its middle is unread), and each line on its first 4096 characters.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import stat

from . import shellscan
from .errors import Refused

FORMATS = ("claude-code", "text")
STRUCTURED = ("claude-code",)
MAX_LINE = 16 * 1024 * 1024
CHUNK = 4 * 1024 * 1024
MAX_TEXT = 64 * 1024
ANCHOR = 4096
CLAUDE_SHELL = ("Bash",)
CLAUDE_FILES = {"Write": ("file_path", "content"), "Edit": ("file_path", "new_string"),
                "MultiEdit": ("file_path", "edits"), "NotebookEdit": ("notebook_path", "new_source")}
CLAUDE_PATH_KEYS = ("file_path", "path", "notebook_path")
KNOWN_BLOCKS = {"assistant": ("text", "thinking", "tool_use"), "user": ("tool_result", "text")}
KNOWN_RESULT_BLOCKS = ("text", "tool_reference")
HOOK_TEXTS = {"hook_blocking_error": None, "hook_non_blocking_error": ("stderr", "content")}
COUNTS = ("lines", "unknown_lines", "other_lines", "oversized", "timed_out", "cut_results", "cut_lines", "outside_runs")


def moment(value):
    """(epoch seconds, normalised timestamp) of an ISO 8601 text, or (None, None)."""
    if not isinstance(value, str) or len(value) > 64:
        return None, None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value)
    except ValueError:
        return None, None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    return parsed.timestamp(), parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def bounded(text):
    """The parts of a text the guards see: all of it up to 128 KiB; beyond that its first 64 KiB and the lines that
    begin in its last 64 KiB (never the end of a line that began before them), and whether its middle is unread."""
    if len(text) <= 2 * MAX_TEXT:
        return {"text": text, "tail": None, "cut": False}
    tail = "".join(text[len(text) - MAX_TEXT - 1:].splitlines(True)[1:])
    return {"text": text[:MAX_TEXT], "tail": tail or None, "cut": True}


def result_text(content):
    """The text of a result's content, and whether a block of it is of a type the parser does not know."""
    if isinstance(content, str):
        return content, False
    if not isinstance(content, list):
        return "", content is not None
    parts = []
    unknown = False
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict) and block.get("type") in KNOWN_RESULT_BLOCKS:
            if isinstance(block.get("text"), str):
                parts.append(block["text"])
        else:
            unknown = True
    return "\n".join(parts), unknown


def command_fields(text):
    """The call's command text, at most 64 KiB of it, with the length and hash of all of it."""
    text = text if isinstance(text, str) else ""
    return {"text": text[:MAX_TEXT], "length": len(text),
            "sha256": hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()}


def call(call_id, tool, kind, text, directory, writes=(), named=()):
    item = {"kind": "call", "id": call_id if isinstance(call_id, str) else None,
            "tool": tool if isinstance(tool, str) else None, "class": kind, "cwd": directory,
            "writes": list(writes), "named": list(named)}
    item.update(command_fields(text))
    return item


def result(call_id, text, error):
    return dict(bounded(text), kind="result", id=call_id if isinstance(call_id, str) else None, error=error)


def claude_call(block, directory):
    name = block.get("name") if isinstance(block.get("name"), str) else None
    arguments = block.get("input") if isinstance(block.get("input"), dict) else {}
    if name in CLAUDE_SHELL:
        return call(block.get("id"), name, "shell", arguments.get("command"), directory)
    if name in CLAUDE_FILES:
        path_key, body_key = CLAUDE_FILES[name]
        path = arguments.get(path_key) if isinstance(arguments.get(path_key), str) else ""
        body = arguments.get(body_key)
        if name == "MultiEdit":
            body = "\n".join(edit.get("new_string", "") for edit in body if isinstance(edit, dict)
                             and isinstance(edit.get("new_string"), str)) if isinstance(body, list) else ""
        written = [found for found in [shellscan.resolve(path, directory)] if found]
        return call(block.get("id"), name, "file", path + "\n" + (body if isinstance(body, str) else ""), directory,
                    written, written)
    named = [found for key in CLAUDE_PATH_KEYS if isinstance(arguments.get(key), str)
             for found in [shellscan.resolve(arguments[key], directory)] if found]
    return call(block.get("id"), name, "other", json.dumps(arguments, sort_keys=True)[:MAX_TEXT], directory, (), named)


def hook_item(attachment):
    """A hook's message about a call, or None for an attachment that is not one."""
    kind = attachment.get("type")
    if kind not in HOOK_TEXTS:
        return None
    if kind == "hook_blocking_error":
        error = attachment.get("blockingError")
        text = error.get("blockingError") if isinstance(error, dict) else None
    else:
        text = next((attachment[key] for key in HOOK_TEXTS[kind] if isinstance(attachment.get(key), str)
                     and attachment[key]), None)
    strings = {key: attachment[key] if isinstance(attachment.get(key), str) else None
               for key in ("toolUseID", "hookEvent", "hookName")}
    return dict(bounded(text if isinstance(text, str) else ""), kind="hook", id=strings["toolUseID"],
                event=strings["hookEvent"], name=strings["hookName"])


def parse_claude(value):
    """(category, items, cwd, timestamp) of one claude-code line. The category is message (an assistant or user line
    read whole), partial (one holding a block of a type the parser does not know), hook, other or unknown."""
    if not isinstance(value, dict) or not isinstance(value.get("type"), str):
        return "unknown", [], None, None
    directory = value.get("cwd") if isinstance(value.get("cwd"), str) and value["cwd"].startswith("/") else None
    at = value.get("timestamp")
    if value["type"] == "attachment":
        attachment = value.get("attachment")
        found = hook_item(attachment) if isinstance(attachment, dict) else None
        return ("hook", [found], directory, at) if found else ("other", [], directory, at)
    if value["type"] not in KNOWN_BLOCKS:
        return "other", [], directory, at
    message = value.get("message")
    if not isinstance(message, dict):
        return "unknown", [], directory, at
    content = message.get("content")
    if isinstance(content, str):
        return "message", [], directory, at
    if not isinstance(content, list):
        return "unknown", [], directory, at
    items = []
    partial = False
    for block in content:
        kind = block.get("type") if isinstance(block, dict) else None
        if kind not in KNOWN_BLOCKS[value["type"]]:
            partial = True
        elif kind == "tool_use":
            items.append(claude_call(block, directory))
        elif kind == "tool_result":
            text, unknown = result_text(block.get("content"))
            partial = partial or unknown
            items.append(result(block.get("tool_use_id"), text, block.get("is_error") is True))
    return ("partial" if partial else "message"), items, directory, at


def anchor(descriptor, offset):
    """The SHA-256 of the 4096 bytes before an offset (fewer when the offset is smaller)."""
    size = min(ANCHOR, offset)
    return hashlib.sha256(os.pread(descriptor, size, offset - size)).hexdigest()


class Record:
    """One record file, read from where the last look stopped; every look opens it again (`opener`), so a record that
    can no longer be read is seen as unreadable at once. A claude-code record is read once its first line is complete:
    the hash of that line, the offset read to and the hash of the 4096 bytes before it are kept (`first`, `seen`,
    `tail`, also from earlier scans), and a file found shorter than that offset or with another first line or other
    bytes before it is `replaced` for good and never read again. The run's own log (text) is read within the run's byte
    range only, and is `truncated` when it is shorter than the end of that range."""

    def __init__(self, path, fmt, index, opener=None, start=0, end=None, run=None, first=None, seen=0, tail=None):
        self.path = self.shown = path
        self.format = fmt
        self.index = index
        self.opener = opener or (lambda: os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)))
        self.start, self.end, self.run, self.first, self.seen, self.tail = start, end, run, first, seen, tail
        self.offset = self.consumed = start
        self.line = None if start else 0
        self.partial = b""
        self.skipping = self.incomplete = self.foreign = self.recognised = self.partly = self.cut = False
        self.finished = False  # read to its end by a final read (the scan's)
        self.launch = None
        self.state = "covered"
        self.counts = {}
        self.other_directory, self.templates, self.launches = set(), set(), set()
        self.mtime = self.cwd = self.real_cwd = self.cursor = None
        self.run_of_cursor = lambda: run  # the scan's: the run an oversized line is counted for

    def count(self, run, key, number=1):
        self.counts.setdefault(run, dict.fromkeys(COUNTS, 0))[key] += number

    def holds(self, descriptor, size):
        """True when the record may be read on: its first line is complete, is the one read before, the file is not
        shorter than what was read and the 4096 bytes before that place are unchanged. Otherwise it is not read yet
        (`incomplete`) or `replaced` for good."""
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            line = handle.readline(MAX_LINE + 1)
        digest = hashlib.sha256(line).hexdigest() if line.endswith(b"\n") else None
        if self.first is not None and (digest != self.first or size < max(self.seen, self.offset) or (
                self.tail is not None and anchor(descriptor, self.seen) != self.tail)):
            self.state = "replaced"
        self.incomplete, self.first = digest is None, self.first or digest
        return self.state == "covered" and not self.incomplete

    def lines(self, final):
        """(line number, byte offset, bytes) of every complete line after the last look; with final, the last line
        too, newline or not."""
        if self.state in ("replaced", "refused-zone"):
            return
        try:
            descriptor = self.opener()
        except (Refused, OSError) as error:
            self.state = "refused-zone" if isinstance(error, Refused) else "unreadable"
            return
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                self.state = "unreadable"
                return
            self.mtime = info.st_mtime
            self.state = "covered"
            if self.format in STRUCTURED and not self.holds(descriptor, info.st_size):
                return
            stop = info.st_size if self.end is None else min(info.st_size, self.end)
            # The run's own log seen shorter than what was already read of it, or than the end of its recorded range: a
            # loss, for good. What is left, and what comes later, is read on from the place the reader had reached.
            self.cut = self.cut or (self.format == "text" and info.st_size < max(self.offset, self.end or 0))
            if self.cut:
                self.state = "truncated"
            if self.line is None:
                self.line = self.count_lines(descriptor, self.offset)
            while self.offset < stop:
                try:
                    data = os.pread(descriptor, min(CHUNK, stop - self.offset), self.offset)
                except OSError:
                    self.state = "unreadable"
                    return
                if not data:
                    break
                self.offset += len(data)
                yield from self.split(data)
            if self.offset > self.seen or self.tail is None:
                self.seen = max(self.seen, self.offset)
                self.tail = anchor(descriptor, self.seen) if self.format in STRUCTURED else None
            if final and (self.partial or self.skipping):
                rest, self.partial = self.partial, b""
                if not self.skipping:
                    self.line += 1
                    begin = self.consumed
                    self.consumed += len(rest)
                    yield self.line, begin, rest
                self.skipping = False
        finally:
            os.close(descriptor)

    def count_lines(self, descriptor, end):
        number = 0
        position = 0
        while position < end:
            data = os.pread(descriptor, min(CHUNK, end - position), position)
            if not data:
                break
            number += data.count(b"\n")
            position += len(data)
        return number

    def split(self, data):
        start = 0
        while True:
            newline = data.find(b"\n", start)
            if newline < 0:
                if not self.skipping:
                    self.partial += data[start:]
                    if len(self.partial) > MAX_LINE:
                        self.partial = b""
                        self.skipping = True
                        self.count(self.run_of_cursor(), "oversized")
                return
            piece = data[start:newline]
            if self.skipping:
                self.skipping = False
                self.line += 1
                self.consumed = self.offset - len(data) + newline + 1
            else:
                line = self.partial + piece
                self.partial = b""
                self.line += 1
                begin = self.consumed
                self.consumed += len(line) + 1
                if len(line) > MAX_LINE:
                    self.count(self.run_of_cursor(), "oversized")
                else:
                    yield self.line, begin, line
            start = newline + 1
