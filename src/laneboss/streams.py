"""The stream readers: one line of a run's log in, a list of plain items out.

``read(name, line)`` is a pure function of one line: no file, no process, no clock.  ``name`` is
``"text"`` or ``"claude-stream-json"``; anything else raises ``ValueError``, and the message never
repeats a name that looks like a credential.  ``line`` is a ``str``: one log line without its
newline.  No ``str`` line gives a traceback; the worst a line can do is one ``raw`` item.

Each item is a plain dict with ``kind`` and, per kind:

``answer``
    ``text``: text of the agent.
``tool``
    ``label``: one line, ``[tool NAME] `` plus the first 100 characters of the tool's command,
    file_path, pattern, path or url (the first of those present, in that order); or ``[tool error] ``
    plus the first 100 characters of the text of a tool's result that is an error.
``mode``
    ``mode``: the permission mode the agent reports.
``result``
    ``cost``: a float or None, ``error``: a bool, ``denials``: label strings made like a tool label
    but with ``[denied NAME] ``.
``notice``
    ``text``: what the agent program wants the person to see, cut to the first 100 characters, as a
    label is: the text of a ``notification`` line, or ``hook NAME: OUTCOME (exit CODE)`` for a hook
    that did not succeed.
``raw``
    ``text``: the line cut to 200 characters.

Every item's text passes through the control-character filter.  In ``answer`` text the C0 control
characters other than tab and newline, DEL and the C1 control characters are removed, so what is
left of an escape sequence stays visible and inert.  In a ``tool`` label, a ``denials`` entry, a
``notice`` and a ``raw`` line every control character becomes a space.

A real session prints more lines than the ones above (the real trial of ``lane attach`` showed about
fifty in three turns), and most of them are the agent program's own bookkeeping, of no use to a
person: they give no item at all, as ``stream_event`` lines of no text do.  They are the ``system``
lines with the subtypes ``QUIET_SUBTYPES``, a ``hook_response`` of a hook that succeeded (its
``outcome`` is ``success`` and its ``exit_code`` is 0 or missing), a ``rate_limit_event`` whose
``rate_limit_info.status`` is ``allowed``, and a ``user`` line whose ``tool_result`` blocks are no
error (the tool's result, which the answer and the tool label already stand for).  What a person must
see is not dropped: a ``hook_response`` of any other outcome or exit code is a ``notice`` made of the
fields that are usable (``hook_name`` and ``outcome`` when they are non-empty strings, ``exit_code``
when it is an integer; a boolean is no integer), and stays ``raw`` when neither the outcome nor the
exit code is usable; a ``user`` line with a ``tool_result`` block whose ``is_error`` is true gives one
``tool`` item, the label of the first such block, with the content's text (a string, or the first
text block of a list; nothing when there is none).  A ``rate_limit_event`` of any other status, or
whose ``rate_limit_info`` is missing or is not an object, may be a refusal, and so stays ``raw``; so
does a ``notification`` whose text is missing, empty or not a string, a ``user`` line of any other
content, and everything else that is not known.

``streamed``
    A whole ``assistant`` line repeats text that the partial-message (``stream_event``) lines may
    already have shown.  A reader sees one line only, so it cannot know what it streamed earlier in
    this turn: it returns every ``assistant`` text block as an ``answer`` item carrying
    ``streamed: False``, and the caller drops the ones it has already shown as deltas.  A
    ``stream_event`` answer carries no ``streamed`` key at all, which is how the two are told apart.
"""

import json
import math
import re


# The readers there are: the values of a runner's `stream` key.
READERS = ("text", "claude-stream-json")
# The permission modes, by the names that a vendor's reader returns in a `mode` item, that mean that approvals are
# bypassed: the warning of `lane attach` is made for these, and the core knows no vendor's name but through this tuple.
BYPASS_MODES = ("bypassPermissions",)

# C0 other than tab (\x09) and newline (\x0a), DEL and C1: removed from the agent's answer text.
UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# Every control character, tab and newline included: turned into a space in a label or a raw line.
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# A name the caller could have meant: short, and nothing a credential can contain.
PLAUSIBLE_NAME = re.compile(r"\A[A-Za-z0-9._+-]{1,64}\Z")
# A name that is more likely a secret than a reader: a known key prefix or a long opaque run.
CREDENTIAL_LIKE = re.compile(r"(?:\A(?:sk|pk|gh[pousr]|xox|AKIA|AIza|ya29)[-_])|[A-Za-z0-9+/]{20,}={0,2}")

# The `system` lines of a Claude Code session that are the agent program's own bookkeeping (a hook that starts, its
# screen, its thinking, its background tasks, its state): they give no item. A `hook_response` is not here: it is quiet
# only when the hook succeeded (`_hook_response_items`).
QUIET_SUBTYPES = ("hook_started", "ui_invalidate", "status", "thinking_tokens", "task_started", "task_notification")

# The fields a tool's one-line label is taken from, in the order they are tried.
TOOL_FIELDS = ("command", "file_path", "pattern", "path", "url")
LABEL_FIELD_LIMIT = 100
RAW_LIMIT = 200


def _answer(text):
    return {"kind": "answer", "text": UNSAFE.sub("", text)}


def _inert(text):
    return CONTROL.sub(" ", text)


def _raw_items(line):
    return [{"kind": "raw", "text": _inert(line[:RAW_LIMIT])}]


def _integer(value):
    """A JSON integer: a boolean is not one."""
    return isinstance(value, int) and not isinstance(value, bool)


def _words(value):
    """A string that has something in it, else None."""
    return value if isinstance(value, str) and value != "" else None


def _hook_response_items(payload, line):
    """A ``hook_response``: no item when the hook succeeded (its outcome is ``success`` and its exit code is 0 or
    missing); else a notice ``hook NAME: OUTCOME (exit CODE)`` of the fields that can be used, and the raw line when
    neither the outcome nor the exit code can."""
    outcome = _words(payload.get("outcome"))
    code = payload.get("exit_code")
    if outcome == "success" and (code is None or (_integer(code) and code == 0)):
        return []
    code = code if _integer(code) else None
    if outcome is None and code is None:
        return _raw_items(line)
    name = _words(payload.get("hook_name"))
    text = "hook" + (" " + name if name else "") + (": " + outcome if outcome else "")
    if code is not None:
        text += " (exit %d)" % code
    return [{"kind": "notice", "text": _inert(text[:LABEL_FIELD_LIMIT])}]


def _result_text(content):
    """The text of a tool's result: the string itself, or the text of the first text block of a list; "" if none."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
                return block["text"]
    return ""


def _name_is_unknown(name):
    """The message for a name that is not a reader: the name only when it is safe to show it."""
    if isinstance(name, str) and PLAUSIBLE_NAME.match(name) and not CREDENTIAL_LIKE.search(name):
        return "unknown stream reader: " + name
    return "unknown stream reader"


def _cost(value):
    """The session's running total: a float only for a finite number that is not a boolean."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:  # a JSON integer too big for a float is not a cost
        return None
    return number if math.isfinite(number) else None


def _label(prefix, name, tool_input):
    """One line: ``[<prefix> NAME] `` and the first 100 characters of the tool's subject."""
    subject = ""
    if isinstance(tool_input, dict):
        for field in TOOL_FIELDS:
            candidate = tool_input.get(field)
            if isinstance(candidate, str):
                subject = candidate[:LABEL_FIELD_LIMIT]
                break
    return _inert("[%s %s] %s" % (prefix, name, subject))


def _denials(value):
    """The denial labels: only objects with a string tool_name and an object tool_input count."""
    if not isinstance(value, list):
        return []
    labels = []
    for denial in value:
        if not isinstance(denial, dict):
            continue
        name = denial.get("tool_name")
        tool_input = denial.get("tool_input")
        if isinstance(name, str) and isinstance(tool_input, dict):
            labels.append(_label("denied", name, tool_input))
    return labels


def _read_text(line):
    return [_answer(line)]


def _read_claude_stream_json(line):
    if not line.strip():
        return []
    try:
        payload = json.loads(line)
    except (ValueError, RecursionError):  # a line that is not JSON, or nested past the interpreter limit
        return _raw_items(line)
    if not isinstance(payload, dict):
        return _raw_items(line)

    kind = payload.get("type")

    if kind == "system":
        subtype = payload.get("subtype")
        if subtype == "init":
            mode = payload.get("permissionMode")
            return [{"kind": "mode", "mode": mode}] if isinstance(mode, str) else []
        if isinstance(subtype, str) and subtype in QUIET_SUBTYPES:
            return []
        if subtype == "hook_response":
            return _hook_response_items(payload, line)
        if subtype == "notification":
            text = payload.get("text")
            if isinstance(text, str) and text:
                return [{"kind": "notice", "text": _inert(text[:LABEL_FIELD_LIMIT])}]
        return _raw_items(line)

    if kind == "rate_limit_event":
        info = payload.get("rate_limit_info")
        if isinstance(info, dict) and info.get("status") == "allowed":
            return []
        return _raw_items(line)

    if kind == "user":
        message = payload.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        results = [block for block in content if isinstance(block, dict) and block.get("type") == "tool_result"] \
            if isinstance(content, list) else []
        if not results:
            return _raw_items(line)
        for block in results:
            if block.get("is_error") is True:  # only a tool that failed is told; the others are in the answer already
                text = _result_text(block.get("content"))[:LABEL_FIELD_LIMIT]
                return [{"kind": "tool", "label": _inert("[tool error] " + text)}]
        return []

    if kind == "stream_event":
        event = payload.get("event")
        if not isinstance(event, dict) or event.get("type") != "content_block_delta":
            return []
        delta = event.get("delta")
        if not isinstance(delta, dict) or delta.get("type") != "text_delta":
            return []
        text = delta.get("text")
        return [_answer(text)] if isinstance(text, str) else []

    if kind == "assistant":
        message = payload.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            return []
        items = []
        for block in content:
            if not isinstance(block, dict):
                continue
            block_type = block.get("type")
            if block_type == "text":
                text = block.get("text")
                if isinstance(text, str):
                    item = _answer(text)
                    item["streamed"] = False  # attach drops it if the deltas already showed it
                    items.append(item)
            elif block_type == "tool_use":
                name = block.get("name")
                if isinstance(name, str):
                    items.append({"kind": "tool", "label": _label("tool", name, block.get("input"))})
        return items

    if kind == "result":
        return [{"kind": "result",
                 "cost": _cost(payload.get("total_cost_usd")),
                 "error": payload.get("is_error") is True,
                 "denials": _denials(payload.get("permission_denials"))}]

    return _raw_items(line)


def read(name, line):
    """Turn one log line into the items ``lane attach`` shows; never raise for a ``str`` line."""
    if not isinstance(name, str) or not PLAUSIBLE_NAME.match(name):
        raise ValueError(_name_is_unknown(name))
    if name not in READERS:
        raise ValueError(_name_is_unknown(name))
    if name == "text":
        return _read_text(line)
    return _read_claude_stream_json(line)
