"""The stream readers: read(name, line) turns one log line into a list of plain items.

A reader lives in ``laneboss.streams`` and is a pure function of one line (docs/architecture.md,
"The stream readers").  ``name`` is ``"text"`` or ``"claude-stream-json"``; anything else raises
``ValueError`` without repeating a name that looks like a credential.  ``line`` is a ``str`` without
its newline.  Each item is a dict with ``kind`` and, per kind: ``answer`` {text}, ``tool`` {label},
``mode`` {mode}, ``result`` {cost, error, denials}, ``raw`` {text}.  No ``str`` line may raise.

Every test below calls the reader of the installed copy and asserts an expected value worked out by
hand from the input, never by asking the code under test what it returned.
"""

import json
import sys
import unittest

from . import support


KINDS = ("answer", "tool", "mode", "result", "raw")

_streams = None
_import_error = None


def installed_library():
    """The ``lib`` directory of the one installed copy this module built."""
    found = sorted((support._installation.prefix / "share" / support.PROGRAM / "versions").glob("*/lib"))
    assert len(found) == 1, "expected one installed version, found %r" % (found,)
    return found[0]


def setUpModule():
    global _streams, _import_error
    support.install()
    library = str(installed_library())
    if library not in sys.path:
        sys.path.insert(0, library)
    try:
        from laneboss import streams
    except Exception as error:  # noqa: BLE001 - the red run: the module does not exist yet
        _import_error = "%s: %s" % (type(error).__name__, error)
    else:
        _streams = streams


def tearDownModule():
    support.uninstall()


def line_of(payload):
    """One JSON object as a log line, keeping control characters as they are."""
    return json.dumps(payload, ensure_ascii=False)


class ReaderTest(unittest.TestCase):
    def setUp(self):
        if _streams is None:
            self.fail("the installed copy has no laneboss.streams (%s)" % (_import_error,))
        self.read = _streams.read

    def call(self, name, line):
        items = self.read(name, line)
        self.assertIsInstance(items, list, "read(%r, ...) must return a list" % (name,))
        for item in items:
            self.assertIsInstance(item, dict)
            self.assertIn(item.get("kind"), KINDS, "unknown kind in %r" % (items,))
        return items


class TestTextReader(ReaderTest):
    def test_plain_line_gives_one_answer(self):
        self.assertEqual(self.call("text", "hello world"), [{"kind": "answer", "text": "hello world"}])

    def test_blank_line_still_gives_an_answer(self):
        self.assertEqual(self.call("text", ""), [{"kind": "answer", "text": ""}])

    def test_answer_is_the_line_itself(self):
        line = 'a line with "quotes" and \\ backslash'
        self.assertEqual(self.call("text", line), [{"kind": "answer", "text": line}])

    def test_never_yields_a_mode_or_a_result(self):
        lines = ["", "not json",
                 line_of({"type": "result", "subtype": "success", "total_cost_usd": 1.5, "is_error": True}),
                 line_of({"type": "system", "subtype": "init", "permissionMode": "plan"}),
                 line_of({"type": "assistant", "message": {"content": [{"type": "text", "text": "x"},
                                                                       {"type": "tool_use", "name": "Bash",
                                                                        "input": {"command": "ls"}}]}})]
        for line in lines:
            items = self.call("text", line)
            self.assertEqual([item["kind"] for item in items], ["answer"], line)
            self.assertEqual(items[0]["text"], line)

    def test_control_chars_removed_from_answer(self):
        # C0 other than tab and newline, DEL and C1 go; what is left of an escape sequence stays visible.
        self.assertEqual(self.call("text", "a\x00b\x07c\x1b[2Jd\x7fe\u0080f"),
                         [{"kind": "answer", "text": "abc[2Jdef"}])

    def test_tab_and_newline_survive_in_answer(self):
        self.assertEqual(self.call("text", "a\tb\nc"), [{"kind": "answer", "text": "a\tb\nc"}])

    def test_nul_byte_dropped_from_answer(self):
        self.assertEqual(self.call("text", "a\x00b"), [{"kind": "answer", "text": "ab"}])

    def test_c1_char_dropped_from_answer(self):
        self.assertEqual(self.call("text", "a\u0085b"), [{"kind": "answer", "text": "ab"}])

    def test_hundred_k_line_returned_whole(self):
        line = "q" * 100000
        self.assertEqual(self.call("text", line), [{"kind": "answer", "text": line}])


class TestClaudeStreamJsonMode(ReaderTest):
    def test_init_gives_permission_mode(self):
        line = line_of({"type": "system", "subtype": "init", "permissionMode": "acceptEdits"})
        self.assertEqual(self.call("claude-stream-json", line), [{"kind": "mode", "mode": "acceptEdits"}])

    def test_init_nonstring_mode_no_item(self):
        for permission_mode in (5, None, ["plan"], True):
            line = line_of({"type": "system", "subtype": "init", "permissionMode": permission_mode})
            self.assertEqual(self.call("claude-stream-json", line), [], line)

    def test_init_without_field_no_item(self):
        self.assertEqual(self.call("claude-stream-json", line_of({"type": "system", "subtype": "init"})), [])

    def test_system_other_subtype_is_raw(self):
        # The subtype was `status` until the real trial of attach showed that a real session prints it all the time (it
        # is dropped now: TestRealTrialShapes), so this test, which is about a subtype that no reader knows, uses one
        # that nothing prints.
        line = line_of({"type": "system", "subtype": "made_up_subtype"})
        self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": line}])


class TestClaudeStreamJsonAnswer(ReaderTest):
    def test_block_delta_gives_answer(self):
        line = line_of({"type": "stream_event",
                        "event": {"type": "content_block_delta", "index": 0,
                                  "delta": {"type": "text_delta", "text": "Hel"}}})
        self.assertEqual(self.call("claude-stream-json", line), [{"kind": "answer", "text": "Hel"}])

    def test_streamed_answer_no_key(self):
        line = line_of({"type": "stream_event",
                        "event": {"type": "content_block_delta",
                                  "delta": {"type": "text_delta", "text": "x"}}})
        self.assertNotIn("streamed", self.call("claude-stream-json", line)[0])

    def test_other_stream_events_give_no_item(self):
        cases = [{"type": "stream_event"},
                 {"type": "stream_event", "event": "nope"},
                 {"type": "stream_event", "event": {"type": "message_start"}},
                 {"type": "stream_event", "event": {"type": "content_block_delta"}},
                 {"type": "stream_event", "event": {"type": "content_block_delta", "delta": "text"}},
                 {"type": "stream_event", "event": {"type": "content_block_delta",
                                                    "delta": {"type": "thinking_delta", "text": "x"}}},
                 {"type": "stream_event", "event": {"type": "content_block_delta",
                                                    "delta": {"type": "text_delta", "text": 5}}}]
        for payload in cases:
            self.assertEqual(self.call("claude-stream-json", line_of(payload)), [], line_of(payload))

    def test_assistant_answer_not_streamed(self):
        line = line_of({"type": "assistant", "message": {"content": [{"type": "text", "text": "Done."}]}})
        self.assertEqual(self.call("claude-stream-json", line),
                         [{"kind": "answer", "text": "Done.", "streamed": False}])

    def test_assistant_answer_filters_control(self):
        line = line_of({"type": "assistant",
                        "message": {"content": [{"type": "text", "text": "\x1b[31mred\x1b[0m"}]}})
        self.assertEqual(self.call("claude-stream-json", line),
                         [{"kind": "answer", "text": "[31mred[0m", "streamed": False}])

    def test_assistant_skips_other_blocks(self):
        line = line_of({"type": "assistant",
                        "message": {"content": [{"type": "thinking", "thinking": "hmm"},
                                                "junk",
                                                {"type": "tool_use"},
                                                {"type": "text", "text": "ok"},
                                                {"type": "text", "text": 7}]}})
        self.assertEqual(self.call("claude-stream-json", line),
                         [{"kind": "answer", "text": "ok", "streamed": False}])

    def test_assistant_bad_message_no_item(self):
        for payload in ({"type": "assistant"},
                        {"type": "assistant", "message": "nope"},
                        {"type": "assistant", "message": {}},
                        {"type": "assistant", "message": {"content": "nope"}},
                        {"type": "assistant", "message": {"content": {}}}):
            self.assertEqual(self.call("claude-stream-json", line_of(payload)), [], line_of(payload))


class TestClaudeStreamJsonTool(ReaderTest):
    def test_tool_use_block_gives_a_tool_label(self):
        line = line_of({"type": "assistant",
                        "message": {"content": [{"type": "tool_use", "name": "Bash",
                                                 "input": {"command": "ls -la"}}]}})
        self.assertEqual(self.call("claude-stream-json", line),
                         [{"kind": "tool", "label": "[tool Bash] ls -la"}])

    def test_label_first_present_field(self):
        cases = [({"command": "c", "file_path": "f"}, "[tool X] c"),
                 ({"file_path": "f", "pattern": "p"}, "[tool X] f"),
                 ({"pattern": "p", "path": "q"}, "[tool X] p"),
                 ({"path": "q", "url": "u"}, "[tool X] q"),
                 ({"url": "u"}, "[tool X] u"),
                 ({}, "[tool X] "),
                 ({"command": 5, "file_path": "f"}, "[tool X] f")]
        for tool_input, label in cases:
            line = line_of({"type": "assistant",
                            "message": {"content": [{"type": "tool_use", "name": "X",
                                                     "input": tool_input}]}})
            self.assertEqual(self.call("claude-stream-json", line), [{"kind": "tool", "label": label}],
                             line_of(tool_input))

    def test_label_cuts_command_to_100(self):
        line = line_of({"type": "assistant",
                        "message": {"content": [{"type": "tool_use", "name": "Bash",
                                                 "input": {"command": "x" * 150}}]}})
        self.assertEqual(self.call("claude-stream-json", line),
                         [{"kind": "tool", "label": "[tool Bash] " + "x" * 100}])

    def test_label_control_becomes_space(self):
        line = line_of({"type": "assistant",
                        "message": {"content": [{"type": "tool_use", "name": "Bash",
                                                 "input": {"command": "a\tb\x00c\nd"}}]}})
        self.assertEqual(self.call("claude-stream-json", line),
                         [{"kind": "tool", "label": "[tool Bash] a b c d"}])

    def test_tool_use_nonstring_name_skipped(self):
        line = line_of({"type": "assistant",
                        "message": {"content": [{"type": "tool_use", "name": 5,
                                                 "input": {"command": "ls"}}]}})
        self.assertEqual(self.call("claude-stream-json", line), [])

    def test_tool_use_bad_input_still_labels(self):
        for tool_input in ("nope", None, 7):
            line = line_of({"type": "assistant",
                            "message": {"content": [{"type": "tool_use", "name": "Bash",
                                                     "input": tool_input}]}})
            self.assertEqual(self.call("claude-stream-json", line),
                             [{"kind": "tool", "label": "[tool Bash] "}], repr(tool_input))


class TestClaudeStreamJsonResult(ReaderTest):
    def test_result_gives_cost_error_denials(self):
        line = line_of({"type": "result", "total_cost_usd": 0.25, "is_error": False,
                        "permission_denials": [{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}]})
        self.assertEqual(self.call("claude-stream-json", line),
                         [{"kind": "result", "cost": 0.25, "error": False,
                           "denials": ["[denied Bash] rm -rf /"]}])

    def test_result_no_fields_defaults(self):
        self.assertEqual(self.call("claude-stream-json", line_of({"type": "result"})),
                         [{"kind": "result", "cost": None, "error": False, "denials": []}])

    def test_cost_none_for_bool_string_nan(self):
        for total_cost_usd in (True, False, "1.5", float("nan"), float("inf"), float("-inf"), {"a": 1}, None):
            line = line_of({"type": "result", "total_cost_usd": total_cost_usd})
            self.assertEqual(self.call("claude-stream-json", line),
                             [{"kind": "result", "cost": None, "error": False, "denials": []}],
                             line_of(total_cost_usd))

    def test_cost_float_for_finite_number(self):
        for total_cost_usd, cost in ((0.25, 0.25), (3, 3.0), (0, 0.0), (-1.5, -1.5)):
            line = line_of({"type": "result", "total_cost_usd": total_cost_usd})
            items = self.call("claude-stream-json", line)
            self.assertEqual(items, [{"kind": "result", "cost": cost, "error": False, "denials": []}], line)
            self.assertIsInstance(items[0]["cost"], float, line)

    def test_error_true_only_for_true(self):
        for is_error, error in ((True, True), ("true", False), (1, False), ([], False), (None, False)):
            line = line_of({"type": "result", "is_error": is_error})
            items = self.call("claude-stream-json", line)
            self.assertEqual(items, [{"kind": "result", "cost": None, "error": error, "denials": []}], line)
            self.assertIsInstance(items[0]["error"], bool, line)

    def test_denials_skip_wrong_shape(self):
        line = line_of({"type": "result", "permission_denials":
                        [{"tool_name": "Bash", "tool_input": {"command": "x"}},
                         {"tool_name": "Read", "tool_input": {"file_path": "f"}},
                         {"tool_name": "Bash"},
                         {"tool_input": {"command": "y"}},
                         {"tool_name": 5, "tool_input": {"command": "z"}},
                         "junk", None, []]})
        self.assertEqual(self.call("claude-stream-json", line),
                         [{"kind": "result", "cost": None, "error": False,
                           "denials": ["[denied Bash] x", "[denied Read] f"]}])

    def test_denials_wrong_type_empty_list(self):
        for denials in ("nope", {"a": 1}, 7, None):
            line = line_of({"type": "result", "permission_denials": denials})
            self.assertEqual(self.call("claude-stream-json", line),
                             [{"kind": "result", "cost": None, "error": False, "denials": []}], repr(denials))

    def test_denial_label_cuts_to_100(self):
        line = line_of({"type": "result", "permission_denials":
                        [{"tool_name": "Bash", "tool_input": {"command": "b" * 150}}]})
        self.assertEqual(self.call("claude-stream-json", line),
                         [{"kind": "result", "cost": None, "error": False,
                           "denials": ["[denied Bash] " + "b" * 100]}])

    def test_denial_label_control_to_space(self):
        line = line_of({"type": "result", "permission_denials":
                        [{"tool_name": "Bash", "tool_input": {"command": "a\tb"}}]})
        self.assertEqual(self.call("claude-stream-json", line),
                         [{"kind": "result", "cost": None, "error": False,
                           "denials": ["[denied Bash] a b"]}])


class TestClaudeStreamJsonRaw(ReaderTest):
    def test_not_json_gives_raw_item(self):
        self.assertEqual(self.call("claude-stream-json", "not json at all"),
                         [{"kind": "raw", "text": "not json at all"}])

    def test_nonobject_json_gives_raw(self):
        for line in ("[1, 2, 3]", '"a string"', "42", "null", "true", "{}"):
            self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": line}], line)

    def test_other_type_gives_raw_item(self):
        line = line_of({"type": "user", "message": {"content": []}})
        self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": line}])

    def test_object_no_type_gives_raw(self):
        line = line_of({"hello": "world"})
        self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": line}])

    def test_blank_line_gives_no_item(self):
        for line in ("", "   ", "\t", "\n", " \t \n "):
            self.assertEqual(self.call("claude-stream-json", line), [], repr(line))

    def test_raw_text_cut_to_200(self):
        self.assertEqual(self.call("claude-stream-json", "z" * 500), [{"kind": "raw", "text": "z" * 200}])

    def test_raw_text_control_to_space(self):
        self.assertEqual(self.call("claude-stream-json", "a\tb\x00c"), [{"kind": "raw", "text": "a b c"}])

    def test_raw_escape_sequence_inert(self):
        self.assertEqual(self.call("claude-stream-json", "\x1b]0;pwn\x07tail"),
                         [{"kind": "raw", "text": " ]0;pwn tail"}])

    def test_raw_c1_becomes_space(self):
        self.assertEqual(self.call("claude-stream-json", '{"type":"x","z":"a\u0085"}'),
                         [{"kind": "raw", "text": '{"type":"x","z":"a "}'}])

    def test_nested_200_gives_raw_item(self):
        line = '{"a":' * 200 + "1" + "}" * 200
        self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": line[:200]}])

    def test_deep_nesting_gives_raw_item(self):
        line = "[" * 1200 + "]" * 1200
        self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": "[" * 200}])

    def test_hundred_k_line_raw_cut_200(self):
        self.assertEqual(self.call("claude-stream-json", "q" * 100000), [{"kind": "raw", "text": "q" * 200}])


class TestItemShapes(ReaderTest):
    def test_items_only_documented_keys(self):
        cases = [(self.call("text", "x"), {"kind", "text"}),
                 (self.call("claude-stream-json", line_of({"type": "system", "subtype": "init",
                                                           "permissionMode": "plan"})), {"kind", "mode"}),
                 (self.call("claude-stream-json", line_of({"type": "stream_event", "event": {
                     "type": "content_block_delta", "delta": {"type": "text_delta", "text": "x"}}})),
                  {"kind", "text"}),
                 (self.call("claude-stream-json", line_of({"type": "assistant", "message": {"content": [
                     {"type": "text", "text": "x"}]}})), {"kind", "text", "streamed"}),
                 (self.call("claude-stream-json", line_of({"type": "assistant", "message": {"content": [
                     {"type": "tool_use", "name": "Bash", "input": {"command": "ls"}}]}})), {"kind", "label"}),
                 (self.call("claude-stream-json", line_of({"type": "result"})),
                  {"kind", "cost", "error", "denials"}),
                 (self.call("claude-stream-json", "nope"), {"kind", "text"})]
        for items, keys in cases:
            self.assertEqual(set(items[0]), keys, items)

    def test_answer_and_delta_differ(self):
        delta = self.call("claude-stream-json", line_of({"type": "stream_event", "event": {
            "type": "content_block_delta", "delta": {"type": "text_delta", "text": "same"}}}))[0]
        whole = self.call("claude-stream-json", line_of({"type": "assistant", "message": {"content": [
            {"type": "text", "text": "same"}]}}))[0]
        self.assertEqual(delta["text"], whole["text"])
        self.assertIs(whole["streamed"], False)
        self.assertNotIn("streamed", delta)


class TestReaderNames(ReaderTest):
    def test_unknown_name_raises_value_error(self):
        for name in ("vendor-json", "", "Text", "claude_stream_json", None, 7, ["text"]):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self.read(name, "x")

    def test_credential_name_not_repeated(self):
        token = "sk-" + "A" * 40
        with self.assertRaises(ValueError) as raised:
            self.read(token, "x")
        self.assertNotIn(token, str(raised.exception))
        self.assertNotIn("A" * 40, str(raised.exception))

    def test_the_two_named_readers_are_accepted(self):
        self.assertEqual(self.call("text", "x"), [{"kind": "answer", "text": "x"}])
        self.assertEqual(self.call("claude-stream-json", "x"), [{"kind": "raw", "text": "x"}])


class TestNeverRaises(ReaderTest):
    def test_no_str_line_gives_a_traceback(self):
        lines = ["", " ", "\x00", "\x00" * 500, "\ud800", "not json", "[", "{\"a\":", "null", "1e999",
                 '{"type":', line_of({"type": None}), line_of({"type": 5}),
                 line_of({"type": "system"}), line_of({"type": "system", "subtype": 5}),
                 line_of({"type": "stream_event", "event": {"type": "content_block_delta",
                                                            "delta": {"type": "text_delta", "text": "\ud800"}}}),
                 line_of({"type": "assistant", "message": {"content": [None, 1, "s", {}]}}),
                 line_of({"type": "result", "total_cost_usd": "x", "is_error": "yes",
                          "permission_denials": [None, {}, {"tool_name": None}]}),
                 '{"a":' * 900 + "1" + "}" * 900, "[" * 900 + "]" * 900, "q" * 100000,
                 "\x1b" * 1000, "\u0080\u009f" * 100, "\t\n\r\x0b\x0c"]
        for name in ("text", "claude-stream-json"):
            for line in lines:
                items = self.call(name, line)
                self.assertIsInstance(items, list)
                for item in items:
                    if item["kind"] == "answer":
                        self.assertIsInstance(item["text"], str)
                        self.assertNotIn("\x00", item["text"])
                        self.assertNotIn("\x1b", item["text"])
                    if item["kind"] == "raw":
                        self.assertLessEqual(len(item["text"]), 200)
                        self.assertNotIn("\x1b", item["text"])


class TestGuardsOfTheReader(ReaderTest):
    """The two guards that no other test reaches (review finding F3): a JSON integer that no float can hold, and nesting
    deeper than the interpreter's recursion limit. Each test fails with its guard removed: the reader then raises for a
    str line, against its contract."""

    def test_huge_integer_cost_is_no_cost(self):
        line = line_of({"type": "result", "total_cost_usd": 10 ** 400, "is_error": False, "permission_denials": []})
        self.assertEqual(self.call("claude-stream-json", line),
                         [{"kind": "result", "cost": None, "error": False, "denials": []}])

    def test_deep_list_gives_raw_item(self):
        line = "[" * 100000 + "]" * 100000
        self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": "[" * 200}])

    def test_deep_assistant_gives_raw_item(self):
        line = '{"type": "assistant", "message": ' * 100000 + "1" + "}" * 100000
        self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": line[:200]}])


def bookkeeping(subtype, **fields):
    """A `system` line of the shape that a real session prints, with made-up values (the real trial of attach)."""
    return dict({"type": "system", "subtype": subtype, "session_id": "sess-made-up", "uuid": "uuid-made-up"}, **fields)


def rate_limit(status):
    return {"type": "rate_limit_event", "rate_limit_info": {"status": status, "rateLimitType": "five_hour"},
            "uuid": "uuid-made-up", "session_id": "sess-made-up"}


def tool_result(content, error=False):
    return {"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "content": content, "is_error": error, "tool_use_id": "toolu_made_up"}]},
            "parent_tool_use_id": None, "session_id": "sess-made-up", "uuid": "uuid-made-up"}


class TestRealTrialShapes(ReaderTest):
    """What a real Claude Code session prints besides the lines the reader reads. The real trial of attach showed about
    fifty such lines in three turns, each one a raw line on the screen. The agent program's own bookkeeping gives no item
    (as `stream_event` does not), a notification gives a `notice` (what the program wants the person to see), a rate limit
    that is anything but `allowed` stays raw (it may be a refusal), and so does everything that is not known. Every line
    here is made up, of the shape of a real one."""

    def call(self, name, line):
        items = self.read(name, line)
        self.assertIsInstance(items, list, "read(%r, ...) must return a list" % (name,))
        for item in items:
            self.assertIsInstance(item, dict)
            self.assertIn(item.get("kind"), KINDS + ("notice",), "unknown kind in %r" % (items,))
        return items

    def test_bookkeeping_lines_give_no_item(self):
        cases = [bookkeeping("hook_started", hook_id="hook-made-up", hook_name="Made:up", hook_event="MadeUp"),
                 bookkeeping("hook_response", hook_id="hook-made-up", hook_name="Made:up", hook_event="MadeUp",
                             output="made-up hook output", exit_code=0, outcome="success"),
                 bookkeeping("ui_invalidate", event="ui.render"),
                 bookkeeping("status", status="requesting"),
                 bookkeeping("thinking_tokens", estimated_tokens=50, estimated_tokens_delta=50),
                 bookkeeping("task_started", task_id="task-made-up", description="a made-up task",
                             task_type="local_bash", is_backgrounded=False),
                 bookkeeping("task_notification", task_id="task-made-up", status="failed", summary="a made-up summary",
                             output_file="")]
        for payload in cases:
            self.assertEqual(self.call("claude-stream-json", line_of(payload)), [], payload["subtype"])

    def test_allowed_rate_limit_gives_no_item(self):
        self.assertEqual(self.call("claude-stream-json", line_of(rate_limit("allowed"))), [])

    def test_other_rate_limits_stay_raw(self):
        cases = [rate_limit("rejected"), rate_limit("allowed_warning"), rate_limit(None), rate_limit(5),
                 {"type": "rate_limit_event"},
                 {"type": "rate_limit_event", "rate_limit_info": None},
                 {"type": "rate_limit_event", "rate_limit_info": "allowed"},
                 {"type": "rate_limit_event", "rate_limit_info": ["allowed"]},
                 {"type": "rate_limit_event", "rate_limit_info": {}}]
        for payload in cases:
            line = line_of(payload)
            self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": line}], line)

    def test_tool_result_user_line_no_item(self):
        # A result that is not an error. (The first case was an `is_error: true` result until delta review 4: such a
        # result is shown now, see test_error_tool_result_gives_a_label; here its place is a result with no `is_error`.)
        no_flag = tool_result("made-up tool output")
        del no_flag["message"]["content"][0]["is_error"]
        cases = [no_flag, tool_result("made-up tool output"),
                 tool_result([{"type": "text", "text": "made-up tool output"}])]
        for payload in cases:
            self.assertEqual(self.call("claude-stream-json", line_of(payload)), [], line_of(payload))

    def test_other_user_lines_stay_raw(self):
        cases = [{"type": "user"}, {"type": "user", "message": "text"},
                 {"type": "user", "message": {"role": "user", "content": "made-up text"}},
                 {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": "made-up text"}]}},
                 {"type": "user", "message": {"role": "user", "content": [None, 1, "s"]}}]
        for payload in cases:
            line = line_of(payload)
            self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": line}], line)

    def test_notification_gives_a_notice(self):
        line = line_of(bookkeeping("notification", key="made-up-key", text="Made-up notice: press x to see",
                                   priority="immediate"))
        self.assertEqual(self.call("claude-stream-json", line),
                         [{"kind": "notice", "text": "Made-up notice: press x to see"}])

    def test_notice_text_is_inert_and_cut(self):
        long_text = line_of(bookkeeping("notification", key="made-up-key", text="n" * 300))
        self.assertEqual(self.call("claude-stream-json", long_text), [{"kind": "notice", "text": "n" * 100}])
        controls = line_of(bookkeeping("notification", key="made-up-key", text="a\x1b[2Jb\x07c\nd\te"))
        self.assertEqual(self.call("claude-stream-json", controls), [{"kind": "notice", "text": "a [2Jb c d e"}])

    def test_notification_no_text_stays_raw(self):
        for text in (None, "", 5, ["made-up"], {"made": "up"}):
            line = line_of(bookkeeping("notification", key="made-up-key", text=text))
            self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": line}], repr(text))
        line = line_of(bookkeeping("notification", key="made-up-key"))
        self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": line}])

    def test_what_is_not_known_stays_raw(self):
        cases = [bookkeeping("made_up_subtype", detail="made-up"), {"type": "system"}, {"type": "system", "subtype": 5},
                 {"type": "system", "subtype": ["status"]}, {"type": "system", "subtype": None},
                 {"type": "made_up_type", "detail": "made-up"}]
        for payload in cases:
            line = line_of(payload)
            self.assertEqual(self.call("claude-stream-json", line), [{"kind": "raw", "text": line}], line)

    def test_the_text_reader_is_unchanged(self):
        line = line_of(bookkeeping("hook_started", hook_id="hook-made-up"))
        self.assertEqual(self.call("text", line), [{"kind": "answer", "text": line}])

    # Delta review 4. A hook that fails reaches the person (G1), and so does a tool that fails (N-k).

    def hook_response(self, **fields):
        return line_of(bookkeeping("hook_response", hook_id="hook-made-up", hook_event="MadeUp", output="made-up output",
                                   stdout="", stderr="made-up stderr", **fields))

    def test_failed_hook_response_is_a_notice(self):
        line = self.hook_response(hook_name="Made:up", outcome="error", exit_code=1)
        self.assertEqual(self.call("claude-stream-json", line), [{"kind": "notice", "text": "hook Made:up: error (exit 1)"}])

    def test_hook_response_names_what_it_has(self):
        cases = [({"hook_name": "Made:up", "outcome": "cancelled"}, "hook Made:up: cancelled"),
                 ({"hook_name": "Made:up", "exit_code": 2}, "hook Made:up (exit 2)"),
                 ({"hook_name": "Made:up", "outcome": "success", "exit_code": 3}, "hook Made:up: success (exit 3)"),
                 ({"hook_name": "Made:up", "exit_code": 0}, "hook Made:up (exit 0)"),
                 ({"outcome": "error", "exit_code": 1}, "hook: error (exit 1)"),
                 ({"hook_name": 5, "outcome": "error", "exit_code": "1"}, "hook: error"),
                 ({"hook_name": "Made:up", "outcome": None, "exit_code": True}, None),
                 ({"hook_name": "Made:up", "outcome": 5, "exit_code": 1.5}, None),
                 ({"hook_name": "Made:up", "outcome": ["error"], "exit_code": "1"}, None),
                 ({"hook_name": "Made:up"}, None)]
        for fields, text in cases:
            line = self.hook_response(**fields)
            expected = [{"kind": "notice", "text": text}] if text is not None else [{"kind": "raw", "text": line[:200]}]
            self.assertEqual(self.call("claude-stream-json", line), expected, repr(fields))

    def test_hook_response_text_inert_and_cut(self):
        cut = self.hook_response(hook_name="Made:up", outcome="e" * 300, exit_code=1)
        self.assertEqual(self.call("claude-stream-json", cut),
                         [{"kind": "notice", "text": ("hook Made:up: " + "e" * 300 + " (exit 1)")[:100]}])
        controls = self.hook_response(hook_name="Ma\x1b[2Jde", outcome="er\x07ror", exit_code=1)
        self.assertEqual(self.call("claude-stream-json", controls),
                         [{"kind": "notice", "text": "hook Ma [2Jde: er ror (exit 1)"}])

    def test_successful_hook_response_no_item(self):
        for fields in ({"outcome": "success", "exit_code": 0}, {"outcome": "success"},
                       {"hook_name": "Made:up", "outcome": "success", "exit_code": 0}):
            self.assertEqual(self.call("claude-stream-json", self.hook_response(**fields)), [], repr(fields))

    def test_hook_started_stays_dropped(self):
        line = line_of(bookkeeping("hook_started", hook_id="hook-made-up", hook_name="Made:up", hook_event="MadeUp"))
        self.assertEqual(self.call("claude-stream-json", line), [])

    def test_error_tool_result_gives_a_label(self):
        label = [{"kind": "tool", "label": "[tool error] made-up error text"}]
        self.assertEqual(self.call("claude-stream-json", line_of(tool_result("made-up error text", error=True))), label)
        listed = tool_result([{"type": "image", "source": "made-up"}, {"type": "text", "text": "made-up error text"},
                              {"type": "text", "text": "a second block"}], error=True)
        self.assertEqual(self.call("claude-stream-json", line_of(listed)), label)
        cut = tool_result("c" * 300, error=True)
        self.assertEqual(self.call("claude-stream-json", line_of(cut)), [{"kind": "tool", "label": "[tool error] " + "c" * 100}])
        controls = tool_result("a\x1b[2Jb\x07c\nd", error=True)
        self.assertEqual(self.call("claude-stream-json", line_of(controls)),
                         [{"kind": "tool", "label": "[tool error] a [2Jb c d"}])

    def test_error_tool_result_no_text(self):
        for content in (None, "", [], [{"type": "image"}], [None, 1, "s"], 5, {"text": "made-up"}):
            self.assertEqual(self.call("claude-stream-json", line_of(tool_result(content, error=True))),
                             [{"kind": "tool", "label": "[tool error] "}], repr(content))

    def test_one_label_for_one_error_line(self):
        blocks = [{"type": "tool_result", "content": "made-up fine", "is_error": False, "tool_use_id": "toolu_made_up"},
                  {"type": "tool_result", "content": "made-up first error", "is_error": True, "tool_use_id": "toolu_made_up"},
                  {"type": "tool_result", "content": "made-up second error", "is_error": True, "tool_use_id": "toolu_made_up"}]
        payload = {"type": "user", "message": {"role": "user", "content": blocks}}
        self.assertEqual(self.call("claude-stream-json", line_of(payload)),
                         [{"kind": "tool", "label": "[tool error] made-up first error"}])

    def test_only_true_is_an_error_flag(self):
        for flag in (False, None, "true", 1, "yes", []):
            result = tool_result("made-up output", error=flag)
            self.assertEqual(self.call("claude-stream-json", line_of(result)), [], repr(flag))


if __name__ == "__main__":
    unittest.main()
