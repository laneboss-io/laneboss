"""The resident search: `laneboss decisions serve` keeps the store's indexes in memory and answers searches over a
Unix socket.

Black box. Every test starts the real command as a process, talks to it over a real socket or with `curl`, changes
the real store with the real commands, and compares what it gets with what `laneboss decisions search` prints for the
same store. The embedding provider is a third party that a test machine cannot use, so a local stand-in answers in its
place (serving.EmbeddingStub); it is the only thing here that is not the real system.

Each test says in its docstring what makes it fail.
"""

import ast
import json
import math
import operator
import os
from pathlib import Path
import random
import re
import shutil
import signal
import socket
import sqlite3
import stat
import statistics
import struct
import subprocess
import sys
import threading
import time
import types
import unittest
from collections import OrderedDict
from contextlib import closing
from unittest import mock
from urllib.parse import urlencode

from . import serving
from .serving import (
    DIMENSION, MODEL, ServeCase, UnixConnection, inet_sockets, search_params, search_words, semantic_vector,
)
from .support import FAULTS, ROOT, ids, plain_record

try:
    from math import sumprod
except ImportError:  # Python before 3.12
    def sumprod(left, right):
        return sum(map(operator.mul, left, right))


def tearDownModule():
    serving.release_fixture()


KEYWORD_QUERIES = (
    "deployment", "billing rollout", "approve", "ab", "不要動", "可以", "straße", "STRASSE", 'release "blocked"',
    "deployment deployment", "zzzzqq", "vendor contract renewal", "é", "keep the audit log untouched", "100%", "a+b",
    "x&y=z", "#hash", "line one\nline two", "😀 smile", "Should we", "  deployment  approve ",
)
EXACT_QUERIES = ("", "D-07", "d-07", "D-99", "D-41")
SEMANTIC_QUERIES = (
    "Should we approve the deployment for the alpha team before the review 3?",
    "billing rollout depends on the invoice export",
    "Identical question about vendor contract renewal",
    "完全無關的句子 about nothing at all",
    "backup schedule",
    "Strasse",
)
FILTERS = (
    {}, {"limit": 3}, {"limit": 1}, {"project": "beta"}, {"area": "security", "limit": 5}, {"kind": "decision"},
    {"topic": "alpha"}, {"all": True}, {"status": ["withdrawn"]}, {"status": ["in_force", "fulfilled"], "limit": 7},
    {"date_from": "2026-10-12", "date_to": "2026-10-15"}, {"date_from": "2026-10-09T05:00:00+08:00"},
    {"id": "D-07"}, {"all": True, "limit": 100},
)


def equivalence_cases():
    cases = []
    for index, query in enumerate(KEYWORD_QUERIES):
        for shift in (0, 5, 9):
            cases.append((query, "keyword", FILTERS[(index + shift) % len(FILTERS)]))
    for index, query in enumerate(EXACT_QUERIES):
        for shift in (0, 3, 7, 11):
            cases.append((query, "exact", FILTERS[(index + shift) % len(FILTERS)]))
    for mode in ("vector", "hybrid"):
        for index, query in enumerate(SEMANTIC_QUERIES):
            for shift in (0, 2, 6, 10):
                cases.append((query, mode, FILTERS[(index + shift) % len(FILTERS)]))
    return cases


def shortcut_cosine(query_vector, vector):
    """The cosine by the faster route that a resident search is tempted to take: both vectors scaled to length 1
    once, then one exact dot product. It is as good a cosine as any, and not the same floating-point number."""
    query_length = math.sqrt(sum(number * number for number in query_vector))
    length = math.sqrt(sum(number * number for number in vector))
    return max(-1.0, min(1.0, sumprod([number / query_length for number in query_vector],
                                      [number / length for number in vector])))


class EquivalenceTest(ServeCase):
    """The served answer is the command's answer: the same bytes."""

    def test_answers_equal_the_commands(self):
        """More than a hundred searches over every mode, with filters and limits, odd characters and short terms:
        the served bytes are the command's bytes. Fails on any difference in records, order, scores or fields, and
        when too many searches find nothing for the comparison to mean anything."""
        server = self.serve()
        answered = dict.fromkeys(("exact", "keyword", "vector", "hybrid"), 0)
        cut = 0
        for query, mode, options in equivalence_cases():
            with self.subTest(query=query, mode=mode, options=options):
                hits = self.both(server, query, mode, **options)
                if hits:
                    answered[mode] += 1
                if len(hits) == options.get("limit"):
                    cut += 1
        # A comparison of two empty answers proves nothing: most searches must have found something, in every mode.
        for mode, count in answered.items():
            self.assertGreaterEqual(count, 8, "too few searches found anything in {} mode: {}".format(mode, answered))
        self.assertGreaterEqual(cut, 5, "too few searches were cut by their limit: {}".format(cut))

    def test_scores_are_bit_for_bit_equal(self):
        """Vector scores are floating-point numbers printed in full. A search that takes the faster route of
        shortcut_cosine ranks the same records but prints scores that differ in their last digits. This test shows
        that the route does differ from the command's, so that the byte comparison is one that could fail. Fails
        when the served scores are not the command's, and when the shortcut gives the command's scores exactly."""
        server = self.serve()
        stored = {}
        with closing(sqlite3.connect(str(self.db))) as connection:
            for record_id, which, blob in connection.execute("SELECT record_id, which_text, vector FROM vectors"):
                stored[(record_id, which)] = struct.unpack("<{}f".format(DIMENSION), blob)
        compared = differing = 0
        for query in SEMANTIC_QUERIES:
            hits = self.both(server, query, "vector", limit=15)
            query_vector = semantic_vector(query)
            for hit in hits:
                for match in hit["matches"]:
                    shortcut = shortcut_cosine(query_vector, stored[(hit["record"]["id"], match["field"])])
                    compared += 1
                    if repr(shortcut) != repr(match["score"]):
                        differing += 1
        self.assertGreater(compared, 100)
        self.assertGreater(differing, 0, "the shortcut formula gave the command's scores exactly in all {} "
                           "comparisons: the byte comparison could not tell the two routes apart".format(compared))

    def test_errors_are_the_commands_errors(self):
        """A refused search gets the command's message and exit code (HTTP 400 and X-Exit-Code 2 here). Fails when
        the status, the code or the text differ, or when a mistake in a parameter is answered with a search."""
        server = self.serve()
        cases = (
            ("deployment", "keyword", {"date_from": "2026-13-45"}),
            ("deployment", "keyword", {"date_from": "2026-10-12", "date_to": "2026-10-10"}),
            ("deployment", "keyword", {"date_to": "not a date"}),
            (" ", "vector", {}),
            ("   ", "hybrid", {}),
        )
        for query, mode, options in cases:
            with self.subTest(query=query, mode=mode, options=options):
                command = self.search_command(query, mode, **options)
                reply = server.search(query, mode, **options)
                self.assertEqual(command.returncode, 2)
                self.assertEqual((reply.status, reply.exit_code), (400, 2), reply.body)
                self.assertEqual(reply.body, command.stderr)
        # Mistakes the command's own parser refuses: the same exit code, the same kind of message.
        for options in ({"mode": "fuzzy"}, {"limit": 0}, {"limit": "many"}, {"kind": "rumour"},
                        {"status": ["pending"]}):
            with self.subTest(options=options):
                command = self.run_command("search", *search_words("deployment", **options))
                reply = server.search("deployment", **options)
                self.assertEqual(command.returncode, 2)
                self.assertEqual((reply.status, reply.exit_code), (400, 2), reply.body)
                self.assertTrue(reply.text().startswith("invalid input: "), reply.text())
        reply = server.get("/search", [("query", "a\x00b")])
        self.assertEqual((reply.status, reply.exit_code), (400, 2))
        self.assertEqual(reply.text(), "invalid input: query must be text without NUL\n")

    def test_ties_keep_their_order(self):
        """Three records say exactly the same, so their vectors tie and the order is by id. The ranking keeps that,
        in vector and in hybrid mode, with and without a limit that cuts the tie. Fails when a tie is broken
        differently from the command, or when a shortcut in scoring lets a last-digit difference reorder it."""
        server = self.serve()
        query = "Identical question about vendor contract renewal"
        for mode in ("vector", "hybrid"):
            for options in ({}, {"limit": 1}, {"limit": 2}, {"limit": 3}, {"project": "gamma"}):
                with self.subTest(mode=mode, options=options):
                    hits = self.both(server, query, mode, **options)
                    tied = [identifier for identifier in ids(hits) if identifier in ("D-41", "D-42", "D-43")]
                    self.assertEqual(tied, sorted(tied))
                    if not options:
                        self.assertEqual(tied, ["D-41", "D-42", "D-43"])


SIDES = {"q_text": "question", "d_text": "decision"}


class RankingTest(unittest.TestCase):
    """The ranking of the resident search against the arithmetic of the command, on vectors made to tie or nearly."""

    def setUp(self):
        source = str(ROOT / "src")
        sys.path.insert(0, source)
        self.addCleanup(sys.path.remove, source)
        from laneboss.decisions import resident
        self.resident = resident

    @staticmethod
    def command_ranking(model, groups, query_vector):
        """What the command does with these vectors, written out again: score each, group by record, rank."""
        query_norm = math.sqrt(sum(number * number for number in query_vector))
        matches = []
        for identifier, entries in groups.items():
            for entry in entries:
                norm = math.sqrt(sum(number * number for number in entry.vector))
                score = sum(left * right for left, right in zip(query_vector, entry.vector)) / (query_norm * norm)
                matches.append({"id": identifier, "index": "vector:" + model, "text": SIDES[entry.side],
                                "field": entry.side, "score": max(-1.0, min(1.0, score))})
        matches.sort(key=lambda match: (-match["score"], match["id"], match["text"]))
        grouped = {}
        for match in matches:
            grouped.setdefault(match["id"], []).append(match)
        return sorted(grouped, key=lambda identifier: (-grouped[identifier][0]["score"], identifier)), grouped

    def groups(self, rng, dimension, count):
        """Records whose vectors are copies of a few base vectors, or those times 3 or 2 (the same direction, a
        different last digit), or moved by 1e-13, or negated, or new."""
        bases = [[rng.gauss(0.0, 1.0) for _ in range(dimension)] for _ in range(max(2, count // 3))]
        groups = {}
        for number in range(count):
            identifier = "R-{:03d}".format(number)
            entries = []
            for side in ("q_text", "d_text")[:rng.randint(1, 2)]:
                source = rng.choice(bases)
                kind = rng.choice(("copy", "copy", "times3", "times2", "nudged", "negated", "fresh"))
                if kind == "copy":
                    vector = list(source)
                elif kind == "times3":
                    vector = [value * 3.0 for value in source]
                elif kind == "times2":
                    vector = [value * 2.0 for value in source]
                elif kind == "nudged":
                    vector = [value + rng.choice((0.0, 0.0, 1e-13)) for value in source]
                elif kind == "negated":
                    vector = [-value for value in source]
                else:
                    vector = [rng.gauss(0.0, 1.0) for _ in range(dimension)]
                norm = math.sqrt(sum(value * value for value in vector))
                entries.append(self.resident.Entry(identifier, side, tuple(vector), norm))
            groups[identifier] = entries
        return groups, bases

    def trials(self, label):
        """400 random stores; returns how many adjacent pairs of the command's ranking tie exactly, and how many
        differ by less than 1e-12."""
        rng = random.Random(20261010)
        tied = near = 0
        for trial in range(400):
            dimension = rng.choice((3, 8, 33, 128))
            groups, bases = self.groups(rng, dimension, rng.randint(2, 40))
            query = rng.choice([list(rng.choice(bases)), [value + rng.gauss(0.0, 0.01) for value in rng.choice(bases)],
                                [rng.gauss(0.0, 1.0) for _ in range(dimension)]])
            expected, grouped = self.command_ranking("m", groups, query)
            best = [grouped[identifier][0]["score"] for identifier in expected]
            tied += sum(1 for left, right in zip(best, best[1:]) if left == right)
            near += sum(1 for left, right in zip(best, best[1:]) if 0 < left - right < 1e-12)
            for depth in (None, 1, 2, 7, 1000):
                ranked = self.resident.rank_vectors("m", groups, query, depth)
                shown = expected if depth is None else expected[:depth]
                with self.subTest(label=label, trial=trial, depth=depth):
                    self.assertEqual(ranked.ranking[:len(shown)], shown)
                    if depth is None:
                        self.assertEqual(len(ranked.ranking), len(expected))
                    for identifier in shown:
                        self.assertEqual(ranked.matches(identifier), grouped[identifier])
                        self.assertEqual(ranked.score(identifier), grouped[identifier][0]["score"])
        return tied, near

    def test_fast_ranking_is_the_exact_one(self):
        """On 400 random stores in which many scores tie and many differ only in the last digit, the ranking, the
        matches and the scores of the resident search are the command's, for the whole ranking and for the top 1,
        2 and 7, with the dot product of this interpreter (math.sumprod from Python 3.12) and with the sum of
        products that older interpreters use. The data is shown to hold ties and near ties. Fails when the margin
        that separates the fast scores from the command's is too small (the order of near ties is then the fast
        one), when a tie is broken another way, or when a printed score is not the command's expression."""
        for label, dot in (("this interpreter's dot product", self.resident.dot),
                           ("sum of products", self.resident.exact_dot)):
            with mock.patch.object(self.resident, "dot", dot):
                tied, near = self.trials(label)
            self.assertGreater(tied, 100, "the data holds too few exact ties")
            self.assertGreater(near, 50, "the data holds too few scores that differ only in the last digits")

    def test_exact_sums_are_the_commands_sums(self):
        """exact_dot and exact_norm give the command's numbers, bit for bit (compared as their repr), on 1500 random
        vectors of 1 to 1100 numbers with magnitudes from 1e-8 to 1e8, some of them whole numbers as a provider may
        return in place of floats. Where the interpreter has math.sumprod, the test also shows that it is not the
        same sum (it differs on many of the vectors), which is why it only orders the records and never gives a
        printed score. Fails when a printed score is made by anything but the same sum of the same products."""
        rng = random.Random(7)
        different = 0
        for trial in range(1500):
            size = rng.randint(1, 1100) if trial % 3 else rng.choice((1, 2, 3, 4, 127, 128, 1024))
            scale = 10.0 ** rng.randint(-8, 8)
            left = [rng.gauss(0.0, 1.0) * scale for _ in range(size)]
            right = [rng.gauss(0.0, 1.0) / scale for _ in range(size)]
            if trial % 11 == 0:
                left = [round(value) for value in left]
            expected = sum(first * second for first, second in zip(left, right))
            self.assertEqual(repr(self.resident.exact_dot(left, right)), repr(expected), (trial, size))
            self.assertEqual(repr(self.resident.exact_norm(left)),
                             repr(math.sqrt(sum(number * number for number in left))), (trial, size))
            if hasattr(math, "sumprod") and repr(math.sumprod(left, right)) != repr(expected):
                different += 1
        if hasattr(math, "sumprod"):
            self.assertGreater(different, 20, "math.sumprod gave the command's sum on nearly all the vectors")


class AnswerBoundsTest(unittest.TestCase):
    """The bound, in bytes, of the answers that a copy of the store remembers. A search over a store of the size that a
    test can make gives an answer of a few kilobytes, far from 16 MiB, so this calls the product's own bookkeeping with
    answers of the size that reaches the bound."""

    def setUp(self):
        source = str(ROOT / "src")
        sys.path.insert(0, source)
        self.addCleanup(sys.path.remove, source)
        from laneboss.decisions import resident
        self.resident = resident
        self.keeper = types.SimpleNamespace(answers=OrderedDict(), answers_size=0, answers_lock=threading.Lock())

    def test_answers_are_bounded_in_bytes(self):
        """Six answers of a quarter of the bound each are given: the last four are kept, the oldest went first and
        the bytes are counted. An answer given again replaces the old one and is counted once, and the next answer
        sends out the oldest again. Fails when the bytes are not bounded, when the newest goes before the oldest, or
        when a size is counted wrong."""
        remember = self.resident.Snapshot.remember_answer
        quarter = b"x" * (self.resident.ANSWER_BYTES // 4)
        for number in range(6):
            remember(self.keeper, ("search", number), quarter)
        self.assertEqual(list(self.keeper.answers), [("search", number) for number in (2, 3, 4, 5)])
        self.assertEqual(self.keeper.answers_size, 4 * len(quarter))
        remember(self.keeper, ("search", 3), b"y")
        self.assertEqual(list(self.keeper.answers), [("search", number) for number in (2, 4, 5, 3)])
        self.assertEqual(self.keeper.answers_size, 3 * len(quarter) + 1)
        remember(self.keeper, ("search", 6), quarter)
        self.assertEqual(list(self.keeper.answers), [("search", number) for number in (4, 5, 3, 6)])
        self.assertEqual(self.keeper.answers_size, 3 * len(quarter) + 1)


# The modules that the decision store imports; every one is of the standard library. A new import is added here on
# purpose.
KNOWN_STANDARD = frozenset({
    "argparse", "base64", "collections", "copy", "datetime", "errno", "hashlib", "http", "json", "math", "operator",
    "os", "pathlib", "re", "signal", "socket", "socketserver", "sqlite3", "stat", "struct", "sys", "threading", "time",
    "urllib",
})


class StandardLibraryTest(unittest.TestCase):
    def test_only_the_standard_library(self):
        """The decision store adds no third-party package: each of its modules imports the standard library and the
        package itself, and nothing else. The import statements are read from the source (nothing is run); the names
        are checked against the interpreter's own list of standard library modules where it has one (Python 3.10 and
        newer) and, everywhere, against KNOWN_STANDARD, so that a new import is added to it on purpose. Fails on any
        other import, however it is written (`import`, `from`, inside a function) and on `__import__` or
        `import_module`."""
        found = set()
        files = sorted((ROOT / "src" / "laneboss" / "decisions").glob("*.py"))
        self.assertGreater(len(files), 8)
        for path in files:
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    found.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    found.add((node.module or "").split(".")[0])
                elif isinstance(node, ast.Name) and node.id == "__import__":
                    found.add("__import__")
                elif isinstance(node, ast.Attribute) and node.attr == "import_module":
                    found.add("import_module")
        outside = found - {"laneboss"}
        listed = getattr(sys, "stdlib_module_names", None)
        if listed is not None:
            self.assertEqual(sorted(outside - set(listed)), [])
        self.assertEqual(sorted(outside - KNOWN_STANDARD), [], "a new import: add it to KNOWN_STANDARD on purpose")
        self.assertTrue({"sqlite3", "socketserver", "http"} <= found, "the check did not read the imports")


class StalenessTest(ServeCase):
    """The store changes while the server runs; the next search sees it."""

    def load(self, operations, name):
        return self.json_cli("load", "--in", self.write_batch(operations, name=name))

    def test_search_sees_load_while_serving(self):
        """A record loaded while the server runs is found by the next search, four times in a row with no pause.
        Fails when the server answers from the index it built first, or checks for changes only now and then."""
        server = self.serve()
        self.assertEqual(self.both(server, "zephyrwidget", "keyword"), [])
        expected = []
        for number in range(4):
            identifier = "N-{}".format(number)
            expected.append(identifier)
            value = plain_record(identifier, "Is zephyrwidget {} ready?".format(number),
                                 "Yes, zephyrwidget {}.".format(number))
            self.load([{"op": "add", "record": value}], "batch-{}.jsonl".format(number))
            self.assertEqual(sorted(ids(self.both(server, "zephyrwidget", "keyword"))), expected)
            self.assertEqual(ids(self.both(server, "", "exact", id=identifier)), [identifier])

    def test_supersede_and_annotate_are_seen(self):
        """A supersession (which changes an old record in place) and an annotation (which changes a record without
        adding one) are seen. Fails when the server notices only new rows."""
        server = self.serve()
        first = plain_record("S-1", "Is qvortex first?", "Yes, qvortex first.")
        self.load([{"op": "add", "record": first}], "one.jsonl")
        self.assertEqual(ids(self.both(server, "qvortex", "keyword")), ["S-1"])
        second = plain_record("S-2", "Is qvortex second?", "Yes, qvortex second.")
        self.load([{"op": "supersede", "target": "S-1", "record": second}], "two.jsonl")
        self.assertEqual(ids(self.both(server, "qvortex", "keyword")), ["S-2"])
        self.assertEqual(sorted(ids(self.both(server, "qvortex", "keyword", all=True))), ["S-1", "S-2"])
        self.json_cli("annotate", "S-2", "--file", self.file("outcome.json", {"evidence": ["proof of ximblefrost"]}))
        hits = self.both(server, "ximblefrost", "keyword")
        self.assertEqual(ids(hits), ["S-2"])
        self.assertIn("proof of ximblefrost", hits[0]["record"]["outcome"]["evidence"])

    def test_vectors_follow_embed_and_annotate(self):
        """A record has no vector until embed; an annotation makes its decision vector stale until embed again.
        The served vector search shows each state as the command does. Fails when vectors are read once."""
        server = self.serve()
        text = "Quasar telemetry uplink calibration schedule"
        self.load([{"op": "add", "record": plain_record("V-1", text, "Calibrate the quasar uplink on Tuesdays.")}],
                  "v1.jsonl")
        self.assertNotIn("V-1", ids(self.both(server, text, "vector", limit=100)))
        self.json_cli("embed", "--config", self.provider_config)
        hits = self.both(server, text, "vector")
        self.assertEqual(ids(hits)[0], "V-1")
        self.assertEqual({match["field"] for match in hits[0]["matches"]}, {"q_text", "d_text"})
        self.json_cli("annotate", "V-1", "--file", self.file("outcome.json", {"followups": ["check zorblat"]}))
        hits = self.both(server, text, "vector")
        self.assertEqual(ids(hits)[0], "V-1")
        self.assertEqual({match["field"] for match in hits[0]["matches"]}, {"q_text"})
        self.json_cli("embed", "--config", self.provider_config)
        hits = self.both(server, text, "vector")
        self.assertEqual({match["field"] for match in hits[0]["matches"]}, {"q_text", "d_text"})

    def test_replaced_store_file_is_followed(self):
        """A store file put in place of the old one by rename (a restore, say) is the store now. Fails when the
        server keeps reading the file it first opened."""
        server = self.serve()
        self.assertGreater(len(self.both(server, "deployment", "keyword")), 1)
        replacement = self.directory / "replacement.sqlite"
        self.cli("init", db=replacement)
        batch = self.write_batch([{"op": "add", "record": plain_record(
            "R-1", "Is the replacement deployment ready?", "Fresh.")}])
        self.json_cli("load", "--in", batch, db=replacement)
        os.replace(str(replacement), str(self.db))
        self.assertEqual(ids(self.both(server, "deployment", "keyword")), ["R-1"])

    def test_deleted_store_is_an_error(self):
        """A store that is gone is the command's error, not the old answers; when it is back it is served again.
        Fails when the server goes on answering from memory."""
        server = self.serve()
        self.both(server, "deployment", "keyword")
        parked = self.directory / "parked.sqlite"
        os.replace(str(self.db), str(parked))
        command = self.search_command("deployment", "keyword")
        reply = server.search("deployment")
        self.assertEqual(command.returncode, 2)
        self.assertEqual((reply.status, reply.exit_code, reply.body), (400, 2, command.stderr))
        os.replace(str(parked), str(self.db))
        self.both(server, "deployment", "keyword")

    def test_vectors_are_checked_ahead(self):
        """The vectors of the configured model are read and checked before the server says it is ready, and again in
        the background after a change, so that the first vector search does not wait for them; a server without a
        configuration holds none. Fails when the vectors are checked only when a search asks."""
        server = self.serve()
        self.assertEqual(server.status()["vector_models"], 1)
        self.load([{"op": "add", "record": plain_record("W-9", "Is the check run ahead?", "Yes.")}], "w9.jsonl")
        server.search("deployment")
        deadline = time.monotonic() + 10
        while server.status()["vector_models"] != 1 and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(server.status()["vector_models"], 1)
        bare = self.serve(config=False, socket_path=self.scratch / "bare" / "s.sock", name="bare")
        self.assertEqual(bare.status()["vector_models"], 0)

    def test_rebuild_only_for_a_real_change(self):
        """The index is built once, not per request, and not again for the egress receipt of a vector question
        (the server's own or another process's), only for a change to records, vectors or models. Fails when
        the builds counter of /status goes up for anything else, or does not go up for a new record."""
        server = self.serve()
        first = server.status()
        self.assertEqual(first["builds"], 1)
        self.assertEqual(first["records"], 47)
        for number in range(10):
            server.search("deployment")
            server.search("", "exact")
        self.assertEqual(server.status()["builds"], 1)
        query = "Should we approve the deployment for the beta team before the review 4?"
        server.search(query, "vector")
        server.search(query, "vector")
        server.search("deployment")
        self.assertEqual(server.status()["builds"], 1)
        self.search_command("billing rollout depends on the invoice export", "vector")
        server.search("deployment")
        self.assertEqual(server.status()["builds"], 1)
        self.json_cli("load", "--in", self.write_batch([{"op": "add", "record": plain_record(
            "B-1", "Is the rebuild counted?", "Yes.")}]))
        server.search("deployment")
        after = server.status()
        self.assertEqual((after["builds"], after["records"]), (2, 48))


class DamageTest(ServeCase):
    QUERY = "billing rollout depends on the invoice export"

    def same_error(self, server, query, mode, code, status, **options):
        command = self.search_command(query, mode, **options)
        reply = server.search(query, mode, **options)
        self.assertEqual(command.returncode, code, command.stderr)
        self.assertEqual((reply.status, reply.exit_code, reply.body), (status, code, command.stderr))

    def test_a_damaged_store_is_an_error(self):
        """A vector whose hashes no longer agree fails vector searches (exit 3, as the command does, before the
        provider is asked) and leaves keyword searches alone; a damaged record fails every search; a store put right
        is served again. Fails when the server answers from the copy it made before the damage, when it makes no
        copy of a damaged store, or when it goes on failing after the repair."""
        server = self.serve()
        self.both(server, "deployment", "keyword")
        self.both(server, self.QUERY, "vector")
        asked = len(self.stub.requests)
        self.tamper(("UPDATE vectors SET vector_sha256 = ? WHERE record_id = 'D-03' AND which_text = 'q_text'",
                     ("0" * 64,)))
        self.both(server, "deployment", "keyword")
        self.same_error(server, self.QUERY, "vector", 3, 500)
        self.tamper(("UPDATE records SET q_sha256 = ? WHERE id = 'D-05'", ("0" * 64,)))
        self.same_error(server, "deployment", "keyword", 3, 500)
        self.same_error(server, "", "exact", 3, 500)
        # The command looks at the dates of a search before it reads the records, so with a damaged record and a
        # wrong date it says the date is wrong (exit 2). So does the server: it meets the damage where the command does.
        self.same_error(server, "deployment", "keyword", 2, 400, date_from="2026-13-45")
        self.same_error(server, "deployment", "keyword", 2, 400, date_from="2026-10-12", date_to="2026-10-10")
        self.assertEqual(len(self.stub.requests), asked, "a question was sent from a damaged store")
        shutil.copy2(str(self.fixture_db), str(self.db))
        self.both(server, "deployment", "keyword")
        self.both(server, self.QUERY, "vector")

    def test_serve_refuses_a_damaged_store(self):
        """A store with a damaged record is not served: serve ends with exit 3 and the message that a search by the
        command gives, and makes no socket. Fails when the server starts on it, or says anything else."""
        self.tamper(("UPDATE records SET q_sha256 = ? WHERE id = 'D-05'", ("0" * 64,)))
        command = self.search_command("deployment", "keyword")
        self.assertEqual(command.returncode, 3, command.stderr)
        path = self.scratch / "run" / "s.sock"
        served = self.run_serve("--db", self.db, "--socket", path, "--config", self.provider_config)
        self.assertEqual((served.returncode, served.stderr), (3, command.stderr.decode("utf-8")))
        self.assertFalse(path.exists())


class CacheAndEgressTest(ServeCase):
    QUERY = "Should we approve the deployment for the beta team before the review 4?"

    def test_the_config_is_read_for_each_search(self):
        """The embedding configuration is read at every vector search, as the command reads it: a model that the
        store has no vectors for is the command's error (exit 2); after embed for that model the server searches
        with it, and asks the provider for it: the answer that the server remembers for the same text under the
        first model is not used for the second. The first model's vectors are searched again when the configuration
        names it again. Fails when the server keeps the configuration, or one model's vectors, for all, or when the
        remembered answers of two models are mixed up."""
        server = self.serve()
        self.both(server, self.QUERY, "vector")
        original = self.provider_config.read_text(encoding="utf-8")
        other = json.loads(original)
        other["model"] = "another-embed"
        self.provider_config.write_text(json.dumps(other), encoding="utf-8")
        command = self.search_command(self.QUERY, "vector")
        reply = server.search(self.QUERY, "vector")
        self.assertEqual(command.returncode, 2)
        self.assertEqual((reply.status, reply.exit_code, reply.body), (400, 2, command.stderr))
        self.json_cli("embed", "--config", self.provider_config)
        asked = len(self.stub.requests)
        reply = server.search(self.QUERY, "vector")
        self.assertEqual(reply.status, 200, reply.body)
        self.assertEqual([(request["body"]["model"], request["body"]["input"], request["body"]["input_type"])
                          for request in self.stub.requests[asked:]],
                         [("another-embed", [self.QUERY], "query")],
                         "the answer remembered under the first model was used for the second")
        self.assertEqual(reply.body, self.search_command(self.QUERY, "vector").stdout)
        self.assertEqual(len(json.loads(reply.body.decode("utf-8"))), 20)
        self.both(server, "backup schedule", "hybrid")
        self.provider_config.write_text(original, encoding="utf-8")
        self.both(server, self.QUERY, "vector")

    def test_a_repeated_question_is_a_hit(self):
        """The second vector question with the same text, in vector or in hybrid mode, makes no provider request and
        writes nothing to the store file; another text (a character more, another case) is another request. The
        searches that repeat the first are asked with another limit, so that the answers the server remembers
        cannot serve them and it is the remembered question that does. Fails when the provider is asked again, when
        the file changes, or when an answer differs from the command's."""
        server = self.serve()
        first = server.search(self.QUERY, "vector")
        self.assertEqual(first.status, 200)
        self.assertEqual(len(self.stub.requests), 1)
        request = self.stub.requests[0]
        self.assertEqual(request["body"]["input"], [self.QUERY])
        self.assertEqual(request["body"]["input_type"], "query")
        self.assertEqual(request["body"]["model"], MODEL)
        self.assertEqual(request["auth"], "Bearer " + self.key)
        state = self.file_state()
        again = server.search(self.QUERY, "vector", limit=7)
        shared = server.search(self.QUERY, "hybrid")
        self.assertEqual((again.status, shared.status), (200, 200))
        self.assertEqual(len(self.stub.requests), 1, "a repeated question went to the provider")
        self.assertEqual(self.file_state(), state, "a cache hit changed the store file")
        cache = server.status()["cache"]
        self.assertEqual((cache["entries"], cache["misses"], cache["hits"]), (1, 1, 2))
        server.search(self.QUERY + " Really?", "vector")
        server.search(self.QUERY.upper(), "vector")
        self.assertEqual(len(self.stub.requests), 3)
        self.assertEqual(again.body, self.search_command(self.QUERY, "vector", limit=7).stdout)
        self.assertEqual(shared.body, self.search_command(self.QUERY, "hybrid").stdout)

    # Every parameter of a search that can change its answer is in one of these, and each search comes after one that it
    # differs from in that parameter alone (and in its answer): a parameter left out of what a search is known by would
    # give it the answer of the earlier one.
    ASKED = (
        ("deployment", "keyword", {}), ("deployment", "keyword", {"limit": 3}),
        ("deployment", "keyword", {"id": "D-08"}), ("deployment", "keyword", {"project": "beta"}),
        ("deployment", "keyword", {"status": ["withdrawn"]}), ("deployment", "keyword", {"all": True}),
        ("deployment", "keyword", {"date_from": "2026-10-15"}), ("Deployment", "keyword", {}),
        ("", "exact", {}), ("", "exact", {"kind": "decision"}), ("", "exact", {"area": "ops"}),
        ("", "exact", {"topic": "alpha"}), ("", "exact", {"date_to": "2026-10-12"}), ("", "exact", {"limit": 50}),
        ("", "exact", {"limit": 50, "all": True}), ("D-07", "exact", {}), ("backup schedule", "vector", {}),
        ("backup schedule", "vector", {"limit": 2}), ("backup schedule", "hybrid", {}),
        ("Backup Schedule", "vector", {}),
    )

    def test_a_repeated_search_is_remembered(self):
        """The same search asked again is answered from the answers the server kept on its copy of the store, and
        the answer is the command's: each of twenty searches that differ from an earlier one in one parameter (the
        query, the mode, the limit, a status, an id, a project, an area, a topic, a kind, a date from, a date to,
        `all`) is asked three times and every reply equals the command's bytes. /status counts the answers kept and
        used (one miss and two hits for each), and the provider is asked once for each question text, not for each
        search. A change of the store ends the answers kept: the next search shows the new record. Fails when a
        repeated search is worked out again, when a parameter that changes the answer is left out of what a search is
        known by (a reply then answers another search), or when an answer outlives the copy it was made on."""
        server = self.serve()
        expected = [self.search_command(query, mode, **options).stdout for query, mode, options in self.ASKED]
        self.assertGreater(len(set(expected)), 12, "the searches do not differ enough for this test to mean anything")
        asked = len(self.stub.requests)
        for number in range(3):
            for (query, mode, options), wanted in zip(self.ASKED, expected):
                reply = server.search(query, mode, **options)
                self.assertEqual(reply.status, 200, reply.body)
                self.assertEqual(reply.body, wanted, (number, query, mode, options))
        count = len(self.ASKED)
        answers = server.status()["answers"]
        self.assertEqual((answers["entries"], answers["misses"], answers["hits"]), (count, count, 2 * count))
        self.assertEqual(len(self.stub.requests) - asked, 2, "the provider was asked for more than the two texts")
        record = plain_record("A-1", "Is the new deployment word in?", "Yes, the new word is in.")
        self.json_cli("load", "--in", self.write_batch([{"op": "add", "record": record}]))
        after = server.search("deployment")
        self.assertEqual(after.body, self.search_command("deployment", "keyword").stdout)
        self.assertIn(b'"A-1"', after.body, "an answer outlived the copy of the store it was made on")
        self.assertEqual(server.status()["answers"]["entries"], 1)

    def test_the_answers_kept_are_bounded(self):
        """A copy of the store remembers at most 128 answers, the ones asked for last: a hundred and thirty different
        searches leave 128, the last of them is still remembered, and the first is worked out again when it is asked
        again. Fails when the answers kept are not bounded, or when the bound drops the newest answer instead of the
        oldest."""
        server = self.serve()
        for limit in range(1, 131):
            reply = server.search("deployment", "keyword", limit=limit)
            self.assertEqual(reply.status, 200, reply.body)
        answers = server.status()["answers"]
        self.assertEqual((answers["entries"], answers["misses"], answers["hits"]), (128, 130, 0))
        server.search("deployment", "keyword", limit=130)
        answers = server.status()["answers"]
        self.assertEqual((answers["entries"], answers["misses"], answers["hits"]), (128, 130, 1))
        server.search("deployment", "keyword", limit=1)
        answers = server.status()["answers"]
        self.assertEqual((answers["entries"], answers["misses"], answers["hits"]), (128, 131, 1))

    def test_the_cache_is_in_memory_only(self):
        """A new server asks the provider again. Fails when answers are kept in a file."""
        server = self.serve()
        server.search(self.QUERY, "vector")
        server.stop()
        server = self.serve(name="second")
        server.search(self.QUERY, "vector")
        self.assertEqual(len(self.stub.requests), 2)

    def test_receipt_comes_before_the_ask(self):
        """When the provider receives a question, the store already holds its receipt, committed, and nobody holds
        any lock on the store (the probe takes the exclusive lock at that moment). Fails when the receipt is written
        after the call, in a transaction still open, or not at all."""
        seen = []

        def observe(body):
            with closing(sqlite3.connect(str(self.db), timeout=0, isolation_level=None)) as connection:
                connection.execute("BEGIN EXCLUSIVE")
                rows = connection.execute(
                    "SELECT which_text, text, input_type, model FROM egress_log ORDER BY id DESC LIMIT 1").fetchall()
                count = connection.execute("SELECT count(*) FROM egress_log").fetchone()[0]
                connection.execute("ROLLBACK")
            seen.append((count, rows))

        server = self.serve()
        before = self.egress_count()
        self.stub.observer = observe
        reply = server.search(self.QUERY, "vector")
        self.assertEqual(reply.status, 200, reply.body)
        self.assertEqual(seen, [(before + 1, [("query", self.QUERY, "query", MODEL)])])
        self.assertEqual(self.egress_count(), before + 1)

    def test_receipt_is_the_commands_receipt(self):
        """The command and the server, on two copies of one store, write receipts that differ in nothing but the
        time and the hash that covers it. Fails on any other difference, and when the chain no longer verifies."""
        copy = self.directory / "copy.sqlite"
        shutil.copy2(str(self.db), str(copy))
        server = self.serve()
        self.assertEqual(self.search_command(self.QUERY, "vector", db=copy).returncode, 0)
        self.assertEqual(server.search(self.QUERY, "vector").status, 200)
        theirs = self.json_cli("egress", "--list", db=copy)[-1]
        ours = self.json_cli("egress", "--list")[-1]
        for entry in (theirs, ours):
            del entry["at"], entry["entry_sha256"]
        self.assertEqual(ours, theirs)
        self.assertEqual((ours["which_text"], ours["input_type"], ours["record_id"], ours["text"]),
                         ("query", "query", None, self.QUERY))
        self.assertEqual(ours["endpoint_host"], "127.0.0.1")
        self.json_cli("verify")

    def test_only_the_receipt_is_written(self):
        """A vector search and a hybrid search add one receipt and change no other table. Fails when the server
        writes anything else to the store."""
        server = self.serve()
        before = self.dump()
        self.assertEqual(server.search(self.QUERY, "vector").status, 200)
        self.assertEqual(server.search(self.QUERY, "hybrid").status, 200)
        after = self.dump()
        for table in before:
            if table != "egress_log":
                self.assertEqual(after[table], before[table], table)
        self.assertEqual(after["egress_log"][:len(before["egress_log"])], before["egress_log"])
        self.assertEqual(len(after["egress_log"]), len(before["egress_log"]) + 1)

    def test_a_failed_call_is_not_cached(self):
        """A provider failure is the command's error (exit 4, HTTP 502), leaves its receipt, and is not remembered:
        the next try asks again. Fails when a failure is cached, or leaves no receipt."""
        copy = self.directory / "copy.sqlite"
        shutil.copy2(str(self.db), str(copy))
        server = self.serve()
        self.stub.status = 503
        command = self.search_command(self.QUERY, "vector", db=copy)
        before = self.egress_count()
        reply = server.search(self.QUERY, "vector")
        self.assertEqual(command.returncode, 4)
        self.assertEqual((reply.status, reply.exit_code, reply.body), (502, 4, command.stderr))
        self.assertEqual(self.egress_count(), before + 1, "the attempt left no receipt")
        self.stub.status = None
        requests = len(self.stub.requests)
        reply = server.search(self.QUERY, "vector")
        self.assertEqual(reply.status, 200)
        self.assertEqual(len(self.stub.requests), requests + 1, "a failed question was remembered as answered")
        self.assertEqual(self.egress_count(), before + 2)
        # Asked once more, with another limit so that the remembered answer cannot serve it: the question is remembered.
        again = server.search(self.QUERY, "vector", limit=5)
        self.assertEqual(again.status, 200)
        self.assertEqual(len(self.stub.requests), requests + 1)
        self.assertEqual(self.egress_count(), before + 2)

    def test_equal_questions_share_a_request(self):
        """Two identical questions that arrive together make one provider request. Fails with two."""
        server = self.serve()
        self.stub.delay = 1.0
        replies = []
        workers = [threading.Thread(target=lambda: replies.append(server.search(self.QUERY, "vector")))
                   for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=60)
        self.assertEqual([reply.status for reply in replies], [200, 200])
        self.assertEqual(replies[0].body, replies[1].body)
        self.assertEqual(len(self.stub.requests), 1)

    def test_an_oversized_question_is_refused(self):
        """A question over the size the provider is sent at a time (24,000 bytes) is refused as the command refuses
        it (exit 4, "nothing was sent"): no receipt is written and the provider is not asked. It is sent as a POST,
        since a question of that size does not go in an address. Fails when the server writes a receipt, asks the
        provider, or says anything else."""
        server = self.serve()
        question = "word " * 6000
        command = self.search_command(question, "vector")
        before = self.egress_count()
        reply = server.ask("POST", "/search", body=urlencode(search_params(question, "vector")),
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(command.returncode, 4, command.stderr)
        self.assertIn(b"nothing was sent", command.stderr)
        self.assertEqual((reply.status, reply.exit_code, reply.body), (502, 4, command.stderr))
        self.assertEqual(self.stub.requests, [])
        self.assertEqual(self.egress_count(), before)

    def test_no_config_is_the_commands_error(self):
        """A server started without --config searches by keyword, and a vector search is the command's own error
        (exit 4, provider disabled) with nothing sent and nothing logged. Fails on any other answer."""
        server = self.serve(config=False)
        before = self.egress_count()
        self.assertEqual(server.search("deployment").status, 200)
        command = self.run_command("search", *search_words("deployment", "vector"))
        reply = server.search("deployment", "vector")
        self.assertEqual(command.returncode, 4)
        self.assertEqual((reply.status, reply.exit_code, reply.body), (502, 4, command.stderr))
        self.assertEqual(self.stub.requests, [])
        self.assertEqual(self.egress_count(), before)


class ProviderOnceTest(ServeCase):
    """One request makes the provider once, so that the key an answer is remembered under names the provider that
    answered it."""

    def test_one_provider_per_search(self):
        """A vector search reads the embedding configuration once and is answered with the command's bytes. Fails when
        a request reads the configuration twice, so that an edit to it between the two reads can remember an answer
        computed with one model under another model's key."""
        from laneboss.decisions import embed
        from laneboss.decisions import resident as resident_module
        from laneboss.decisions import search as search_module
        from laneboss.decisions import serve as serve_module

        asked = []
        real = embed.provider_from_config

        def counted(path=None):
            asked.append(path)
            return real(path)

        with mock.patch.object(resident_module, "provider_from_config", counted), \
                mock.patch.object(search_module, "provider_from_config", counted), \
                mock.patch.dict(os.environ, {"TEST_EMBED_KEY": self.key}):
            hold = resident_module.Resident(str(self.db), str(self.provider_config))
            self.addCleanup(hold.close)
            arguments = serve_module.Requests(self.db, str(self.provider_config)).arguments(
                [("query", "backup schedule"), ("mode", "vector")])
            body = hold.answer(arguments)
        self.assertEqual(len(asked), 1, "the configuration was read {} times for one search".format(len(asked)))
        command = self.search_command("backup schedule", "vector")
        self.assertEqual(command.returncode, 0, command.stderr)
        self.assertEqual(body, command.stdout)


class ReadOnlyTest(ServeCase):
    """The store stays read-only to the server: it changes nothing and holds no lock."""

    def test_searching_leaves_the_file_alone(self):
        """Exact and keyword searches leave the store file as it was: same bytes, size, modification time and
        directory listing (a rollback journal would show). Fails when the server writes, even a pragma."""
        server = self.serve()
        before = self.file_state()
        for query in ("deployment", "billing rollout", "不要動", "zzzzqq", "ab"):
            for mode in ("keyword", "exact"):
                self.assertEqual(server.search(query, mode).status, 200)
        self.assertEqual(server.status()["records"], 47)
        self.assertEqual(self.file_state(), before)

    def test_no_lock_between_requests(self):
        """Between requests, another connection can take the exclusive lock at once (no timeout). Fails when the
        server keeps a read transaction open, or a write lock."""
        server = self.serve()
        for moment in ("just after it started", "after searches"):
            with self.subTest(moment=moment):
                with closing(sqlite3.connect(str(self.db), timeout=0, isolation_level=None)) as connection:
                    connection.execute("BEGIN EXCLUSIVE")
                    connection.execute("ROLLBACK")
            server.search("deployment")
            server.search("deployment", "keyword", status=["withdrawn"], limit=2)

    def test_a_writer_does_not_block_search(self):
        """While another connection holds the write lock (a long `load` does) searches are answered at once. Fails
        when a search waits for the lock, or takes it."""
        server = self.serve()
        server.search("deployment")
        with closing(sqlite3.connect(str(self.db), timeout=0, isolation_level=None)) as writer:
            writer.execute("BEGIN IMMEDIATE")
            try:
                started = time.monotonic()
                for query in ("deployment", "billing rollout", "approve"):
                    self.assertEqual(server.search(query).status, 200)
                self.assertLess(time.monotonic() - started, 3.0)
            finally:
                writer.execute("ROLLBACK")

    def test_others_can_write_while_serving(self):
        """`load` runs at once while a server is up, and its record is found. Fails when the load waits for a
        lock the server holds (it would wait ten seconds and fail with exit 5)."""
        server = self.serve()
        server.search("deployment")
        started = time.monotonic()
        self.json_cli("load", "--in", self.write_batch([{"op": "add", "record": plain_record(
            "W-1", "Does the writer wait for the server?", "No.")}]))
        self.assertLess(time.monotonic() - started, 8.0)
        self.assertEqual(ids(self.both(server, "writer wait", "keyword")), ["W-1"])

    def test_unwritable_store_while_serving(self):
        """The store file and its directory become read-only while the server runs: keyword and exact searches go
        on, and a vector search fails exactly as the command's does (exit 6) with nothing sent to the provider,
        because its receipt cannot be written. Fails on any other answer, and when a question is sent anyway."""
        server = self.serve()
        os.chmod(str(self.db), 0o444)
        os.chmod(str(self.directory), 0o555)
        self.addCleanup(os.chmod, str(self.directory), 0o755)
        self.both(server, "deployment", "keyword")
        self.both(server, "", "exact", limit=3)
        command = self.search_command("billing rollout depends on the invoice export", "vector")
        reply = server.search("billing rollout depends on the invoice export", "vector")
        self.assertEqual(command.returncode, 6)
        self.assertEqual((reply.status, reply.exit_code, reply.body), (500, 6, command.stderr))
        self.assertEqual(self.stub.requests, [], "a question was sent although its receipt could not be written")

    def test_unwritable_store_at_start(self):
        """A server starts on a store it cannot write and serves it. Fails when it needs write access to open."""
        os.chmod(str(self.db), 0o444)
        os.chmod(str(self.directory), 0o555)
        self.addCleanup(os.chmod, str(self.directory), 0o755)
        server = self.serve()
        self.both(server, "deployment", "keyword")


class SocketTest(ServeCase):
    """Who can reach the server: its owner, over a Unix socket, and no one else."""

    def test_socket_and_directory_are_private(self):
        """Under every umask the socket is 600 and the directory the server makes is 700. Fails on any other
        mode."""
        for umask in (0o000, 0o022, 0o077):
            with self.subTest(umask=oct(umask)):
                directory = self.scratch / "run-{:03o}".format(umask)
                path = directory / "search.sock"
                server = self.serve(socket_path=path, umask=umask, name="umask-{:03o}".format(umask))
                self.assertEqual(stat.S_IMODE(os.stat(str(directory)).st_mode), 0o700)
                self.assertTrue(stat.S_ISSOCK(os.stat(str(path)).st_mode))
                self.assertEqual(stat.S_IMODE(os.stat(str(path)).st_mode), 0o600)
                self.assertEqual(server.search("deployment").status, 200)
                server.stop()

    def test_socket_is_private_from_birth(self):
        """The socket is made private by the mask it is bound under, not only changed afterwards: with the mask of
        the process at 000, its mode is already 600 when bind returns (faults.py reads it at that moment). Fails
        when the server binds under the mask it inherited and puts the mode right later."""
        marker = self.scratch / "bound"
        self.serve(umask=0o000, name="born",
                   launcher=[sys.executable, str(FAULTS), "socket-bound", str(marker), "serve"])
        self.assertEqual(marker.read_text(encoding="utf-8"), "0o600")

    def test_a_shared_directory_is_refused(self):
        """A directory that others can enter (755) is refused with exit 2 and a message that names it and mode
        700, and is left as it was, with no socket in it. Fails when the server makes the socket there, or
        changes the mode of a directory it did not make."""
        directory = self.scratch / "shared"
        directory.mkdir()
        os.chmod(str(directory), 0o755)
        result = self.run_serve("--db", self.db, "--socket", directory / "search.sock")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("700", result.stderr)
        self.assertIn(str(directory), result.stderr)
        self.assertEqual(stat.S_IMODE(os.stat(str(directory)).st_mode), 0o755)
        self.assertEqual(os.listdir(str(directory)), [])

    def test_a_long_socket_path_is_refused(self):
        """A socket path longer than the system allows (108 bytes on Linux, 104 on macOS) is refused with exit 2 and a
        message that names the length of the path, the limit and a shorter place to put it, before any directory is
        made. Fails when serve ends with another message or without the length, the limit and the remedy in it, or
        when the socket's directory was made before the refusal."""
        directory = self.scratch / ("d" * 120)
        path = directory / "search.sock"
        limit = 104 if sys.platform == "darwin" else 108
        result = self.run_serve("--db", self.db, "--socket", path)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(str(len(os.fsencode(str(path)))), result.stderr)
        self.assertIn(str(limit), result.stderr)
        self.assertIn("$TMPDIR", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(directory.exists(), "the refused server made the socket's directory")

    def test_a_plain_file_is_refused(self):
        """A file that is not a socket, at the socket's path, is refused and left alone. Fails when it is
        replaced."""
        directory = self.scratch / "run"
        directory.mkdir(mode=0o700)
        path = directory / "search.sock"
        path.write_text("not a socket", encoding="utf-8")
        result = self.run_serve("--db", self.db, "--socket", path)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("not a socket", result.stderr)
        self.assertEqual(path.read_text(encoding="utf-8"), "not a socket")

    def test_dead_socket_replaced_live_kept(self):
        """The socket a killed server left is replaced by a new server; a second server on a live socket is
        refused (exit 2, "already") and the first goes on. Fails when a stale socket blocks the start, or when
        a live server's socket is taken over."""
        path = self.scratch / "run" / "search.sock"
        dead = self.serve(socket_path=path, name="dead")
        dead.process.kill()
        dead.process.wait(timeout=30)
        self.assertTrue(path.exists(), "a killed server cannot have removed its socket")
        live = self.serve(socket_path=path, name="live")
        self.assertEqual(live.search("deployment").status, 200)
        result = self.run_serve("--db", self.db, "--socket", path)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("already", result.stderr)
        self.assertEqual(live.search("deployment").status, 200, "the refused second server disturbed the first")

    def test_relative_paths_start_from_cwd(self):
        """A relative database path and a relative socket path are taken from where the server started, and the
        directory of the socket is made. Fails when the server cannot find them."""
        server = self.serve(db="decisions.sqlite", socket_path="./sock/search.sock", cwd=self.directory)
        self.assertEqual(server.search("deployment").status, 200)
        self.assertTrue(stat.S_ISSOCK(os.stat(str(self.directory / "sock" / "search.sock")).st_mode))
        self.assertEqual(os.path.realpath(server.socket_path),
                         os.path.realpath(str(self.directory / "sock" / "search.sock")))

    def test_paths_with_spaces_and_unicode(self):
        """The database, the configuration and the socket may be under directories whose names have spaces and
        non-ASCII characters: the server starts, prints the socket's path as it was given, and answers a keyword
        search and a vector search with the command's bytes. Fails when a path is changed on its way."""
        base = self.scratch / "資料 夾 é"
        base.mkdir()
        database = base / "決定 store.sqlite"
        shutil.copy2(str(self.db), str(database))
        config = base / "設定 config.json"
        config.write_text(self.provider_config.read_text(encoding="utf-8"), encoding="utf-8")
        path = base / "套接字 dir" / "search.sock"
        server = self.serve(config=False, db=database, socket_path=path, extra=["--config", config])
        self.assertEqual(server.ready["socket"], str(path))
        keyword = self.run_command("search", *search_words("deployment", "keyword"), db=database)
        self.assertEqual(server.search("deployment").body, keyword.stdout)
        question = "backup schedule"
        vector = self.run_command("search", *search_words(question, "vector"), "--config", str(config), db=database)
        self.assertEqual(vector.returncode, 0, vector.stderr)
        self.assertEqual(server.search(question, "vector").body, vector.stdout)

    def test_no_network_port(self):
        """After searches, including a vector search that calls the provider, the server holds no listening TCP
        socket and no UDP socket. The check is shown to find a listener, in a process that has one. Fails when
        the server listens on a port."""
        server = self.serve()
        server.search("billing rollout depends on the invoice export", "vector")
        self.assertEqual(inet_sockets(server.pid), [])
        listener = subprocess.Popen(
            [sys.executable, "-c", "import socket, time\ns = socket.socket()\ns.bind(('127.0.0.1', 0))\ns.listen()\n"
             "print('listening', flush=True)\ntime.sleep(60)\n"],
            stdout=subprocess.PIPE, text=True)
        self.addCleanup(listener.stdout.close)
        self.addCleanup(listener.wait)
        self.addCleanup(listener.terminate)
        self.assertEqual(listener.stdout.readline().strip(), "listening")
        self.assertEqual(len(inet_sockets(listener.pid)), 1)


class KeyTest(ServeCase):
    def files_holding_the_key(self, *roots):
        needle = self.key.encode("utf-8")
        return [path for root in roots for path in sorted(Path(root).rglob("*"))
                if path.is_file() and needle in path.read_bytes()]

    def test_the_key_is_never_shown(self):
        """The embedding key is in the server's environment and goes to the provider; it is in no reply (searches,
        a provider failure, /status, a 404), not in the server's output, not in the list of processes, and not in
        any file. The search of the files is shown to find a key that is there. Fails if the key appears anywhere."""
        server = self.serve()
        replies = [server.search("billing rollout depends on the invoice export", "vector"),
                   server.search("billing rollout depends on the invoice export", "vector"),
                   server.search("backup schedule", "hybrid"), server.search("deployment")]
        self.stub.status = 500
        replies.append(server.search("a question the provider will refuse", "vector"))
        replies.append(server.get("/status"))
        replies.append(server.get("/nowhere"))
        self.assertEqual([reply.status for reply in replies], [200, 200, 200, 200, 502, 200, 404])
        self.assertTrue(self.stub.requests)
        self.assertTrue(all(request["auth"] == "Bearer " + self.key for request in self.stub.requests))
        seen = [reply.body.decode("utf-8") + repr(reply.headers) for reply in replies]
        listing = subprocess.run(["ps", "-eo", "args="], capture_output=True, text=True, timeout=60).stdout
        self.assertIn("laneboss.decisions", listing)
        seen.append(listing)
        server.stop()
        self.assertTrue(server.stdout_complete,
                        "the server's output was not read to its end, so the key could sit in the part that was not")
        seen.append(server.stdout_text)
        seen.append(server.stderr())
        for text in seen:
            self.assertNotIn(self.key, text)
        decoy = self.scratch / "decoy.txt"
        decoy.write_text("token " + self.key + "\n", encoding="utf-8")
        self.assertEqual(self.files_holding_the_key(self.scratch), [decoy])
        decoy.unlink()
        self.assertEqual(self.files_holding_the_key(self.directory, self.scratch, self.fixture_db.parent), [])


class LifecycleTest(ServeCase):
    def test_idle_exit_after_the_last_request(self):
        """With --idle-exit 0.1 (six seconds) a request at 3.5 seconds postpones the exit: the server is still up
        at about 7.5 seconds, stops after six idle seconds with exit 0 and removes its socket. Fails when the
        server stops six seconds after it started, or never, or leaves the socket."""
        server = self.serve(idle_exit=0.1)
        path = Path(server.socket_path)
        started = time.monotonic()
        time.sleep(3.5)
        self.assertEqual(server.search("deployment").status, 200)
        time.sleep(4.0)
        self.assertTrue(server.alive(), "the server stopped {:.1f} seconds after its last request, before the "
                        "6 idle seconds were over".format(time.monotonic() - started - 3.5))
        self.assertTrue(path.exists())
        self.assertEqual(server.wait_exit(timeout=40), 0)
        self.assertGreaterEqual(time.monotonic() - started, 9.0, "the server stopped before 6 idle seconds")
        self.assertFalse(path.exists(), "the socket was left behind")

    def test_idle_exit_waits_for_a_request(self):
        """A request that takes longer than the idle time (3.5 seconds against 2.4) is answered, and the server
        stops after it. Fails when idle time is counted while a request is in flight."""
        server = self.serve(idle_exit=0.04)
        self.stub.delay = 3.5
        reply = server.search("billing rollout depends on the invoice export", "vector")
        self.assertEqual(reply.status, 200, "the server stopped for being idle while a request was in flight")
        self.assertEqual(server.wait_exit(timeout=40), 0)
        self.assertFalse(Path(server.socket_path).exists())

    def test_sigterm_ends_cleanly(self):
        """SIGTERM ends the server with exit 0 and removes the socket. Fails otherwise."""
        server = self.serve()
        self.assertEqual(server.search("deployment").status, 200)
        server.process.send_signal(signal.SIGTERM)
        self.assertEqual(server.wait_exit(), 0)
        self.assertFalse(Path(server.socket_path).exists())

    def test_ignored_signals_stay_ignored(self):
        """A server that was started with SIGHUP and SIGINT ignored (as `nohup` starts one, and as a shell starts a
        command it runs in the background) goes on after either of them, still answers, and still stops on SIGTERM
        with exit 0 and no socket. A server started without them ignored stops on SIGHUP, with exit 0 and no
        socket. Fails when the server takes back a signal that was ignored for it: it would then stop when the
        terminal it was started from closes."""
        ignoring = ["sh", "-c", 'trap "" HUP INT; exec "$@"', "sh", sys.executable, "-m", "laneboss.decisions",
                    "serve"]
        server = self.serve(launcher=ignoring, name="ignoring")
        for number in (signal.SIGHUP, signal.SIGINT):
            server.process.send_signal(number)
            time.sleep(0.5)
            self.assertTrue(server.alive(), "the server stopped on {}, which was ignored for it".format(number.name))
            self.assertEqual(server.search("deployment").status, 200)
        server.process.send_signal(signal.SIGTERM)
        self.assertEqual(server.wait_exit(), 0)
        self.assertFalse(Path(server.socket_path).exists())
        plain = self.serve(socket_path=self.scratch / "plain" / "s.sock", name="plain")
        plain.process.send_signal(signal.SIGHUP)
        self.assertEqual(plain.wait_exit(), 0)
        self.assertFalse(Path(plain.socket_path).exists())

    def test_idle_exit_is_a_positive_number(self):
        """0, a negative number, text, nan and inf are refused with exit 2 and a message that names the option.
        Fails when the server starts or the message does not name --idle-exit."""
        for value in ("0", "-3", "abc", "nan", "inf"):
            with self.subTest(value=value):
                result = self.run_serve("--db", self.db, "--socket", self.scratch / "run" / "s.sock",
                                        "--idle-exit", value)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("--idle-exit", result.stderr)
        self.assertFalse((self.scratch / "run" / "s.sock").exists())

    def test_idle_exit_defaults_to_60(self):
        """Without the option the idle time is sixty minutes. Fails on any other default."""
        program = ("import laneboss.decisions.cli as cli\n"
                   "arguments = cli.parser().parse_args(['serve', '--db', 'a', '--socket', 'b'])\n"
                   "print(arguments.idle_exit)\n")
        result = subprocess.run([sys.executable, "-c", program], cwd=str(ROOT), env=self.environment,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(float(result.stdout), 60.0)

    def test_a_path_through_a_file(self):
        """A database path that runs through a file is "does not exist", as the other commands say it; serve's own
        look at the file must say the same. Fails when serve says anything else."""
        path = self.provider_config / "decisions.sqlite"
        command = self.run_command("stats", db=path)
        served = self.run_serve("--db", path, "--socket", self.scratch / "run" / "s.sock")
        self.assertEqual(command.returncode, 2)
        self.assertEqual(command.stderr.decode("utf-8"), "invalid input: database does not exist; run init first\n")
        self.assertEqual((served.returncode, served.stderr), (2, command.stderr.decode("utf-8")))

    def test_serve_refuses_what_commands_refuse(self):
        """A missing store (exit 2), a store of the older schema (exit 3, naming migrate) and a missing --socket
        (exit 2) are refused with the commands' own messages, and no socket is made. Fails otherwise."""
        path = self.scratch / "run" / "s.sock"
        missing = self.run_serve("--db", self.directory / "missing.sqlite", "--socket", path)
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(missing.stderr, "invalid input: database does not exist; run init first\n")
        old = self.directory / "old.sqlite"
        shutil.copy2(str(self.db), str(old))
        self.make_version1(old)
        result = self.run_serve("--db", old, "--socket", path)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("unsupported database schema_version 1", result.stderr)
        self.assertIn("migrate", result.stderr)
        no_socket = self.run_serve("--db", self.db)
        self.assertEqual(no_socket.returncode, 2)
        self.assertIn("--socket", no_socket.stderr)
        self.assertFalse(path.exists())


class ProtocolTest(ServeCase):
    def test_the_documented_curl_line(self):
        """The first curl line of the "Resident search" section of docs/decisions.md, run as written with the
        socket in $SOCKET, prints the command's answer; with no server (socket removed, or left by a killed server)
        it prints nothing and curl exits 7, which is what a wrapper falls back on. Fails when the section or the
        line is missing, when the line does not work, or when the documentation and the server drift apart."""
        text = (ROOT / "docs" / "decisions.md").read_text(encoding="utf-8")
        section = re.search(r"(?ms)^## Resident search[ \t]*$(.*?)(?=^## |\Z)", text)
        self.assertIsNotNone(section, 'docs/decisions.md has no section "Resident search"')
        blocks = [block for block in re.findall(r"(?ms)^```sh\n(.*?)^```$", section.group(1))
                  if "--unix-socket" in block]
        self.assertTrue(blocks, "the section shows no curl line with --unix-socket")
        line = blocks[0]
        server = self.serve()
        environment = dict(self.environment, SOCKET=server.socket_path)
        result = subprocess.run(["sh", "-c", line], env=environment, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = self.search_command("backup schedule", "keyword", limit=5)
        self.assertEqual(result.stdout, expected.stdout)
        self.assertGreater(len(json.loads(result.stdout.decode("utf-8"))), 1)
        server.stop()
        self.assertFalse(os.path.exists(server.socket_path))
        gone = subprocess.run(["sh", "-c", line], env=environment, capture_output=True, timeout=60)
        self.assertEqual((gone.returncode, gone.stdout), (7, b""), gone.stderr)
        killed = self.serve(name="killed")
        killed.process.kill()
        killed.process.wait(timeout=30)
        self.assertTrue(os.path.exists(killed.socket_path))
        stale = subprocess.run(["sh", "-c", line], env=dict(environment, SOCKET=killed.socket_path),
                               capture_output=True, timeout=60)
        self.assertEqual((stale.returncode, stale.stdout), (7, b""), stale.stderr)

    def test_the_documented_wrapper_falls_back(self):
        """The shell function of the "Resident search" section, run as written, answers from the server while it
        is up (the stand-in `laneboss`, which logs each run, is not run), and runs the command when the server is
        gone, and when the server refuses the search, and then prints the command's message and has its exit code.
        Fails when the function is not in the documentation, does not use the server, or does not fall back."""
        text = (ROOT / "docs" / "decisions.md").read_text(encoding="utf-8")
        section = re.search(r"(?ms)^## Resident search[ \t]*$(.*?)(?=^## |\Z)", text)
        self.assertIsNotNone(section, 'docs/decisions.md has no section "Resident search"')
        blocks = [block for block in re.findall(r"(?ms)^```sh\n(.*?)^```$", section.group(1)) if "search()" in block]
        self.assertTrue(blocks, "the section shows no shell function search()")
        bin_directory = self.scratch / "bin"
        bin_directory.mkdir()
        log = self.scratch / "launcher.log"
        launcher = bin_directory / "laneboss"
        launcher.write_text('#!/bin/sh\necho run >> "$LB_TEST_LOG"\n[ "$1" = decisions ] || exit 64\nshift\n'
                            'exec "$LB_TEST_PYTHON" -m laneboss.decisions "$@"\n', encoding="utf-8")
        launcher.chmod(0o755)
        server = self.serve()
        environment = dict(self.environment, SOCKET=server.socket_path, DB=str(self.db), CONFIG=str(self.provider_config),
                           LB_TEST_LOG=str(log), LB_TEST_PYTHON=sys.executable,
                           PATH=str(bin_directory) + os.pathsep + os.environ["PATH"])

        def call(arguments):
            return subprocess.run(["sh", "-c", blocks[0] + "\nsearch " + arguments + "\n"], env=environment,
                                  capture_output=True, timeout=60)

        expected = self.search_command("backup schedule", "keyword", limit=5).stdout
        served = call('"backup schedule" keyword 5')
        self.assertEqual((served.returncode, served.stdout), (0, expected), served.stderr)
        self.assertFalse(log.exists(), "the command was run although the server was up")
        refused = call('"backup schedule" fuzzy 5')
        self.assertEqual((refused.returncode, refused.stdout), (2, b""), refused.stderr)
        self.assertIn(b"invalid choice", refused.stderr)
        self.assertEqual(log.read_text(encoding="utf-8").count("run"), 1)
        server.stop()
        gone = call('"backup schedule" keyword 5')
        self.assertEqual((gone.returncode, gone.stdout), (0, expected), gone.stderr)
        self.assertEqual(log.read_text(encoding="utf-8").count("run"), 2)

    def test_curl_form_equals_curl_get(self):
        """curl with --data-urlencode, as a GET (-G) and as a POST of a form, carries a query with &, =, % and +
        unchanged and gets the command's answer both times. Fails when the characters are altered on the way."""
        server = self.serve()
        query = "x&y=z 100% a+b"
        got = subprocess.run(
            ["curl", "-sS", "--fail-with-body", "--unix-socket", server.socket_path, "-G", "http://localhost/search",
             "--data-urlencode", "query=" + query, "--data-urlencode", "limit=4"],
            capture_output=True, timeout=60)
        posted = subprocess.run(
            ["curl", "-sS", "--fail-with-body", "--unix-socket", server.socket_path, "http://localhost/search",
             "--data-urlencode", "query=" + query, "--data-urlencode", "limit=4"],
            capture_output=True, timeout=60)
        self.assertEqual((got.returncode, posted.returncode), (0, 0), got.stderr + posted.stderr)
        self.assertEqual(got.stdout, posted.stdout)
        self.assertEqual(got.stdout, self.search_command(query, "keyword", limit=4).stdout)
        self.assertEqual(ids(json.loads(got.stdout.decode("utf-8"))), ["D-47"])

    def test_other_requests_are_refused(self):
        """An unknown path is 404, a method that is not GET or POST is 405 (with Allow), and a search with no
        query, an unknown parameter, a repeated parameter or a `config` (the server's provider settings are its
        own) is 400, exit 2, "invalid input", and reaches no provider. Fails on any other answer."""
        server = self.serve()
        cases = (
            ("GET", "/nowhere", None, 404),
            ("PUT", "/search?query=x", None, 405),
            ("DELETE", "/status", None, 405),
            ("GET", "/search", None, 400),
            ("GET", "/search?query=x&bogus=1", None, 400),
            ("GET", "/search?query=x&mode=keyword&mode=exact", None, 400),
            ("GET", "/search?query=x&mode=vector&config=" + str(self.provider_config), None, 400),
        )
        for method, target, body, status in cases:
            with self.subTest(method=method, target=target):
                reply = server.ask(method, target, body)
                self.assertEqual(reply.status, status, reply.body)
                if status == 400:
                    self.assertEqual(reply.exit_code, 2)
                    self.assertTrue(reply.text().startswith("invalid input: "), reply.text())
        self.assertEqual(self.stub.requests, [])
        self.assertIn("GET", server.ask("PUT", "/search?query=x").header("Allow"))

    def test_a_body_is_never_read_as_a_request(self):
        """The body of a request is never read as the next request on its connection. The body used here is itself
        a request for /status: if the server read it as one, a second reply would follow the first.
        (1) A body that the server does not read (a POST to an unknown path or to /status, a PUT, a GET with a body)
        ends the connection with the one reply, which says Connection: close; the server closes. (2) A body that
        the server reads whole and refuses (a bad query string, a type that is not a form, text that is not UTF-8,
        an unknown parameter) is answered once, and the connection stays clean and usable. Fails when a second reply
        appears, when the server keeps open a connection it has left bytes on, or when a refused body spoils the
        connection."""
        server = self.serve()
        hidden = b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n"

        def open_connection():
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(10)
            connection.connect(server.socket_path)
            self.addCleanup(connection.close)
            return connection

        def one_reply(connection):
            """One reply, read by its Content-Length: (status line, header text, body)."""
            received = b""
            while b"\r\n\r\n" not in received:
                chunk = connection.recv(65536)
                self.assertTrue(chunk, "the connection ended before a whole reply: {!r}".format(received[:200]))
                received += chunk
            head, _, rest = received.partition(b"\r\n\r\n")
            length = int(re.search(rb"(?i)content-length: *([0-9]+)", head).group(1))
            while len(rest) < length:
                chunk = connection.recv(65536)
                self.assertTrue(chunk, "the connection ended inside a reply")
                rest += chunk
            return head.split(b"\r\n")[0], head, rest[:length], rest[length:]

        unread = (("POST /nowhere", b"404"), ("POST /status", b"405"), ("PUT /search?query=x", b"405"),
                  ("GET /search?query=deployment", b"200"), ("GET /status", b"200"))
        for line, status in unread:
            with self.subTest(unread=line):
                connection = open_connection()
                connection.sendall((line + " HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + str(len(hidden))
                                    + "\r\n\r\n").encode("ascii") + hidden)
                first, head, body, extra = one_reply(connection)
                self.assertTrue(first.startswith(b"HTTP/1.1 " + status), first)
                self.assertIn(b"connection: close", head.lower())
                # What follows the reply is the end of the connection, and no second reply.
                try:
                    rest = extra + connection.recv(65536)
                except socket.timeout:
                    self.fail("the server kept the connection open after a body it did not read")
                self.assertEqual(rest, b"", "a second reply followed the first: {!r}".format(rest[:300]))
        form = "Content-Type: application/x-www-form-urlencoded\r\n"
        read = (("POST /search?query=%ff", form, hidden), ("POST /search", "Content-Type: text/plain\r\n", hidden),
                ("POST /search", form, b"\xff\xfe" + hidden), ("POST /search", form, b"bogus=1&" + hidden))
        for line, header, body in read:
            with self.subTest(read=line, body=body[:12]):
                connection = open_connection()
                connection.sendall((line + " HTTP/1.1\r\nHost: localhost\r\n" + header + "Content-Length: "
                                    + str(len(body)) + "\r\n\r\n").encode("ascii") + body)
                first, head, answer, extra = one_reply(connection)
                self.assertTrue(first.startswith(b"HTTP/1.1 400"), first)
                self.assertEqual(extra, b"")
                connection.settimeout(0.5)
                try:
                    stray = connection.recv(65536)
                except socket.timeout:
                    stray = None
                self.assertIsNone(stray, "bytes came after the reply: {!r}".format(stray))
                connection.settimeout(10)
                # The connection is clean: the next request on it gets its own, single reply.
                connection.sendall(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n")
                first, head, answer, extra = one_reply(connection)
                self.assertTrue(first.startswith(b"HTTP/1.1 200"), first)
                self.assertEqual(json.loads(answer.decode("utf-8"))["records"], 47)
                self.assertEqual(extra, b"")

    def test_unusable_bodies_are_refused(self):
        """A POST whose body cannot be read (a length over 1 MiB that the client never sends, a length that is not a
        number, chunked coding, a negative length) is refused with 400 and exit code 2 at once, without waiting for
        the body, and its connection ends: what follows the header cannot be told from the next request. Fails when
        the server waits for the missing body, answers with another status, or keeps the connection."""
        server = self.serve()
        for header in ("Content-Length: 2000000", "Content-Length: many", "Transfer-Encoding: chunked",
                       "Content-Length: -5"):
            with self.subTest(header=header):
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(10)
                connection.connect(server.socket_path)
                self.addCleanup(connection.close)
                connection.sendall(("POST /search HTTP/1.1\r\nHost: localhost\r\n" + header + "\r\n\r\n").encode("ascii"))
                received = b""
                try:
                    while True:
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        received += chunk
                except socket.timeout:
                    self.fail("the server kept waiting after {!r}: {!r}".format(header, received[:200]))
                self.assertTrue(received.startswith(b"HTTP/1.1 400"), received[:200])
                self.assertIn(b"X-Exit-Code: 2", received)
                self.assertIn(b"connection: close", received.lower())
                self.assertEqual(received.count(b"HTTP/1.1 "), 1)

    def test_bad_clients_do_no_harm(self):
        """A client that connects and leaves, sends half a request line, sends bytes that are no HTTP, or asks for a
        slow vector search and leaves before the answer, does not stop the server or spoil the next search, and
        leaves nothing on its standard error. Fails when the server ends, stops answering, or prints (a traceback,
        or a line for each broken connection)."""
        server = self.serve()
        self.stub.delay = 0.5
        for label, send in (("leave at once", b""), ("half a request", b"GET /sea"),
                            ("no http", b"\x00\x01\x02 not http at all\r\n\r\n"),
                            ("leave before the answer",
                             b"GET /search?query=billing+rollout&mode=vector HTTP/1.1\r\nHost: localhost\r\n\r\n")):
            with self.subTest(client=label):
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(10)
                connection.connect(server.socket_path)
                if send:
                    connection.sendall(send)
                connection.close()
                self.assertTrue(server.alive())
                self.assertEqual(server.search("deployment").status, 200)
        # The question of the last client is still being asked: let it end, then look at what the server said.
        deadline = time.monotonic() + 10
        while len(self.stub.requests) < 1 and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(1.0)
        self.assertEqual(server.search("deployment").status, 200)
        self.assertEqual(server.stderr(), "")

    def test_keep_alive_connection(self):
        """One HTTP/1.1 connection carries three searches; each reply has its Content-Length and the command's
        bytes. Fails when the server closes after one reply or the length is wrong."""
        server = self.serve()
        connection = UnixConnection(server.socket_path)
        try:
            for query in ("deployment", "billing rollout", "approve"):
                connection.request("GET", "/search?" + urlencode(search_params(query)))
                response = connection.getresponse()
                body = response.read()
                self.assertEqual((response.status, response.version), (200, 11))
                self.assertEqual(response.getheader("Content-Type"), "application/json")
                self.assertEqual(int(response.getheader("Content-Length")), len(body))
                self.assertEqual(body, self.search_command(query, "keyword").stdout)
        finally:
            connection.close()

    def test_served_search_is_much_faster(self):
        """A served keyword search is at least five times faster than the command, in medians (30 served requests
        against 5 runs of the command). Fails when each request starts a process, or rebuilds the index."""
        server = self.serve()
        server.search("deployment")
        served = []
        for _ in range(30):
            started = time.perf_counter()
            self.assertEqual(server.search("deployment", limit=5).status, 200)
            served.append(time.perf_counter() - started)
        command = []
        for _ in range(5):
            started = time.perf_counter()
            self.assertEqual(self.search_command("deployment", "keyword", limit=5).returncode, 0)
            command.append(time.perf_counter() - started)
        self.assertLess(statistics.median(served) * 5, statistics.median(command),
                        "served {:.4f} s, command {:.4f} s (medians)".format(statistics.median(served),
                                                                              statistics.median(command)))


class ConcurrencyTest(ServeCase):
    def test_many_clients_at_once(self):
        """Eight clients make fifteen searches each, at once; every reply is the command's. Fails on a wrong reply,
        an error, or a dropped connection."""
        server = self.serve()
        queries = ("deployment", "billing rollout", "approve", "Should we", "vendor contract renewal", "straße")
        expected = {query: self.search_command(query, "keyword", limit=6).stdout for query in queries}
        mistakes = []

        def client(number):
            try:
                for turn in range(15):
                    query = queries[(number + turn) % len(queries)]
                    reply = server.search(query, "keyword", limit=6)
                    if reply.status != 200 or reply.body != expected[query]:
                        mistakes.append((number, turn, query, reply.status, reply.body[:200]))
            except Exception as error:  # a broken connection is a mistake of the server, and is reported as one
                mistakes.append((number, "exception", repr(error)))

        workers = [threading.Thread(target=client, args=(number,)) for number in range(8)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=120)
        self.assertEqual(mistakes, [])

    def test_a_slow_provider_blocks_no_one(self):
        """While a vector question waits three seconds for the provider, a keyword search is answered in under
        a second and a half. Fails when the server serves one request at a time, or holds a lock during the
        call."""
        server = self.serve()
        self.stub.delay = 3.0
        slow = []
        worker = threading.Thread(
            target=lambda: slow.append(server.search("billing rollout depends on the invoice export", "vector")))
        worker.start()
        deadline = time.monotonic() + 30
        while not self.stub.requests and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(self.stub.requests), 1, "the provider was never asked")
        started = time.monotonic()
        reply = server.search("deployment")
        self.assertEqual(reply.status, 200)
        self.assertLess(time.monotonic() - started, 1.5, "a keyword search waited for the provider")
        worker.join(timeout=60)
        self.assertEqual([item.status for item in slow], [200])

    def test_no_torn_state_while_loading(self):
        """A reader searches without a pause while five records are loaded one after another. Every answer shows
        a state the store really had (the first n records, for some n), and the reader sees more than one state.
        Fails on an error, on a state that never existed, or when the reader never sees a change."""
        server = self.serve()
        expected = []
        stop = threading.Event()
        shown = []
        failures = []

        def reader():
            while not stop.is_set():
                reply = server.search("zephyrwidget")
                if reply.status != 200:
                    failures.append((reply.status, reply.body[:200]))
                    return
                shown.append(tuple(sorted(ids(reply.json()))))
                time.sleep(0.005)

        worker = threading.Thread(target=reader)
        worker.start()
        try:
            for number in range(5):
                identifier = "C-{}".format(number)
                expected.append(identifier)
                value = plain_record(identifier, "Is zephyrwidget {} ready?".format(number), "Yes.")
                self.json_cli("load", "--in", self.write_batch([{"op": "add", "record": value}],
                                                               name="c-{}.jsonl".format(number)))
                time.sleep(0.2)
        finally:
            stop.set()
            worker.join(timeout=60)
        self.assertEqual(failures, [])
        allowed = {tuple(expected[:count]) for count in range(len(expected) + 1)}
        self.assertEqual({state for state in shown} - allowed, set(), "a search showed a state that never existed")
        self.assertEqual(sorted(ids(self.both(server, "zephyrwidget", "keyword"))), expected)
        self.assertGreater(len(set(shown)), 1, "the reader never saw the store change")


if __name__ == "__main__":
    unittest.main()
