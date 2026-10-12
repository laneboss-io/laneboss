"""The lane records of the decision store: keyword search, the append-only triggers and the keyword-only rule.

A lane record is text the launcher's own records gave, kept for keyword search. These tests write one into the
test's own store the way the store's writer does (support.put_lane_record) and then drive the installed command
line, so what is asserted is what the commands print and what SQLite refuses."""

import json
import sqlite3

from .support import StoreCase, digest, plain_record, stub_server


LANE_TEXT = "the lane's final report: quixotic zephyr measurements"
LANE_ID = "alpha/a-lane/report/" + digest(LANE_TEXT)[:16]


class LaneRecordSearchTest(StoreCase):
    def setUp(self):
        super().setUp()
        self.add()
        self.identifier = self.put_lane_record(LANE_TEXT, lane="a-lane")

    def test_keyword_finds_the_lane_record(self):
        hits = self.hits("quixotic")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["lane_record"]["id"], self.identifier)
        self.assertEqual(hits[0]["lane_record"]["part"], "report")
        self.assertEqual(hits[0]["lane_record"]["text"], LANE_TEXT)
        self.assertEqual(hits[0]["matched_text"], "lane")
        self.assertNotIn("record", hits[0])

    def test_kind_filter_selects_lane_rows(self):
        lane_hits = self.hits("quixotic", kind="lane_record")
        self.assertEqual([hit["lane_record"]["id"] for hit in lane_hits], [self.identifier])
        self.assertEqual(self.hits("quixotic", kind="decision"), [])

    def test_decision_records_are_still_found(self):
        self.assertEqual([hit["record"]["id"] for hit in self.hits("deployment")], ["D-22"])

    def test_lane_record_id_matches(self):
        hits = self.hits("a-lane")
        self.assertEqual([hit["lane_record"]["id"] for hit in hits], [self.identifier])

    def test_a_long_term_matches_the_index(self):
        hits = self.hits("zephyr", kind="lane_record")
        self.assertEqual([hit["lane_record"]["id"] for hit in hits], [self.identifier])

    def test_exact_mode_returns_no_lane_record(self):
        hits = self.json_cli("search", "", "--mode", "exact", "--all")
        self.assertEqual([hit["record"]["id"] for hit in hits], ["D-22"])

    def test_project_search_skips_lane_rows(self):
        self.assertEqual(self.hits("quixotic", project="phase-a"), [])


class LaneRecordGuardTest(StoreCase):
    def setUp(self):
        super().setUp()
        self.identifier = self.put_lane_record(LANE_TEXT, lane="a-lane")

    def test_an_update_is_refused(self):
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self.execute("UPDATE lane_records SET text = 'changed' WHERE id = ?", (self.identifier,))
        self.assertIn("lane records never change", str(caught.exception))

    def test_a_delete_is_refused(self):
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self.execute("DELETE FROM lane_records WHERE id = ?", (self.identifier,))
        self.assertIn("lane records are never deleted", str(caught.exception))

    def test_a_replacement_is_refused(self):
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self.execute(
                "INSERT OR REPLACE INTO lane_records (id, config, lane, part, source_path, source_sha256, text, "
                "created_utc, ingested_utc) VALUES (?, 'alpha', 'a-lane', 'report', '/invented/report.txt', ?, "
                "'other', '2026-10-12T00:00:00+00:00', '2026-10-12T00:00:01+00:00')",
                (self.identifier, digest(LANE_TEXT)))
        self.assertIn("written once and never replaced", str(caught.exception))


class LaneRecordStatsTest(StoreCase):
    def test_stats_and_verify_include_lane_rows(self):
        self.add()
        self.put_lane_record(LANE_TEXT, lane="a-lane")
        stats = self.json_cli("stats")
        self.assertEqual(stats["lane_records"], 1)
        self.assertEqual(stats["lane_record_triggers"],
                         ["lane_records_no_delete", "lane_records_no_replace", "lane_records_no_update"])
        self.assertEqual(self.json_cli("verify")["lane_records"], 1)

    def test_verify_refuses_a_broken_index_row(self):
        """A row rewritten consistently, text and hash and id together, leaves its keyword index row pointing at
        the old text. The row itself is sound, so only the index comparison can refuse this store."""
        self.put_lane_record(LANE_TEXT, lane="a-lane")
        other = "other text"
        other_id = "alpha/a-lane/report/" + digest(other)[:16]
        self.tamper(("UPDATE lane_records SET id = ?, text = ?, source_sha256 = ? WHERE id = ?",
                     (other_id, other, digest(other), LANE_ID)))
        result = self.cli("verify", code=3)
        self.assertIn("keyword index mismatch", result.stderr)

    def test_verify_refuses_a_wrong_id(self):
        self.put_lane_record(LANE_TEXT, lane="a-lane")
        self.tamper(("UPDATE lane_records SET source_sha256 = ? WHERE id = ?", ("0" * 64, LANE_ID)))
        result = self.cli("verify", code=3)
        self.assertIn("id does not name its configuration, lane, part and source hash", result.stderr)

    def test_verify_refuses_a_wrong_source_hash(self):
        """A write path that stored text other than the bytes it hashed. The text and its keyword index row are
        rewritten together, so the index comparison cannot see it and only the row's own source hash can."""
        self.put_lane_record(LANE_TEXT, lane="a-lane")
        rewritten = LANE_TEXT + " (rewritten)"
        self.tamper(("UPDATE lane_records SET text = ? WHERE id = ?", (rewritten, LANE_ID)),
                    ("UPDATE lane_keyword_index SET text = ? WHERE id = ?", (rewritten, LANE_ID)))
        result = self.cli("verify", code=3)
        self.assertIn("source_sha256 does not name the record's own text", result.stderr)

    def test_import_refuses_lane_rows_standing(self):
        source = self.directory / "source.sqlite"
        self.json_cli("init", db=source)
        self.json_cli("add", "--file", self.file("other.json", plain_record("P-1")), db=source)
        export = self.directory / "export.jsonl"
        self.json_cli("export", "--out", export, db=source)
        self.put_lane_record(LANE_TEXT, lane="a-lane")
        result = self.cli("import", "--in", export, code=2)
        self.assertIn("import requires an empty initialized store", result.stderr)


class LaneRecordEgressTest(StoreCase):
    """Lane records are keyword-only: no text of theirs is ever embedded or sent anywhere, and the egress log
    holds no entry for them. The embedding service is a third party the target cannot reach, so a local stub
    stands in for it and records every text it is sent."""

    def test_embed_and_hybrid_skip_lane_text(self):
        self.add()
        self.put_lane_record(LANE_TEXT, lane="a-lane")
        with stub_server() as (endpoint, requests):
            config = self.config(model="voyage-4-large", provider="voyage", endpoint=endpoint, dimension=256,
                                 api_key_env="LANEBOSS_TEST_EMBED_KEY")
            environment = dict(self.environment, LANEBOSS_TEST_EMBED_KEY="invented-key")
            self.json_cli("embed", "--config", config, environment=environment)
            # Hybrid mode searches keywords and vectors; both legs are run, and the second query is the lane
            # record's own word, which a hybrid search that read lane records would return as a hit.
            for query in ("deployment", "quixotic"):
                with self.subTest(query=query):
                    hits = json.loads(self.cli(
                        "search", query, "--mode", "hybrid", "--config", config,
                        environment=environment).stdout)
                    self.assertFalse(any("lane_record" in hit for hit in hits))
                    self.assertEqual([hit["record"]["id"] for hit in hits], ["D-22"])
        sent = [text for request in requests for text in request["body"]["input"]]
        self.assertTrue(sent, "the stub received nothing, so this proves nothing")
        # No text of a lane record leaves this machine, in a document or in a query: a query goes to the provider
        # just as a document does. The one text that may carry the lane record's own word is the caller's own
        # query, and every sent text that does is exactly that word, in a request of type query.
        self.assertNotIn(LANE_TEXT, sent)
        for request in requests:
            for text in request["body"]["input"]:
                self.assertNotIn(LANE_TEXT, text)
                if "quixotic" in text:
                    self.assertEqual(text, "quixotic")
                    self.assertEqual(request["body"]["input_type"], "query")
        documents = [text for request in requests for text in request["body"]["input"]
                     if request["body"]["input_type"] == "document"]
        self.assertTrue(documents, "the stub received no document, so it was never called for the records")
        entries = self.json_cli("egress", "--list")
        logged = [entry for entry in entries if entry["input_type"] == "document"]
        # The ordinary decision records did reach the stub, so the stub really was called for them.
        self.assertTrue(logged)
        self.assertEqual({entry["record_id"] for entry in logged}, {"D-22"})
        self.assertTrue({digest(text) for text in documents} & {entry["text_sha256"] for entry in logged})
        self.assertFalse(any(entry["text_sha256"] == digest(LANE_TEXT) for entry in entries))
        for entry in entries:
            self.assertNotIn(LANE_TEXT, entry["text"])
            if "quixotic" in entry["text"]:
                self.assertEqual(entry["text"], "quixotic")
                self.assertEqual(entry["input_type"], "query")

    def test_vector_search_returns_no_lane_row(self):
        self.add()
        self.put_lane_record(LANE_TEXT, lane="a-lane")
        with stub_server() as (endpoint, requests):
            config = self.config(model="voyage-4-large", provider="voyage", endpoint=endpoint, dimension=256,
                                 api_key_env="LANEBOSS_TEST_EMBED_KEY")
            environment = dict(self.environment, LANEBOSS_TEST_EMBED_KEY="invented-key")
            self.json_cli("embed", "--config", config, environment=environment)
            hits = json.loads(self.cli("search", "quixotic", "--mode", "vector", "--config", config,
                                       environment=environment).stdout)
        # A vector search ranks the decision records it holds vectors for; no lane record is among them.
        self.assertTrue(hits)
        self.assertEqual([hit["record"]["id"] for hit in hits], ["D-22"])
        self.assertFalse(any("lane_record" in hit for hit in hits))
        sent = [text for request in requests for text in request["body"]["input"]
                if request["body"]["input_type"] == "document"]
        self.assertTrue(sent)
        self.assertFalse(any("quixotic" in text for text in sent))
