import json
import sqlite3
import subprocess
import threading
import uuid
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .support import ROOT, VERBATIM, StoreCase, digest, record, stub_server


class CLITest(StoreCase):
    def test_verbatim_round_trip(self):
        self.add()
        actual = self.json_cli("get", "D-22")
        self.assertEqual(actual["answer"]["verbatim"].encode("utf-8"), VERBATIM.encode("utf-8"))
        self.assertEqual(actual["answer"]["sha256"], digest(VERBATIM))
        self.assertEqual(actual["answer"]["channel"], "terminal")
        self.assertEqual(actual["answer"]["message_id"], "message-7")
        self.assertIn("interpretation", actual["answer"]["interpretation_label"])

    def test_required_metadata(self):
        required = ["id", "kind", "asked_at", "answered_at", "project", "area", "topics",
                    "question.text", "question.background", "answer.verbatim", "answer.channel",
                    "scope.applies_to", "status", "provenance", "provenance.recorded_by",
                    "provenance.recorded_at", "provenance.sources"]
        for field in required:
            with self.subTest(field=field):
                value = record()
                target = value
                parts = field.split(".")
                for part in parts[:-1]:
                    target = target[part]
                del target[parts[-1]]
                result = self.cli("add", "--file", self.file("invalid.json", value), code=2)
                self.assertEqual(result.stderr, "invalid input: missing required field: " + field + "\n")
        value = record()
        value["topics"] = []
        self.assertIn("topics", self.cli("add", "--file", self.file("empty.json", value),
                                        code=2).stderr)
        self.assertEqual(self.json_cli("stats")["records"], 0)

    def test_duplicate_and_changed_answer(self):
        self.add()
        duplicate = self.cli("add", "--file", self.file("same.json", record()), code=2)
        self.assertEqual(duplicate.stderr, "invalid input: duplicate id: D-22\n")
        value = record()
        value["answer"]["verbatim"] = "A changed answer"
        result = self.cli("add", "--file", self.file("changed.json", value), code=2)
        self.assertIn("answer.verbatim", result.stderr)
        self.assertEqual(self.json_cli("get", "D-22")["answer"]["verbatim"], VERBATIM)

    def test_keyword_and_punctuation(self):
        self.add()
        for identifier in ("A-1", "B-2"):
            other = record(identifier, project="phase-b")
            other["topics"] = ["inventory"]
            other["question"] = {"text": "Manage spare supplies", "background": "Restock shelves"}
            other["answer"]["verbatim"] = "Count the supplies"
            other["answer"]["interpreted_as"] = "Inventory adjustment"
            other["scope"]["applies_to"] = "Stock room"
            self.add(other)
        for query in ["部署策略", "部署", "D-22", "voyage-4-large", "BILLING"]:
            with self.subTest(query=query):
                hits = self.hits(query)
                self.assertEqual([hit["record"]["id"] for hit in hits], ["D-22"])
                self.assertNotIn("score", hits[0]["record"])
                self.assertNotIn("index", hits[0]["record"])
                self.assertIsInstance(hits[0]["score"], (int, float))
                self.assertIn(hits[0]["matched_text"], ["question", "decision"])
                self.assertIn("keyword", hits[0]["index"])
                self.assertEqual(hits[0]["record"]["answer"]["sha256"], digest(VERBATIM))
        for query in ['"', "*", "no-match:", 'a"*-:b', '" OR * NOT - :']:
            with self.subTest(punctuation=query):
                self.assertEqual(self.hits(query), [])
        for query in ("billing rollout", "rollout billing"):
            with self.subTest(multi_word=query):
                self.assertEqual([hit["record"]["id"] for hit in self.hits(query)], ["D-22"])
        self.assertEqual(self.hits("billing absent-term"), [])
        self.assertEqual(self.hits("keep")[0]["matched_text"], "decision")

    def test_exact_filters_and_dates(self):
        self.add()
        value = record("D-23", project="phase-b", status="fulfilled")
        value["answered_at"] = "2026-10-09T09:04:00+08:00"
        value["area"] = "billing"
        value["kind"] = "instruction"
        value["topics"] = ["storage"]
        self.add(value)
        self.assertEqual([hit["record"]["id"] for hit in self.hits("", "exact")], ["D-22", "D-23"])
        self.assertEqual([hit["record"]["id"] for hit in self.hits("D-22", "exact")], ["D-22"])
        for mode in ["exact", "keyword"]:
            query = "" if mode == "exact" else "keep"
            self.assertEqual([hit["record"]["id"] for hit in self.hits(query, mode, project="phase-a")], ["D-22"])
            self.assertEqual([hit["record"]["id"] for hit in self.hits(query, mode, status="fulfilled")], ["D-23"])
            self.assertEqual([hit["record"]["id"] for hit in self.hits(query, mode, date_from="2026-10-09")], ["D-23"])
            self.assertEqual([hit["record"]["id"] for hit in self.hits(query, mode, date_to="2026-10-08")], ["D-22"])
            self.assertEqual([hit["record"]["id"] for hit in self.hits(query, mode, area="billing", topic="storage",
                                                           kind="instruction")], ["D-23"])
        self.assertEqual(self.hits("keep", status="withdrawn"), [])
        self.cli("search", "keep", "--limit", "0", code=2)
        self.cli("search", "keep", "--date-from", "not-a-date", code=2)

    def test_strict_timestamp_grammar(self):
        for field, bad in (("asked_at", "2026-10-08T09:00:00+0800"),
                           ("answered_at", "2026-10-08T09:00:00.1+08:00"),
                           ("provenance.recorded_at", "2026-10-08T09:00:00.1234+08:00")):
            with self.subTest(field=field):
                value = record()
                target = value
                parts = field.split(".")
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = bad
                self.cli("add", "--file", self.file("bad-time.json", value), code=2)
        self.cli("search", "deployment", "--date-from", "2026-10-08T09:04:00+0800", code=2)

    def test_supersession_is_linked(self):
        self.add()
        value = record("D-23")
        value["answer"]["verbatim"] = "Use the updated approach"
        self.json_cli("supersede", "D-22", "--file", self.file("new.json", value))
        old = self.json_cli("get", "D-22")
        new = self.json_cli("get", "D-23")
        self.assertEqual(old["status"], "superseded")
        self.assertEqual(old["status_before_superseded"], "in_force")
        self.assertEqual(old["superseded_by"], "D-23")
        self.assertEqual(new["supersedes"], "D-22")
        self.assertEqual(old["answer"]["verbatim"], VERBATIM)
        self.assertEqual(old["answer"]["sha256"], digest(VERBATIM))
        self.assertEqual([hit["record"]["id"] for hit in self.hits("部署")], ["D-23"])
        self.assertEqual({hit["record"]["id"] for hit in self.hits("部署", all=True)}, {"D-22", "D-23"})
        self.cli("supersede", "D-22", "--file", self.file("again.json", record("D-24")), code=2)
        self.json_cli("verify")

    def test_failed_supersede_is_atomic(self):
        self.add()
        same_id = self.cli("supersede", "D-22", "--file", self.file("same-id.json", record("D-22")), code=2)
        self.assertIn("supersede requires a new id", same_id.stderr)
        self.cli("supersede", "missing", "--file", self.file("new.json", record("D-23")), code=2)
        self.assertEqual(self.json_cli("stats")["records"], 1)
        invalid = record("D-23")
        invalid["supersedes"] = "different"
        self.cli("supersede", "D-22", "--file", self.file("invalid.json", invalid), code=2)
        self.assertEqual(self.json_cli("get", "D-22")["status"], "in_force")
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.executescript("CREATE TRIGGER reject_status BEFORE UPDATE OF status ON records "
                                     "BEGIN SELECT RAISE(ABORT, 'test rejection'); END;")
        self.cli("supersede", "D-22", "--file", self.file("blocked.json", record("D-23")), code=2)
        self.cli("get", "D-23", code=2)
        self.assertEqual(self.json_cli("stats")["records"], 1)
        self.assertEqual(self.json_cli("get", "D-22")["status"], "in_force")
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("DROP TRIGGER reject_status")
        self.json_cli("verify")

    def test_fake_vectors_and_hybrid(self):
        target = record()
        target["question"]["text"] = "Amber lanterns illuminate a quiet cedar garden beside the river"
        self.add(target)
        other = record("D-23", "phase-b")
        other["question"]["text"] = "Crimson turbines rotate quickly inside a metallic copper factory"
        self.add(other)
        config = self.config()
        self.json_cli("embed", "--config", config)
        for mode in ["vector", "hybrid"]:
            hits = self.hits(target["question"]["text"], mode, config=config)
            self.assertEqual(hits[0]["record"]["id"], "D-22")
            self.assertEqual(hits[0]["matched_text"], "question")
            self.assertTrue(any(match["index"].startswith("vector") for match in hits[0]["matches"]))
            self.assertEqual([hit["record"]["id"] for hit in self.hits(target["question"]["text"], mode,
                                                           config=config, project="phase-b")], ["D-23"])
            self.assertEqual(self.hits(target["question"]["text"], mode, config=config,
                                       date_from="2026-10-09"), [])

    def test_stale_vectors_and_two_models(self):
        self.add()
        first = self.config()
        self.json_cli("embed", "--config", first)
        logs = self.json_cli("egress", "--list")
        self.assertEqual(len(logs), 2)
        self.json_cli("embed", "--config", first)
        self.assertEqual(len(self.json_cli("egress", "--list")), 2)
        addition = {"actions": [{"at": "2026-10-08T09:10:00+08:00", "text": "Checked the build"}],
                    "evidence": ["checks/result.txt"], "followups": ["Review later"]}
        self.json_cli("annotate", "D-22", "--file", self.file("outcome.json", addition))
        self.json_cli("verify")
        self.json_cli("embed", "--config", first)
        logs = self.json_cli("egress", "--list")
        self.assertEqual(len(logs), 3)
        self.assertEqual(logs[-1]["which_text"], "d_text")
        self.assertNotEqual(logs[1]["text_sha256"], logs[2]["text_sha256"])
        second = self.config("fake-b")
        self.json_cli("embed", "--config", second)
        stats = self.json_cli("stats")
        self.assertEqual(stats["vectors"], 4)
        self.assertEqual({model["model"] for model in stats["models"]}, {"fake-a", "fake-b"})
        self.json_cli("verify")

    def test_annotation_only_appends_outcome(self):
        self.add()
        addition = {"evidence": ["checks/second.txt"]}
        self.json_cli("annotate", "D-22", "--file", self.file("outcome.json", addition))
        self.json_cli("annotate", "D-22", "--file", self.file("outcome.json", addition))
        actual = self.json_cli("get", "D-22")
        self.assertEqual(actual["outcome"]["evidence"],
                         ["notes/request-7.txt", "checks/second.txt", "checks/second.txt"])
        self.cli("annotate", "D-22", "--file", self.file("bad.json", {"answer": {"verbatim": "changed"}}), code=2)
        self.assertEqual(self.json_cli("get", "D-22")["answer"]["verbatim"], VERBATIM)

    def test_disabled_provider_sends_nothing(self):
        self.add()
        with stub_server() as (endpoint, requests):
            config = self.file("none.json", {"provider": "none", "endpoint": endpoint})
            self.assertIn("disabled", self.cli("embed", "--config", config, code=4).stderr)
            self.cli("embed", code=4)
            self.cli("search", "question", "--mode", "vector", "--config", config, code=4)
            self.assertEqual(requests, [])
            self.assertEqual(self.json_cli("egress", "--list"), [])

    def test_http_provider_and_egress(self):
        self.add()
        key = "test-" + uuid.uuid4().hex
        environment = dict(self.environment, TEST_EMBED_KEY=key)
        with stub_server() as (endpoint, requests):
            config = self.file("http.json", {"provider": "voyage", "endpoint": endpoint,
                                            "api_key_env": "TEST_EMBED_KEY", "dimension": 256})
            result = self.cli("embed", "--config", config, environment=environment)
            self.assertNotIn(key, result.stdout + result.stderr)
            self.assertEqual(len(requests), 1)
            request = requests[0]
            self.assertTrue(request["auth"] == "Bearer " + key, "bearer header mismatch")
            self.assertEqual(request["path"], "/v1/embeddings")
            self.assertEqual(request["type"], "application/json")
            body = request["body"]
            self.assertEqual(body["model"], "voyage-4-large")
            self.assertEqual(body["input_type"], "document")
            self.assertEqual(body["output_dimension"], 256)
            self.assertEqual(body["output_dtype"], "float")
            self.assertIs(body["truncation"], False)
            self.assertEqual(len(body["input"]), 2)
            logs = self.json_cli("egress", "--list")
            self.assertEqual([entry["text"] for entry in logs], body["input"])
            self.assertEqual([entry["text_sha256"] for entry in logs], list(map(digest, body["input"])))
            self.assertEqual([entry["which_text"] for entry in logs], ["q_text", "d_text"])
            self.assertTrue(all(entry["endpoint_host"] == "127.0.0.1" for entry in logs))
            result = self.cli("search", "deployment", "--mode", "vector", "--config", config,
                              environment=environment)
            self.assertNotIn(key, result.stdout + result.stderr)
            self.assertEqual(requests[-1]["body"]["input_type"], "query")
            self.assertEqual(self.json_cli("egress", "--list")[-1]["which_text"], "query")
            self.json_cli("verify")
        for path in self.directory.rglob("*"):
            if path.is_file():
                self.assertFalse(key.encode() in path.read_bytes(), "key persisted to a file")

    def test_provider_failure_is_redacted(self):
        self.add()
        key = "test-" + uuid.uuid4().hex
        environment = dict(self.environment, TEST_EMBED_KEY=key)
        with stub_server("echo_error") as (endpoint, requests):
            config = self.file("http.json", {"provider": "voyage", "endpoint": endpoint,
                                            "api_key_env": "TEST_EMBED_KEY"})
            result = self.cli("embed", "--config", config, environment=environment, code=4)
            self.assertNotIn(key, result.stdout + result.stderr)
            self.assertEqual(len(requests), 1)
            self.assertEqual(len(self.json_cli("egress", "--list")), 2)
            self.assertEqual(self.json_cli("stats")["vectors"], 0)
        self.json_cli("verify")

    def test_provider_validation(self):
        self.add()
        environment = dict(self.environment, TEST_EMBED_KEY="invented-test-value")
        # Every value here is transcribed from the raise in src/laneboss/decisions/embed.py that the response mode
        # reaches, as cli.py prints it: "provider failed: <message>". Invalid vectors comes from the catch-all raise
        # of embed.py:150; a redirect comes from embed.py:33.
        invalid_vectors = "provider failed: embedding provider request failed or returned invalid vectors\n"
        expected = {
            "bad_dimension": invalid_vectors,
            "bad_index": invalid_vectors,
            "nonfinite": invalid_vectors,
            "redirect": "provider failed: embedding provider redirects are refused\n",
            "truncated": invalid_vectors,
            "bad_status": invalid_vectors,
        }
        for response_mode in expected:
            with self.subTest(response=response_mode):
                with stub_server(response_mode) as (endpoint, requests):
                    config = self.file("http.json", {"provider": "voyage", "endpoint": endpoint,
                                                    "api_key_env": "TEST_EMBED_KEY", "dimension": 256})
                    result = self.cli("embed", "--config", config, environment=environment, code=4)
                    self.assertEqual(result.stderr, expected[response_mode])
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(len(requests), 1)
                    self.assertEqual(self.json_cli("stats")["vectors"], 0)

    def test_egress_precedes_http(self):
        self.add()
        observed = []
        database = self.db

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format_string, *arguments):
                return

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                with closing(sqlite3.connect(database)) as connection, connection:
                    observed.append(connection.execute("SELECT count(*) FROM egress_log").fetchone()[0])
                self.send_response(503)
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            config = self.file("http.json", {
                "provider": "voyage", "api_key_env": "TEST_EMBED_KEY",
                "endpoint": "http://127.0.0.1:{}/v1/embeddings".format(server.server_port),
            })
            self.cli("embed", "--config", config, code=4,
                     environment=dict(self.environment, TEST_EMBED_KEY="invented-test-value"))
            self.assertEqual(observed, [2])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)

    def test_verify_detects_corrupt_row(self):
        self.add()
        self.json_cli("verify")
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("UPDATE records SET record_json = replace(record_json, 'keep', 'kept') WHERE id = ?",
                               ("D-22",))
        result = self.cli("verify", code=3)
        self.assertIn("D-22", result.stderr)

        record_hash_db = self.directory / "record-hash.sqlite"
        self.json_cli("init", db=record_hash_db)
        self.json_cli("add", "--file", self.file("record-hash.json", record()), db=record_hash_db)
        with closing(sqlite3.connect(record_hash_db)) as connection, connection:
            connection.execute("UPDATE records SET record_sha256 = ? WHERE id = ?", ("0" * 64, "D-22"))
        self.assertIn("record_sha256", self.cli("verify", db=record_hash_db, code=3).stderr)

        blob_db = self.directory / "blob.sqlite"
        self.json_cli("init", db=blob_db)
        self.json_cli("add", "--file", self.file("blob.json", record()), db=blob_db)
        with closing(sqlite3.connect(blob_db)) as connection, connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE records SET verbatim = ? WHERE id = ?", (b"changed", "D-22"))
            connection.execute("DROP TRIGGER immutable_answer")
            connection.execute("UPDATE records SET verbatim = ? WHERE id = ?", (b"changed", "D-22"))
        self.assertIn("schema", self.cli("verify", db=blob_db, code=3).stderr)
        with closing(sqlite3.connect(blob_db)) as connection, connection:
            connection.executescript("CREATE TRIGGER immutable_answer BEFORE UPDATE OF verbatim ON records\n"
                                     "WHEN NEW.verbatim != OLD.verbatim BEGIN\n"
                                     "    SELECT RAISE(ABORT, 'answer.verbatim is immutable');\nEND;")
        self.assertIn("verbatim", self.cli("verify", db=blob_db, code=3).stderr)

    def test_verify_detects_schema_changes(self):
        trigger_db = self.directory / "trigger.sqlite"
        self.json_cli("init", db=trigger_db)
        self.json_cli("add", "--file", self.file("trigger.json", record()), db=trigger_db)
        with closing(sqlite3.connect(trigger_db)) as connection, connection:
            connection.execute("DROP TRIGGER immutable_answer")
        self.assertIn("schema", self.cli("verify", db=trigger_db, code=3).stderr)

        index_db = self.directory / "index.sqlite"
        self.json_cli("init", db=index_db)
        self.json_cli("add", "--file", self.file("index.json", record()), db=index_db)
        with closing(sqlite3.connect(index_db)) as connection, connection:
            connection.execute("DROP TABLE keyword_index")
            connection.execute("CREATE VIRTUAL TABLE keyword_index USING fts5(id, q_text, d_text, tokenize='unicode61')")
            row = connection.execute("SELECT row_id, id, q_text, d_text FROM records").fetchone()
            connection.execute("INSERT INTO keyword_index(rowid, id, q_text, d_text) VALUES (?, ?, ?, ?)", row)
        self.assertIn("schema", self.cli("verify", db=index_db, code=3).stderr)

    def test_verify_missing_link(self):
        self.add()
        with closing(sqlite3.connect(self.db)) as connection, connection:
            raw = connection.execute("SELECT record_json FROM records WHERE id = 'D-22'").fetchone()[0]
            value = json.loads(raw)
            value["supersedes"] = "MISSING"
            serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            connection.execute("UPDATE records SET record_json = ?, record_sha256 = ? WHERE id = ?",
                               (serialized, digest(serialized), "D-22"))
        result = self.cli("verify", code=3)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("supersedes", result.stderr)

    def test_verify_detects_bad_index(self):
        self.add()
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("DELETE FROM keyword_index")
        self.assertIn("keyword", self.cli("verify", code=3).stderr)

    def test_export_import_is_portable(self):
        self.add()
        self.json_cli("supersede", "D-22", "--file", self.file("new.json", record("D-23")))
        self.json_cli("annotate", "D-23", "--file", self.file("outcome.json", {"evidence": ["checks/result.txt"]}))
        self.json_cli("embed", "--config", self.config())
        target = self.directory / "portable.jsonl"
        self.json_cli("export", "--out", target)
        other = self.directory / "imported.sqlite"
        self.json_cli("init", db=other)
        self.json_cli("import", "--in", target, db=other)
        self.json_cli("verify", db=other)
        for identifier in ["D-22", "D-23"]:
            self.assertEqual(self.json_cli("get", identifier), self.json_cli("get", identifier, db=other))
        self.assertEqual(self.json_cli("stats"), self.json_cli("stats", db=other))
        self.assertEqual(self.json_cli("egress", "--list"), self.json_cli("egress", "--list", db=other))
        reexport = self.directory / "again.jsonl"
        self.json_cli("export", "--out", reexport, db=other)
        self.assertEqual(target.read_bytes(), reexport.read_bytes())

    def test_import_failure_is_atomic(self):
        self.add()
        target = self.directory / "portable.jsonl"
        self.json_cli("export", "--out", target)
        entries = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
        entries[0]["counts"]["records"] = 2
        invalid = record("D-23")
        del invalid["question"]["text"]
        entries.append({"type": "record", "record": invalid})
        target.write_text("\n".join(json.dumps(entry) for entry in entries) + "\n", encoding="utf-8")
        other = self.directory / "imported.sqlite"
        self.json_cli("init", db=other)
        self.cli("import", "--in", target, db=other, code=2)
        self.assertEqual(self.json_cli("stats", db=other)["records"], 0)
        self.json_cli("verify", db=other)

    def test_import_bad_bindings(self):
        for identifier, filename in ((2 ** 80, "oversized.jsonl"), ([], "binding.jsonl")):
            with self.subTest(identifier=identifier):
                other = self.directory / ("import-" + filename + ".sqlite")
                self.json_cli("init", db=other)
                payload = {
                    "type": "manifest", "format": "laneboss-decisions-jsonl", "schema_version": 1,
                    "counts": {"records": 0, "models": 0, "vectors": 0, "egress": 1},
                }
                egress = {
                    "id": identifier, "record_id": None, "which_text": "query", "text": "query",
                    "text_sha256": digest("query"), "model": "fake-a", "at": "2026-10-08T09:00:00Z",
                    "endpoint_host": "local", "input_type": "query", "previous_entry_sha256": "",
                    "entry_sha256": "0" * 64,
                }
                path = self.directory / filename
                path.write_text(json.dumps(payload) + "\n" + json.dumps({"type": "egress", "egress": egress}) + "\n",
                                encoding="utf-8")
                result = self.cli("import", "--in", path, db=other, code=2)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(self.json_cli("stats", db=other)["egress_entries"], 0)

    def test_invalid_types_and_json(self):
        for field, value in [("kind", "unknown"), ("status", "unknown"),
                             ("schema_version", 2), ("answered_at", "2026-10-08T09:00:00"),
                             ("topics", "not a list"), ("id", "   ")]:
            with self.subTest(field=field):
                invalid = record()
                invalid[field] = value
                self.assertIn(field, self.cli("add", "--file", self.file("bad.json", invalid), code=2).stderr)
        malformed = self.directory / "bad.json"
        malformed.write_text('{"id":"D-22","id":"D-23"}', encoding="utf-8")
        self.cli("add", "--file", malformed, code=2)
        self.cli("get", "absent", code=2)

    def test_unknown_keys_and_id_shape(self):
        cases = []
        value = record()
        value["interpretation"] = "misspelled"
        cases.append(value)
        value = record()
        value["answer"]["interpretation"] = "misspelled"
        cases.append(value)
        value = record()
        value["question"]["options"][0]["typo"] = "misspelled"
        cases.append(value)
        for index, value in enumerate(cases):
            with self.subTest(index=index):
                self.cli("add", "--file", self.file("unknown-{}.json".format(index), value), code=2)
        for identifier in ("-bad", " " + "A", "A" * 129):
            value = record(identifier)
            self.cli("add", "--file", self.file("bad-id.json", value), code=2)
        self.assertEqual(self.json_cli("stats")["records"], 0)

    def test_json_output_is_ascii_safe(self):
        self.add()
        result = self.cli("get", "D-22", environment=dict(self.environment, LC_ALL="C", LANG="C"))
        result.stdout.encode("ascii")
        self.assertNotIn("照", result.stdout)
        self.assertIn("\\u", result.stdout)

    def test_absent_message_id_is_explicit(self):
        value = record()
        del value["answer"]["message_id"]
        self.add(value)
        self.assertIsNone(self.json_cli("get", "D-22")["answer"]["message_id"])
        self.assertIsNone(self.hits("部署")[0]["record"]["answer"]["message_id"])

    def test_verbatim_allows_nul_bytes(self):
        value = record()
        value["answer"]["verbatim"] = "before\x00after 🙂 \n"
        self.add(value)
        answer = self.json_cli("get", "D-22")["answer"]
        self.assertEqual(answer["verbatim"].encode(), value["answer"]["verbatim"].encode())
        self.assertEqual(answer["sha256"], digest(value["answer"]["verbatim"]))
        self.json_cli("verify")

    def test_source_line_snapshot_hash(self):
        value = record()
        source = value["provenance"]["sources"][0]
        source["line_text"] = VERBATIM
        self.add(value)
        self.json_cli("verify")
        value["id"] = "D-23"
        source["line_text"] = "The wrong source line"
        result = self.cli("add", "--file", self.file("bad-source.json", value), code=2)
        self.assertIn("sha256_of_line", result.stderr)

    def test_stale_sides_are_excluded(self):
        self.add()
        config = self.config()
        self.json_cli("embed", "--config", config)
        self.json_cli("annotate", "D-22", "--file", self.file("outcome.json", {"evidence": ["checks/fresh.txt"]}))
        self.assertEqual(self.json_cli("stats")["stale_vectors"], 1)
        hits = self.hits("deployment", "vector", config=config)
        self.assertEqual([match["field"] for match in hits[0]["matches"]], ["q_text"])
        result = self.json_cli("embed", "--config", config)
        self.assertEqual((result["embedded"], result["skipped"]), (1, 1))

    def test_vector_corruption_is_refused(self):
        self.add()
        config = self.config()
        self.json_cli("embed", "--config", config)
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("UPDATE vectors SET vector = ? WHERE which_text = 'q_text'",
                               (bytes([0, 0, 128, 63]) * 128,))
        self.assertIn("vector", self.cli("verify", code=3).stderr)
        self.cli("search", "deployment", "--mode", "vector", "--config", config, code=3)
        self.cli("embed", "--config", config, code=3)

    def test_egress_corruption_is_detected(self):
        self.add()
        self.json_cli("embed", "--config", self.config())
        self.tamper("UPDATE egress_log SET endpoint_host = 'changed' WHERE id = 1")
        self.assertIn("egress", self.cli("verify", code=3).stderr)

    def test_egress_chain_gap(self):
        self.add()
        self.add(record("D-23"))
        self.json_cli("embed", "--config", self.config())
        self.tamper("DELETE FROM egress_log WHERE id = 2")
        result = self.cli("verify", code=3)
        self.assertIn("egress", result.stderr)

    def test_model_dimension_is_pinned(self):
        self.add()
        self.json_cli("embed", "--config", self.config())
        self.cli("embed", "--config", self.config(dimension=64), code=2)
        self.assertEqual(self.json_cli("stats")["vectors"], 2)

    def test_http_batches_and_size_guard(self):
        self.add()
        self.add(record("D-23"))
        environment = dict(self.environment, TEST_EMBED_KEY="invented-test-value")
        with stub_server() as (endpoint, requests):
            config = self.file("http.json", {"provider": "voyage", "endpoint": endpoint,
                                            "api_key_env": "TEST_EMBED_KEY", "dimension": 256,
                                            "batch_size": 1})
            self.json_cli("embed", "--config", config, environment=environment)
            self.assertEqual(len(requests), 4)
            self.assertEqual([entry["text"] for entry in self.json_cli("egress", "--list")],
                             [text for request in requests for text in request["body"]["input"]])
            huge = record("D-24")
            huge["question"]["text"] = "x" * 25000
            self.add(huge)
            self.cli("embed", "--config", config, environment=environment, code=4)
            self.assertEqual(len(requests), 4)
            self.assertEqual(len(self.json_cli("egress", "--list")), 4)

    def test_config_failure_sends_nothing(self):
        self.add()
        with stub_server() as (endpoint, requests):
            config = self.file("http.json", {"provider": "voyage", "endpoint": endpoint,
                                            "api_key_env": "ABSENT_EMBED_KEY"})
            environment = dict(self.environment)
            environment.pop("ABSENT_EMBED_KEY", None)
            self.cli("embed", "--config", config, environment=environment, code=4)
            for values in [{"provider": "fake", "dimension": 0},
                           {"provider": "fake", "batch_size": 1001},
                           {"provider": "voyage", "dimension": 257},
                           {"provider": "fake", "api_key": "invented-test-value"}]:
                self.cli("embed", "--config", self.file("invalid-config.json", values), code=2)
            self.assertEqual(requests, [])
            self.assertEqual(self.json_cli("egress", "--list"), [])

    def test_filters_apply_in_all_modes(self):
        self.add()
        value = record("D-23", "phase-b", "withdrawn")
        value["area"] = "billing"
        value["topics"] = ["storage"]
        value["kind"] = "instruction"
        value["answered_at"] = "2026-10-09T09:04:00+08:00"
        self.add(value)
        config = self.config()
        self.json_cli("embed", "--config", config)
        for mode in ["exact", "keyword", "vector", "hybrid"]:
            query = "" if mode == "exact" else "deployment"
            filters = {} if mode in ("exact", "keyword") else {"config": config}
            hits = self.hits(query, mode, id="D-23", project="phase-b", area="billing", topic="storage",
                             kind="instruction", status="withdrawn", date_from="2026-10-09",
                             date_to="2026-10-10", limit="1", **filters)
            self.assertEqual([hit["record"]["id"] for hit in hits], ["D-23"])
            self.assertEqual([hit["record"]["id"] for hit in self.hits(query, mode, **filters)], ["D-22"])
            self.assertEqual({hit["record"]["id"] for hit in self.hits(query, mode, all=True, **filters)}, {"D-22", "D-23"})

    def test_offset_date_and_export_refusal(self):
        self.add()
        hits = self.hits("D-22", "exact", date_from="2026-10-07T23:04:00-02:00",
                         date_to="2026-10-08T01:04:00Z")
        self.assertEqual([hit["record"]["id"] for hit in hits], ["D-22"])
        target = self.directory / "portable.jsonl"
        self.json_cli("export", "--out", target)
        previous = target.read_bytes()
        self.cli("export", "--out", target, code=2)
        self.assertEqual(target.read_bytes(), previous)
        self.cli("import", "--in", target, code=2)

    def test_scanner_enforces_all_rules(self):
        directory = self.directory / "scan"
        directory.mkdir()
        fixture = directory / "fixture.txt"
        fixture.write_text("127.0.0.1", encoding="utf-8")
        cases = [("-----" + "BEGIN " + "PRIVATE KEY" + "-----", "private-key-header"),
                 ("X9" * 21, "long-secret-like-token"),
                 ("192" + ".0" + ".2" + ".8", "non-loopback-ipv4"),
                 ("sample" + "@" + "invalid.example", "email-address")]
        result = subprocess.run(["sh", ROOT / "scripts/scan.sh", directory], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        generated = directory / "__pycache__"
        generated.mkdir()
        (generated / "noise.pyc").write_bytes((b"Z9" * 30) + b"\n")
        result = subprocess.run(["sh", ROOT / "scripts/scan.sh", directory], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        for content, rule in cases:
            fixture.write_text(content, encoding="utf-8")
            result = subprocess.run(["sh", ROOT / "scripts/scan.sh", directory], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn(rule, result.stdout)
            self.assertNotIn(content, result.stdout)

    def test_private_database_and_export(self):
        self.add()
        target = self.directory / "private.jsonl"
        self.json_cli("export", "--out", target)
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
