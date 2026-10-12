"""Black-box tests for the schema version, the migrate command and export compatibility."""

import json
import shutil

from .support import CURRENT_FORMAT, EARLIER_FORMAT, StoreCase, in_current_format, legacy_export, record


class UpgradeCase(StoreCase):
    def populate(self):
        """Records, a supersession, an annotation, two models' vectors and a query receipt."""
        self.add()
        self.json_cli("supersede", "D-22", "--file", self.file("new.json", record("D-23")))
        self.json_cli("annotate", "D-23", "--file", self.file("outcome.json", {"evidence": ["checks/result.txt"]}))
        config = self.config()
        self.json_cli("embed", "--config", config)
        self.json_cli("embed", "--config", self.config("fake-b"))
        self.hits("deployment", "vector", config=config)


class VersionThreeTest(UpgradeCase):
    def test_new_store_is_version_three(self):
        self.assertEqual(self.user_version(), 3)
        self.assertEqual(self.json_cli("init"), {"ok": True, "schema_version": 3})
        self.assertEqual(self.user_version(), 3)
        self.assertEqual(self.json_cli("stats")["schema_version"], 3)
        self.json_cli("verify")

    def test_earlier_versions_are_refused(self):
        """Nothing is upgraded automatically. Every command but `migrate` refuses a store of an earlier version,
        names the migrate command, and leaves the store's bytes and its schema version as they were. Both versions
        this code still migrates are checked, and `ingest-lane` is checked like the rest."""
        self.populate()
        incoming = self.file("incoming.json", record("D-30"))
        outcome = self.file("outcome-2.json", {"evidence": ["checks/more.txt"]})
        batch = self.write_batch([{"op": "add", "record": record("D-31")}])
        commands = (
            ("init", ()),
            ("add", ("--file", incoming)),
            ("supersede", ("D-23", "--file", incoming)),
            ("annotate", ("D-23", "--file", outcome)),
            ("get", ("D-23",)),
            ("search", ("deployment",)),
            ("embed", ("--config", self.config())),
            ("egress", ("--list",)),
            ("ingest-lane", ("--config", "some-config", "--lane", "a-lane")),
            ("stats", ()),
            ("verify", ()),
            ("export", ("--out", self.directory / "out.jsonl")),
            ("import", ("--in", batch)),
            ("load", ("--in", batch)),
        )
        # Version 2 first, then version 1: each downgrade is applied to the store of the version above it, so
        # every store really holds that version's objects. Made the other way round, the version-2 store would be
        # a version-1 layout stamped 2, and the assertions below would not be about version 2 at all.
        for version in (2, 1):
            with self.subTest(version=version):
                if version == 1:
                    self.make_version1()
                else:
                    self.make_version2()
                before = self.db.read_bytes()
                for command, arguments in commands:
                    with self.subTest(version=version, command=command):
                        result = self.cli(command, *arguments, code=3)
                        self.assertIn("unsupported database schema_version", result.stderr)
                        self.assertIn("migrate", result.stderr)
                        self.assertEqual(self.db.read_bytes(), before)
                self.assertFalse((self.directory / "out.jsonl").exists())
                self.assertEqual(self.user_version(), version)

    def test_other_versions_are_refused(self):
        self.add()
        for version in (0, 4, 99):
            self.set_version(version)
            for command, arguments in (("verify", ()), ("stats", ()), ("get", ("D-22",)), ("migrate", ())):
                with self.subTest(version=version, command=command):
                    result = self.cli(command, *arguments, code=3)
                    self.assertIn("unsupported database schema_version", result.stderr)


class MigrateTest(UpgradeCase):
    def test_migrate_stamps_a_verified_store(self):
        self.populate()
        self.make_version1()
        before = self.dump()
        previous_export = legacy_export(self.db)
        result = self.json_cli("migrate")
        self.assertIs(result["migrated"], True)
        self.assertEqual((result["from_schema_version"], result["to_schema_version"]), (1, 3))
        self.assertEqual((result["records"], result["vectors"], result["egress_entries"]), (2, 8, 9))
        self.assertTrue(result["message"])
        self.assertEqual(self.user_version(), 3)
        self.json_cli("verify")
        after = self.dump()
        self.assertEqual(after.pop("first_written"), [])
        self.assertEqual(after, before)
        target = self.directory / "after.jsonl"
        self.json_cli("export", "--out", target)
        self.assertEqual(target.read_text(encoding="utf-8"), in_current_format(previous_export))
        self.assertEqual(self.json_cli("stats")["records_without_first_written"], 2)
        again = self.json_cli("migrate")
        self.assertIs(again["migrated"], False)

    def test_migrate_v2_keeps_all_rows(self):
        """Version 2 to version 3 adds the lane-record objects only: every row of every table that was there
        before is unchanged, proven by a hash of them all."""
        self.populate()
        self.make_version2()
        existing = self.table_names()
        before_rows = self.hash_rows(tables=existing)
        before_bytes = self.db.read_bytes()
        result = self.json_cli("migrate")
        self.assertIs(result["migrated"], True)
        self.assertEqual((result["from_schema_version"], result["to_schema_version"]), (2, 3))
        self.assertEqual(self.user_version(), 3)
        self.assertEqual(self.hash_rows(tables=existing), before_rows)
        self.assertNotEqual(self.db.read_bytes(), before_bytes)
        self.json_cli("verify")
        self.assertEqual(self.json_cli("stats")["lane_records"], 0)
        again = self.json_cli("migrate")
        self.assertIs(again["migrated"], False)
        self.assertEqual(self.hash_rows(tables=existing), before_rows)
        self.assertEqual(self.user_version(), 3)

    def test_migrate_is_a_noop(self):
        self.populate()
        before = self.db.read_bytes()
        result = self.json_cli("migrate")
        self.assertIs(result["migrated"], False)
        self.assertEqual((result["from_schema_version"], result["to_schema_version"]), (3, 3))
        self.assertIn("already", result["message"])
        self.assertEqual(self.db.read_bytes(), before)

    def test_migrate_an_empty_store(self):
        fresh = self.objects()
        self.make_version1()
        self.assertIs(self.json_cli("migrate")["migrated"], True)
        self.assertEqual(self.user_version(), 3)
        self.assertEqual(self.objects(), fresh)
        self.json_cli("verify")

    def test_older_layout_is_refused(self):
        self.populate()
        self.make_version1()
        self.make_older_layout()
        before = self.db.read_bytes()
        result = self.cli("migrate", code=3)
        self.assertIn("older layout", result.stderr)
        self.assertIn("export", result.stderr)
        self.assertIn("import", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.user_version(), 1)
        self.assertEqual(self.db.read_bytes(), before)

    def test_damaged_store_is_not_stamped(self):
        self.populate()
        damages = (
            ("record", "UPDATE records SET record_json = replace(record_json, 'keep', 'kept') WHERE id = 'D-23'"),
            ("trigger", "DROP TRIGGER immutable_answer"),
            ("egress", "UPDATE egress_log SET endpoint_host = 'changed' WHERE id = 1"),
            ("vector", "UPDATE vectors SET vector_sha256 = '" + "0" * 64 + "' WHERE rowid = 1"),
        )
        for name, damage in damages:
            with self.subTest(damage=name):
                damaged = self.directory / (name + ".sqlite")
                shutil.copyfile(str(self.db), str(damaged))
                self.make_version1(db=damaged)
                self.execute(damage, db=damaged)
                before = damaged.read_bytes()
                result = self.cli("migrate", code=3, db=damaged)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(self.user_version(db=damaged), 1)
                self.assertEqual(damaged.read_bytes(), before)

    def test_damaged_earlier_store_is_refused(self):
        """The version-2 legs, beside the version-1 test above: migrate refuses a version-1 and a version-2 store
        whose objects or rows do not match the version it claims, and leaves it exactly as it was. The removed
        trigger is applied with `self.execute`, outside `tamper`: a trigger cannot stop its own removal, so nothing
        had to be lifted for it, and `tamper` would put it back — hiding exactly the damage that proves a store
        which has lost one of its own objects is refused. The other damages go through `tamper`, because a
        version-2 store carries the row-protection triggers version 1 does not. The extra trigger is kept: an
        object that does not belong is refused too."""
        self.populate()
        damages = (
            ("record", "UPDATE records SET record_json = replace(record_json, 'keep', 'kept') WHERE id = 'D-23'"),
            ("trigger", "DROP TRIGGER immutable_answer"),
            ("extra-trigger", "CREATE TRIGGER extra_guard AFTER INSERT ON records BEGIN SELECT 1; END"),
            ("egress", "UPDATE egress_log SET endpoint_host = 'changed' WHERE id = 1"),
            ("vector", "UPDATE vectors SET vector_sha256 = '" + "0" * 64 + "' WHERE rowid = 1"),
        )
        for version in (1, 2):
            for name, damage in damages:
                with self.subTest(version=version, damage=name):
                    damaged = self.directory / ("{}-{}.sqlite".format(version, name))
                    shutil.copyfile(str(self.db), str(damaged))
                    if version == 1:
                        self.make_version1(db=damaged)
                    else:
                        self.make_version2(db=damaged)
                    if name == "trigger":
                        self.execute(damage, db=damaged)
                    else:
                        self.tamper(damage, db=damaged)
                    before = damaged.read_bytes()
                    result = self.cli("migrate", code=3, db=damaged)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(self.user_version(db=damaged), version)
                    self.assertEqual(damaged.read_bytes(), before)

    def test_missing_database(self):
        self.cli("migrate", db=self.directory / "absent.sqlite", code=2)


class OldExportTest(UpgradeCase):
    def test_export_adds_first_written_values(self):
        self.populate()
        target = self.directory / "current.jsonl"
        self.json_cli("export", "--out", target)
        lines = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
        manifest = lines[0]
        self.assertEqual((manifest["type"], manifest["format"], manifest["schema_version"], manifest["first_written"]),
                         ("manifest", CURRENT_FORMAT, 1, 2))
        for line in lines:
            if line["type"] == "record":
                self.assertRegex(line.pop("first_written_sha256"), "^[0-9a-f]{64}$")
        del manifest["first_written"]
        previous = [json.loads(line) for line in legacy_export(self.db).splitlines()]
        # The two identifiers are the only difference in the manifest; everything else is the earlier export.
        self.assertEqual(previous[0].pop("format"), EARLIER_FORMAT)
        self.assertEqual(manifest.pop("format"), CURRENT_FORMAT)
        self.assertEqual(lines, previous)

    def test_old_export_imports(self):
        self.populate()
        old = self.directory / "old.jsonl"
        old.write_bytes(legacy_export(self.db).encode("utf-8"))
        fresh = self.directory / "fresh.sqlite"
        self.json_cli("init", db=fresh)
        self.json_cli("import", "--in", old, db=fresh)
        self.json_cli("verify", db=fresh)
        again = self.directory / "again.jsonl"
        self.json_cli("export", "--out", again, db=fresh)
        self.assertEqual(in_current_format(old.read_text(encoding="utf-8")).encode("utf-8"), again.read_bytes())
        for name in ("records", "egress_entries", "vectors", "statuses", "models"):
            self.assertEqual(self.json_cli("stats", db=fresh)[name], self.json_cli("stats")[name])
        imported, original = self.dump(db=fresh), self.dump()
        self.assertEqual(imported.pop("first_written", []), [])
        original.pop("first_written", None)
        self.assertEqual(imported, original)


class ExportFormatTest(UpgradeCase):
    """Exports are rebuild points: the importer reads the identifier that earlier code wrote as well as the
    one current code writes, and nothing else."""

    def current_export(self):
        self.populate()
        target = self.directory / "current.jsonl"
        self.json_cli("export", "--out", target)
        return target

    def with_manifest(self, source, name, change):
        """A copy of an export whose manifest line went through `change` (a function on the parsed manifest)."""
        first, separator, rest = source.read_text(encoding="utf-8").partition("\n")
        manifest = json.loads(first)
        change(manifest)
        path = self.directory / name
        path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + separator + rest,
                        encoding="utf-8")
        return path

    def test_exports_write_current_name(self):
        target = self.current_export()
        manifest = json.loads(target.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(manifest["format"], CURRENT_FORMAT)
        self.assertNotEqual(CURRENT_FORMAT, EARLIER_FORMAT)

    def test_importer_accepts_both_identifiers(self):
        current = self.current_export()
        earlier = self.with_manifest(current, "earlier.jsonl", lambda manifest: manifest.update(format=EARLIER_FORMAT))
        self.assertEqual(json.loads(earlier.read_text(encoding="utf-8").splitlines()[0])["format"], EARLIER_FORMAT)
        for name, source in (("current", current), ("earlier", earlier)):
            with self.subTest(name):
                fresh = self.directory / (name + ".sqlite")
                self.json_cli("init", db=fresh)
                self.json_cli("import", "--in", source, db=fresh)
                self.json_cli("verify", db=fresh)
                again = self.directory / (name + "-again.jsonl")
                self.json_cli("export", "--out", again, db=fresh)
                self.assertEqual(again.read_bytes(), current.read_bytes())
                for stat in ("records", "egress_entries", "vectors", "statuses", "models"):
                    self.assertEqual(self.json_cli("stats", db=fresh)[stat], self.json_cli("stats")[stat])

    def test_other_identifiers_are_refused(self):
        current = self.current_export()
        wrong = (("other", "other-decisions-jsonl"), ("empty", ""), ("upper case", CURRENT_FORMAT.upper()),
                 ("earlier plus a suffix", EARLIER_FORMAT + "2"), ("earlier plus a prefix", "x" + EARLIER_FORMAT),
                 ("a list", [EARLIER_FORMAT]), ("a number", 1), ("null", None))
        for label, value in wrong:
            with self.subTest(label):
                path = self.with_manifest(current, "wrong.jsonl", lambda manifest: manifest.update(format=value))
                fresh = self.directory / "refusing.sqlite"
                self.json_cli("init", db=fresh)
                result = self.cli("import", "--in", path, db=fresh, code=2)
                self.assertIn("invalid import manifest", result.stderr)
                self.assertEqual(self.json_cli("stats", db=fresh)["records"], 0)
                fresh.unlink()
        path = self.with_manifest(current, "no-format.jsonl", lambda manifest: manifest.pop("format"))
        fresh = self.directory / "no-format.sqlite"
        self.json_cli("init", db=fresh)
        self.assertIn("invalid import manifest", self.cli("import", "--in", path, db=fresh, code=2).stderr)

    def test_earlier_identifier_same_checks(self):
        current = self.current_export()
        for label, change, message in (
                ("counts", lambda manifest: manifest["counts"].update(records=99), "counts mismatch"),
                ("first-written count", lambda manifest: manifest.update(first_written=5), "first_written count mismatch"),
                ("version", lambda manifest: manifest.update(schema_version=2), "invalid import manifest")):
            with self.subTest(label):
                def earlier(manifest, change=change):
                    manifest["format"] = EARLIER_FORMAT
                    change(manifest)
                path = self.with_manifest(current, "earlier-bad.jsonl", earlier)
                fresh = self.directory / "checked.sqlite"
                self.json_cli("init", db=fresh)
                result = self.cli("import", "--in", path, db=fresh, code=2)
                self.assertIn(message, result.stderr)
                if label != "version":
                    self.assertNotIn("invalid import manifest", result.stderr.replace(message, ""))
                self.assertEqual(self.json_cli("stats", db=fresh)["records"], 0)
                self.json_cli("verify", db=fresh)
                fresh.unlink()
