"""E. Integrity: the database refuses changes; a store rewritten around that protection fails verify.

These tests deliberately open the store file with sqlite3 to tamper with it; every outcome is
still asserted through the installed command.
"""

from contextlib import closing
from pathlib import Path
import sqlite3

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class IntegrityTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.write_config("alpha")
        for index in range(1, 4):
            self.append(self.event(id="int-{}".format(index), payload={"n": index}))
        self.store = Path(self.laneboss_json("config", "path", "alpha")["store"])

    def verify(self, code=0):
        return self.run_laneboss("state", "verify", "--config", "alpha", code=code)

    def event_triggers(self, connection):
        return connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'events' ORDER BY name"
        ).fetchall()

    def test_clean_store_verifies(self):
        result = self.laneboss_json("state", "verify", "--config", "alpha")
        self.assertIs(result["ok"], True)
        self.assertEqual(result["events"], 3)

    def test_database_refuses_changes(self):
        with closing(sqlite3.connect(str(self.store))) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE events SET payload = ? WHERE seq = 2", ('{"n":20}',))
            connection.rollback()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM events WHERE seq = 2")
            connection.rollback()
        self.verify()
        self.assertEqual(self.events()[1]["payload"], {"n": 2})

    def test_rewrite_around_protection(self):
        with closing(sqlite3.connect(str(self.store))) as connection:
            triggers = self.event_triggers(connection)
            self.assertTrue(triggers, "the store must protect its events with triggers")
            for name, _ in triggers:
                connection.execute('DROP TRIGGER "{}"'.format(name))
            connection.execute("UPDATE events SET payload = ? WHERE seq = 2", ('{"n":20}',))
            for _, sql in triggers:
                connection.execute(sql)
            connection.commit()
        result = self.verify(code=3)
        self.assertIn("seq 2", result.stderr)
        self.run_laneboss("state", "events", "--config", "alpha", code=3)

    def test_dropped_protection_fails(self):
        with closing(sqlite3.connect(str(self.store))) as connection:
            for name, _ in self.event_triggers(connection):
                connection.execute('DROP TRIGGER "{}"'.format(name))
            connection.commit()
        self.assertIn("schema", self.verify(code=3).stderr)

    def test_deleted_event_fails(self):
        with closing(sqlite3.connect(str(self.store))) as connection:
            triggers = self.event_triggers(connection)
            for name, _ in triggers:
                connection.execute('DROP TRIGGER "{}"'.format(name))
            connection.execute("DELETE FROM events WHERE seq = 2")
            for _, sql in triggers:
                connection.execute(sql)
            connection.commit()
        self.assertIn("seq", self.verify(code=3).stderr)
