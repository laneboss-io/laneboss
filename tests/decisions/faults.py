"""Runs the decision store's command line with one fault or synchronisation point, for tests that must change the
world between two steps of a command.

    python faults.py <point> <marker> <command> --db <path> [arguments...]

The product has no hook for any of this and cannot be asked to stop anywhere: the point is installed from outside,
in this process, before the command starts. The marker file is created when the point is reached. The points:

    pipe-checked  the export has looked at its destination and found a named pipe (its first check, which runs
                  before it asks for the write lock)
    lock-wanted   the command is about to ask SQLite for the write lock (BEGIN IMMEDIATE)
    io-error      the first statement the command runs once the store is open fails with the error SQLite reports
                  when the operating system refuses a read: OperationalError("disk I/O error"). A failing disk
                  cannot be made to order on every system the tests run on: a file truncated under SQLite is
                  reported as malformed, not as an I/O error, and macOS's SQLite guards its file descriptors, so
                  replacing one kills the process. On Linux, replacing the descriptor of the database file by
                  that of a directory makes SQLite's next page read fail with exactly this error.
    socket-bound  `serve` has bound its Unix socket: the marker file then holds the mode of the socket file at the
                  moment bind returned, as an octal number, before anything the command does afterwards can change
                  it. The mode of a finished server's socket cannot show whether the socket was private from the
                  start.
"""

import os
import socket
import sqlite3
import stat
import sys

import laneboss.decisions.cli as cli
import laneboss.decisions.store as store


def touch(path):
    open(path, "w").close()


def through_connection(before_execute):
    """Make every connection that the command opens call before_execute(sql) before it runs a statement."""
    connect = sqlite3.connect

    class Watched(sqlite3.Connection):
        def execute(self, sql, *arguments):
            before_execute(sql)
            return super().execute(sql, *arguments)

    def watched(*arguments, **options):
        options["factory"] = Watched
        return connect(*arguments, **options)

    sqlite3.connect = watched


def pipe_checked(marker):
    first_check = store.export_into_pipe

    def checked(path):
        result = first_check(path)
        touch(marker)
        return result

    store.export_into_pipe = checked


def lock_wanted(marker):
    def before(sql):
        if sql.lstrip().upper().startswith("BEGIN IMMEDIATE"):
            touch(marker)

    through_connection(before)


def io_error(marker):
    def before(sql):
        # The store opens with two pragmas; the first statement after them belongs to the command.
        if not sql.lstrip().upper().startswith("PRAGMA"):
            touch(marker)
            raise sqlite3.OperationalError("disk I/O error")

    through_connection(before)


def socket_bound(marker):
    bind = socket.socket.bind

    def bound(self, address):
        bind(self, address)
        if isinstance(address, str):
            with open(marker, "w") as handle:
                handle.write(oct(stat.S_IMODE(os.stat(address).st_mode)))

    socket.socket.bind = bound


POINTS = {"pipe-checked": pipe_checked, "lock-wanted": lock_wanted, "io-error": io_error,
          "socket-bound": socket_bound}


if __name__ == "__main__":
    POINTS[sys.argv[1]](sys.argv[2])
    sys.exit(cli.main(sys.argv[3:]))
