"""JSON command-line interface and stable exit codes."""

import argparse
import math
import sqlite3
import sys

from .embed import embed_store, provider_from_config
from .lane import ingest_lane, launcher_failure
from .layout import SCHEMA_VERSION
from .load import load_file
from .schema import AccessProblem, IntegrityError, InvalidInput, KINDS, ProviderError, STATUSES, read_json, render
from .search import search
from .store import Progress, Store, is_access_problem, is_busy, is_storage_problem

BUSY = "database busy: another process held the write lock for longer than the 10-second wait"
PERMISSION = (
    "permission problem: SQLite cannot write the database ({}). verify, export, migrate and every command that "
    "writes need write permission on the database file; commands that change the store also need write "
    "permission on its directory, where SQLite keeps its rollback journal"
)
# A command that only reads can fail only in a read. (The journal clause: the first process to open a file that an
# earlier write left half done restores it from the journal, whatever that process was going to do.)
STORAGE_READ = (
    "storage problem: SQLite failed ({}) while it read the database file, or restored it from the rollback journal "
    "of an earlier write that did not finish: the disk may be failing or full, or a file-size limit may have been "
    "reached. This command only reads, so nothing was changed"
)
# Any other command reads before it writes, and a failed I/O call does not say which of the two it was.
STORAGE_WRITE = (
    "storage problem: SQLite failed ({}) while it read or wrote the database file or its rollback journal: the disk "
    "may be full, a file-size limit may have been reached, or the system reported an I/O error. SQLite rolls a "
    "failed write back from the rollback journal (if this process could not finish that, the next one to open the "
    "file does), so it does not reach the store"
)


def only_reads(arguments):
    """True for a command that never writes a page of the database. verify and export take the write lock but write
    nothing; search writes the receipt of its query only in vector and hybrid mode; serve opens the store read-only
    (the receipts of the vector questions it is asked are written one at a time, by the search that asks)."""
    command = arguments.command
    if command in ("get", "stats", "egress", "verify", "export", "serve"):
        return True
    if command == "load":
        return arguments.dry_run
    return command == "search" and arguments.mode in ("exact", "keyword")


def outcome(progress, command):
    """What the failed command left behind: nothing, the database file that init created, or what it had already
    committed (embed commits often)."""
    if not progress:
        return "; nothing was changed"
    if progress.created:
        return ". This command had created the database file {}; it is still there and holds no store".format(
            progress.created)
    text = ". Before that, " + progress.describe()
    if command == "embed":
        text += ". Run embed again: it sends only the texts that still have no current vector"
    return text


def positive_integer(value):
    try:
        number = int(value)
        if number < 1:
            raise ValueError()
        return number
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error


def positive_number(value):
    try:
        number = float(value)
    except ValueError:
        number = None
    if number is None or not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a positive number of minutes")
    return number


def parser(parser_class=argparse.ArgumentParser):
    root = parser_class(prog="laneboss-decisions", description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("init", "migrate", "add", "supersede", "annotate", "get", "search", "embed", "egress", "stats",
                 "verify", "export", "import", "load", "serve", "ingest-lane"):
        command = commands.add_parser(name)
        command.add_argument("--db", required=True)
        if name in ("get", "supersede", "annotate"):
            command.add_argument("id")
        if name in ("add", "supersede", "annotate"):
            command.add_argument("--file", required=True)
        if name in ("embed", "search", "serve"):
            command.add_argument("--config")
        if name == "ingest-lane":
            command.add_argument("--config", required=True, metavar="NAME",
                                 help="the launcher configuration the lane belongs to")
            command.add_argument("--lane", required=True)
            command.add_argument("--attach", action="append", default=[], metavar="FILE",
                                 help="a file to ingest as one lane record (repeatable)")
        if name == "serve":
            command.add_argument("--socket", required=True)
            command.add_argument("--idle-exit", type=positive_number, default=60.0, metavar="MINUTES",
                                 help="stop after this many minutes without a request (default 60)")
        if name == "egress":
            command.add_argument("--list", action="store_true", required=True)
        if name == "export":
            command.add_argument("--out", required=True)
        if name in ("import", "load"):
            command.add_argument("--in", dest="input_file", required=True)
        if name == "load":
            command.add_argument("--dry-run", action="store_true")
        if name == "search":
            command.add_argument("query")
            command.add_argument("--mode", choices=("exact", "keyword", "vector", "hybrid"), default="keyword")
            for field in ("id", "project", "area", "topic"):
                command.add_argument("--" + field)
            command.add_argument("--kind", choices=sorted(KINDS | {"lane_record"}))
            command.add_argument("--status", action="append", choices=sorted(STATUSES))
            command.add_argument("--date-from", "--from", "--since", dest="date_from")
            command.add_argument("--date-to", "--to", "--until", dest="date_to")
            command.add_argument("--limit", type=positive_integer, default=20)
            command.add_argument("--all", action="store_true")
    return root


def dispatch(store, arguments):
    command = arguments.command
    if command == "init":
        return {"ok": True, "schema_version": SCHEMA_VERSION}
    if command == "migrate":
        return store.migrate()
    if command == "load":
        return load_file(store, arguments.input_file, arguments.dry_run)
    if command == "add":
        return store.add(read_json(arguments.file))
    if command == "supersede":
        return store.supersede(arguments.id, read_json(arguments.file))
    if command == "annotate":
        return store.annotate(arguments.id, read_json(arguments.file))
    if command == "get":
        return store.get(arguments.id)
    if command == "search":
        return search(store, arguments)
    if command == "embed":
        return embed_store(store, provider_from_config(arguments.config))
    if command == "egress":
        return store.egress()
    if command == "ingest-lane":
        return ingest_lane(store, arguments.config, arguments.lane, arguments.attach)
    if command == "stats":
        return store.stats()
    if command == "verify":
        return store.verify()
    if command == "export":
        return store.export(arguments.out)
    return store.import_file(arguments.input_file)


def failure(error, arguments, progress):
    """What a command says when it fails with `error`, and its exit code: (message, code); None for an error that the
    command does not know, which is a fault and not a failure. `progress` is what the command had done by then."""
    if isinstance(error, InvalidInput):
        return "invalid input: " + str(error), 2
    if isinstance(error, IntegrityError):
        return "integrity problem: " + str(error), 3
    if isinstance(error, ProviderError):
        return "provider failed: " + str(error), 4
    if isinstance(error, AccessProblem):
        return "permission problem: " + str(error) + outcome(progress, arguments.command), 6
    if isinstance(error, sqlite3.IntegrityError):
        return "refused write: database constraint", 2
    if isinstance(error, sqlite3.OperationalError):
        if is_busy(error):
            return BUSY + outcome(progress, arguments.command) + ("." if progress else "; try again later"), 5
        if is_access_problem(error):
            return PERMISSION.format(error) + outcome(progress, arguments.command), 6
        if is_storage_problem(error):
            if only_reads(arguments):
                return STORAGE_READ.format(error), 7
            return STORAGE_WRITE.format(error) + outcome(progress, arguments.command), 7
        return "integrity problem: SQLite operation failed", 3
    if isinstance(error, sqlite3.Error):
        return "integrity problem: SQLite operation failed", 3
    if isinstance(error, OverflowError):
        return "invalid input: oversized integer or unsupported numeric value", 2
    known_launcher = launcher_failure(error)
    if known_launcher is not None:
        return known_launcher
    if isinstance(error, (OSError, UnicodeError, ValueError, RecursionError)):
        return "invalid input: unreadable path or unsupported text", 2
    return None


def main(argv=None):
    arguments = parser().parse_args(argv)
    # What the command has done so far, kept here because no Store exists to ask when its constructor fails.
    progress = Progress()
    store = None
    try:
        if arguments.command == "serve":
            # Imported here: the server is needed by no other command, and its imports are not free.
            from .serve import serve
            return serve(arguments)
        store = Store(arguments.db, initialize=arguments.command == "init", migrating=arguments.command == "migrate",
                      progress=progress)
        result = dispatch(store, arguments)
        sys.stdout.write(render(result))
        return 0
    except Exception as error:
        known = failure(error, arguments, progress)
        if known is None:
            raise
        print(known[0], file=sys.stderr)
        return known[1]
    finally:
        if store is not None:
            store.close()
