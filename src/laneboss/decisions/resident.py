"""The resident search: the store held in memory, and the command's own search code run over it.

A Resident keeps a Snapshot, a copy of the store file made in one read, and searches it with the code of search.py
through a Reader (ResidentReader) that answers from memory what the command's Reader asks of the file. Before every
request it asks whether the file has changed; if it has, it makes a new Snapshot, so an answer never comes from an
index older than the file.

Keeping the answer the command's answer is the rule of this module:

- The records are checked once, when the Snapshot is made, with the checks the command makes at every search, and a
  store that fails them fails every request, as it does the command.
- The keyword index is the store's own FTS5 index, copied with the rest of the file, so BM25 gives the same numbers.
- A vector's cosine is computed in two steps. A fast step, on the stored vector and the query vector scaled to length
  1 (math.sumprod where the interpreter has it), orders the records to within a margin far larger than its error.
  The scores that are printed, and the order wherever two scores are within the margin of each other, are computed
  with the command's own expression, so they are the command's floating-point numbers, bit for bit.
- A question for the embedding provider is answered from memory if the same text was asked of the same provider
  and model before; otherwise it is asked the way the command asks it, receipt first.
"""

from collections import OrderedDict
import errno
import hashlib
import math
import operator
import os
import sqlite3
import stat
import threading

from .embed import provider_from_config
from .layout import SCHEMA_VERSION
from .schema import AccessProblem, IntegrityError, InvalidInput, ProviderError, SIDES, render, timestamp
from .search import Ranked, Reader, search
from .store import Progress, Store, unsupported_version


def exact_dot(left, right):
    """The sum of products that the command computes, `sum(a * b for a, b in zip(left, right))`, found faster: the
    products are made by map instead of a generator, the same numbers in the same order, so the sum is the same
    number, bit for bit. (math.sumprod is not the same: it rounds differently.)"""
    return sum(map(operator.mul, left, right))


def exact_norm(vector):
    """The length of a vector, as the command computes it."""
    return math.sqrt(exact_dot(vector, vector))


# The fast dot product that orders the records: math.sumprod where the interpreter has it (Python 3.12 and newer),
# the exact one where not. Either is within SLACK of the exact score; only exact_dot gives the printed scores.
dot = getattr(math, "sumprod", exact_dot)

# How far the fast cosine of a vector may be from the command's: it is within about 1e-13 even for the largest
# vectors the store takes (4096 numbers), so this is a margin of four orders of magnitude.
SLACK = 1e-9
CACHE_ENTRIES = 512
# How many answers a copy of the store remembers, and the most bytes they may take together.
ANSWERS = 128
ANSWER_BYTES = 16 << 20

# What an answer depends on, as SQLite itself joins it into one text per table (it does that at the speed of C, and the
# digest below is made of three long texts instead of thousands of rows). The texts come in the order SQLite reads the
# table, which is the same for two copies of one file; if it ever were not, the digests would differ for a table that
# did not change, which costs a new copy and never an answer from an old one.
FINGERPRINT_QUERIES = (
    "PRAGMA user_version",
    "SELECT count(*), group_concat(row_id || ':' || id || ':' || record_sha256 || ':' || q_sha256 || ':' || d_sha256,"
    " ';') FROM records",
    "SELECT count(*), group_concat(model || ':' || provider || ':' || dimension || ':' || entry_sha256, ';') "
    "FROM models",
    "SELECT count(*), group_concat(record_id || ':' || which_text || ':' || model || ':' || text_sha256 || ':' || "
    "vector_sha256 || ':' || entry_sha256, ';') FROM vectors",
    "SELECT count(*), group_concat(id || ':' || source_sha256, ';') FROM lane_records",
)


def fingerprint(connection):
    """A digest of what an answer depends on: the schema version and the hashes that the store keeps of every
    record, model and vector. It does not cover the egress log, which no answer depends on. The reads are made in
    one transaction, so that the digest is of one state of the file."""
    own = not connection.in_transaction
    if own:
        connection.execute("BEGIN")
    try:
        digest = hashlib.sha256()
        for query in FINGERPRINT_QUERIES:
            for row in connection.execute(query):
                for value in row:
                    digest.update(value.encode("utf-8") if isinstance(value, str) else repr(value).encode("ascii"))
                    digest.update(b"\x00")
            digest.update(b"--\n")
        return digest.hexdigest()
    finally:
        if own and connection.in_transaction:
            connection.execute("ROLLBACK")


class LockedConnection:
    """What a keyword search does to a connection: run a query and read all its rows. Threads take turns."""

    def __init__(self, connection, lock):
        self.connection = connection
        self.lock = lock

    def execute(self, sql, parameters=()):
        with self.lock:
            return self.connection.execute(sql, parameters).fetchall()


class Entry:
    """One stored vector of one record that still belongs to the text the record has now, with what scoring it
    needs: the vector as the command reads it, and its norm as the command computes it."""
    __slots__ = ("record_id", "side", "vector", "norm")

    def __init__(self, record_id, side, vector, norm):
        self.record_id = record_id
        self.side = side
        self.vector = vector
        self.norm = norm


class LazyRanked(Ranked):
    """A ranking whose matches (and so whose scores) are worked out, exactly, when a hit is made from a record."""

    def __init__(self, ranking, compute):
        Ranked.__init__(self, ranking, {}, None)
        self.compute = compute

    def matches(self, identifier):
        found = self.grouped.get(identifier)
        if found is None:
            found = self.grouped[identifier] = self.compute(identifier)
        return found

    def score(self, identifier):
        return self.matches(identifier)[0]["score"]


class VectorTable:
    """The vectors of one model, read and checked once. The checks, and the order in which they run, are the
    command's, so the same stored data fails with the same error."""

    def __init__(self, snapshot, provider):
        self.model = provider.model
        models = snapshot.connection.execute("SELECT * FROM models WHERE model = ?", (provider.model,))
        model = models[0] if models else None
        if model:
            snapshot.checked_model(model)
        if not model or model["dimension"] != provider.dimension or model["provider"] != provider.name:
            raise InvalidInput("model has no compatible embeddings; run embed with this config first")
        self.by_record = {}
        for row in snapshot.connection.execute("SELECT * FROM vectors WHERE model = ?", (provider.model,)):
            vector = snapshot.checked_vector(row, provider.dimension)
            current = snapshot.rows_by_id.get(row["record_id"])
            if current is None:
                continue
            side = row["which_text"]
            if row["text_sha256"] != current["q_sha256" if side == "q_text" else "d_sha256"]:
                continue
            self.by_record.setdefault(row["record_id"], []).append(
                Entry(row["record_id"], side, vector, exact_norm(vector)))

    def groups(self, eligible):
        """The current vectors of the eligible records, by record."""
        return {identifier: entries for identifier, entries in self.by_record.items() if identifier in eligible}

    def rank(self, groups, query_vector, depth):
        return rank_vectors(self.model, groups, query_vector, depth)


def rank_vectors(model, groups, query_vector, depth):
    """The records of `groups` (record id -> its Entry objects) by cosine similarity to the query vector, ranked as
    the command ranks them: by the best score of a record, then by id, with the scores and matches the command
    prints. `depth` is how many records of the top will be looked at, or None for the whole ranking.

    The score of every Entry is first worked out fast, from the query vector scaled to length 1 and the stored
    vector: that is within about 1e-13 of the command's, far inside SLACK. It decides the order wherever two records
    are further apart than the margin 2 * SLACK; the records that are not are put in order by the command's own
    expression, which is also what every printed score is."""
    query_norm = exact_norm(query_vector)
    unit = [number / query_norm for number in query_vector]
    known = {}

    def compute(identifier):
        found = known.get(identifier)
        if found is None:
            found = []
            for entry in groups[identifier]:
                score = exact_dot(query_vector, entry.vector) / (query_norm * entry.norm)
                found.append({"id": identifier, "index": "vector:" + model, "text": SIDES[entry.side],
                              "field": entry.side, "score": max(-1.0, min(1.0, score))})
            found.sort(key=lambda match: (-match["score"], match["id"], match["text"]))
            known[identifier] = found
        return found

    best = {}
    for identifier, entries in groups.items():
        top = max(dot(unit, entry.vector) / entry.norm for entry in entries)
        best[identifier] = max(-1.0, min(1.0, top))
    order = sorted(best, key=best.__getitem__, reverse=True)
    if depth is not None:
        # A record that is further than the margin below the depth-th best is surely not among the top `depth`.
        cut = best[order[depth - 1]] if len(order) >= depth else -2.0
        listed = []
        for identifier in order:
            if best[identifier] < cut - 2 * SLACK:
                break
            listed.append(identifier)
        listed.sort(key=lambda identifier: (-compute(identifier)[0]["score"], identifier))
        return LazyRanked(listed, compute)
    ranking = []
    start = 0
    while start < len(order):
        end = start + 1
        while end < len(order) and best[order[end - 1]] - best[order[end]] <= 2 * SLACK:
            end += 1
        members = order[start:end]
        if len(members) > 1:
            members.sort(key=lambda identifier: (-compute(identifier)[0]["score"], identifier))
        ranking.extend(members)
        start = end
    return LazyRanked(ranking, compute)


class Snapshot(Store):
    """The store as one read of the file found it, in memory. It is not changed after it is made; a request that
    started on it finishes on it, whatever is made after."""

    def __init__(self, source):
        """Copy the database of the connection `source` into memory, in one read, and check what the command
        checks at every search. There is no file here, so Store's constructor is not run."""
        self.progress = Progress()
        memory = sqlite3.connect(":memory:", check_same_thread=False)
        try:
            source.backup(memory)
            memory.row_factory = sqlite3.Row
            version = memory.execute("PRAGMA user_version").fetchone()[0]
            if version != SCHEMA_VERSION:
                raise unsupported_version(version)
            self.raw = memory
            self.lock = threading.Lock()
            self.connection = LockedConnection(memory, self.lock)
            self.stored = memory.execute("SELECT * FROM records ORDER BY id").fetchall()
            # The command meets a damaged record when it first looks at the records, which is after it has looked at
            # the dates and the other words of the search. This copy meets it at the same place: the error is kept
            # here, and raised by require_sound, which the reader of a search calls where the command reads records.
            self.damage = None
            self.checked = {}
            try:
                for row in self.stored:
                    self.checked[row["id"]] = Store.checked_record(self, row)
            except IntegrityError as error:
                self.damage = error
                self.checked = {}
            self.rows_by_id = {row["id"]: row for row in self.stored if row["id"] in self.checked}
            self.pairs = [(row, self.checked[row["id"]]) for row in self.stored if row["id"] in self.checked]
            # The lane records are checked once, too: a keyword search reads them and every request on this copy
            # must meet the same error the command meets.
            self.stored_lane = memory.execute("SELECT * FROM lane_records ORDER BY id").fetchall()
            self.lane_damage = None
            self.checked_lane = {}
            try:
                for row in self.stored_lane:
                    self.checked_lane[row["id"]] = Store.checked_lane_record(self, row)
            except IntegrityError as error:
                self.lane_damage = error
                self.checked_lane = {}
            self.answered = {identifier: timestamp(record["answered_at"], "answered_at")
                             for identifier, record in self.checked.items()}
            self.folds = {}
            self.tables = {}
            self.tables_lock = threading.Lock()
            # The answers given on this copy, by search (see Resident.answer): a new copy starts with none.
            self.answers = OrderedDict()
            self.answers_size = 0
            self.answers_lock = threading.Lock()
            self.fingerprint = fingerprint(memory)
        except BaseException:
            memory.close()
            raise

    def close(self):
        self.raw.close()

    def require_sound(self):
        """Raise the error that the command raises when it reads the records of this store, if one is damaged."""
        if self.damage is not None:
            raise type(self.damage)(*self.damage.args)

    def require_sound_lane(self):
        """Raise the error that the command raises when it reads the lane records of this store, if one is damaged."""
        if self.lane_damage is not None:
            raise type(self.lane_damage)(*self.lane_damage.args)

    def remembered_answer(self, key):
        with self.answers_lock:
            found = self.answers.get(key)
            if found is not None:
                self.answers.move_to_end(key)
            return found

    def remember_answer(self, key, body):
        with self.answers_lock:
            old = self.answers.pop(key, None)
            if old is not None:
                self.answers_size -= len(old)
            self.answers[key] = body
            self.answers_size += len(body)
            while self.answers and (len(self.answers) > ANSWERS or self.answers_size > ANSWER_BYTES):
                dropped = self.answers.popitem(last=False)[1]
                self.answers_size -= len(dropped)

    def rows(self):
        return self.stored

    def checked_record(self, row):
        return self.checked[row["id"]]

    def folded(self, row, column):
        key = (row["id"], column)
        found = self.folds.get(key)
        if found is None:
            found = self.folds[key] = row[column].casefold()
        return found

    def vector_table(self, provider):
        """The checked vectors of the provider's model, or the error that checking them gave."""
        key = (provider.model, provider.dimension, provider.name)
        with self.tables_lock:
            if key not in self.tables:
                try:
                    self.tables[key] = VectorTable(self, provider)
                except (IntegrityError, InvalidInput) as error:
                    self.tables[key] = error
            found = self.tables[key]
        if isinstance(found, Exception):
            raise type(found)(*found.args)
        return found


class ResidentReader(Reader):
    """The questions of a search, answered from a Snapshot and from the Resident's memory of earlier questions."""

    def __init__(self, snapshot, resident):
        Reader.__init__(self, snapshot)
        self.resident = resident

    def records(self):
        self.store.require_sound()
        return self.store.pairs

    def answered_at(self, record):
        return self.store.answered[record["id"]]

    def hit_record(self, record):
        # The record of a Snapshot is never changed, and a hit is only turned into text: no copy is needed.
        return record

    def folded(self, row, column):
        return self.store.folded(row, column)

    def lane_records(self):
        self.store.require_sound_lane()
        return [(row, self.store.checked_lane[row["id"]]) for row in self.store.stored_lane
                if row["id"] in self.store.checked_lane]

    def lane_folded(self, row, column):
        return row[column].casefold()

    def lane_query(self, sql, parameters):
        return self.store.connection.execute(sql, parameters)

    def vector_ranking(self, query, eligible, provider, depth):
        table = self.store.vector_table(provider)
        groups = table.groups(eligible)
        if not groups:
            return Ranked([], {}, {})
        return table.rank(groups, self.resident.query_vector(provider, query), depth)


class Resident:
    """A store held in memory and searched with the command's code. Every method may be called from any thread."""

    def __init__(self, path, config):
        self.path = os.path.abspath(path)
        self.config = config
        self.refresh_lock = threading.Lock()
        self.monitor = None
        self.identity = None
        self.snapshot = None
        self.stamp = None
        self.failure = None
        self.builds = 0
        self.cache = OrderedDict()
        self.cache_lock = threading.Lock()
        self.flights = {}
        self.hits = 0
        self.misses = 0
        self.answer_hits = 0
        self.answer_misses = 0

    # Is the snapshot still the file?

    def stamp_now(self):
        """What can be seen of the file cheaply: which file it is, its size and modification time, and SQLite's own
        count of changes made by other connections (PRAGMA data_version). The count is the reliable part, the rest
        catches a file that was replaced. A change of the file is a change of the stamp, never the other way."""
        try:
            info = os.stat(self.path)
        except PermissionError:
            raise AccessProblem("cannot reach the database path: permission denied") from None
        except OSError as error:
            # The errors for which Path.exists(), which the command asks, answers "no".
            if error.errno in (errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP):
                raise InvalidInput("database does not exist; run init first") from None
            raise
        if not stat.S_ISREG(info.st_mode):
            raise InvalidInput("database does not exist; run init first")
        if self.monitor is None or (info.st_dev, info.st_ino) != self.identity:
            self.close_monitor()
            monitor = Store(self.path, readonly=True, shared=True)
            monitor.connection.isolation_level = None
            self.monitor, self.identity = monitor, (info.st_dev, info.st_ino)
        version = self.monitor.connection.execute("PRAGMA data_version").fetchone()[0]
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, version

    def close_monitor(self):
        if self.monitor is not None:
            self.monitor.close()
            self.monitor = self.identity = None

    def current(self):
        """The Snapshot to answer a request from. The file is looked at first. If its stamp has changed, what an
        answer depends on is compared with what the Snapshot was made from (the file also changes when a vector
        question is logged, which changes no answer); only a change that matters makes a new Snapshot."""
        with self.refresh_lock:
            stamp = self.stamp_now()
            if self.snapshot is not None and stamp == self.stamp:
                return self.snapshot
            if self.failure is not None and stamp == self.failure[0]:
                raise type(self.failure[1])(*self.failure[1].args)
            if self.snapshot is not None and fingerprint(self.monitor.connection) == self.snapshot.fingerprint:
                self.stamp, self.failure = stamp, None
                return self.snapshot
            try:
                snapshot = Snapshot(self.monitor.connection)
            except (IntegrityError, InvalidInput) as error:
                self.failure = (stamp, error)
                raise
            self.snapshot, self.stamp, self.failure = snapshot, stamp, None
            self.builds += 1
            if self.builds > 1:
                # The first Snapshot is warmed by the server before it says it is ready; a later one in the
                # background, while the request that needed it goes on.
                threading.Thread(target=self.warm, args=(snapshot,), daemon=True).start()
            return snapshot

    def warm(self, snapshot):
        """Read and check the vectors of the configured model now, so that the first vector search on this
        Snapshot does not have to. Where the configuration cannot be used, or the vectors fail their checks, the
        search that needs them meets the same error and reports it."""
        if self.config is None:
            return
        try:
            provider = provider_from_config(self.config)
        except (ProviderError, InvalidInput):
            return
        try:
            snapshot.vector_table(provider)
        except (IntegrityError, InvalidInput):
            return

    # A search

    def provider_for(self, arguments):
        """The provider a vector or hybrid search will ask, made once for the request so that the key it is remembered
        under names the provider that answered. None where the search asks no provider, and None where none can be
        made: that search takes the ordinary way, its error included."""
        if arguments.mode not in ("vector", "hybrid"):
            return None
        try:
            return provider_from_config(arguments.config)
        except (ProviderError, InvalidInput):
            return None

    def answer_key(self, arguments, provider):
        """What a search is known by: every word the parser read for it, except the command, the database and the
        configuration, which decide nothing about an answer on one copy of the store, with the provider that answered
        where there is one. The whole of what the parser gives a search is in the key, so an option added to the
        parser later is in the key of the search that uses it. None when a vector or hybrid search has no provider to
        name: such a search takes the ordinary way, its error included."""
        if arguments.mode in ("vector", "hybrid") and provider is None:
            return None
        words = tuple(sorted((name, tuple(value) if isinstance(value, list) else value)
                             for name, value in vars(arguments).items()
                             if name not in ("command", "db", "config")))
        provider_key = None
        if arguments.mode in ("vector", "hybrid"):
            provider_key = (provider.name, provider.model, provider.dimension, getattr(provider, "endpoint", ""))
        return words, provider_key

    def answer(self, arguments):
        """The bytes that a successful search prints. What a search answers is a function of the copy of the store,
        of the search and, for a vector or hybrid search, of the provider's vector for the question; so a search
        asked again on the same copy is answered with the bytes it was answered with before, and neither the store
        nor the provider is asked again. A failed search is never remembered, and a new copy starts with no answers."""
        snapshot = self.current()
        provider = self.provider_for(arguments)
        key = self.answer_key(arguments, provider)
        if key is not None:
            found = snapshot.remembered_answer(key)
            if found is not None:
                with self.cache_lock:
                    self.answer_hits += 1
                return found
        body = render(search(snapshot, arguments, ResidentReader(snapshot, self), provider)).encode("ascii")
        with self.cache_lock:
            self.answer_misses += 1
        if key is not None:
            snapshot.remember_answer(key, body)
        return body

    # Questions for the embedding provider

    def query_vector(self, provider, query):
        key = (provider.name, provider.model, provider.dimension, getattr(provider, "endpoint", ""),
               hashlib.sha256(query.encode("utf-8")).hexdigest())
        with self.cache_lock:
            found = self.remembered(key)
            if found is not None:
                return found
            flight = self.flights.get(key)
            if flight is None:
                flight = self.flights[key] = threading.Lock()
        try:
            with flight:
                # One request at a time asks the provider a given question; the others wait for its answer.
                with self.cache_lock:
                    found = self.remembered(key)
                    if found is not None:
                        return found
                    self.misses += 1
                vector = self.ask(provider, query)
                with self.cache_lock:
                    self.cache[key] = vector
                    while len(self.cache) > CACHE_ENTRIES:
                        self.cache.popitem(last=False)
                return vector
        finally:
            with self.cache_lock:
                if self.flights.get(key) is flight:
                    del self.flights[key]

    def remembered(self, key):
        found = self.cache.get(key)
        if found is not None:
            self.cache.move_to_end(key)
            self.hits += 1
        return found

    def ask(self, provider, query):
        """The question as the command asks it: its text is checked, its receipt is committed, and only then is the
        provider asked. The receipt is written with the command's own code, in a transaction of its own that is over
        before the provider is asked."""
        batch = [{"record_id": None, "which_text": "query", "text": query}]
        list(provider.batches(batch))
        writer = Store(self.path)
        try:
            writer.log_egress(batch, provider, "query")
        finally:
            writer.close()
        return tuple(provider.embed([query], "query")[0])

    def status(self):
        snapshot = self.snapshot
        with self.cache_lock:
            cache = {"entries": len(self.cache), "hits": self.hits, "misses": self.misses}
            answers = {"entries": len(snapshot.answers) if snapshot is not None else 0, "hits": self.answer_hits,
                       "misses": self.answer_misses}
        held = 0 if snapshot is None else sum(1 for table in list(snapshot.tables.values())
                                              if not isinstance(table, Exception))
        return {"pid": os.getpid(), "builds": self.builds, "cache": cache, "answers": answers,
                "schema_version": SCHEMA_VERSION, "records": len(snapshot.rows()) if snapshot is not None else 0,
                "vector_models": held}

    def close(self):
        with self.refresh_lock:
            self.close_monitor()
