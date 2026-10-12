"""Literal keyword, cosine and reciprocal-rank-fusion retrieval.

Everything a search does is here, in terms of a Reader: the few questions it asks of the stored data. The command's
Reader asks the file each time. The resident search (resident.py) has a Reader that answers the same questions from
what it kept in memory, so the ranking, the fusion and the form of a hit are the same code for both.
"""

import copy
from datetime import datetime, timedelta, timezone
import math
import re
import sqlite3

from .embed import embed_query, provider_from_config
from .schema import InvalidInput, SIDES, timestamp


class Ranked:
    """Records in rank order, each with its score and its matches (the evidence for its rank)."""

    def __init__(self, ranking, grouped, scores):
        self.ranking = ranking
        self.grouped = grouped
        self.scores = scores

    def matches(self, identifier):
        return self.grouped[identifier]

    def score(self, identifier):
        return self.scores[identifier]


class Fused(Ranked):
    """The reciprocal-rank fusion of several rankings: 1 / (60 + rank), summed over the rankings in order, ids
    breaking ties. A record's matches are those of each ranking that lists it, in the order of the rankings."""

    def __init__(self, parts):
        scores = {}
        for part in parts:
            for rank, identifier in enumerate(part.ranking, 1):
                scores[identifier] = scores.get(identifier, 0.0) + 1.0 / (60 + rank)
        Ranked.__init__(self, sorted(scores, key=lambda identifier: (-scores[identifier], identifier)), None, scores)
        self.parts = [(part, set(part.ranking)) for part in parts]

    def matches(self, identifier):
        found = []
        for part, members in self.parts:
            if identifier in members:
                found.extend(part.matches(identifier))
        return found


class Reader:
    """What a search asks of the stored data. This is the command's reader: it reads the file and checks what it
    reads every time it is asked."""

    def __init__(self, store):
        self.store = store

    def records(self):
        """(row, record) for every stored record in id order. Each record is checked as it is read."""
        for row in self.store.rows():
            yield row, self.store.checked_record(row)

    def answered_at(self, record):
        return timestamp(record["answered_at"], "answered_at")

    def hit_record(self, record):
        """The record as it goes into a hit: a copy, so that nothing done with a hit can change what is read next."""
        return copy.deepcopy(record)

    def folded(self, row, column):
        return row[column].casefold()

    def query(self, sql, parameters):
        """The rows of a query on the keyword index."""
        return self.store.connection.execute(sql, parameters)

    def lane_records(self):
        """(row, record) for every stored lane record in id order. Each record is checked as it is read. A lane
        record is text kept for keyword search only; it is never a document a vector or hybrid search may use."""
        for row in self.store.lane_rows():
            yield row, self.store.checked_lane_record(row)

    def lane_folded(self, row, column):
        return row[column].casefold()

    def lane_query(self, sql, parameters):
        """The rows of a query on the lane records' keyword index."""
        return self.store.connection.execute(sql, parameters)

    def vector_ranking(self, query, eligible, provider, depth):
        """The records with a current vector of the provider's model, by cosine similarity to the query's vector.
        `depth` is how many records of the top the caller will look at, or None for all of them: this reader
        always ranks all."""
        ranking, grouped = rank_records(vector_matches(self.store, query, eligible, provider))
        return Ranked(ranking, grouped, {identifier: grouped[identifier][0]["score"] for identifier in ranking})


def date_bound(value, upper=False):
    if value is None:
        return None
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        try:
            parsed = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
            return parsed + timedelta(days=1) if upper else parsed
        except ValueError as error:
            raise InvalidInput("invalid search date") from error
    return timestamp(value, "search date")


def filtered_records(reader, arguments):
    start = date_bound(arguments.date_from)
    end = date_bound(arguments.date_to, upper=True)
    end_exclusive = bool(arguments.date_to and len(arguments.date_to) == 10)
    if start and end and (start > end or (end_exclusive and start == end)):
        raise InvalidInput("date-from must not be after date-to")
    eligible = {}
    for row, record in reader.records():
        if arguments.status:
            if record["status"] not in arguments.status:
                continue
        elif not arguments.all and record["status"] not in ("in_force", "fulfilled"):
            continue
        if any(getattr(arguments, field) is not None and record[field] != getattr(arguments, field)
               for field in ("id", "project", "area", "kind")):
            continue
        if arguments.topic and arguments.topic not in record["topics"]:
            continue
        answered_at = reader.answered_at(record)
        if start and answered_at < start:
            continue
        if end and (answered_at >= end if end_exclusive else answered_at > end):
            continue
        eligible[record["id"]] = (record, row)
    return eligible


KEYWORD_COLUMNS = (("id", "question"), ("q_text", "question"), ("d_text", "decision"))
# The columns of a lane record that a keyword search reads, and the side they are reported under. A lane record
# has one text; both its id and its text are matched.
LANE_KEYWORD_COLUMNS = (("id", "lane"), ("text", "lane"))


def lane_eligible(arguments):
    """True when this search may return lane records. Lane records are text kept for keyword search only, so they
    are returned by keyword mode alone, are selected by `--kind lane_record`, and are left out of every search that
    is restricted to a decision record's own fields."""
    if arguments.mode != "keyword":
        return False
    if arguments.kind not in (None, "lane_record"):
        return False
    return not any(getattr(arguments, field) is not None
                   for field in ("id", "project", "area", "topic", "status", "date_from", "date_to"))


def filtered_lane_records(reader, arguments):
    if not lane_eligible(arguments):
        return {}
    return {record["id"]: (record, row) for row, record in reader.lane_records()}


def quoted(term):
    return '"' + term.replace('"', '""') + '"'


def same_fts_term(left, right):
    """Whether the trigram tokenizer folds two terms to the same text, answered by SQLite itself: each term must
    match the other as a document. The tokenizer folds every character to exactly one character, so terms of
    different lengths always differ, and equal folded texts are exactly the ones that contain each other."""
    if left == right:
        return True
    if len(left) != len(right):
        return False
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE VIRTUAL TABLE fold USING fts5(text, tokenize='trigram')")
        connection.executemany("INSERT INTO fold(rowid, text) VALUES (?, ?)", ((1, left), (2, right)))

        def contains(rowid, term):
            return connection.execute("SELECT 1 FROM fold WHERE fold MATCH ? AND rowid = ?",
                                      (quoted(term), rowid)).fetchone() is not None

        return contains(2, left) and contains(1, right)
    finally:
        connection.close()


def distinct_terms(query):
    """The query's terms with repeats removed, by the same rule each term is matched with: a term under three
    characters is a case-insensitive substring (Python casefold), a longer one an FTS5 trigram phrase."""
    kept, short, long_terms = [], set(), []
    for term in query.split():
        if len(term) < 3:
            if term.casefold() in short:
                continue
            short.add(term.casefold())
        elif any(same_fts_term(term, other) for other in long_terms):
            continue
        else:
            long_terms.append(term)
        kept.append(term)
    return kept


def term_matches(reader, term, eligible, lane_eligible_records=None):
    """Every place one query term matches an eligible record: its id, question text or decision text, and, when
    lane records take part, the id or text of an eligible lane record."""
    lane_eligible_records = lane_eligible_records or {}
    matches = []
    if len(term) < 3:
        folded = term.casefold()
        for identifier, (record, row) in eligible.items():
            for column, side in KEYWORD_COLUMNS:
                count = reader.folded(row, column).count(folded)
                if count:
                    matches.append({"id": identifier, "index": "keyword:substring", "text": side,
                                    "field": column, "score": float(count)})
        for identifier, (record, row) in lane_eligible_records.items():
            for column, side in LANE_KEYWORD_COLUMNS:
                count = reader.lane_folded(row, column).count(folded)
                if count:
                    matches.append({"id": identifier, "index": "keyword:substring", "text": side,
                                    "field": "lane_" + column, "score": float(count)})
    else:
        literal = quoted(term)
        for column, side in KEYWORD_COLUMNS:
            expression = column + " : " + literal
            rows = reader.query(
                "SELECT id, bm25(keyword_index) AS score FROM keyword_index "
                "WHERE keyword_index MATCH ? ORDER BY score, id", (expression,))
            for row in rows:
                if row["id"] in eligible:
                    matches.append({"id": row["id"], "index": "keyword:fts5", "text": side,
                                    "field": column, "score": -row["score"]})
        for column, side in LANE_KEYWORD_COLUMNS:
            expression = column + " : " + literal
            rows = reader.lane_query(
                "SELECT id, bm25(lane_keyword_index) AS score FROM lane_keyword_index "
                "WHERE lane_keyword_index MATCH ? ORDER BY score, id", (expression,))
            for row in rows:
                if row["id"] in lane_eligible_records:
                    matches.append({"id": row["id"], "index": "keyword:fts5", "text": side,
                                    "field": "lane_" + column, "score": -row["score"]})
    return matches


def competition_ranks(best):
    """Rank ids by descending score: tied ids share a rank and the next rank skips (1, 2, 2, 4)."""
    ranks = {}
    previous = None
    rank = 0
    for position, (identifier, score) in enumerate(sorted(best.items(), key=lambda item: (-item[1], item[0])), 1):
        if score != previous:
            rank = position
            previous = score
        ranks[identifier] = rank
    return ranks


def keyword_ranking(reader, query, eligible, lane_eligible_records=None):
    """Records that match every whitespace-separated term, ordered by the combined per-term ranks.

    Each distinct term (see distinct_terms) ranks the records that match all terms by the term's best score in
    any field (BM25 for terms of three or more characters, an occurrence count for shorter ones), so scores of
    different kinds are never compared with each other. A record's score is the exactly rounded sum (fsum) of
    1 / (60 + rank) over the terms; ids break ties. Nothing depends on the order of the terms.
    Returns (ranking, evidence, scores).
    """
    lane_eligible_records = lane_eligible_records or {}
    terms = distinct_terms(query)
    per_term = []
    for term in terms:
        matches = term_matches(reader, term, eligible, lane_eligible_records)
        if not matches:
            return [], {}, {}
        per_term.append(matches)
    common = set(eligible) | set(lane_eligible_records)
    for matches in per_term:
        common.intersection_update(match["id"] for match in matches)
    if not terms or not common:
        return [], {}, {}
    contributions = {identifier: [] for identifier in common}
    found = {identifier: [] for identifier in common}
    for matches in per_term:
        best = {}
        for match in matches:
            if match["id"] in common and match["score"] > best.get(match["id"], float("-inf")):
                best[match["id"]] = match["score"]
        ranks = competition_ranks(best)
        for identifier, rank in ranks.items():
            contributions[identifier].append(1.0 / (60 + rank))
        for match in matches:
            if match["id"] in common:
                found[match["id"]].append((ranks[match["id"]], match))
    scores = {identifier: math.fsum(values) for identifier, values in contributions.items()}
    evidence = {}
    for identifier, entries in found.items():
        entries.sort(key=lambda entry: (entry[0], -entry[1]["score"], entry[1]["text"], entry[1]["field"],
                                        entry[1]["index"]))
        evidence[identifier] = [match for rank, match in entries]
    ranking = sorted(scores, key=lambda identifier: (-scores[identifier], identifier))
    return ranking, evidence, scores


def vector_matches(store, query, eligible, provider):
    model = store.connection.execute("SELECT * FROM models WHERE model = ?", (provider.model,)).fetchone()
    if model:
        store.checked_model(model)
    if not model or model["dimension"] != provider.dimension or model["provider"] != provider.name:
        raise InvalidInput("model has no compatible embeddings; run embed with this config first")
    candidates = []
    for row in store.connection.execute("SELECT * FROM vectors WHERE model = ?", (provider.model,)):
        vector = store.checked_vector(row, provider.dimension)
        if row["record_id"] not in eligible:
            continue
        side = row["which_text"]
        current = eligible[row["record_id"]][1]
        hash_column = "q_sha256" if side == "q_text" else "d_sha256"
        if row["text_sha256"] == current[hash_column]:
            candidates.append((row, vector))
    if not candidates:
        return []
    query_vector = embed_query(store, provider, query)
    query_norm = math.sqrt(sum(number * number for number in query_vector))
    matches = []
    for row, vector in candidates:
        norm = math.sqrt(sum(number * number for number in vector))
        score = sum(left * right for left, right in zip(query_vector, vector)) / (query_norm * norm)
        matches.append({"id": row["record_id"], "index": "vector:" + provider.model,
                        "text": SIDES[row["which_text"]], "field": row["which_text"],
                        "score": max(-1.0, min(1.0, score))})
    return sorted(matches, key=lambda match: (-match["score"], match["id"], match["text"]))


def rank_records(matches):
    grouped = {}
    for match in matches:
        grouped.setdefault(match["id"], []).append(match)
    return sorted(grouped, key=lambda identifier: (-grouped[identifier][0]["score"], identifier)), grouped


def search(store, arguments, reader=None, provider=None):
    """The hits of one search. `provider` is the embedding provider a vector or hybrid search asks, made by the
    caller when it has one to make (the resident search makes it once for a request, so that the provider it knows
    the answer by is the provider that answered); where it is None, the configuration is read here, as the command
    reads it."""
    reader = Reader(store) if reader is None else reader
    eligible = filtered_records(reader, arguments)
    lane_records = filtered_lane_records(reader, arguments)
    query = arguments.query
    if not isinstance(query, str) or "\x00" in query:
        raise InvalidInput("query must be text without NUL")
    query.encode("utf-8")
    if arguments.mode == "exact":
        matches = [{"id": identifier, "index": "exact", "text": "question", "field": "id", "score": 1.0}
                   for identifier in eligible if not query or identifier == query]
        ranking, grouped = rank_records(matches)
        result = Ranked(ranking, grouped, {identifier: 1.0 for identifier in ranking})
    else:
        keyword = vector = None
        if arguments.mode in ("keyword", "hybrid"):
            keyword = Ranked(*keyword_ranking(reader, query, eligible, lane_records))
        if arguments.mode in ("vector", "hybrid"):
            if provider is None:
                provider = provider_from_config(arguments.config)
            if not query.strip():
                raise InvalidInput("vector and hybrid queries cannot be empty")
            vector = reader.vector_ranking(query, eligible, provider,
                                           None if arguments.mode == "hybrid" else arguments.limit)
        if arguments.mode == "hybrid":
            result = Fused([keyword, vector])
        else:
            result = keyword if arguments.mode == "keyword" else vector
    hits = []
    for identifier in result.ranking[:arguments.limit]:
        evidence = result.matches(identifier)
        if arguments.mode == "hybrid":
            strongest = next((match for match in evidence if match["index"].startswith("vector:")), evidence[0])
        else:
            strongest = evidence[0]
        common = {"score": result.score(identifier),
                  "index": arguments.mode if arguments.mode == "hybrid" else strongest["index"],
                  "matched_text": strongest["text"],
                  "matches": [{key: value for key, value in match.items() if key != "id"} for match in evidence]}
        if identifier in eligible:
            common["record"] = reader.hit_record(eligible[identifier][0])
        else:
            # A lane record: text the launcher kept for keyword search, returned under its own label and never
            # embedded or sent anywhere.
            common["lane_record"] = copy.deepcopy(lane_records[identifier][0])
        hits.append(common)
    return hits
