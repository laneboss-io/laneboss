# Laneboss decision store

The first launcher module keeps questions, context, and the owner's decisions
in one portable SQLite file. It uses Python 3.9+ and the standard library at
runtime. SQLite must include FTS5 and its `trigram` tokenizer (SQLite 3.34+).
No other launcher behavior is implemented here.

## Run

From a checkout, prefix commands with `PYTHONPATH=src`, or install with
`python -m pip install .` to get the `laneboss-decisions` console script.
Packaging uses a conventional build backend; the installed package has no
runtime dependencies. The package as a whole requires Python 3.11, so `pip`
installs it only there; on Python 3.9 and 3.10 run the store from a checkout
with `PYTHONPATH=src`, which needs nothing else.

```sh
PYTHONPATH=src python -m laneboss.decisions init --db decisions.sqlite
PYTHONPATH=src python -m laneboss.decisions add --db decisions.sqlite --file record.json
PYTHONPATH=src python -m laneboss.decisions get --db decisions.sqlite D-22
PYTHONPATH=src python -m laneboss.decisions search --db decisions.sqlite "部署"
PYTHONPATH=src python -m laneboss.decisions search --db decisions.sqlite "" --mode exact --project phase-a
PYTHONPATH=src python -m laneboss.decisions supersede --db decisions.sqlite D-22 --file newer.json
PYTHONPATH=src python -m laneboss.decisions annotate --db decisions.sqlite D-23 --file outcome.json
PYTHONPATH=src python -m laneboss.decisions verify --db decisions.sqlite
PYTHONPATH=src python -m laneboss.decisions stats --db decisions.sqlite
PYTHONPATH=src python -m laneboss.decisions export --db decisions.sqlite --out portable.jsonl
PYTHONPATH=src python -m laneboss.decisions init --db restored.sqlite
PYTHONPATH=src python -m laneboss.decisions import --db restored.sqlite --in portable.jsonl
PYTHONPATH=src python -m laneboss.decisions load --db decisions.sqlite --in batch.jsonl --dry-run
PYTHONPATH=src python -m laneboss.decisions load --db decisions.sqlite --in batch.jsonl
PYTHONPATH=src python -m laneboss.decisions migrate --db old.sqlite
PYTHONPATH=src python -m laneboss.decisions ingest-lane --db decisions.sqlite --config alpha --lane lb-record \
    --attach ledger.md
PYTHONPATH=src python -m laneboss.decisions serve --db decisions.sqlite --socket "$SOCKET"
```

In zsh, a command kept in a shell variable is not split into words: after
`store='python -m laneboss.decisions'`, `$store stats --db decisions.sqlite`
looks for a program whose whole name is `python -m laneboss.decisions` and fails
with exit `127`. Type the plain command, or use a shell function, for example
`store() { PYTHONPATH=src python -m laneboss.decisions "$@"; }`.

Every successful command emits one JSON value. Errors go to stderr. Exit
codes are `0` success, `2` invalid input/refused write, `3` integrity problem,
`4` embedding provider disabled/failed, `5` database busy, `6` permission
problem, and `7` storage problem. A missing database is exit `2`. `init` is idempotent for an existing
store and refuses unrelated databases. Missing databases are not silently
created by other commands.

Exit `5` means another process held the write lock for longer than the
10-second wait. A lock timeout is never reported as corruption. Every command
except `embed` writes in one transaction, so for them the message says that
nothing was changed, and that is true; an `init` that had created the database
file before it failed says that instead (see exit `7`). `embed` commits several
times: the model row, then for each batch the egress receipts, the provider call
and the vectors. If it times out after a commit, the message says what this run
had already stored (the model row, how many egress receipts and vectors) and how
many texts it had already sent to the provider; running `embed` again sends
only the texts that still have no current vector.

Exit `6` means SQLite could not write the database file, or could not create
its rollback journal in the database's directory. It is never reported as an
integrity problem. `verify`, `export` and `migrate` take the write lock, so they
need write permission on the database file even though `verify` and `export`
change nothing; with a writable file they work in a read-only directory.
`migrate` and every command that changes the store also need write permission
on the directory. `get`, `stats`, `egress --list`, `load --dry-run` and
`search` in `exact` or `keyword` mode only read.

Exit `7` means SQLite failed on the storage under the database while it read or
wrote the database file or its rollback journal: the disk is full, a file-size
limit was reached, or the system reported an I/O error. The message says what
is true afterwards, by kind of command:

- A command that only reads (`get`, `stats`, `egress --list`, `verify`,
  `export`, `load --dry-run`, and `search` in `exact` or `keyword` mode; `verify`
  and `export` take the write lock but write no page) says that SQLite failed
  while it read the file, or restored it from the journal of an earlier write
  that did not finish, and that nothing was changed.
- Any other command says that SQLite failed while it read or wrote, because a
  failed I/O call does not say which. SQLite rolls a failed write back from its
  journal (if the failing process cannot finish that, the next process that
  opens the file does), so the command's changes do not reach the store, and the
  message says that nothing was changed.
- Two of them say more. As with exit 5, `embed` names what earlier commits of
  the same run had already stored. An `init` that had created the database file
  names it and says that it is still there and holds no store; running `init`
  again, once the problem is fixed, makes it a store. An `init` of a file that
  already existed changes nothing.

## Schema versions and upgrading

A new store is schema version 4 (SQLite `user_version`). Version 1 is the
layout the previous release wrote, and version 2 the one the release after it
wrote. Versions 2 and 3 keep every earlier version's tables, indexes and triggers
unchanged and add their own. Version 2 adds:

- the `first_written` table: for each record, the SHA-256 of the record exactly
  as it was first written (see "Loading a batch");
- triggers that make SQLite itself refuse to delete or replace a record or
  change its `id` or its row id, and refuse any update, delete or replacement
  of a model row, an egress receipt or a first-written hash. The record guard
  runs on every update of `records`, so it holds however the row id is spelled
  (`row_id`, `rowid`, `_rowid_` or `oid`). A replacement (`INSERT OR REPLACE`,
  `REPLACE`, an upsert, `UPDATE OR REPLACE`) is refused before it starts,
  because SQLite removes the replaced row without firing delete triggers unless
  `recursive_triggers` is on. The existing trigger that keeps
  `answer.verbatim` from changing is unchanged. Vectors and the keyword index
  are derived data and are not protected; `verify` checks them.

Version 3 adds the `lane_records` table, its `lane_keyword_index` (FTS5
trigram, on the row's text) and three triggers that make a lane record
append-only: an update, a delete and a replacement are each refused (see "Lane
records"). Version 4 appends nullable `level` and `instance` columns to both
`records` and `lane_records`, adds scope indexes, and adds the `feedback` table
and its append-only triggers. It retains every earlier trigger and adds a
guard against changing a decision record's scope. Existing JSON, hashes,
verbatim bytes, ids, timestamps and keyword rows are preserved; legacy scopes
are NULL and are excluded by scoped history queries. A new scope supplies both
an integer level (3–6) and an instance name. Nothing upgrades automatically.

`migrate` upgrades versions 1, 2 and 3 to version 4, one step at a time inside
one transaction. Each layout and its data are verified before the next step,
and the complete version-4 result is verified before the version is stamped.
A failed verification or write rolls the migration back. No old record is
rewritten to invent an instance or level.

The layout check compares the stored text of every table, index, trigger and
view (including the tables FTS5 creates for the keyword index and SQLite's
automatic indexes) with the exact definitions of the store's version. Objects
are told apart by type and name, because SQLite lets a trigger share an
index's or a table's name. Any missing, changed or extra object is refused,
statistics tables included. These commands run the check:

- `verify`, and `export`, which verifies before it writes anything (exit 3);
- `migrate` on a version-1, version-2 or version-3 store, before it changes anything
  (exit 3);
- `import`, on the destination store under its own write lock, before it
  writes anything (exit 3): a layout change that another connection makes while
  the import waits for the lock is found there, not mistaken for a fault of the
  imported data; and again in its final verification, where a failure caused by
  the imported data is an invalid import (exit 2);
- `load`, in the verification it runs inside its transaction after the writes
  (a failure exits 3 and rolls the whole batch back); `load --dry-run` does not
  verify.

Every other command checks only the schema version and the records, models
and vectors it reads or writes, so `get`, `search`, `stats`, `egress`, `add`,
`supersede`, `annotate` and `embed` still work on a version-4 store that has,
for example, an extra index. `migrate` on a version-4 store changes nothing,
says so, and does not check the layout; run `verify` for that.

Every command except `migrate` refuses versions 1–3 with exit 3 and a message
that names `migrate`. Migration takes the write lock, verifies each exact
layout, preserves old content, and prints `migrated`, `from_schema_version`,
`to_schema_version`, record/vector/egress counts, and a message. Version-1
records retain the absence of a first-written hash (see "Loading a batch").
A failed check exits 3, a lock timeout exits 5, a permission problem exits 6,
and a failed write exits 7. Migration of version 4 is a no-op. Other versions
are refused by every command, `migrate` included.

### Older layout

Stores written before the egress hash chain also say schema version 1, but
their `egress_log` has no `previous_entry_sha256` column, and their superseded
records do not record their earlier status. `migrate` recognises that exact
layout and refuses it, naming what works:

- With no egress receipts (never embedded, never searched in `vector` or
  `hybrid` mode): export the store with the old release and import that export
  into a new store with this release. The records come over as they are.
- With egress receipts: the egress history cannot be carried into a version-2
  store, and the vectors cannot come without their receipts. Importing such an
  export fails with a message that says so. Its records can still be moved:
  keep the manifest line and the record lines of the old export, set the
  `models`, `vectors` and `egress` counts in the manifest to 0, import the
  result into a new store, and run `embed` again (this sends the texts to the
  provider again and logs new receipts). Keep the old store file and its export
  as the only record of what was sent before. With the old export in
  `old-export.jsonl`:

```sh
head -n 1 old-export.jsonl | sed -e 's/"egress":[0-9]*/"egress":0/' -e 's/"models":[0-9]*/"models":0/' -e 's/"vectors":[0-9]*/"vectors":0/' > records-only.jsonl
grep '^{"record":' old-export.jsonl >> records-only.jsonl
PYTHONPATH=src python -m laneboss.decisions init --db new.sqlite
PYTHONPATH=src python -m laneboss.decisions import --db new.sqlite --in records-only.jsonl
```

The first line keeps the `format` value the old release wrote, and import reads it
(see "Export format"). Run `embed` afterwards, as above.

### Export format

The manifest's `schema_version` is `1` (the export and record schema, not the
database layout) and has not changed. Its `format` is `laneboss-decisions-jsonl`
in every export this code writes. Exports written by earlier code, before the
project had its name, say `sup-decisions-jsonl`. They are rebuild points and stay
importable: import reads both `format` values and refuses every other value
(including a missing one) with `invalid import manifest`. Apart from that value
the two kinds of export are the same format. Version 2 adds two things: each
record line of a record that has a first-written hash carries it as
`first_written_sha256`, and the manifest then states how many do as
`first_written`. Both appear only when there is at least one such record.

- An export written by the previous release (version 1) imports into a version-2
  store as it is; its records get no first-written hash. Exporting that store
  again writes the same file byte for byte, except that the manifest line says
  `laneboss-decisions-jsonl`.
- An export written by the version-2 code before the rename imports with every
  first-written hash, and exporting again reproduces it byte for byte in the
  same way: only the manifest's `format` value differs.
- An export written by this code imports into a version-2 store with every
  first-written hash, and exporting again reproduces it byte for byte.
- An export written before the egress hash chain (the older layout) imports when
  it has no egress receipts. With receipts it is refused, with a message that
  names the cause; the records-only way out under "Older layout" moves its
  records.
- Earlier code does not read an export written by this code: it knows only its
  own `format` value.

An import refuses a record line with any other extra field, a first-written
hash that is not a SHA-256 hex digest, a hash the manifest does not declare,
and a count that does not match.

## Records

`tests/decisions/support.py` contains invented schema-1 records. Required fields are
`id`, `kind`, `asked_at`, `answered_at`, `project`, `area`, nonempty `topics`,
`question.text`, `question.background`, `answer.verbatim`, `answer.channel`,
`scope.applies_to`, `status`, and `provenance` with `recorded_by`, `recorded_at`,
and `sources`. Each source has `path`, a positive `line`, and `sha256_of_line`.
Source paths are references, never implicitly opened. An empty source list is
allowed when the channel/message is the original source.
An optional `line_text` snapshot makes its source-line hash independently
verifiable without reading another file; a mismatched snapshot is refused.

Timestamps use exactly `YYYY-MM-DDTHH:MM:SS`, optionally followed by a
three- or six-digit fraction, and then `Z` or an offset in `+HH:MM`/
`-HH:MM` form. The same grammar applies to search bounds. `schema_version`
defaults to `1`. Kinds: `decision`, `answer`, `instruction`, `preference`,
`correction`, `question_from_owner`, `owner-decision`, `ledger`, `report`,
`board`, `bulletin`. Optional `level` and `instance` supply the immutable org
scope, with both present together. Statuses: `in_force`, `superseded`,
`withdrawn`, `fulfilled`. `scope.applies_to` is a nonempty string or string list;
`reversible` is a boolean. Optional fields retain their original values.

The decoded UTF-8 bytes of `answer.verbatim` are stored independently, without
trimming, case changes, or Unicode normalization. `answer.sha256` is calculated
from those bytes. JSON whitespace/escape spelling is not part of the answer.
Embedded NUL bytes are preserved as well. Missing `answer.message_id` is
returned explicitly as `null`, including in search hits.
Unknown record or sub-object keys are refused. IDs match
`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. `interpreted_as` is always accompanied by
`interpretation_label: "supervisor interpretation"`; it never substitutes
for the owner's words. There is no edit, delete or upsert command. Reusing an
id is refused. `supersede` creates a new record and updates only the old
record's status and backward link, atomically; the old status is retained in
`status_before_superseded`. `annotate` accepts an object
containing only `actions`, `evidence`, and `followups`, appending their lists.
Actions contain an offset timestamp `at` and a `text`; the other lists contain
strings. A duplicate annotation is an additional append, not a silent edit.

## Lane records

A lane's own records have a place beside the owner's decisions. The
`lane_records` table holds one row per source, and `lane_keyword_index` is an
FTS5 trigram index on the row's `text`, the same way `records` has one. The
columns are `row_id`, `id`, `config`, `lane`, `part` (`report`, `events` or
`attachment`), `source_path`, `source_sha256`, `text`, `created_utc` and
`ingested_utc`, `level` and `instance` (NULL for legacy/unscoped rows). The id is stable and names its source:
`<config>/<lane>/<part>/<first 16 hex digits of source_sha256>`. A row is
append-only: an update, a delete and a replacement are refused by triggers, on
the same terms as a decision record.

**Nothing from a lane record leaves the machine.** The owner's data table does
not yet name an embedding provider for lane records, so they are searchable by
keyword only. `embed` reads `records` and never `lane_records`, and a vector or
hybrid search reads `vectors` and `records` and never `lane_records`; no text of
a lane record is embedded, sent to a provider or written to `egress_log`. A
lane record is returned by `search` in `keyword` mode alone.

`ingest-lane` reads a finished lane through the launcher's own records and
writes one row per source:

```sh
PYTHONPATH=src python -m laneboss.decisions ingest-lane --db decisions.sqlite \
    --config CONFIG --lane LANE [--attach FILE ...] [--org-dir ORG --instance NAME]
```

- **The report** is the runner's final message: the bytes of
  `lanes/LANE/output.log` that belong to the lane's latest run, between the
  offsets the run record of that launch keeps (`lanes/LANE/runs/LAUNCH.json`,
  `log.start` and `log.end`). The launcher writes a runner's standard output and
  error to that one file and nothing else does, and the run record is the only
  launcher-written record of which bytes belong to which run, so those bytes are
  the runner's own final message. An empty report is refused: an empty report
  row is never written.
- **The events** are the lane's events from the event store, in order, one
  stored envelope a line of JSON — started, ended, resumed, marks, verdicts and
  the rest of `lane.*`, except the `lane.ingested` receipts. An ingest records
  its own receipt with the lane, and that receipt names the rows the next ingest
  compares; keeping it would change the events source on every ingest, so the
  same lane could never be ingested twice without adding a row.
- **Each `--attach FILE`** is one `attachment` row: the file's bytes as UTF-8
  text. A supervisor's ledger rows are the example.

The command refuses a lane that is running (its records are not yet final) and
a lane that has no readable report. It is idempotent: a source whose SHA-256 is
already stored with its id adds nothing. It prints one JSON receipt
(`lane`, `rows_added`, `rows_existing`, and each row's `id` and `sha256`) and
records a `lane.ingested` event in the launcher's own event store carrying that
receipt, so the lane's history says what was ingested and when. `stats` reports
the table's row count and the triggers present, and `verify` checks every row,
its id and its keyword index row. Export and import do not carry lane records:
they still move the owner's decisions alone.

With an org binding, ingestion reads `level` and `instance` from that
instance's `instance.toml` and requires `--db` to equal the org's configured
history store. It appends feedback for accepted/merged/abandoned marks and
refusals, and for ids previously injected to this instance and later cited in
the report. Rows and feedback are written in one decision-store transaction;
the launcher receipt is appended afterwards to its separate event store. If
that receipt fails, the history rows are already committed and can be
re-ingested safely. The automatic launcher callback records an explicit
failure receipt and preserves the lane's exit status. See [Org history](org-history.md)
for that integration point and the curated-records command.

## Retrieval

All modes accept `--id`, `--project`, `--area`, `--topic`, `--kind`, repeatable
`--status`, `--date-from`, `--date-to`, `--limit` and `--all`. Labels match exactly.
They also accept `--level`, `--instance` and `--scope intersection|own-or-level`.
The default intersects level and instance filters. `own-or-level` requires
both and returns their union, including lane records in keyword mode. A
store is one org's boundary; scoped retrieval never combines stores.
Dates filter `answered_at`, compared in UTC. A date-only lower bound is midnight
UTC inclusive; a date-only upper bound includes the entire day. Full timestamp
bounds are inclusive. `--from`/`--since` and `--to`/`--until` are aliases.
Default status selection is `in_force` and `fulfilled`; `--all` removes that
restriction, and explicit `--status` selects the supplied statuses instead.

- `exact`: the query is an exact id, or an empty string to enumerate filtered
  records.
- `keyword` (default): FTS5 trigram search with each whitespace-separated term
  quoted independently, so operators/punctuation are not interpreted as query
  syntax. All terms must match the same record across its id or either text
  side. Terms under three Unicode characters use case-insensitive substring
  post-filters (Python `casefold`, so `ß` and `ss` are the same short term).
  A repeated term counts once, judged by the rule that term is matched with: two
  short terms are the same when they casefold alike, and two longer terms when
  SQLite's trigram tokenizer folds them to the same text (it lowercases letters
  one by one, so `STRASSE` and `strasse` are the same term, `Straße` and
  `STRASSE` are not). A short and a longer term are never the same. Records are
  ordered by combining per-term ranks: for each term, the records that match
  every term are ranked by that term's best score in any field (BM25 for FTS5
  terms, an occurrence count for substring terms; equal scores share a rank),
  and a record's `score` is the exactly rounded sum over the terms of
  `1 / (60 + rank)`. Scores of different kinds are never compared with each
  other. Id order breaks ties. The order of the terms never changes the hits,
  their scores or their matches.
- `vector`: brute-force cosine similarity against both current text vectors
  for the model in `--config`. Stale vectors are excluded until re-embedded.
- `hybrid`: reciprocal rank fusion of the filtered keyword and vector record
  lists, using `1 / (60 + rank)`, summed over the two lists. Filtering precedes
  ranking; limiting occurs after fusion. Deterministic id order breaks ties.

Each record has two text projections: `q_text` combines question text,
background, options, recommendation and topics; `d_text` combines verbatim,
interpretation, scope and outcome. The id is separately indexed by FTS5 rather
than contaminating the embedding text. Nested values flatten deterministically
with newline separators. Each hit puts the stored record under `record` beside
`score`, `index`, `matched_text` (`question` or `decision`), and all
contributing `matches` (one for each term and field) with their index, text
side, source field and score. In
keyword mode a hit's `score` is the combined rank score described above, while
each match keeps its own raw BM25 or count. Id-only matches are attributed to
the question side with `field: "id"`.

In `keyword` mode a search may also return lane records (see "Lane records").
They are matched with the same rules — every term must match the same lane
record, across its id and its text — and they are ranked and fused with the
decision records in one keyword ranking, so the two kinds are ordered together
and id order breaks ties between them. A lane record's hit puts the stored
record under `lane_record` (not `record`), beside `score`, `index`,
`matched_text` (`lane`) and the same `matches`, whose fields are `lane_id` and
`lane_text`. A `--kind lane_record` filter selects lane records alone; a search
that names a decision record's own field (`--id`, `--project`, `--area`,
`--topic`, `--status`, a date bound) leaves lane records out, because a lane
record has none of those fields. `exact`, `vector` and `hybrid` never return a
lane record: the keyword half of a hybrid search is restricted to decision
records, so no lane-record text is ever put near a vector.

### Time and outcome ranking

`--rank time` applies `relevance × recency × outcome` to every candidate before
`--limit`, in exact, keyword, vector and hybrid modes. Relevance is the existing
mode's score, floored at zero for negative cosine similarity. Recency is
`2 ** (-age_days / half_life_days)`, with future source times treated as age
zero. Defaults are 14 days for lane/ledger/report/board/bulletin cases and 60
days for other decisions; `owner-decision` never decays. Repeatable
`--half-life KIND=DAYS` overrides finite positive half-lives, except owner
decisions. `--now ISO_TIMESTAMP` fixes the clock for reproducible searches.
`--now` and `--half-life` require `--rank time`. Superseded cases are excluded
from time ranking even with `--all`.

The append-only `feedback` table records `case_id`, `event`, `at`, `source`,
and an integrity hash, with a numeric row id. `accepted`, `merged` and `cited`
each contribute +1; `abandoned` and `refusal` each contribute -1. Outcome is
`2 ** reward_sum`, with the sum capped to [-8, 8]. Only events at or before
the search clock count. The same case/event/source is one immutable event;
re-ingestion retains its original time and does not multiply its reward.
Every event is kept, including ones beyond the cap. No feedback edits a case.

```sh
laneboss decisions feedback --db decisions.sqlite CASE_ID --event accepted --source EVENT_REFERENCE
laneboss decisions search --db decisions.sqlite "release" --rank time --now 2026-10-13T00:00:00Z
```

Time-ranked hits include `ranking` with each factor, the clock, half-life and
contributing feedback. Any negative event adds `do_not_repeat: true` and
`warning: "do not repeat"`; negative cases remain candidates with positive
weights. An empty keyword query with time ranking enumerates scoped history
with equal relevance, which lets SessionStart retrieve cases before a prompt
exists. The ordinary keyword empty-query behavior is unchanged.

Decision JSONL exports carry scoped curated and owner decisions as records,
but do not carry lane records or feedback. Preserve the SQLite store when
moving a complete org history, including its rewards.

## Embeddings and egress

No provider is enabled by default. A local deterministic test configuration is:

```json
{"provider":"fake","model":"fake-v1","dimension":128}
```

```sh
PYTHONPATH=src python -m laneboss.decisions embed --db decisions.sqlite --config config.json
PYTHONPATH=src python -m laneboss.decisions search --db decisions.sqlite "deployment" --mode hybrid --config config.json
PYTHONPATH=src python -m laneboss.decisions egress --db decisions.sqlite --list
```

For the required HTTP provider use `provider: "voyage"`, a named
`api_key_env`, optional `endpoint`, `model`, `dimension`, `batch_size`, and
`timeout`. Only the named environment variable is read for its key; config
cannot contain a literal key. The documented default model is
`voyage-4-large`, with 1024 dimensions; 256, 512 and 2048 are also supported.
The official documentation URLs and retrieval date appear in `embed.py`.
HTTPS is required except loopback HTTP for tests. Redirects and implicit
environment proxy routing are disabled; response/error bodies are not logged.
Requests use `input_type: "document"` for stored texts and `"query"` for search.
`output_dtype: "float"` and `truncation: false` prevent silent quantization or
truncation. Batches are at most 1,000 items, conservatively capped at 80,000
UTF-8 bytes; individual texts at 24,000 bytes. Oversize input is refused before
any send. The byte limits deliberately underuse the model's token limits
because no external tokenizer is installed. Provider failures are not retried
automatically.

Two little-endian float32 blobs are stored per record and model, with
dimension, text snapshot and its SHA-256. Models coexist, but changing a
model's provider or dimension requires a new model name. `embed` sends only
missing/stale sides; annotation invalidates the decision side only. Every text
is durably recorded in `egress_log` before provider invocation, including fake
calls and search queries (`record_id: null`, `which_text: "query"`). Receipts
contain the exact text, SHA-256, model, timestamp and endpoint host. Their
hashes form a chain in contiguous numeric id order; `verify` detects a deleted
middle entry, a reordered entry, or a changed link. Truncating only the tail
remains undetectable by a hash chain. This is a write-ahead log of attempted
disclosure, not proof the server accepted it.
Keys are never persisted, printed or logged. The E2E HTTP tests use only a
local stub and invented test secrets; no live API is needed.
Vector hashes are checked before retrieval or cache reuse; corruption is
refused rather than silently used or repaired.

## Resident search

Each run of `search` starts an interpreter, imports the store, opens the file and checks every record before it
searches. On a store of a few hundred records that start is most of the time a search takes. `serve` is one process
that does all of this once and then answers searches over a Unix socket, with the code of `search`:

```sh
laneboss decisions serve --db decisions.sqlite --config config.json --socket "$SOCKET" &
```

`--db` is the store, `--socket` is where to listen, and `--config` is the embedding configuration that `search`
takes: without it a vector or hybrid search fails as the command fails without `--config` (exit 4, provider disabled)
and keyword and exact searches work. `--idle-exit MINUTES` stops the server after that many minutes without a
request (default 60). Once the server listens it prints one JSON line, `{"ok": true, "pid": 4242, "socket":
"/path/to/socket"}`, and then nothing more on standard output. A store that cannot be searched (it is missing, of
another schema version, or fails the checks of a search) ends `serve` with the exit code and the message that any
command gives for it; a socket directory that others can enter, something that is not a socket at the path and a live
server on the socket end it with exit 2, and so does a `--socket` path that is longer than the system takes (104 bytes
on macOS, 108 on Linux: the limit of a Unix socket path). All of this happens before any socket, and before the
socket's directory, is made.

### Asking

A search is a request to `/search`; `curl` sends it with no launcher and no Python:

```sh
curl -sS --fail-with-body --unix-socket "$SOCKET" -G http://localhost/search \
    --data-urlencode "query=backup schedule" --data-urlencode "mode=keyword" --data-urlencode "limit=5"
```

The parameters are the options of `search`: `query` (required; it may be empty for `exact` or time-ranked keyword history), `mode`, `id`,
`project`, `area`, `topic`, `kind`, `status` (as often as wanted), `date-from` (also `from`, `since`), `date-to` (also
`to`, `until`), `limit` and `all` (the value `1` or `true`). They go in the query string (`-G`, above) or, without `-G`, in the
body of a POST, which `curl` sends as a form (up to 1 MiB; the address of a GET is limited to about 64 KB by the HTTP
library, so a longer query goes in a POST). The parameters are turned into the words of the command and read by the
command's own parser. Scope/ranking options `level`, `instance`, `scope`, `rank`,
`now` and repeatable `half-life` are accepted too. Time-ranked answers with a
live clock are recomputed on each request; a fixed `now` is cacheable. Feedback
changes invalidate the resident snapshot and its remembered answers. `/status`
includes `store_id`, the SHA-256 of the real database path, so an org hook can
reject a resident wired to another store before asking it for any cases.
A wrong `mode`, `limit` or date is refused as the command refuses it. A parameter that is not
in the list, a parameter given twice (`status` and `half-life` excepted) and a `config` are refused: the embedding configuration is the
server's own, set when it started, and no request can choose another. `GET /status` shows what the server holds: its
process id, how many times it built its index (`builds`), the records and the schema version of the index, the number
of embedding models whose vectors it holds checked (`vector_models`), the vectors it remembers for questions (`cache`:
`entries`, `hits`, `misses`) and the answers it remembers (`answers`: `entries` on the current copy, `hits`, `misses`).

A search that works is answered with status 200 and, as the body, the bytes that `laneboss decisions search` prints for
the same store, query, mode, filters and limit: the same records in the same order with the same fields. A keyword or
an exact search is answered with exactly the command's bytes, scores to the last digit. A vector or hybrid search is
answered with the command's bytes for the same question vector and the same Python version: such an answer is a
function of the store and of the vector that the provider returns for the question, and a provider may return a
different vector for the same text on another call (`voyage-4-large` does), so two runs of the command can differ, and
a fresh command run can differ from the server, in the scores and in the order of records whose scores are close. The
server asks the provider once per question and answers that question again with the vector it got the first time,
which is what makes its repeated vector answers stable (see "Questions for the embedding provider"). One that fails is
answered with the message that the command prints on standard
error, as the body, and the command's exit code in the header `X-Exit-Code`, under the status that fits it: 400 for 2
(invalid input), 500 for 3, 6 and 7, 502 for 4 (the provider) and 503 for 5 (the store was busy). An unknown path is 404
and a method that is neither GET nor POST is 405. `curl` exits 22 on a status of 400 or more (`--fail-with-body`, which
needs curl 7.76 or newer, still prints the body; `--fail` prints nothing), and exits 7 when there is no server: the
socket is missing, or is the file that a killed server left.
A wrapper that falls back to the command on any failure of `curl` therefore gets the command's own answer, errors
included. This one uses `--fail`, so that when a search is refused only the command prints the message, and two time
limits, so that a server that does not answer is given up on: 2 seconds to connect, and 130 seconds for the whole
request, which is the longest a call to the embedding provider may take (its `timeout` is at most 120 seconds) and a
little more:

```sh
search() {   # search QUERY [MODE [LIMIT]]
    curl -sS --fail --connect-timeout 2 --max-time 130 --unix-socket "$SOCKET" -G http://localhost/search \
        --data-urlencode "query=$1" --data-urlencode "mode=${2:-keyword}" --data-urlencode "limit=${3:-20}" \
        2>/dev/null ||
        laneboss decisions search "$1" --db "$DB" --config "$CONFIG" --mode "${2:-keyword}" --limit "${3:-20}"
}
```

### What the server keeps, and when it looks again

At start the server makes a copy of the store file in memory in one read, checks every record as every `search` does,
and keeps the keyword index (the store's own FTS5 index, so BM25 gives the same numbers) and the vectors of the model
that the embedding configuration names, checked as `search` checks them: before the server says it is ready, and after
a later change in the background, while the request that found the change goes on. (A model that the configuration
names later is checked when a search first needs it.) A search is answered from that copy and holds no lock on the
file. A record or a vector that fails its checks fails the searches that read it with the error that `search` gives,
and at the same place: `search` looks at the dates and the other words of a search before it reads the records, so a
search with a wrong date is refused for its date, damaged store or not; and `serve` does not start on a store with a
damaged record.

Before each request the server looks at the file: which file it is, its size and modification time, and SQLite's own
count of changes made by other connections (`PRAGMA data_version`), which is the reliable part. Nothing is cached in
time: a record that `load` or `add` has written is found by the next search, and so are a supersession, an annotation,
new vectors from `embed`, a store file put in place by rename, and a store that has been deleted (an error, as for the
command, not the old answers). When the file has changed, the server compares the hashes that the store keeps of every
record, model and vector with those of its copy, and makes a new copy only if they differ. A change of the file that is
not a change of an answer does not cost a copy: the egress receipt of a vector question, written by this server or by
any other process, is such a change. A request that started on a copy finishes on it.

The server also remembers the answers it has given, up to 128 on each copy of the store and 16 MiB together. A search is
known by everything that decides its answer on one copy: the mode, the query, the filters, the limit and, for a vector or
hybrid search, the provider and its model. A search asked again on the same copy is answered with the bytes it was
answered with before, with no work and no question to the provider (the question's vector is itself remembered, as the
next section says, for the searches that share a question and differ in anything else). A search that failed is never
remembered, and a new copy starts with no answers, so no answer outlives a change of the store.

### Questions for the embedding provider

The server remembers the vector it got for a question: a repeated vector or hybrid search with the same text, for the
same provider, model, dimension and endpoint, sends nothing to the provider and writes nothing to the store. The text
is compared as it is, to the character. A question is answered again with the vector the server got for it the first
time, so the server's repeated vector answers are stable where the command's are not, until the server restarts or the
vector leaves the 512 it keeps; after that the question is asked again and may be answered from a different vector, so
two answers on one copy of the store (say one with `limit 5` and one with `limit 10`) can then rest on different
vectors. A remembered question is answered while the provider is down, where the command would fail (exit 4). The
server keeps 512 question vectors, in memory only, so a new server asks again, and a question that failed is not
remembered. Two equal questions that arrive together make one request.

A question that is not remembered is asked as the command asks it: its text is checked, its receipt is committed to the
egress log, in a transaction of its own that has ended before anything else happens, and only then is the provider
asked. The receipt is the one the command writes, written by the command's own code. It is the only thing the server
writes to the store: the store is opened read-only for everything else, and a store whose file or directory cannot be
written is served, and answers a vector search that is not remembered with the command's error (exit 6) without asking
the provider. While the provider is being asked, no lock is held and other searches are answered.

### Who can reach it

The server listens on a Unix socket and on nothing else: no network port. The socket has mode 600 whatever the mask of
the process, and the directory it is in must be yours alone (mode 700): `serve` makes the directory with that mode if
its parent exists, and refuses, naming it, a directory that others can enter, without changing it. That path must also
be short, since a Unix socket path is at most 104 bytes on macOS and 108 on Linux: `serve` refuses a longer `--socket`
before it makes anything, so give it a directory of your own with a short path (`$TMPDIR` on macOS,
`$XDG_RUNTIME_DIR` on Linux) rather than one under `/tmp`. `serve` also refuses
a path that holds something that is not a socket, and a socket on which a server answers; the socket that a killed
server left is replaced. A relative `--db`, `--socket` or `--config` is taken from where `serve` started. The key of the
embedding service is read from the environment variable that the configuration names, at each vector search, as the
command reads it; it is never a command-line argument and the server writes it nowhere: not in a reply, not in its
output, not in a file. (It stays in the environment of the process, as in every process started with it.)

The server stops when it has been idle for `--idle-exit` minutes (a request that is being answered is not idle time),
and on SIGTERM, and on SIGINT or SIGHUP unless it was started with them ignored (as `nohup` starts it, which keeps it
running when the terminal closes), with exit code 0, and removes its socket. A server that is killed with SIGKILL
leaves its socket file behind, which is how `curl` comes to exit 7 and how the next `serve` finds the way free.

### Limits

- One server serves one store. It is for Linux and macOS (it needs Unix sockets). It uses only the standard library
  and nothing newer than Python 3.9, the minimum of the decision store; its tests have run on Python 3.12 only.
  `math.sumprod` (Python 3.12 and newer) orders the records where the interpreter has it, and a sum of products where
  not; the ranking test runs both.
- The copy of the store is in memory: the size of the file, and for each vector of the model about 32 bytes a number,
  as Python floats (32 KB for 1,024 numbers).
- Changes are found by the hashes that the store keeps of each record, model and vector, which is what every command
  that writes them changes. An edit made to the file behind the store's back, which leaves those hashes as they were,
  is not noticed until a change that alters a hash; `verify` and the next `search` by the command report such an edit
  as damage.
- A rollback journal that a crashed writer left behind can be rolled back only by a connection that may write, and
  the server only reads: the next command that opens the store with write access does it. No test covers this case.
- Vector scores are computed in two steps, a fast one that orders the records and the command's own expression for
  the scores that are printed and for the order of any records whose fast scores are within 1e-9 of each other; this
  is why the scores are the command's to the last digit.
- The first search after a change of the store builds a new copy, which takes time in proportion to the size of the
  store. Requests that arrive meanwhile wait for the new copy: a request that starts after a change is never answered
  from the older one.
- A search that is not remembered looks at the filters of every record, and a vector search compares the question with
  every current vector of the model, so its time grows with the number of records and, for a vector search, with the
  number of vectors times their size. On one two-core Arm cloud machine the server took about 3 ms for a one-word
  keyword search of 600 records, about 25 ms for a keyword search of twelve words, and about 20 ms for a vector search
  of 1,200 vectors of 1,024 numbers (about 50 ms for 3,000); yours will differ. A search that is asked again costs none
  of this.

## Integrity and portability

`verify` recomputes record, verbatim, projection, vector-blob, model and egress
hashes; validates required metadata, bidirectional supersession and the format
of every first-written hash; checks the exact definition of every table, index
and trigger (see "Schema versions and upgrading"); compares every keyword row
with the record projections; and runs both SQLite and FTS5 internal integrity
checks in one transaction. That transaction takes the write lock before it
reads anything, so a writer that is in the middle of a transaction is waited
for (up to the 10-second wait, then `database busy`, exit 5) and verification
then sees one consistent state. Stale embedding snapshots remain valid history,
but are reported in `stats` and excluded from retrieval. External source-line
hashes without `line_text` snapshots are caller assertions: their format is
validated, not their absent external files. `verify` reports their count as
`source_hashes_unverified`. Provided snapshots are hashed and checked.
Hashes detect accidental corruption, not a malicious writer with permission
to rewrite both data and hashes; the row-protection triggers stop accidental
deletes and replacements by other SQLite clients, but a writer can drop them,
which `verify` then reports. New databases and exports use owner-only file
permissions; existing file permissions are never widened. Neither is
encrypted.

Export is canonical UTF-8 JSONL containing a versioned manifest, all records
with their first-written hashes, models, float32 blobs encoded as base64, and
egress history. It verifies the store and reads everything in one transaction
that holds the write lock, ends that transaction, and only then writes the
output, so a slow reader never holds up other writers. The output is a new
file, created owner-only, or an existing named pipe (FIFO) that has a reader;
any other existing path, a regular file included, is refused to avoid
replacing evidence. A pipe is checked twice: by its path when export starts,
and by the file actually opened before the first byte is written, so a pipe
replaced by a regular file in the meantime is refused and left untouched. Import targets an empty initialized store, validates
everything in one transaction and rolls back completely on an error.
Re-export is byte-identical; source paths are not required on the destination
host. Keep the export private: it includes the owner's verbatim words and past
egress text.

## Loading a batch

`import` needs an empty store. `load --db X --in batch.jsonl [--dry-run]` adds
a batch to a store that already holds records. Each line of the batch is one
JSON object:

```json
{"op":"add","record":{"id":"D-30"}}
{"op":"supersede","target":"D-22","record":{"id":"D-31"}}
```

(the records are shortened here; each is a full record as `add` takes it).
`add` writes a new record as the `add` command does, so the record may not
carry `supersedes` or `superseded_by`. `supersede` writes the new record and
links it to `target` exactly as the `supersede` command does: the target keeps
its answer, gets status `superseded` and `superseded_by`, and its earlier
status is kept in `status_before_superseded`. Anything else is refused: another
`op`, a missing or extra key, a line that is not an object, a blank line,
invalid UTF-8, invalid JSON (a duplicate key is invalid), or an empty file.
Lines end with `\n`; `\r\n` is accepted.

A batch is a set: the order of its lines never changes whether it is accepted
or what it writes. A target may be a stored record or a record that any other
line of the batch writes. A target can be superseded by one record only, a
stored target that is already superseded is refused, and records of the batch
that would supersede each other in a loop are refused. Records are written in
line order, each target right after the record that supersedes it.

The whole file is read and validated first, and the whole batch is planned
against the stored records. Only then is anything written, in one transaction,
after which the whole store is verified as `verify` does; a failure rolls
everything back. A batch is applied completely or not at all. A refusal exits 2,
names the line number and the field or record (for example
`line 3: missing required field: question.text`) and leaves the database file
byte-identical. A write that fails after earlier lines were written, for example
because a trigger refuses it, names its line and record id the same way
(`line 4: record D-33 could not be written: ...`) and also rolls everything
back.

Re-running a batch is safe. Every line that writes an id that already exists,
and every repeated line, counts as `unchanged` when its record is identical; a
`supersede` line also needs its target to be superseded by that record. A
record that differs refuses the whole batch with exit 2 and names the line, the
id and the first field that differs, for example
`line 2: id D-22 already exists with different content (answer.verbatim)`.

"Identical" is decided by the first-written hash. When a record is first
written (by `add`, `supersede`, `load` or an `import` of an export that carries
the value) the store keeps the SHA-256 of the record exactly as written, after
validation filled in its defaults (`schema_version`, `outcome`,
`answer.message_id`, `answer.sha256`, `answer.interpretation_label`) and, for a
`supersede`, set `supersedes`. It is kept apart from the record, so later
annotation and supersession do not change it, and the database refuses to
change or delete it. An incoming line is identical only when the SHA-256 of its
own record, prepared the same way, equals that value. Key order, JSON spelling
and omitted defaults therefore do not matter, and every field does, the answer's
UTF-8 bytes included: a trailing space, LF in place of CRLF, or a composed
accent in place of a decomposed one is a difference. A record that was
annotated after it was first written still re-runs as `unchanged` with its
original line; a line that shortens, empties or omits an outcome list, or that
already contains the annotations, does not.

A matching hash is not taken on its own: the stored record must also still
agree with the line in its answer bytes and in every field that `supersede` and
`annotate` do not change (the comparison described in the next paragraph).
Otherwise the batch is refused, naming the field, because the stored hash does
not belong to the stored record (an import can carry a hash it cannot prove).

Records without a first-written hash (migrated from version 1, or imported
from an export that does not carry it; `stats` counts them as
`records_without_first_written`) keep the earlier, weaker comparison: the
answer bytes, then every field of both records as first written, where a
superseded record's `status` is taken from `status_before_superseded`,
`superseded_by` and `status_before_superseded` are left out on both sides (so
an explicit `null` in either is the same as an absent key, as the previous
release wrote and compared them), and each incoming outcome list only has to be
the start of the stored one, because `annotate` may have grown it. Their ids are listed under
`unchanged_by_weaker_comparison`, so the weaker comparison is never silent. A
superseded record of an older release that did not record its earlier status
cannot be compared: a line for it is refused with a message that says so, and
it must be left out of the batch.

`--dry-run` reads, validates and plans in a read-only transaction and writes
nothing; the file's bytes and modification time stay the same. The output is
one JSON value with `added`, `superseded`, `unchanged`, `records_before`,
`records_after` and `unchanged_by_weaker_comparison` (a dry run also has
`"dry_run": true`). `superseded` counts the supersede lines that wrote a record,
so `records_after` is `records_before + added + superseded`.

`load` never calls an embedding provider and sends nothing anywhere. `stats`
reports `records_without_vectors`, the records that have no vector under any
model; `embed` fills them, and `verify` passes before and after.

## Acceptance and publication checks

```sh
python -m unittest discover -s tests/decisions -t .
sh scripts/scan.sh
```

These are the decision store's own tests. The interpreter needs to be Python 3.9
or newer; nothing beyond the standard library is imported, and the tests never
import the launcher. The system tools are a separate matter: the scanner test
(`ScannerCheckoutTest`) runs `git`, `sh` and `python3` from `PATH`, and the
tests of the resident search (`tests/decisions/test_serve.py`) run `curl`, `sh`
and `ps` (and `lsof` on macOS). `python -m
unittest discover -s tests` runs these tests together with the launcher's
(Python 3.11 or newer). Apart from three groups of tests that import the product
and call it in the test process (`LibraryTest`; `RankingTest` of the
resident search, which holds its ranking and the sums that print its scores
against the command's arithmetic on vectors made to tie, which no store and no
provider would make to order; and `AnswerBoundsTest`, which calls the
bookkeeping of the remembered answers with answers as large as their bound,
which no search over a store that a test can make would give), and one test
(`StandardLibraryTest`) that reads the source of the decision store's modules,
without running them, to check that they import nothing but the standard
library, the tests are black-box
command-line tests: each case creates its databases and files in a private
temporary directory and removes them afterwards, and runs the command with the
test process's own environment, `HOME` included. The tests of the resident
search start `serve` as a process of its own and talk to it over its socket;
the embedding service, which a test machine cannot use, is replaced by a local
stand-in that answers with vectors that depend on the text, checks the bearer
key and counts its requests. A few tests start the command
through `tests/decisions/faults.py`, which installs one fault or one point to
synchronise on (a statement that fails with SQLite's disk I/O error, a marker
file when the command is about to ask for the write lock, the mode of the
server's socket at the moment it is bound) in the command's own
process before it runs; the command has no hook for it. Run them on an
authorized disposable test host, not an editing machine, as an unprivileged
user: the permission tests need file modes to be enforced. Inside a Git checkout
the scan examines tracked files only. Outside Git it examines every file except
those under `.git` or `__pycache__` and the `*.pyc` files. It fails on
private-key headers, contiguous secret-like tokens of 40 or more characters,
IPv4 addresses other than the loopback address, and email addresses. It
reports only path, line and rule, never the suspicious value. Do not store
generated databases, credentials or exports inside the source tree.

Before publication: test the supported interpreter
and SQLite matrix, add portable source-line snapshots if independent provenance
verification is needed, and review any future retention/encryption policy.
The package/provider/model identifiers and official documentation hosts are
required integration names; all decision fixtures are invented and no private
workspace names are used.
