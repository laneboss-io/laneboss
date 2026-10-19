# Laneboss decision store

The decision store keeps questions, context and the owner's decisions in one portable SQLite file.
It runs inside the Go `laneboss` binary, with SQLite and FTS5 included.

## Run

Install with [the Go installer](install.md), then use `laneboss decisions`:

```sh
laneboss decisions init --db decisions.sqlite
laneboss decisions add --db decisions.sqlite --file record.json
laneboss decisions get --db decisions.sqlite D-22
laneboss decisions search --db decisions.sqlite "部署"
laneboss decisions search --db decisions.sqlite "" --mode exact --project phase-a
laneboss decisions supersede --db decisions.sqlite D-22 --file newer.json
laneboss decisions annotate --db decisions.sqlite D-23 --file outcome.json
laneboss decisions verify --db decisions.sqlite
laneboss decisions stats --db decisions.sqlite
laneboss decisions export --db decisions.sqlite --out portable.jsonl
laneboss decisions init --db restored.sqlite
laneboss decisions import --db restored.sqlite --in portable.jsonl
laneboss decisions load --db decisions.sqlite --in batch.jsonl --dry-run
laneboss decisions load --db decisions.sqlite --in batch.jsonl
laneboss decisions migrate --db old.sqlite
laneboss decisions ingest-lane --db decisions.sqlite --config alpha --lane lb-record \
    --attach ledger.md
laneboss decisions serve --db decisions.sqlite --socket "$SOCKET"
```

In zsh, a command kept in a shell variable is not split into words: after
`store='laneboss decisions'`, `$store stats --db decisions.sqlite`
looks for a program whose whole name is `laneboss decisions` and fails
with exit `127`. Type the plain command, or use a shell function, for example
`store() { laneboss decisions "$@"; }`.

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
laneboss decisions init --db new.sqlite
laneboss decisions import --db new.sqlite --in records-only.jsonl
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

`laneboss-e2e:tests/decisions/support.py` contains invented schema-1 records. Required fields are
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
laneboss decisions ingest-lane --db decisions.sqlite \
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
- `lane archive` retains `output.log` and its run records at those paths. Calling
  `ingest-lane` after archival still reads the recorded span and later supervisor
  marks; diagnostic logs may have been collected. The archive's compact receipt
  references its manifest instead of putting a full worktree removal list in
  this event history.
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
laneboss decisions embed --db decisions.sqlite --config config.json
laneboss decisions search --db decisions.sqlite "deployment" --mode hybrid --config config.json
laneboss decisions egress --db decisions.sqlite --list
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
answered with the command's bytes for the same question vector and the same launcher build: such an answer is a
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

- One server serves one store on Linux or macOS, using Unix sockets.
- The resident copy of the store and its vectors are held in memory.
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

## Guiding agents

A recorded decision that no agent reads changes nothing: the lane asks the owner again, or does what the owner already
ruled out. The guide puts an org's recorded decisions in front of its agents in three places. A judge (TypeSafe
through the judge adapter, or another compatible judge) supplies typed probabilities; ordinary guidance observes and warns:

1. every lane brief and every follow-up or turn message carries the decisions that apply to its project and level, in a
   short section that is headed so that it cannot be missed;
2. the org hook asks whether a tool call conflicts with a decision and adds advice;
3. a question that a recorded decision already answers gets the recorded answer back instead of becoming a new question.

It needs an org with a decision store (`laneboss decisions init`, [Org history](org-history.md)). A lane of a
configuration with no org, and an org with no store, behave exactly as before.

### Which decisions apply

A record guides an agent when all of these hold:

- its `kind` is `decision`, `answer`, `instruction`, `preference`, `correction` or `owner-decision`. A ledger, report,
  board or bulletin entry is history, and a `question_from_owner` is a question: none of them is a decision;
- its `status` is `in_force` (a superseded, withdrawn or fulfilled record is not), and its `scope.valid_until`, when it
  has one, has not passed;
- it is in scope. **For a lane** the scope is the lane's project and level: the record's `project` label equals the name
  given to `lane start --project`, and the record has no `level` or the lane's level (`--level`, default 3). A lane
  without a project has no label to compare, so it gets the decisions of every project, or only of the labels that the
  `projects` setting below names. **For the org hook**, which runs inside one org instance and does not know the lane's
  project, the scope is the instance: the record has no `level`, or the instance's level, or its `instance` is the
  instance's name; every project's decisions are considered unless `projects` narrows them. (A decision that
  `org capture-decision` stores carries the project label `org-history` and the level and name of the instance that
  received it: it guides that instance's hook and the projectless lanes of its level, and a lane of a lower level learns
  it from its supervisor's brief.)

### In every brief and every turn

`lane start`, `lane resume`, `lane turn` and `lane adopt` put one section between the org's role text and the task, read
from the store when the message is composed, so a turn carries a decision that was recorded after the lane started:

```markdown
## Recorded decisions that apply to this lane

Project demo, level L3. These are the owner's recorded decisions, and they bind this lane until the owner supersedes
them. Follow each one. Do not ask a question that one of them already answers: use its answer. ...

- **D-22** (owner-decision, answered 2026-10-08T09:04:00Z)
  - Decided: "Never skip approval for the production release."
  - It answered: "May we skip approval for the production release?"
```

The newest decisions come first (by `answered_at`), at most twelve are shown, an answer is cut to 600 bytes and its
question to 240, each text is put on one line, and a final line says how many more decisions apply and how to list them
(`laneboss decisions search --db STORE "" --mode exact --project NAME`). A quoted text that looks like a credential is
withheld. The section never fails a brief: a store that cannot be read puts a notice in its place (with the error
code) that tells the agent to ask its supervisor, and a section that the launcher's credential detector would refuse
as a whole is replaced by a shorter notice, so a recorded decision can never stop a lane from starting. The section
is part of the rendered brief, which the launcher keeps under its hash, so the bytes an agent was given stay on record.

### The dial

The hook runs org policy before decision guidance. Guidance adds advice to an
allowed call. Ordinary decisions and catalog matches have no refusal authority;
refusal authority belongs to the org blacklist policy.
Missing, uncertain or unavailable model results also remain advisory.

Org blacklist entries with `pattern_only = true` use only their deterministic
matcher and are excluded from TypeSafe candidate selection in both the hook and
`org blacklist try`. The default raw-task pack uses this setting; it cannot
consume decision-judge capacity or add unscored warnings to unrelated calls.
Other authored blacklist entries retain their existing scoring behavior. See
[Org hook policy](org-hooks.md#writing-blacklist-entries) for the entry schema.

The guide uses a Noul for one binary proposition: does this action conflict
with this recorded decision? A Noul is the probability of yes, not a measure of
conflict severity. Near 0.5 means the model is uncertain. If a future feature
needs a degree of severity, it should use a Score with concrete ordered levels,
then normalize by the top level index before combining dimensions.

All scoreable candidate decisions and bounded action windows share **one typed request**.
Its named state contains `decisions` (complete id, kind, answer and prior
question text) and `texts` (the action windows or the new question). Every
Noul has the full question in `instructions`, backticked paths such as
`decisions[0]` and `texts[1]`, and `criteria.true`/`criteria.false`
describing a conflict and a consistent or unrelated action. Question IDs only
join answers to code; TypeSafe does not send them to the inference model.

A shell action includes its complete command. A file action includes its path,
new text, every edit in a multiple edit, and remaining input fields as JSON;
`apply_patch` includes its patch. Plain reads (`Read`, `read_file`,
`Glob`, `LS`, `Grep`) are exempt before guide/history loading.

Long calls use up to three 3,500-character windows with 300-character overlap
and a part heading, covering at most 9,900 characters. All windows remain in
the same request. The strongest returned probability is used only if all
windows and complete decision text were evaluated. A longer call is `partial`
even if a covered window returned a high probability. Each decision is screened
separately: a text over 4,000 characters is `cut`, and a credential-shaped text
is `withheld`. Only that decision is excluded; the others remain in one batch
with complete text and explicit paths to the filtered state. An uncovered
decision cannot silently clear its comparison or blind another decision.
Oversized or credential-shaped action windows still affect every remaining
comparison because the action state is shared. An oversized overall batch also
remains unscored. A panic while preparing or asking the advisory batch produces
an unscored notice, never an ordinary-work denial; catalog asks do the same.

At most `max_decisions` decisions are selected, by shared words then recency.
Left-out decisions are explicitly unscored. The internal batch allows at most
36 Noul questions (12 decisions times 3 windows), question IDs of at most 64
ASCII identifier bytes, and 256 KiB of total input. These are application
bounds, not TypeSafe API question-count limits. The API supports many
independent questions per state.

A `request_user_input` call instead asks `decision.answers`: does this
particular recorded decision already settle this question? It uses the same
batch machinery and adds the recorded answer as advice. Explicit
`lane send --ask` and `report --ask` can return an already recorded answer
using the lookup cutoff described below.

Settings in `.laneboss/shared/services/guide.toml` are read on every call.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Disable guide/catalog judging with `false`. |
| `jobs` | `true` | Add catalog advice to baseline-allowed shell calls. |
| `judge` | none | Configured external judge supporting typed batches. Without it, a short notice lists applicable decisions. |
| `configuration` | history configuration | The session's bound configuration defining the judge. |
| `warn_threshold` | `0.5` | Inclusive yes-probability cutoff for advisory context. At 0.5 yes and no are equally likely, so the context asks the agent to review. |
| `refuse_threshold` | `0.85` | Legacy name retained as the decided-answer lookup cutoff. It never authorizes ordinary hook refusal. |
| `jobs_refuse_threshold` | none | Legacy validated setting; it never authorizes catalog refusal. |
| `max_decisions` | `5` | Candidate count, 1 through 12. Left-out decisions get an unscored notice. |
| `unavailable` | `"warn"` | Unscored calls warn. Legacy `"refuse"` is accepted as `"warn"`. |
| `projects` | every project | Limit decision labels in hook guidance and projectless lane briefs. |

Thresholds are policy probability cuts, not medium/high intensity levels.
TypeSafe communicates uncertainty through calibrated probabilities
(docs.typesafe.ai, Concepts, "How to build with TypeSafe").
Validate performance in the target domain; no individual answer is guaranteed.
These defaults have **no measured
domain-calibration claim**. Tune warning and answer-reuse cutoffs against
labeled domain examples and inspect uncertain cases; a stand-in only verifies
transport and policy. Thresholds are finite values in [0,1]. For configuration
compatibility, `warn_threshold` must not exceed `refuse_threshold` or an
explicit `jobs_refuse_threshold`.

```toml
judge = "jev"
warn_threshold = 0.5
max_decisions = 5
unavailable = "warn"
# Optional lookup cutoff; this does not enable hook refusal:
# refuse_threshold = 0.85
```

| Result | Hook behavior |
|---|---|
| Yes probability at or above `warn_threshold` | Allow with decision id, text and probability in `additionalContext`. |
| Probability below the warning cutoff, with complete coverage | Allow with the baseline reason and no decision context. |
| Partial/malformed answers, timeout, nonzero exit, missing judge, cut/withheld state, omitted decisions or unreadable store/history | Allow with an explicit unscored notice and applicable decisions. |
| Malformed/unreadable guide settings | Allow with `config invalid: FIELD` and a settings-error receipt; no judge runs. |
| Missing/disabled guide or no applicable decision | Use org policy. |

A malformed or missing answer invalidates the entire typed batch. The guide
does not treat a missing value as zero. One sent/outcome pair records each
adapter invocation; a batch outcome carries the individual `probabilities`
map and a null scalar probability. Callback receipts retain each decision's
outcome and probability (the legacy field name is `score`), without raw call
text.

The org's policy protects `shared/services`, guide/history definitions,
decision-store journal files and configured judge inputs from agent edits.
Edit policy sources through the org's authorized policy workflow and render.
Guide/catalog judging shares a 30-second context deadline; execution, log locks
and cleanup consume that same deadline. Process execution reserves the smaller
of three seconds or one quarter of the remaining budget for cleanup and outcome
logging. An unavailable result warns. Generated hook
entries use a 60-second runner timeout; re-render after upgrading.

### Laneboss jobs at the hook

For a shell call that passes baseline policy, the org hook also asks whether it does a job on a Laneboss-managed
object that a Laneboss command already does. The catalog describes lane lifecycle, worktrees, event-store and dashboard
jobs; it is not a list of raw commands that the hook can always inspect. The complete catalog is generated from
`internal/cli/syntax.json`, the CLI's expanded command tree
(including commands added in code), and the org's levels and role sources. A newly defined CLI command appears without
editing a second command list. The Go launcher consumes its embedded syntax and needs no Python at hook time;
`scripts/laneboss_jobs.py` generates the same state for standalone use and independent verification.

This tree has bounded adapters for `printf`, ordinary Git forms, explicit-PID `kill`, curl URL/HEAD forms, and selected
tmux operations with an inspectable payload. Unsupported options, dynamic inputs, sqlite3 and other commands can remain
opaque and be refused by baseline rules before a judge is asked. In particular, the L3 lane boundary still refuses raw
network clients, including unrelated curl URLs. The job catalog cannot relax that boundary. Broader unknown-command
behavior belongs to the blacklist integration; do not infer model coverage from the catalog's choices.

`org init` and `org render` manage `.laneboss/shared/services/laneboss-jobs.json` and record it in the render manifest.
Render an existing org after upgrading the CLI or changing its role sources. The catalog records the SHA-256 of the
embedded syntax bytes, exact `org.toml` bytes, the sorted map of hashes of `L3` through `L6` role Markdown and TOML
sources, and the generated job rows. Its fingerprint hashes those four source hashes. Before asking the judge, the hook
regenerates the expected state and compares the whole catalog, so a stale source hash or altered row is not trusted.
The catalog, its source policy paths and every named judge configuration candidate belong to `{hook_paths}`. Protection
is the union of the launcher binding, the guide/history resolver, the independently read `org.toml` `[history]`
configuration, and readable root `configuration` assignments in guide/history service files. An override or resolver
failure cannot remove another source's candidate. A malformed guide retains independently parseable configuration
assignments; recovery skips comments, table-scoped keys and string contents. Source reads use no-follow, non-blocking
opens, regular-file checks and a 64 KiB bound. Unrelated configuration files remain outside this added set.
Edit sources and render; do not hand-edit the catalog
or its manifest.

When `guide.toml` is present and enabled, `jobs` defaults to `true`. The job judge is the same `judge` in the same
`configuration` used for decisions. One ask carries the whole shell command and catalog as TypeSafe state, an `owned`
Noul and a `command` Choice over every generated job plus `none`. The TypeSafe adapter supports both this multi-question
request and typed decision batches. The launcher requires the official model/answers/usage envelope, matching types, complete normalized option probabilities, a selected maximum and finite confidence. The reason comes from catalog purpose text.

The `owned` Noul asks whether the command performs a catalog job on an
object supported by the named `managed_objects` inventory. Its true/false
criteria distinguish recorded managed work from ordinary unrelated shell work.
An empty inventory cannot establish ownership. The inventory is evidence for
advice, not refusal authority.

Catalog results always remain advisory, including an explicit legacy
`jobs_refuse_threshold`. At or above `warn_threshold`, a non-`none` choice
adds a catalog-derived recommendation when Choice confidence is at least 0.5.
Below that confidence floor it adds an uncertainty notice, with no chosen
route and `flagged: false`. The floor is a conservative application default
requiring domain evaluation, not a measured accuracy guarantee. `none` adds
no route even with owned probability 0.99. Low owned probabilities add nothing.
Receipts retain `guard.jobs`, including band, outcome, judge, owned
probability, Choice confidence, the full option `probabilities` and managed
target evidence. The log records no raw command text.

Org policy runs first. A call it denies never reaches either advisory judge.
A stale catalog, unreachable judge, malformed/partial output or timeout adds a
`Baseline only` notice to an allowed call. Missing guide settings use org
policy; invalid settings warn with the field to repair. Ordinary guidance
cannot introduce a refusal by threshold or unavailability.

The managed-object inventory is built lazily once per configuration within one hook invocation. All inspected commands
use that snapshot, and repeated inventory requests reuse it, including a read failure. A new hook builds a fresh snapshot
and rechecks process liveness. This cache does not persist across separate tool calls or renew the guard deadline.

The whole job ask, including owner/log locks and egress handling, gets `min(10 seconds, remaining guard budget)`;
its subprocess also honors a shorter configured timeout. Three seconds inside the ask budget are reserved for process
cleanup and outcome logging, so a lone slow job process may stop around seven seconds. Managed-record lookup and catalog
validation remain within the parent 30-second context. A held log lock returns a timeout notice rather than renewing the
budget. HJ6 exercises the slow process, HJ13 the ten-second job-lock budget, and HJ14 combines a 24-second decision
judge, a slow job judge and a real held judges-directory lock. HJ14 requires an actual timeout receipt, elapsed below
33 seconds and below the rendered 60-second timeout. G18/G19 cover decision timeout and lock outcomes.

Run `sh e2e-rows/check-job-hook.sh` on the authorized disposable Linux machine, or supply its absolute release and
fault-build paths as the two arguments. It retains source bytes, both binaries and hashes, inputs, callback and egress
records, transcripts and the exit code. Require exit 0 and `PASS: job hook rows`. The adapter is a stand-in using the
actual request and random row markers, matching the catalog's existing stand-in approach. These rows do not measure
TypeSafe model accuracy and use no service credentials. Setup first requires a plain allow with jobs off, with
`fixture: the bypass input must pass the baseline` as its failure message. HJ1–3/5/6/8/10 use adapter-covered `printf`
carrying a recorded lane marker, so their assertions concern transport, generated choices and bands. HJ15 retains a
real supported tmux form as a blacklist integration control; the stand-in still supplies no model-accuracy evidence.

| Row | What makes it fail |
|---|---|
| HJ1 high probability | A high owned probability denies ordinary work, loses its advisory catalog route, or omits the actual request/egress outcome. |
| HJ2 warn | The inclusive warning band denies, adds no warning, or omits the generated command. |
| HJ3 nothing | A score below warn changes the baseline reason or adds context. |
| HJ4 control | An unrelated shell call is flagged, its whole actual command never reaches the adapter, or a `none` choice with owned 0.99 on a recorded target changes the plain allow. |
| HJ5 stale catalog | Changed org/role sources or a stale syntax hash reach the judge, lose the baseline notice, or rendering does not restore scoring. |
| HJ6 timeout | A longer configured timeout defeats the fixed cap, missing scoring changes the baseline, the timeout outcome is lost, or the judge leader survives. |
| HJ7 acceptance | Enabling jobs changes a baseline refusal's decision or complete reason, adds context, or makes a judge request for that refusal. |
| HJ8 unavailable | Erroring, unreachable or malformed judging changes the baseline, an out-of-catalog Choice is trusted, or `unavailable = "refuse"` blocks solely for a missing job score. |
| HJ9 generation | The built CLI's catalog differs from the standalone generator, omits source hashes, or a new syntax job needs a hand-maintained list. |
| HJ10 configured dial | A fixed probability ignores the inclusive warning cutoff, or a legacy refusal cutoff introduces a denial. |
| HJ11 advisory policy | A high probability refuses a managed job with default settings or either explicit legacy refusal setting. |
| HJ12 natural controls | Supported unrelated tmux, Git, curl and explicit-PID kill calls fail their baseline control; high probabilities refuse or lose advice, low probabilities warn, or legacy catalog thresholds deny unrecorded targets. |
| HJ13 job lock | A real held judges-directory lock renews the budget, exceeds the job cap or loses its timeout outcome. |
| HJ14 combined deadline | Both actual slow judges fail to receive their marker-bearing requests, a held log lock renews the shared deadline, the job loses its timeout receipt, the response exceeds the rendered timeout, or the slow job leader survives. |
| HJ15 tmux integration | A supported real tmux form fails its baseline control, fails to reach the adapter or stops warning under default catalog policy. Broader forms remain blacklist integration work. |

| HJ16 official response and uncertainty | Missing distributions/answers are accepted, low Choice confidence still recommends a route, or the valid control loses advice. |

The acceptance assertion is HJ7's unchanged `deny`, byte-identical `permissionDecisionReason`, absent
`additionalContext`, and unchanged judge-request count. The `jobs-relax-baseline` mutation is compiled only with
`laneboss_faults`. It deliberately asks after a baseline refusal and replaces that refusal when the judge allows.
The mutation harness requires HJ7 to fail at `HJ7 baseline refusal must remain unchanged`, a real reach marker, and
the unchanged row to pass on the release with the same fault request ignored and no marker. Runtime RED/GREEN evidence
must be collected on Linux before acceptance; static checks alone are insufficient.

### Decided questions

A lane asks its recorded supervisor with `report`; `--ask` marks the file as a question. A permitted lane message can
also carry a question:

```sh
laneboss report --config NAME --file question.md --ask
laneboss lane send --config NAME --lane PERMITTED_LANE --file question.md --ask
```

The decisions considered are those of the authenticated asking lane's recorded project and level. A sender label or
an environment label cannot select another lane's scope. For `lane send`, a supervisor without a sending lane uses the
receiving lane's scope, after the normal message-access check. For `report`, a supervisor uses its recorded level across
projects. The caller identity gate applies before either lookup. The lookup probability is a binary already-answered judgment; its cutoff requires domain calibration.

1. **The same question.** The text is compared with the question of each decision after its lines are joined, its case is
   folded and its closing `?`, `!` and `.` are dropped. A match is answered at once and needs no judge:
   `{"lane": "...", "decided": true, "sent": false, "match": "exact", "score": 1, "judge": "not-asked", "related": [],
   "decision": {"id": "D-22", "kind": "...", "project": "...", "answered_at": "...", "question": "...", "answer": "..."}}`.
2. **Another wording.** When `guide.toml` names a judge, one typed request asks `decision.answers` for each of at most
   `max_decisions` candidates over named `decisions` and `texts` state. A yes probability at or above the legacy lookup cutoff `refuse_threshold`
   answers the question the same way, with `"match": "judge"` and the score; the highest score wins.
3. **Not decided.** The message is sent as `lane send` always sends it, and its result gains `"decided": false`,
   `"related"` (the decisions that scored from `warn_threshold` up to `refuse_threshold`, each with its id and score) and
   `"judge"`, which says what became of the judge: `answered`, `unavailable` (at least one ask got no answer),
   `unconfigured`, `settings-error`, `store-error` or `no-org`. A question that went unchecked is never taken for one that
   was checked.

An answered question is not sent: `lane send` writes no mail or `lane.mailed` event, and `report` calls no channel or
`report.sent` event. When no answer exists, `report --ask` prints a question-check object (`decided`, `judge`, `related`)
followed by its usual per-channel outcomes and preserves the report command's delivery exit codes. Without `--ask`,
both commands keep their ordinary delivery behavior and never consult the guide.

Before either `--ask` command returns a recorded answer, the guide and the caller's credential detector screen
its full question, answer and metadata. If either text looks like a credential, both texts become
`[withheld: looks like a credential]` and the result adds `"withheld": true`. The result still says
`"decided": true` and `"sent": false`: the unsafe text is not echoed or forwarded. Ask the supervisor for a usable,
non-secret rendering of that decision. Clean responses keep their original text and report `"withheld": false`.
Related decision ids are screened as well.

### Proof

The rows in `e2e-rows/test_decision_guide.py` (run `sh e2e-rows/check-decision-guide.sh` on the disposable Linux
machine) drive the installed CLI, real lanes in tmux, the real hook and the real store. Only the vendor program and the
judge are stand-ins. The judge stands in for the TypeSafe service the way rows J4 and J5 of
`test_laneboss_jobs.py` do: the stand-in emits the official model/answers/usage envelope and answers from marker rules applied to the actual named state. G3 includes incomplete and legacy-shape negative controls. These rows prove wiring and policy; they measure no model accuracy.

| Row | What makes it fail |
|---|---|
| G1 brief | The section is missing, is after the task, lacks a decision that applies, carries one that does not (another project or level, superseded, expired, not a decision), lists more than twelve, hides how many it left out, quotes a long answer whole, or a lane without a project gets no section or ignores the `projects` setting. |
| G2 follow-up and turn | A turn or a follow-up is composed without the section, or with the decisions of the lane's start. |
| G3 dial | High/uncertain probabilities fail to warn, low probabilities alter a fully covered call, questions split into separate requests, raw state/reference paths are lost, or batch egress loses individual answers. |
| G4 thresholds | A fixed score does not move between the bands when the thresholds change, or a threshold is not inclusive. |
| G5 no answer | Failed/unknown judging loses its notice, a legacy unavailable setting stops warning, or invalid settings lose their field and receipt. |
| G6 decided question | Recorded-answer lookup loses its answer/scope, unchecked questions appear checked, or question tools are judged as actions, refused by guidance, or lose the recorded advice. |
| G7 controls | The guard acts with no decision recorded, judges a read, ignores `enabled = false` or `projects`, asks about a decision of another level, a superseded, an expired or a non-decision record, an agent that can write the whole org folder can still write `guide.toml`. |
| G8 mutants | A fault build that ignores the thresholds (always allow), drops the warning, omits the section, never echoes a decided question, lets the guard's answer override a refusal of the org's rules, leaves the guard's inputs unprotected, drops the decisions that `max_decisions` left out, judges a long call by its head, takes the answer about a withheld placeholder for a score, or keeps the text of a multiple edit from the judge is not caught by the row that names it, or its restored row does not pass. |
| G9 the guard only adds | An installed-rule or actual L3 lane-boundary refusal (unlisted tool, push, out-of-scope write, uninspectable call, write inside `writable_repos` but outside the recorded worktree, raw curl) is allowed, loses its first line or complete text, carries context or reaches either judge. The matrix runs ten guide states with jobs off and on. |
| G10 the guard's inputs | An agent that can write the whole org folder can remove, move, replace or create `guide.toml`, `history.toml`, the decision store or its journal files, or remove the folder or its parent (by the write tool or by `rm`, `mv`, `truncate` and a redirection), or the guard stops judging after the attempts. |
| G11 left out | Omitted decisions disappear, legacy unavailable settings deny ordinary work, or the selected comparisons stop sharing one bounded request. |
| G12 long calls | Tail content loses its advice, windows create separate requests, complete low-probability controls warn, or beyond-limit text loses its partial notice. |
| G13 withheld text | Credential-shaped state reaches the adapter or passes as scored, the unscored notice disappears, or legacy unavailability denies ordinary work. |
| G14 multiple edit | What a multiple edit writes stays out of what the judge reads. |
| G15 no judge | With a `guide.toml` that names no judge the hook asks anybody, refuses, lists more than the newest three decisions or does not say how many more apply; or it adds anything when there is no `guide.toml`, no decision applies, the guard is off or the call is a read. |
| G16 report ask | A decided report question is delivered, loses its exact answer, uses another lane's project/level, ignores the shared judge dial, or ordinary reports stop delivering. |
| G17 missing/unreadable guide | A missing guide changes the baseline, or an unreadable guide refuses by default or loses its config-invalid warning and settings-error receipt. |
| G18 decision deadline | Slow judging loses its timeout outcome, exceeds the shared deadline, or introduces an ordinary-work refusal. |
| G19 decision lock | A held judges-directory lock exceeds the shared deadline or loses its timeout notice. |
| G20 missing store | An enabled guide loses its store without the unavailable/no-store receipt. |
| G21 scoped cap | More than 1,000 newer records in another project/level hide an applicable decision. |
| G22 judge definition | A broad write scope permits replacing the configured judge definition, or the ordinary-write control fails. |
| G23 default guidance | A high decision probability refuses ordinary work with defaults or either explicit legacy threshold. |
| G24 invalid settings | Malformed guide/history settings block reads or ordinary work, lose their field notice or normalized warning receipt, or query a judge. The fault-only `guide-settings-refuse-all` row must fail its read-exemption assertion and reach its marker before the restored release passes. |
| G25 judge configuration | A launcher binding hides a different judge configuration selected directly by the guide or inherited through history settings; either definition is writable, or the ordinary broad-scope write control fails. |
| G26 independent judge sources | With no binding, an org-only configuration loses protection when the effective resolver is overridden or the guide is malformed; readable guide keys before/after a parse error are lost; or an unrelated configuration is protected, including a name appearing only inside a string. The fault-only `judge-drop-org-source` mutant must fail the first org-source assertion and reach its marker, then the restored release must pass. |

`TestManagedCache` and `TestManagedCacheError` require one inventory load per configuration per hook, fresh loads in a
new hook, unchanged command matching, cancellation checks on cached reads, and reuse of inventory errors. Extra loads,
stale inventories across hooks, changed matches, discarded cancellation or swallowed errors fail these unit checks.
These rows, the new mutant and unit checks require Linux execution; source/static checks are not runtime evidence.
`TestRawJudgeNames` covers valid, quoted and multiline names, recovery before/after errors, and comment/string/table
controls. `TestJudgeSourceBounds` requires exact regular-file bytes and refusal to follow symlinks or read directories,
missing files and oversized sources. Lost/extra names, altered bytes or an accepted unsupported source fail these checks.

### Limits

- The decision judge does not receive the resolved working directory (P2-6). A directory-sensitive decision needs human review; the deterministic baseline still inspects resolved paths.
- Catalog refusal requires recorded target evidence. Unregistered dashboard addresses and targets not represented by those records remain advice-only even at a high score. Judge programs and their external dependency files still require operator-controlled write permissions; the configuration definition is protected.

- The hook does not know a lane's project, so it considers the decisions of every project unless `projects` narrows it.
- A judge's answer is a probability, not a proof: a conflict can score low and a harmless call can score high. The
  thresholds trade one error for the other, and the egress log and the callback receipts show what each call scored.
- Only the call's own text is judged. A command that builds its arguments at run time is judged by what the hook can
  read, which is the same text the org rules inspect.
- The decisions' texts go to the judge, and so do the calls' texts, after the credential screen of the judge
  machinery; a judge that sends them over a network sends them there. Use a judge that suits the data.
- Each judged call costs one judge ask for each decision asked about and each window of the call (one window up to 3,500
  characters, at most three), so the cost and the latency of a call grow with `max_decisions` and with the call's length.
- A call that is not scored (a judge that is down, a long call, a credential-shaped text, a decision left out) is warned
  about by default, and a warning is advice: an agent that ignores it carries on. The legacy setting
  `unavailable = "refuse"` is accepted as the same warn-only behavior. The maximum is 12; with more than 12 applicable
  decisions, narrow `projects` or supersede decisions if the notice is too broad.
- The guard reads at most 1,000 applicable in-force records after applying project, level and instance filters in SQL. Other scopes cannot consume this cap. A further applicable row is detected and the hook receipt records scope_capped; remaining records are not claimed to have been checked.

- A store that `[history] db` puts outside `shared/services` is not covered by the protected set (see above).
- Whoever can run `laneboss decisions` can supersede or withdraw a decision, which changes what the guard enforces. The
  protected set stops an agent from editing the store's files; an org whose rules let an agent run that command lets it
  change the decisions, so keep it out of agents' rules.

## Acceptance and publication checks

The black-box harness is moving to a separate e2e repository. On an authorized disposable machine,
build the single binary and set `LANEBOSS_BIN` to its absolute executable path. The decision harness
runs `LANEBOSS_BIN decisions`; its existing per-group Go selection remains available.

Tests that directly import retired product modules or inject interpreter faults need migration in
that repository. They are not runtime checks of the Go binary. Run permission tests as an unprivileged
user, with temporary stores and no production credentials.

Run `scripts/scan.sh` before publication. Do not store generated databases, credentials or exports in
the source tree. The publication scanner retains its separate interpreter requirement.

The referenced black-box files live in the separate `laneboss-e2e` repository. Run its commands there with `LANEBOSS_SRC` set to an absolute laneboss checkout. Go unit tests remain `go test ./...` in this repository.
