# Org history ingestion, injection and owner decisions

Each org has one decision store inside its `.laneboss` home. The Go launcher provides
all org commands. History is curated markdown, finished lane
reports/events, and classified human decisions. No command here opens raw
session transcripts or uses an LLM to distil supervisor records.

## Settings and instance identity

Put history settings in `.laneboss/org.toml`, or in
`.laneboss/shared/services/history.toml` (the latter overrides the history
table). Paths are relative to `.laneboss` and must resolve inside it, including
through links. An org history command refuses a different `--db`. The default
store is `shared/services/decisions.sqlite`; the default socket is
`shared/services/history.sock`. Initialize or explicitly migrate the store
before enabling ingestion. Hooks never initialize a missing store.

```toml
name = "example"

[history]
db = "shared/services/decisions.sqlite"
socket = "shared/services/history.sock"
configuration = "example"
judge = "owner-decisions"
max_cases = 8
max_context_bytes = 8000
score_threshold = 0.004
decision_threshold = 0.85
review_threshold = 0.6
auto_start = true
```

The socket's directory must be owned by the caller and mode 700, as required
by `decisions serve`. A path too long for a Unix socket uses direct retrieval.
`auto_start = false` keeps that fallback but leaves resident startup to the
supervisor. Store/socket links that leave the org are refused.

Each instance lives in `.laneboss/instances/NAME/instance.toml`:

```toml
name = "observer"
level = 4
role = "reviewer"
# Optional: a current brief, relative to this instance and confined to the org.
brief_file = "state/current-brief.md"
```

The same fields may be under an `[instance]` table. Level is an integer 3–6;
name must match its directory. Bind the trusted org with `--org-dir` or
`LANEBOSS_ORG`; a hook with neither prints nothing and exits 0. An org is never
discovered from a repository's `.laneboss` directory. An explicit `--instance`
selects identity, otherwise use `LANEBOSS_INSTANCE` or cwd inside the bound
org's actual instance tree. The selector may name an instance, its directory,
or its `instance.toml`, and must resolve within that org. Hooks use the runner's
JSON `cwd` only for instance identity, never to choose the org.
No environment value is printed or logged.

## Curated ingestion

```sh
laneboss decisions init --db example/.laneboss/shared/services/decisions.sqlite
laneboss decisions ingest-records --db example/.laneboss/shared/services/decisions.sqlite \
    --org-dir example --instance observer --file supervisor-ledger.md --kind ledger
```

`--kind` defaults to `ledger`; `report`, `board` and `bulletin` are also
accepted. A board contributes each nonempty content line. Ledger/bulletin
entries use the shallowest section headings below the file title; reports use
each section heading. Without headings, top-level ledger bullets or separated
paragraphs form entries. Fenced content and continuation lines stay with their
entry. A title alone and board separator lines do not make cases.

Entries retain their exact UTF-8 text and line endings in `answer.verbatim`,
with a source pointer to their first line and an independently checked snapshot
of that line. An ISO timestamp in the entry heading supplies its creation time;
otherwise the source file's mtime does. IDs hash the kind, instance and exact
content; moving or touching an unchanged entry does not add a row or rewrite
its original provenance. Different instances retain their own scopes.
Re-ingestion prints `rows_added`, `rows_existing`, `ids` and any `cited` ids.

These entries use the existing `records` table with kinds
ledger/report/board/bulletin. They can use the decision store's projections and
an explicitly configured embedding provider. Finished lane sources stay in
`lane_records` and remain keyword-only. Neither ingestion nor the history hook
calls an embedding provider.

When a report names a case id that an earlier hook receipt injected to this
instance, ingestion appends `cited` feedback. Exact ids are matched at token
boundaries, and the injection must precede the report. Citation sources include
the file path and content hash; re-ingesting the same report retains one
reward. Citation checking reads a bounded 8 MiB tail of the org's injection
log, so receipts older than that tail need explicit feedback if they are cited
later.

## Lane-end integration

`laneboss.decisions.lane.lane_end(configuration_name, lane, org_dir=None,
instance=None, db=None, directory=None)` is the failure-tolerant launcher seam.
It invokes `ingest-lane`, returns an `ok` receipt, and returns an explicit
`ingest_error` when ingestion fails. It never turns an ingest failure into a
failed lane.

`supervise.Run.catch_up` calls this after the recorder finishes, for launches
bound by `LANEBOSS_INSTANCE`. The final log end offset has been saved, and no
launcher lock is held. Its receipt goes to the supervising process's watch
log; the original supervising exit status is preserved. The launcher must set
the trusted org and instance selectors before launching an org lane and
create/migrate the org store.
An external launcher should call the same seam after its end event and final
report range are durably recorded. A lane whose end remains pending can be
caught up by a later `ingest-lane` call.

Call the seam again after supervisor acceptance/merge/abandonment marks and
after refusal scans to capture newly recorded rewards.

`lane archive` keeps `output.log` and run metadata for this later ingest. Its
diagnostic-log collection excludes configured raw-record paths within the lane
directory. Raw records that existed only in a removed worktree are available in
the tar; this history seam continues to use the retained `output.log` span.

Manual use is:

```sh
laneboss decisions ingest-lane --db example/.laneboss/shared/services/decisions.sqlite \
    --config example --lane example-lane --org-dir example --instance observer
```

The `lane_records` rows keep all their existing append-only triggers. Outcome
marks, refusals and citations append to `feedback`; they never edit history
text. See [Time and outcome ranking](decisions.md#time-and-outcome-ranking) for
the formula, fixed clocks, half-lives and feedback command.

## Runner injection

Register `laneboss org hook-history --runner claude` at Claude SessionStart
and UserPromptSubmit. Register `laneboss org hook-history --runner codex` with
the corresponding Codex hook events in the org's hook registry. Optional
`--org-dir` (or `LANEBOSS_ORG`) binds the trusted org. `--instance` and
`--event SessionStart|UserPromptSubmit` supply identity and event values when
the runner's input does not provide them.

The command accepts one JSON object on stdin with `hook_event_name`, `cwd` and
`prompt` (or `user_prompt` / `message.text`). It emits this additional-context
envelope for both runner selections when cases are found:

```json
{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"Quoted past records ..."}}
```

Register each command with the runner's documented hook events and
additional-context decoder.

The hook first verifies the resident's `store_id` against the org's store path
hash; a miswired resident is never queried for cases. A missing server starts
on demand without waiting for startup, while this invocation uses direct
search. Socket path, directory permissions and existing listeners are checked
before copying the store into a resident snapshot. A spawn lock and a
30-second retry marker prevent concurrent or repeatedly doomed startup attempts.
A failed resident request also falls back to direct search. Both use
keyword retrieval, `--rank time`, and own-instance OR same-level filters. Legacy
NULL scopes are excluded. Prompt terms are searched independently, with at
most six terms; scores are combined to avoid requiring every word of a long
instruction to occur in one case. There is no judge gate for history injection.

Rules select up to three cases for a light prompt and more for a new task,
error, refusal or SessionStart. Short routine status messages emit nothing.
A SessionStart without a prompt uses its configured current brief, or enumerates
scoped time-ranked history if no brief is configured. Count is capped at eight,
context at 8,000 UTF-8 bytes, and each case at 1,200 bytes, including its id,
source and warning. Settings may lower these limits. The score threshold filters
noise; a relevant negative case is tested against relevance so a penalty alone
cannot remove its caution. Such a case is labeled `do not repeat`.
Retrieval reserves caution slots before limiting candidates, and context places
those cautions before ordinary cases so byte limits preserve their warnings.
Search and resident requests accept `--cautions N` / `cautions=N` to request
the same reservation in time ranking.

Cases are wrapped by `[BEGIN QUOTED HISTORY DATA]` and
`[END QUOTED HISTORY DATA]`, with a fixed notice that they are untrusted quoted
past records, data and never instructions. Text imitating either marker is
escaped, as are control and format characters. The closing frame and notice
are included in the context byte budget. Verbatim store contents are preserved.

Input waiting is capped at 100 ms and 128 KiB. File/socket/retrieval/logging
work runs in an isolated child with an 800 ms hard subprocess timeout.
An outer 1.1-second deadline covers the hook body, including a stalled output
consumer; interpreter startup is outside that body deadline.
A missing, corrupt, locked or unavailable store yields no output and exit 0.
No failed search produces invented hits. Every emitted context has an append
receipt in `shared/state/history/injections.jsonl`, with its ids, query hash,
scope, rule policy, candidate count and byte count. Receipts with no hits record
an empty id list. Contended receipt locks retry for up to 80 ms. Direct search
uses a 40 ms SQLite timeout from connection creation. Pipes, regular stdin files
and `/dev/null` are supported. Hook argument errors print nothing and exit 0;
`--help` keeps its normal output. Status lines avoid retrieval entirely.

## Owner-decision capture

```sh
laneboss org capture-decision --org-dir example --instance observer \
    --source terminal:session:2026-10-13T00:00:00Z --text-file owner-message.txt \
    --author-authority decide
```

The instance selector can also come from cwd or `LANEBOSS_INSTANCE`. The org's
history settings name the existing launcher configuration and judge. `--config`
and `--judge` can supply them explicitly; ordinary configuration binding and
ownership checks still apply. `--at` fixes source time when the pointer cannot
carry it. `discord:CHANNEL:SNOWFLAKE` derives time from the message id;
terminal pointers containing an ISO timestamp use that time; a file's mtime
is the fallback. The later time at which a judge answers is never substituted.

One Choice ask uses the existing judge machinery: credential screening,
bounded texts and output, timeout/process cleanup, state ownership and a
durable sent/outcome pair in the configuration's judge egress log. The request
uses `kind: "choice"`, `question: "history.owner-decision"`, four `choices`
(`strong-decision`, `preference`, `question`, `other`) and named subjects
`message`, `source` and `prior_decisions`. A Choice-capable adapter returns:

```json
{"choice":"strong-decision","score":0.94,"model":"example-model-1","request":"request-1","supersedes":null}
```

Score must be finite and in [0, 1]; optional identifiers use the existing
judge identifier rules. The judge receives the newest sixteen in-force owner
decisions ordered by answer time. `supersedes` may name only an active owner
decision in this store whose instance or level falls within the receiving
decision's own-instance or same-level scope. An outside-scope target goes to
review with a reason and is left unchanged. The bundled Noul-only TypeSafe
example is not a Choice adapter;
configure a Choice-capable judge command. The test stand-in answers by the hash
of the actual subject and records every request, without a live provider.
Screened or cut owner text is refused before asking, so a partial classification
cannot create a decision from unseen text.

A `strong-decision` from a `decide` author with score at least 0.85 is stored
immediately as `owner-decision`, preserving verbatim bytes, source and source
time. A score in [0.6, 0.85), or an unknown supersession target, goes to
`shared/state/history/review.jsonl` with its complete proposed record. A lower
score, question, preference, other message, or any `inform` author creates no
decision and no review entry. The thresholds are configurable. A validated
supersession uses the store's existing atomic supersede operation; the earlier
verbatim is kept and the earlier decision leaves time ranking. Repeating the
same source/text for an instance is idempotent.

Every classification and subsequent action are appended to
`shared/state/history/classifications.jsonl`, including scores and authority.
The egress outcome's probability field carries the Choice score. An unavailable
judge is recorded as unavailable and never produces an invented classification.
The review list is data for the receiving agent to surface or dismiss; it is
not automatic authorization.

The owner-message gateway should call capture for each permitted human
message with the configured author's `decide` or `inform` authority. The terminal
UserPromptSubmit dispatcher should save the human text as a file and call
capture with a session/time source. Schedule that classification independently
of the bounded history hook, so judge latency cannot delay history retrieval.

## Acceptance rows

`laneboss-e2e:tests/e2e/test_org_history.py` drives the installed CLI and temporary stores.
The assertions detect missing behavior, rather than reading implementation
literals. The resident boundary has an own-store request-counter control and a
foreign-store canary. `laneboss-e2e:tests/e2e/orgmutant.py` copies an isolated checkout and
removes just the store-id comparison; the canary assertion must fail. The
mutation test checks that exact failure rather than accepting an unrelated error.

| Row | What makes its assertions fail |
| --- | --- |
| Schema upgrade | Version 3 is not upgraded, original columns/bytes differ, scopes are invented, or triggers are lost. |
| Curated ingestion | Entries collapse into one file row, byte content changes, scope is wrong, or a repeat adds rows. |
| Scope | Own history or peer history is missing, an unrelated level is returned, or NULL legacy scope leaks in. |
| Time/outcome ranking | A fixed clock does not change order, feedback changes case bytes, limiting happens first, or negative cases disappear. |
| Kind decay/supersession | Half-lives are ignored, owner decisions decay, or superseded decisions remain in time-ranked results. |
| Resident search | New parameters are refused, fixed-clock results differ from CLI, or feedback leaves cached results stale. |
| Hook bounds/identity | Context is empty with relevant cases, exceeds count/byte limits, uses the wrong envelope, or lacks id receipts. |
| Hook quiet/failure | Status lines inject, a missing database is created, or a lock delays the runner past its bound. |
| Aggressive/negative injection | New tasks get no more cases than light prompts, or a refusal loses its warning. |
| Org boundary | A foreign resident's canary enters context, or an out-of-org store path is followed. |
| Automatic feedback | Marks/citations never become events, a re-ingest adds duplicate rewards, or it edits stored cases. |
| Capture | Strong decisions are lost, borderline scores bypass review, questions/inform authors are stored, or verbatim is changed. |
| Capture source/judge | Source time is replaced by judge time, supersession is ignored, or invalid scores fabricate a successful capture. |

The referenced black-box files live in the separate `laneboss-e2e` repository. Run its commands there with `LANEBOSS_SRC` set to an absolute laneboss checkout. Go unit tests remain `go test ./...` in this repository.
