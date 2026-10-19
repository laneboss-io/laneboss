# Authenticated local dashboard

Run `laneboss dashboard --config example --port 0` and open the address printed on
stdout, including its per-run `#t=...` token fragment. Omitting `--port` also chooses a free port. The server binds only to
`127.0.0.1`; the optional `--bind` flag accepts only that exact address. Stop the
server with Ctrl-C. No dashboard request starts, stops, marks or scans a lane.
Human messages and false-block reports are its guarded write actions.

## Demo

[Capture instructions, captions and image embeds](assets/README-shots.md) describe
four screenshots from a synthetic `demo` org with `shop-api` and `shop-web`.
The script uses a held stand-in, records L3–L5 roles and actual
CLI lifecycle events, and runs the human dashboard under a Python pseudo-terminal
on a disposable Ubuntu box. It makes no authenticated AI-service request.
Headless Chromium captures the real dashboard; PNGs are published only after the
images, rendered source text and OCR output pass the publication scan and review.

The page includes its own CSS and JavaScript, supports light and dark mode, and
refreshes all panels every five seconds. It fetches only its own local JSON
endpoints. A failed refresh marks the affected panel as unavailable and labels
any retained data as stale. Empty panels show the absence of recorded data.

The theme defaults to the system colour setting and follows changes live.
System / Light / Dark offers complete light and charcoal palettes for panels,
charts, timelines, dialogs and focus indicators. Theme and language preferences
are stored in localStorage through guarded reads/writes; blocked storage keeps
the page usable. The token is never stored there.

EN / 中文 switches every interface label through one en/zh-TW message table.
Browser zh-TW, zh-Hant and zh-HK default to Traditional Chinese; other languages
default to English. Intl formats numbers and timestamps with the selected
locale, including a timezone. Product/model names, IDs, code and message bodies
are marked recorded data and remain literal. Language-key/argument parity tests
and a rendered text/attribute audit detect missing translations.

The hero is a live org graph. Each configured instance, supervisor and recorded
lane retains its own principal node ID. Models
stay at their full recorded names; unrecorded state/model/activity is labelled
explicitly. Running nodes pulse gently; recorded failures use a failed colour.
Node sparklines count events in five-minute buckets over the last hour. The level
rail shows a numbered level only when the source explicitly records it. Lanes
without a level appear in “Lanes · level not recorded” / “泳道 · 未記錄層級”,
grouped under a recorded starter when present. The human is the root, and numbered
bands descend from the highest recorded level. `/api/graph` exposes the human
`root`, missing-supervisor `groups`, and each node's `parent`. A lane links to its
recorded starter's node ID or `human`; missing supervisor records use the
“Unrecorded supervisor” group. Configured instances/supervisors sit under the human
and explicitly show that they have no recorded supervisor unless their latest
heartbeat records a `starter`. A heartbeat may record `state` (running,
verifying, idle, ended or failed) and `starter`, alongside its instance/supervisor,
runner and model. These are observations, not permission grants: the graph uses
only an explicitly recorded parent whose principal node exists, never a self
parent or a relationship guessed from the level. Absent fields remain unknown.
For lanes, `level`, `level_source` and `starter` come from the latest start/adopt
record; old missing fields stay
null. `level_source` is `protocol` for the protocol's own L3 lane, `org` for a
higher level that the org's role policy chose (`lane start --level N` with the
org's role template at that level), and `supervisors` or `instance` for a level
that an older start read from a configured supervisor or org instance by name.
A missing starter's report line points to the human without inventing a
starter or a numbered level. Lane-start writers are maintained separately.

Open a node to read its lifecycle, screened thinking timeline, messages and recent refusals,
or send through the existing token/Origin-guarded endpoint. Thinking is muted and
italic; assistant messages use ordinary text; tool chips expand to capped,
screened input/output and recorded status/exit codes. Matching tool-use/result
IDs share a chip. Follow keeps new items in view, while paused timelines preserve
their position and open disclosures.

The lifecycle table reads the latest 1000 events for the selected lane and shows
Time / Step / Who / Recorded details in sequence order. It includes start, adopt,
resume, turn, stop, accepted, merged, abandoned, clean and lost records. The API
retains the envelope's `actor`; the display labels `laneboss` as Launcher and
keeps other recorded principal IDs literal. Missing actors remain unrecorded.
The Messages panel also shows `report.sent` addressed to `human`.
The file owner channel receives only these human-addressed reports, under the
configuration's state directory; reports to a recorded supervisor do not append
the owner file.

The standalone report/dashboard rows are in `e2e-rows/test_report_dashboard.py`.
On the disposable Linux box, supply `LANEBOSS_BIN` and `LANEBOSS_FAULTS_BIN` for
the release and tagged binaries, then run `python3 e2e-rows/test_report_dashboard.py`.
R7 uses real PTYs and role tickets, reaches recorded L3–L6 lanes through the
dashboard, and checks 401 without a token, cross-supervisor refusal and refusal
to open a dashboard from a real lane process. Its human-exception mutant must
deny deliveries and fail the normal delivery assertion. R8 creates real CLI
lifecycle steps and checks their actors and graph parents against the API.
The shared caller/peer implementation and its writer wiring must be integrated
before these rows can pass; compilation does not establish that acceptance.

GET /api/now supplies running lanes, vendor turn receipts attributed to the last
five minutes, last-hour refusals, lanes idle over 15 minutes while running,
recorded decision changes today in UTC, and current kernel disk free. Sources
and target IDs accompany each signal. Clicking filters the graph or opens the
relevant panel. Turn timing uses vendor timestamps when recorded, otherwise the
recorded run boundary, as in Analytics; incomplete usage stays partial. Historical
running/stuck values replay the CLI projection reducer in event sequence, with
recorded-at timestamps determining when records became available and last-event
times supplying idle detection. Missing history stays null. Disk history appears
only where stored records contain free_bytes; the current reading creates no
synthetic curve.

GET /api/graph supplies hero nodes and last-hour activity. Both new endpoints use
the existing authentication and screen. Panels share a verified SQLite snapshot.
Ownership marker, directory identity, database/journal identity, size or mtime
changes invalidate it; unchanged sources receive a full integrity read again
after 30 seconds. It writes no index, database or projection. This reduces
duplicate reads. Startup prepares the verified snapshot before advertising the
URL. Each refreshed snapshot precomputes graph node bindings and sorted activity
timestamps; graph requests use range counts without parsing events again.
Graph `Server-Timing` reports current snapshot/request rendering time separately
from `last_verify` and `last_index`, which describe the most recent preparation.
The 200 ms first/repeated HTTP response target is unchanged. Startup preparation
and a complete refresh have their own costs; a response target pass does not
claim those costs are below 200 ms. Org metadata refreshes with the snapshot,
at most 30 seconds after an unchanged store.

Analytics adds an outcome area, p50–p90 latency bands labelled by runner/model,
a rule/hour refusal heatmap and model token bars. Hover and keyboard links show
exact values and filtered sources; event source queries also accept outcome.
Decisions draws recorded supersession chains as linked graphs and retains its
own search/verifier. The page shows no shortcut hint in its header. Press ? (with
focus outside a text field) to open a small panel that lists the shortcuts; Escape,
its Close button or ? again dismisses it, and ? does not open it over another
dialog. The shortcuts are / to search agents, g then o for the live org, g then a
for Analytics, and g then d for Decisions. They stay inactive while editing and
while the panel is open. The panel's text is in the one message table, in English
and zh-TW.
Pause live stops polling/motion. Hidden tabs cancel reads and stop polling and
animation, then resume on visibility. Reduced-motion preferences disable motion.
Stable graph/timeline nodes preserve focus and disclosure state on refresh.

The test-box rows use the real CLI writer to create 200 lanes and 10,000 events,
then check initial/repeated response bounds. The optional installed-Chromium row
is `python3 -m unittest tests.e2e.dashboard_browser.BrowserTest.test_graph_screenshot_and_console`.
It calibrates console detection with a real console.error control before checking
the recorded graph node set and no console output at laptop/phone widths. PNGs
remain in a temporary directory prefixed lb-dashboard-browser- for collection.
A missing browser reports NOT DONE, with no skipped pass. Compilation does not
establish runtime latency, frame rate, console, screenshot or source-immutability
results.

The presentation row is
`python3 -m unittest tests.e2e.dashboard_browser.BrowserTest.test_themes_and_locales`.
It creates records through the real CLI for usage, refusals, decisions, messages,
judge answers, proposals and tools, opens a recorded timeline and employee ledger,
then audits both locales with both themes. It checks computed palette/graphic,
placeholder and focus colours, actual page reload persistence, live system changes,
blocked storage, the title and `lang`, every panel's body and full-document PNG
dimensions. It calibrates literal detection with unmarked DOM text, contrast with
an unreadable computed colour and panel detection with a hidden real panel. PNGs
remain under a temporary directory prefixed `lb-dashboard-presentation-`.
The Go rows `TestMessageLanguages` and `TestUnrecordedGraphLevel` check both
languages/arguments and the graph's recorded metadata, including missing-language
and all-L3 negative controls. These rows must run on the disposable Linux box;
their presence and successful compilation do not establish runtime passes.

The Org panel shows configured supervisors, and instances and enabled levels when
a structured org tree is connected. Runner bindings come from supervisor
configuration or recorded runs/heartbeats. Models are full recorded names; an
unrecorded model displays a dash. No model is inferred from a routing default.
Instances named `L5-top`, for example, can use the configuration's supervisor
named `top`.

The Lanes panel reads the same stored projections used by the CLI. Running lanes
display as running, the stored verifying state displays as verifying, waiting or
queued lanes display as idle, and settled lanes display as ended. The JSON also
includes `recorded_state` for the original CLI state. Budget left is calculated
from the current run's real start event and budget; inactive lanes have no live
budget. Last exit refers to the most recent recorded run exit.

Activity lists the newest 100 events with operational payload summaries capped at
200 Unicode characters. It omits commands, prompt text, mail contents, environment
tables and file contents. Refusals come from the `lane.refusal` events already
recorded by the launcher's hook/guard scanning. Opening this panel does not run a
scan. Health uses the same kernel disk reader as `laneboss disk`, without updating
the disk latch or recording an event. It shows the newest recorded heartbeat per
supervisor when events with a `.heartbeat` kind name a `supervisor` or `instance`.

Every string in JSON output passes the event command's existing credential/value
screen. A detected value becomes `[withheld]`. Event summaries screen the entire
payload before truncation. The display reader still verifies canonical event
payloads and their hashes, and opens SQLite in read-only mode. A corrupt or
unreadable store produces HTTP 503 instead of fabricated data. The normal event
CLI keeps its existing policy of refusing credential-shaped stored values.

## Optional org and board settings

Add this section to the selected configuration's `config.toml`:

```toml
[dashboard]
org = "/srv/example/org"
board = "state/board.md"
```

`org` is the absolute folder created by `laneboss org init`. If it is omitted,
the dashboard uses the configured organisation directory when that directory
contains a structured `.laneboss/org.toml`; otherwise it shows the configuration's
supervisors. `board` is a Markdown file relative to the configuration directory.
Its path must stay within that directory, including through symbolic links. It is
read only when explicitly configured. Neither path can be supplied in an HTTP
request. Leave out either setting when that source is absent.

The board uses a Markdown table with the four headings `ID`, `Status`, `Due` and
`Title`, in any order. IDs must be unique. Due values are a date in `YYYY-MM-DD`,
an RFC3339 timestamp, a dash or empty. A date becomes late after that UTC day has
ended. Completed, closed or cancelled items are not marked late. Escaped pipes in
titles are supported. Malformed rows and invalid due dates produce HTTP 503.

```markdown
| ID | Status | Due | Title |
| --- | --- | --- | --- |
| B-1 | queued | 2026-11-01 | Review the next milestone |
| B-2 | done | - | Complete the handoff |
```

## JSON endpoints and checks

Read endpoints accept GET only. Every other method on those paths returns HTTP 405 with
`Allow: GET`, after authentication and before any configuration or state read. Unlisted paths return 404,
unrecognised query options return 400, and a foreign Host header returns 403.
Responses disable caching and do not allow cross-origin reads or framing.

| Endpoint | Result |
| --- | --- |
| `/api/org` | Org name, levels, instances and configured supervisors |
| `/api/lanes` | Lane state, runner, model, start, budget, last event and last exit |
| `/api/events?limit=N` | Newest events first; default 100, accepted range 1–1000 |
| `/api/refusals` | Newest 100 recorded refusals, with rule, lane, time and text |
| `/api/board` | Configured board items, with a computed `late` boolean |
| `/api/health` | Disk free/used and newest supervisor heartbeats |
| `/api/messages` | Human/agent and agent/agent recorded messages, each newest 100 |
| `/api/judge` | Newest recorded judge asks joined with their outcomes |
| `/api/plugins` | Installed launcher plugin metadata and manifest health |
| `/api/logs?lane=NAME&tail=N` | Parsed recorded vendor timeline; tail defaults to 200 and is at most 2000 lines |
| `POST /api/messages/send` | Deliver a screened human message through a lane inbox or instance-addressed event |
| `/api/analytics?window=1h|24h|7d` | Recorded lifecycle, duration, usage, refusal, stuck, seat and event-volume measurements |
| `/api/decisions?q=TEXT` | Decision list/search, chains, exact integrity result, recorded changes and citations |

Analytics scans the selected event window and a prefix capped at 8 MiB per run.
Lines over 2 MiB are drained and skipped; later complete receipts remain usable.
Skipped lines, a byte cap or the 8192-receipt cap mark usage as partial. The
ledger and Analytics expose skipped-line, scanned-byte and cap metadata. A
handler-owned cache deduplicates simultaneous run reads and keys retained
receipts by run, file identity, size, modification time and recorded bounds.
It holds at most 64 entries and a 32 MiB accounting budget for encoded receipts
plus per-record overhead. Cancellation reaches usage, output, judge, registered
message/history logs and SQLite snapshot reads, and interrupts cache waiters.
It does not sample the log tail. Completed run
usage is attributed to its recorded end time when the vendor has no timestamp;
active run usage uses the start time and remains partial. Timestamped receipts
from runs overlapping the window use their vendor timestamps directly. Per-hour links respect both the bucket and the
selected window. Event IDs and recorded run/log-line references accompany the
metrics. Missing measurements are null and display as no data; a recorded zero
remains zero. Percentiles use the nearest-rank definition over all recorded
values. Lane durations come from lane.ended, turn durations from vendor result
duration_ms or explicit turn runs, and first commit/report times only from
recorded commit/report or report-ingestion events.

Token totals use the vendor's input_tokens and output_tokens fields. Cached use
comes from Codex cached_input_tokens or Claude cache_read_input_tokens, while
USD cost is reported only when total_cost_usd exists. There is no inferred
pricing. Totals, per-lane/run rows, per-model/account aggregates and a top-10
table retain partial markers when usage is unavailable. Refusals and noisy-rule
counts come from lane.refusal; repeated failures require at least two consecutive
matching ended reasons/exits. Stuck detection uses the latest recorded event
while a lane is running, with a default 15-minute threshold, adjustable through
idle_minutes. Seats count the recorded vendor turn/result receipts by account.

Decisions reads decisions.sqlite in the selected configuration's state directory.
Create/populate that store with the real decisions CLI and that --db path. The
endpoint does not accept a database path from HTTP. It opens the source read-only,
creates an in-memory SQLite snapshot with the existing driver, and runs the
same decision-store record checks, keyword search and verifier as the CLI.
Verification's rollback-only FTS command runs in memory, leaving the source
database unchanged. The list includes every recorded status; chains use the
recorded supersedes/superseded_by links. Changes count recorded provenance dates
and feedback events, not undocumented edits. Recorded cited feedback supplies
usage counts and source labels; a lane is named only when that source matches a
known lane. Lookups that were never persisted have no usage count. An exact
record ID uses the store's exact search; other text uses keyword search. Integrity
problems preserve the CLI's problem text after the secret screen. Both new panels
clear their charts when the endpoint fails instead of displaying old measurements
as a successful refresh.

Every data request is authenticated on the server. The page's token header is
`X-Laneboss-Token`. Release responses issue no cookie, and a cookie alone never
authenticates a request. Tokens are random 256-bit values unique to a server run.
The Host must exactly match the printed loopback address and port. A send also
requires Origin to equal that HTTP origin. Missing or invalid tokens return 401.
A foreign Host or Origin returns 403. These refusals have no API body detail,
and no CORS headers are sent.

A URL fragment never reaches HTTP. The initial navigation returns the static,
data-free document with status 200. Its script reads the fragment token once,
removes the fragment with history.replaceState, and keeps the token inside its
closure. Every fetch sends the header and omits cookies. Source links fetch with
that header and show records as text in a dialog. Without a token, the document
shows “Open the latest dashboard URL.” and starts no refresh. No token is put
into a cookie, local storage or session storage. Only theme and locale choices
use localStorage. Reloading requires the latest
dashboard URL again.

CLI actor/sender names beginning with `human` are reserved, ignoring case.
`event append` rejects reserved actors and explicit sender/role metadata; `lane
send --from` rejects reserved senders. A `lane send` records the caller the
launcher resolved (`lane:NAME`, `supervisor:NAME`, `instance:NAME`, or `human`
for a terminal human) as both sender and actor, and `--from` must equal it.
CLI refusal reports use `cli`. Only the dashboard's internal write path supplies
`human (dashboard)` (instance-addressed messages and refusal proposals); its
messages to a lane are recorded as the `human` principal. Event-store message
rows display the stored `recorded_at` timestamp, while registered channel
records retain their intrinsic timestamps.

The human is the only caller that may start the dashboard or write from it.
`laneboss dashboard` resolves its caller like every other command and starts
only for the human (a controlling terminal that is not a lane pane). A lane, a
supervisor, an instance or a process that cannot be identified is refused with
exit 2 before any port opens, so none of them ever holds a token. The compose
box and the refusal report endpoint also check that the server's principal is the
human, and a message to a lane goes through the peer rule, which lets the human
reach a lane at any level.

The Messages compose box lists all configured instance/supervisor levels and
known lanes. Sending accepts only JSON with `to` and `text`, at most 8 KB total
and 4000 Unicode characters of nonempty text. Credential-shaped outgoing text is
refused with 422 before touching state. Unknown targets return 404. Eligible
turn-based lanes receive mail through the same code as `lane send`, as the
`human` principal: sender and recorded actor are both `human`. The event holds
its recorded time, lane target and byte length. A lane that cannot receive inbox
mail refuses delivery with 409. Other known instances/supervisors receive an
instance-addressed `owner.message.received` event through the existing event-store
append path, visible through `event tail`, with human actor, target and lengths.
The page reports that a message was recorded; it does not invent an agent read
acknowledgement. No dashboard-private queue or file is created.

Logs selects only known targets and reads the fixed `output.log` recorded under
their laneboss lane state. An instance can use its matching recorded lane name or
the same level/name binding used by the org view. If there is no recorded lane
log for that target, the response says `available: false`; no other tool's files
are consulted. Traversal names, unlisted query fields, escaping links and devices
are refused. Log reads are bounded to the last 16 MiB, with partial first lines
dropped, at most 2000 selected raw lines and 2000 timeline entries.

The timeline parses Claude stream-json thinking, assistant text, tool-use inputs
and tool-result status/tails, and Codex exec JSON reasoning, agent messages,
command execution with exits/output tails, and errors. Unknown event kinds show
one bracketed type. Every raw line and decoded event passes the existing secret
screen before extraction; a hit withholds that whole line. Oversized events are
also withheld. Display text is capped at 1000 characters. User-input text and
nested tool-input prompt/environment documents are not expanded in the timeline.
The Logs panel refreshes with the page while Follow is selected; selecting a target while paused fetches
one tail without starting follow.

Messages has Human ↔ agent and Agent ↔ agent tabs. It reads message records
already in the selected event store, hash-checked files announced by
`lane.mailed`, and the registered orgdiscord role event logs in each instance's
laneboss `state/` folder. A record's file/path fields cannot select another file.
No tool's home, settings, private inbox or credential file is read. Brief and
resume delivery events show their recorded metadata without opening prompt
files. The drawer labels those rows Brief delivered, Follow-up delivered or
Mail delivered; those labels do not invent message bodies. For a textual
instruction, `lane send --file` retains inbox text for turn-based lanes. Ordinary
resume inputs remain prompt metadata: an org can also record a screened
`supervisor.message.sent` event with its actual `from`, `to` and `text`, and
deliver that same file through `lane resume`. Message text is screened before a
500-character cap. The page previews
160 characters and uses a native More disclosure for the remainder of that cap.

The event board accepts `lane`, `kind` and `level` filters, applied before the
`limit`. Levels are 3–6. The event's own level wins, followed by its lane's most
recent start/adopt record available at that event. Unscoped instance/supervisor
events can use their explicitly named configured principal's level. This applies
to end, resume, state and clean events without
their own level; a later reused lane's level never rewrites earlier rows.
An event without a recorded level shows one non-wrapping `—`; the tooltip gives
the full localized “Level not recorded” label.
Metric source URLs also accept `runner`, `model`, `account`, `rule`, `since` and
`until`, using recorded run metadata and RFC3339 times before the display limit.
A lane's missing level, including delivery metadata before its first start,
stays unknown. A name shared with a configured supervisor does not supply a
lane's level. Add `view=board` to
receive an object with `events`, `counts_last_hour` and `since`. Hourly counts
cover matching events before the display limit and use their occurred time, or
recorded time when there is no occurred time. The default response remains the
original event array. The page shows controls for all three filters and hourly
counts by kind.

On the disposable Linux box, the new row is
`python3 e2e-rows/test_report_dashboard.py ReportDashboardTest.test_r9_event_level_cells`
with `LANEBOSS_BIN` naming the supplied release binary and Playwright/Chromium
installed. It makes real L3/L4 lifecycle records and checks the API and rendered
level cells in English and zh-TW. Missing inherited-level, verbose unknown-level
and wrapping DOM controls must fail the same assertions before the actual rows
pass. The Go rows
`TestEventBoardRecordedLevels`, `TestHeartbeatGraphMetadata` and
`TestCompactEventLevelMarkup` cover inheritance/filtering, explicit heartbeat
metadata and source rendering, with negative controls. Source checks do not
establish a runtime pass; these rows run on the box.

The Refusals panel requests `/api/refusals?view=groups`. It groups persisted
refusals by effect, rule, employee and level, with hourly counts, first/last seen
and screened examples. Effect labels come from the recorded refusal message;
an unresolved effect is `unknown_opaque`. They do not determine permissions.
The plain `/api/refusals` response remains compatible with earlier clients.

`POST /api/refusals/report` requires the current dashboard authentication,
exact Host and matching Origin. The JSON body selects exactly one `refusal`
or `rule`, optionally an `effect`, and includes a nonempty `note` of at most
4000 characters. The whole request is capped at 8 KiB and screened for
credentials. A report appends one `rule.proposal` event with recorded examples,
refusal IDs, employees, counts and the human note. Rule-group reports include
all employees matching that effect/rule; the form states that scope.
The Proposals panel and Activity read the recorded event. Review and tool-post
remain the org's normal path for a policy change. CLI equivalents are
`laneboss refusal report --config example --refusal ID --note TEXT` and
`laneboss refusal proposals --config example`.

`laneboss tool submit --config example --lane NAME --file FILE --purpose TEXT`
records path, SHA-256, purpose and a screened preview. An `--instance ID` can
replace the lane selector. Submissions contain bounded UTF-8 text and never
grant permission. The Tool submissions panel reads `/api/tools` and filters by
employee without reopening submitted files. Employee ledgers include proposal,
tool and employee-associated judge records, alongside existing refusal hits.

TypeSafe / judge uses the same strict egress reader as `laneboss judge egress`.
It joins real sent/outcome records by ask ID and shows time, question, lane,
outcome, model and typed probability. The current judge contract records Noul
probabilities; Choice or Score answers are not inferred. Input text is not kept
by that log, so the summary is null and the dashboard never opens a judge input
file. An unfinished recorded ask displays as pending.

`/api/judge?view=control` adds recorded latency and explicit rule/result links
from `guard.decision` or `refusal.decision` events joined by ask ID. The judged
share uses only those explicit decision records as its denominator; absent
records leave the share null. Current refusal processing does not emit those
links automatically. The view highlights probabilities strictly between 0.25
and 0.75 as low confidence. Probability alone never supplies an allow/refuse
result. Choice/Score support and automatic refusal-path linkage remain pending.

The add-6 black-box rows generate six effect classes through real lane CLI
records, check report authentication and validation, compare proposals with the
CLI, and hash configuration/policy bytes before and after reports/submissions.
The tagged `refusal-writes-policy` mutant physically appends policy bytes and
must fail the same hash assertion. These new runtime rows still require a
disposable test machine; static compilation supplies no runtime pass evidence.

CLI report/submission commands return the event store's standard append receipt:
ID, sequence, recorded time, hash and duplicate status. The stored event owns
the kind, actor and payload. Black-box rows resolve receipt ID/sequence to that
actual event before asserting payload fields. The tagged `dashboard-cookie`
mutant restores signed-cookie issuance and replay; the normal no-cookie
assertion must fail against it. Long-line and byte-cap rows use the real CLI
provider output, and Go rows check cancelled reads and cache invalidation.

Plugins uses the same installed-asset reader as `laneboss plugin list`, including
the asset root used by `plugin path`. Name and version come from installed
manifests. Health reflects whether a bounded regular manifest with a name and
version can be read; errors have a fixed safe description. Agent enablement is
not recorded by the launcher, so `enabled` is null and the page shows Unknown.
A publisher's optional `defaultEnabled` appears separately as `default_enabled`.
No private agent registry is read to invent an enablement state.

On the test box, run `python3 -m unittest tests.e2e.test_dashboard`. The black-box
rows use the existing throwaway org/lane helpers and real launcher binaries. They
compare live lane data with CLI output, inspect real recorded refusals, exercise
board updates and heartbeat ordering, and hash configuration/state files before
and after requests. A valid-hash credential canary and an invalid-hash control
distinguish redaction from an integrity error.

The `laneboss_faults` build supports `dashboard-no-screen` and
`dashboard-any-bind` as private fault points. The mutant rows assert the unwanted
effect and then require the corresponding normal security assertion to fail for
that reason. A release-binary row confirms that these switches cannot disable
release protections. These tests are intended for the test box; compiling their
Python source does not claim that the runtime rows or mutants have passed.
