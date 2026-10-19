# Demo dashboard screenshots

This revision prepares a populated, live capture for the release tree. Its new
PNGs still require a Linux run and review. After capture and review, publish the four
images under `docs/assets/demo/`, alongside their `.txt`, `.html`, `.ocr.txt` and
`captures.json` sources. The embeds below are snippets until those files exist.

## Capture on the disposable box

Run from the release tree root on a fresh Ubuntu box with Go and Python 3 already
installed. The box needs outbound access for Go's pinned toolchain/modules,
Ubuntu packages, PyPI and Chromium, and root or noninteractive sudo for system
dependencies. The script installs Git, tmux, jq, Python's venv support, Tesseract
and Chromium dependencies, then installs Playwright into its own venv. It launches
no box; machine launch and log harvesting belong to the supervising run.

The exact suite line is:

```sh
LB_SUITE='bash scripts/demo-screenshots.sh'
```

For a box already assigned to this task, execute:

```sh
bash scripts/demo-screenshots.sh
```

The entry point refuses macOS and an existing `/tmp/shots`. It keeps the caller's
configuration binding and creates a separate empty-environment process with an
isolated HOME under `/tmp/lb-dash-shots.*`. It snapshots its release sources,
builds `cmd/laneboss` with the pinned Go toolchain and retains the binary bytes,
input/binary hashes, toolchain information and every command's output.
The same entry point runs the dashboard package's Go tests and the rendered
event-level browser row against that binary. Their logs, including rejected
negative controls, are retained and printed into the harvested transcript.
It never lists environment values or copies authentication files.

`laneboss init demo --project <shop-api> --project <shop-web> --runner claude`
creates the org with its built-in roles and two throwaway Git repositories. For
this demo only, the executable named `claude` is a copy of the shipped stand-in;
init checks its presence and invokes no model. Before dispatch, the file-backed
demo configuration replaces every runner/default route with `demo-agent`
and synthetic full model labels. No vendor CLI is installed or invoked.
The helper edits only ordinary configuration, role driver sources and instance
notes, then uses `org render`, `org validate`, `config validate` and `doctor`.

The four default placeholder instances are read and moved intact into private
evidence outside the demo org. The CLI re-renders its own rules, manifests and
hooks; no generated file is hand-edited. The built-in role library remains.
The CLI adds `shop-lead` at L5 with the `top` role and `stream-lead` at L4 with
the `supervisor` role, both with generated hooks. Their persistent control
processes emit real heartbeat observations while they remain alive. Keeping a real
instance matters: `org validate` rejects an org with no instances because there
are no runner hooks to verify. The script checks the configuration, every selected
(level, role)'s driver list, `org validate --config demo` and `org check-hooks`.
It declares no Git landing authority; no real merge is performed.

After reading the complete human and JSON briefings, a persistent headless child
reads `start --config demo --role bootstrap` in both formats. This registers its
actual process identity as the configured L6 launch supervisor. The same child
then starts a persistent L5 control child, which registers
`start --config demo --role shop-lead`. Its persistent L4 control child registers
`start --config demo --role stream-lead` before starting all five L3 lanes.
Each control process verifies that the CLI's private `sessions/PID.json` record
names its own PID, configuration and
principal. Registrations and subsequent dispatches occur in the same processes;
no environment label or manually written session record supplies identity.

The held lane runners only read their inputs and wait for capture release.
Levels, models, states and parents come from actual CLI records and running
processes. The L4 instance records `instance:shop-lead` as its report target;
each L3 lane reports to `instance:stream-lead`. Supervisor instances and executor
lanes have distinct names and independent principal IDs; no matching dummy
supervisor lane is needed to supply state.
Every held runner records a heartbeat through the CLI every ten seconds at the
current time. The control processes also record their current elapsed time,
state, model and actual parent through instance heartbeats.
Capture waits for ninety seconds of activity after dispatch becomes ready;
it checks stored receipts, recent supervisor heartbeats, control-process liveness
and real running lane status. No history is backdated.

| Lane | Project | Level / role | State when captured |
| --- | --- | --- | --- |
| `demo-api` | `shop-api` | L3 / executor | Two runs, accepted, marked merged and cleaned |
| `demo-web` | `shop-web` | L3 / executor | Running, held through capture |
| `demo-cart` | `shop-api` | L3 / executor | Running, held through capture |
| `demo-docs` | `shop-web` | L3 / docs | Verifying after successful stand-in exit |
| `demo-review` | `shop-api` | L3 / reviewer | Accepted after successful stand-in exit |

The L5/L4 instance names are `shop-lead` and `stream-lead`. Both processes remain
running through capture and record their actual elapsed time and parent. The API
follow-up is read from `message.md`, recorded with its exact text as an
instance-to-lane instruction, and delivered through the real resume command.

Only the disposable repositories receive an empty initial commit. The stand-in
reads the walkthrough's actual brief and follow-up files and changes no work.
`merged` records a demo review decision; it performs no Git merge or deployment.
`example-model-large-1`, `example-model-medium-1` and `example-model-small-1`
are synthetic full model labels. The held runners remain alive until capture
finishes. The stand-in writes Claude-compatible stream-json thinking, Read tool
calls, paired results and assistant messages. Read byte counts and task headings
are measured from the actual kept brief/follow-up files. It reports no invented
test pass or vendor usage. Thinking and assistant text are marked demo narration.

The dashboard starts in a separate Python `pty.fork()` controlling terminal,
with no supervisor ticket in its ancestry, so its principal is the human.
This pseudo-terminal is required on a box without an interactive terminal:
starting the dashboard from a recorded supervisor or lane would be refused.
The token-bearing URL stays in private evidence and browser memory. It is never
printed in the harvested transcript or put into image/text sources.
The browser and every PNG use 1440 × 900, light theme, English, UTC and reduced
motion. The two tree images are ordinary upper/lower scroll positions of the
populated tree. `capture.css` widens the drawer and wraps table columns for these
frames; it changes no recorded state, model, report line or timeline content.
A synthetic-demo banner remains visible, including inside the modal drawer.
The real Find an agent control selects `example-model` for the populated capture;
the temporary L6 launch identity remains recorded but outside these frames.

## Artifact names and captions

All four PNGs are written to `/tmp/shots/` on the box. Keep the demo disclosure
with every published set: **Synthetic demo using demo-agent; captured with
headless Chromium on disposable Ubuntu. The human dashboard runs under a Python
pseudo-terminal. This is not an authenticated AI-service test.**

| PNG | Caption |
| --- | --- |
| `01-org-tree.png` | Demo org: recorded and running L5/L4 supervisor instances, model names and live activity. |
| `02-lane-tree.png` | Five L3 demo lanes under their L4 stream, with Running, Verifying and Ended states. |
| `03-lane-detail.png` | Demo API lane: its `instance:stream-lead` report line, thinking, real read/result and recorded follow-up text. |
| `04-lifecycle-events.png` | Demo API events: recorded start, resume, acceptance, merge decision and collection history. |

For each image, the helper retains the exact rendered region's text and HTML,
plus Tesseract OCR text from the PNG. `captures.json` names the browser, viewport
context, dimensions and captions without recording tokens or session IDs.
The source text is checked for paths, UUID-shaped IDs and token fragments;
`bash scripts/scan.sh /tmp/shots` scans the PNG bytes and every source file.
A missing check, mismatched report line, bad lane exit, browser error, scan
finding or incomplete collection stops the export. An unreviewed guard refusal
never gets a bypass or an automatic retry.

The capture also fails if any rendered text says `No state recorded`,
`No model recorded`, `[unparsed event]`, `Message text not recorded` or
`Level not recorded`; if recorded or displayed card names repeat; if a non-top
card has no recorded supervisor; if the API drawer omits the delivered follow-up
text; if either tree frame has fewer than
two fully visible Running cards; if fewer than two L3 lanes are genuinely running;
if the Verifying/Ended states or three model labels are missing; if the expected
L5 → L4 → L3 parents or recorded sparklines are absent; if any lane lacks the
parsed thinking/tool/result/message sequence; or if a lifecycle table overflows
horizontally. Recorded lifecycle rows must show their lane's L3 level. Rows
before the lane's first start retain a compact unknown dash. These are checks of
actual API responses, DOM and PNG dimensions. Duplicate-name, missing-message
and verbose-level controls must fail the same capture text checks before any
image is taken.

After capture, the dashboard receives SIGTERM at its recorded PID and is reaped.
The held runners receive the shared release file only after capture and privacy
scanning finish. Their actual successful end events and process quiescence are
checked before any lane is marked or collected.
Each lane is checked for supervising/tmux processes and survivors, stopped if
needed, and collected only after successful checks of its unchanged repository.
The final state verification requires five cleaned lanes, exited supervisor
control processes with retained exit codes, no surviving processes or
pending/refused events, and an intact event store. On failure, process stopping
and evidence retention take precedence; worktrees are preserved and no image
archive is advertised. A CLI refusal also stops further CLI operations. Failed
capture release does not append final controller heartbeats.

Success requires script exit 0, `PASS: demo dashboard screenshots`, and exactly
one `SHOTS:` line containing a base64 gzip-compressed tar archive of the images
and their publication sources. Keep that line intact in the harvested log.
The private evidence directory printed by the script contains the source archive,
tested binary, command outputs, hashes, transcript, exit code and final state.
Every failed command also prints its exact stdout and stderr into the captured
standard output. Package/build/browser failures print their retained command log;
controller failures and failed runner output are forwarded to the main transcript.
Diagnostics can therefore survive box collection even when its evidence directory
is no longer available. Dashboard token URLs still remain private.
Archive those through the supervising run before reclaiming the box; the `SHOTS:`
archive carries only the publication assets, not the token log or raw session
records. Static checks on the source are not screenshot/E2E evidence.

## Harvest and publication gate

Decode the one `SHOTS:` line from a successful harvested log into a separate
review directory. Inspect all four images, their text/HTML/OCR sources and the
reported demo-only labels before adding them to the repository. Do not publish
the private token log, raw state, source/binary checksum files or session records.

Run the artifact scan again with the publication denylist supplied separately
outside the checkout, then scan the staged assets and source before committing.
The scanner reports filenames, line numbers and rule names, never matched values.
Every command must exit 0 and each scan must print `SCAN PASS:`. A scan finding
stops publication and preserves the original harvested bytes for review.

```sh
set -euo pipefail
test -n "${LANEBOSS_SCAN_DENYLIST:-}"
test -r "$LANEBOSS_SCAN_DENYLIST"
bash scripts/scan.sh /absolute/path/to/reviewed-shots
bash scripts/scan.sh --staged
```

Only after that gate, copy the reviewed images and sources to `docs/assets/demo/`
and use the snippets below. Replace the prepared-capture paragraphs in the README
and dashboard guide with the corresponding block; do not advertise missing PNGs.

## README embed snippet

Paths here are relative to the repository's README.

```markdown
## Demo

Synthetic demo using the credential-free demo-agent with shop-api and shop-web.
Captured with headless Chromium on a disposable Ubuntu box. The dashboard runs
as the human principal under a Python pseudo-terminal because the box has no
interactive terminal. This is not an authenticated AI-service test.

![Demo org tree with running L5 and L4 supervisors](docs/assets/demo/01-org-tree.png)

Demo org: recorded and running L5/L4 supervisor instances, model names and activity.

![Demo L3 lanes grouped by their recorded stream supervisor](docs/assets/demo/02-lane-tree.png)

Five L3 lanes under the L4 stream, with Running, Verifying and Ended states.

![Demo lane detail with its recorded report line](docs/assets/demo/03-lane-detail.png)

Demo API lane: recorded L3 level, instance:stream-lead report line and parsed timeline.

![Demo lane lifecycle and events](docs/assets/demo/04-lifecycle-events.png)

Demo API events: start, resume, acceptance, merge decision and collection history.
```

## Dashboard guide embed snippet

Paths here are relative to `docs/dashboard.md`.

```markdown
## Demo

Synthetic demo using demo-agent, shop-api and shop-web. Headless Chromium
captures the real dashboard on disposable Ubuntu. The human dashboard runs
under a Python pseudo-terminal on the headless box. This is not an authenticated
AI-service test.

![Demo org tree, upper levels](assets/demo/01-org-tree.png)

![Demo org tree, recorded L3 lanes and their stream supervisor](assets/demo/02-lane-tree.png)

![Demo lane detail and supervisor report line](assets/demo/03-lane-detail.png)

![Demo lane lifecycle events](assets/demo/04-lifecycle-events.png)
```
