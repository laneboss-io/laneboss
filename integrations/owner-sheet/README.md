# Owner decision sheet

Put questions that require the owner's judgment in an `.xlsx` file they can
open in a synced folder. The owner answers when convenient; a supervisor reads
new answers and notes, handles them, then acknowledges them. This standalone
integration does not send messages, run decisions or schedule supervisor ticks.

It needs Python 3.9+ and **openpyxl**, its only third-party dependency:

```sh
python3 -m pip install openpyxl
```

Use an interpreter or virtual environment with openpyxl installed. A missing
dependency exits 2 with an installation instruction. TOML configuration uses
stdlib `tomllib` on Python 3.11+. On Python 3.9/3.10, use an equivalent **JSON
configuration with a `.json` extension**; no extra TOML dependency is needed.

## Setup and configuration

From this checkout, create a new configuration and empty queue:

```sh
python3 integrations/owner-sheet/owner_sheet.py --config ./decisions/owner-sheet.toml init
```

For Traditional Chinese, add `--language zh-TW` after `init`. An optional
`--title 'Owner decisions'` sets the workbook title and first help row.
On Python 3.9/3.10, use `owner-sheet.json` instead. Init refuses existing config,
queue, sheet or state paths and creates no workbook until `build`.

Edit the generated configuration. These are the complete supported keys:

```toml
queue = "owner-queue.json"
sheet = "synced/owner-decisions.xlsx"
state = "owner-sheet.state.json"
language = "en"
title = "Owner decisions"
```

`queue`, `sheet` and `state` are required, distinct file paths; `sheet` must end
in `.xlsx`. Relative paths resolve beside the configuration, regardless of the
working directory. Absolute paths and `~` are supported. `language` defaults to
`en`; `zh-TW` is the other built-in label/help set. `title` is optional and has
a localized default. JSON configuration uses the same keys and string values.
Keep the queue, config and ack state local unless you intend to share them.

The queue is UTF-8 JSON with one `rows` array:

```json
{
  "rows": [
    {
      "id": "D-001",
      "priority": "high",
      "category": "planning",
      "question": "Which meeting time: a) morning or b) afternoon?",
      "recommendation": "a) morning",
      "blocks": "Sending the invitation",
      "default_if_unanswered": "Wait for an answer",
      "where": "Reply here; about one minute"
    }
  ]
}
```

Every field is a string. `id` and `question` must be nonempty; the other six
fields default to empty strings. Unknown fields and duplicate IDs are refused.
Keep IDs stable and never reuse one for a different decision. Priority/category
are free text, `blocks` explains what is waiting, `default_if_unanswered` states
the proposed reversible default, and `where` gives the place/time needed.
No default authorizes a legal, payment or account action.

## Supervisor tick

Use the same configuration on every command:

```sh
python3 integrations/owner-sheet/owner_sheet.py --config ./decisions/owner-sheet.toml build
python3 integrations/owner-sheet/owner_sheet.py --config ./decisions/owner-sheet.toml read
python3 integrations/owner-sheet/owner_sheet.py --config ./decisions/owner-sheet.toml ack D-001
python3 integrations/owner-sheet/owner_sheet.py --config ./decisions/owner-sheet.toml build
```

Build once after preparing the queue. On each configured supervisor tick,
finish syncing, run `read`, review/handle each returned decision, and only then
`ack ID...` for the IDs handled. Rebuild after updating the queue or handling
answers to refresh the displayed statuses. Stop on a nonzero exit; do not
acknowledge an answer whose work is still pending.

`read [ID...]` prints one JSON line per changed row, in worksheet order (open
questions followed by closed ones), or in requested-ID order when IDs are given:

```json
{"id": "D-001", "answer": "OK", "note": "Send it tomorrow"}
```

A never-answered row is omitted. An answer-only or note-only edit is new; clearing
an acknowledged answer/note is also a change. Unchanged acknowledged rows produce
no output. Both `read` and `ack` validate all requested IDs before emitting rows
or writing state, including IDs in the closed worksheet. An unknown ID exits 2.
`ack` requires at least one ID and records its current answer/note pair. It
prints `{"acknowledged": ["D-001"]}` and does not itself modify the workbook.
`build` prints counts, such as `{"built": 1, "closed": 0}`. Keep the state file;
losing it makes existing nonempty answers appear new again.

The owner edits only **Your answer** and **Note (optional)**, highlighted in
yellow. The Help worksheet explains `OK` to accept the recommendation,
`a / b / c` for options and free text for other instructions. Answer text keeps
whitespace and newlines. JSON output renders numbers/booleans as strings and
dates/times as ISO strings; formulas are read as formula text, never evaluated.
Rebuilding preserves owner cell values, types and number formats by ID.

Questions removed from the queue move to **Closed** (`已結束` in `zh-TW`), keeping
their answers and notes indefinitely. They remain readable/acknowledgeable and
can be edited there. Reintroducing the same ID restores its entries to the open
worksheet. Changing the configured language also preserves entries.

## Google Drive and other synced folders

Install and configure the owner's sync client separately. Set `sheet` to an
absolute `.xlsx` path inside its local Google Drive, OneDrive or Dropbox folder.
Build it, wait for sync to finish, and open that exact file from Drive or the
local folder. Use an editor that saves changes back to the same `.xlsx`, rather
than converting it into a separate native online spreadsheet. Do not rename or
move the workbook, its worksheets or columns; do not edit IDs or add worksheets.

Use one supervisor writer. Save and close the editor and finish syncing before
`build` or `ack`; avoid editing between reading and acknowledging. Writes use a
temporary file in the destination directory, flush it, then atomically rename
it over the destination. An observed concurrent file change causes a refusal
without replacement. This does not merge offline edits or conflicting cloud
copies, and no cross-client lock is possible. Retain sync version history or
backups. No Google API credentials or service authentication are used here.

## Black-box verification on the disposable Linux box

Install openpyxl in the box's test interpreter using the approved environment
setup, then run these from the checkout root. First challenge the preservation
row with the mutant; it must exit **1**, with `build lost an owner answer or note`
at the preservation assertion. The mutant changes a disposable copy of the
CLI to drop existing answers; it does not change the checkout. Any other failure
or a skip does not demonstrate a killed mutant.

```sh
OWNER_SHEET_EVIDENCE='/tmp/lb-plug-sheet-evidence/mutant' python3 e2e-rows/test_owner_sheet.py --mutant-drop-answers OwnerSheetRows.test_rebuild_preserves_answers_by_id
```

After confirming that expected failure, run the unchanged control:

```sh
OWNER_SHEET_EVIDENCE='/tmp/lb-plug-sheet-evidence/control' python3 e2e-rows/test_owner_sheet.py
```

The control must report eight passing tests and zero skips. The only allowed
skip is missing openpyxl, reported loudly as `SKIP OWNER-SHEET ROWS`; it is an
incomplete verification. The dependency-refusal row launches the CLI with
`-I -S`, excluding site packages, and requires a clear error without any writes.
The rows retain product bytes/hash, original queue/config/workbook/state inputs,
CLI argument bytes, stdout/stderr and exit codes under the printed evidence
directories. Collect these before the box is reclaimed.

| Row | What makes it fail |
| --- | --- |
| Changed answers | Returning untouched/acknowledged rows, missing answer/note edits or clears, or changing their text. |
| Rebuild | Losing any typed value after IDs reorder and metadata changes, moving values by position, or changing cell types. This is the mutant target. |
| Closed rows | Dropping removed answers/notes, missing closed-row reads/acks or losing entries when an ID reopens. |
| Unknown IDs / queue | Accepting unknown IDs, emitting partial rows, accepting duplicate/oversized input or overwriting preserved files. |
| Languages | Incorrect English/Traditional Chinese columns/help or lost answers on a language switch. |
| Init / config | Overwriting existing setup, incorrect relative paths, or failing the documented TOML/JSON version behavior. |
| Malformed input | Overwriting a workbook with duplicate IDs or an invalid acknowledgement store. |
| Dependency | Failing to clearly refuse with openpyxl excluded, or creating workbook/state files anyway. |

Local static checks only: `python3 -m py_compile integrations/owner-sheet/owner_sheet.py e2e-rows/test_owner_sheet.py`
and `bash scripts/scan.sh`. Do not run these runtime rows on the development Mac.
