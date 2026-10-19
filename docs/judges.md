# Judges

A judge is an external command the launcher can ask a bounded scalar question or a batch of typed questions. The launcher does not know what is behind
it: a rule engine, a small model, a service. This page holds the contract between the launcher and a judge, the
configuration, the three commands, the egress rule, the known limits and a stand-in judge to start from. Adapters for
particular providers live under `examples/judges/`.

A judge adds coverage where rules alone are too narrow (for example, telling whether a tool result is a refusal by a
guard). This layer only lets a configuration name judges and lets the launcher ask one, bounded, logged and without
sending a secret. The org's decision capture (`org capture-decision`) and decision guard (the org hook, and
`lane send --ask`; [Guiding agents](decisions.md#guiding-agents)) ask judges in this way; `laneboss judge ask` is the
same machinery from the command line.

## The judge contract

A judge is an external COMMAND the launcher runs for one scalar ask or typed batch. The launcher writes ONE JSON object to the
command's standard input and reads ONE JSON object from its standard output.

Request (UTF-8, one object, a final newline):

    {"laneboss_judge": 1,
     "question": "refusal.is-refusal",            an identifier: lower-case words joined by dots and hyphens
     "kind": "noul",                              the scalar version-1 contract: a yes/no question
     "prompt": "Is this tool result a refusal by a guard, a hook or a permission layer?",
     "subject": {"result": "<text>", "command": "<text>"}}     one to eight named texts, each at most 4000 characters

Answer (exit status 0, one object on standard output):

    {"probability": 0.93,                         the probability of YES, a number from 0 to 1
     "model": "judge-model-1.0",                  a string or null: what answered
     "request": "req_01..."}                      a string or null: the provider's own request identifier

Anything else is NO ANSWER: a non-zero exit status, a time-out, output that is not one such object, a probability
outside 0 to 1. The launcher then reports the judge as unavailable for that question; it never invents a verdict. A
judge writes nothing but its answer to standard output; one line of explanation on standard error is allowed and is
never shown beyond its first 300 characters.

(The comments after the members above are not part of the JSON; the example model name is invented.)

### Typed batches and the TypeSafe boundary

The guide's extension uses `kind: "typed"`; the job catalog uses
`kind: "laneboss-jobs"`. Both carry named `state` and a `questions` map:

```json
{
  "laneboss_judge": 1,
  "question": "decision.conflicts",
  "kind": "typed",
  "state": {
    "decisions": ["D-22: Require approval before publishing."],
    "texts": ["Publish without approval."]
  },
  "questions": {
    "comparison": {
      "type": "noul",
      "instructions": "Does the action in \u0060texts[0]\u0060 contradict the decision in \u0060decisions[0]\u0060?",
      "criteria": {
        "true": "The specified action contradicts the recorded decision.",
        "false": "The action is consistent with or unrelated to that decision."
      }
    }
  }
}
```

The TypeSafe adapter sends **one HTTP request for the batch**:
`POST https://api.typesafe.ai/v1/systemone`, Bearer authorization, JSON content
type, and only `state`, `model` and `questions` in the body. The documented
default model alias is `jev-latest`. Choose a supported version with `--model`
using the provider's [Models](https://docs.typesafe.ai/models) reference.
Returned records keep the model the provider reports; the saved response
examples report `jev-1.13.0`.
Question IDs are response lookup keys and are not sent to the inference model.
Every instruction must therefore express the complete judgment and reference
its named state. Noul criteria define yes/no; a catalog Choice includes `none`.

The official response has `model`, `answers` and `usage`:

```json
{
  "model": "jev-1.13.0",
  "answers": {"comparison": {"type": "noul", "noul": 0.95}},
  "usage": {"input_tokens": 296, "output_tokens": 20}
}
```

The shared validator in `internal/typesafe` checks the official wire shape.
A typed adapter returns it, preserving all documented answer fields and adding
only its optional sanitized header-derived `request` identifier. A legacy
scalar ask translates `answers.answer.noul` into the launcher's
`probability` field. That field is a launcher contract, not a TypeSafe field.

| Primitive | Question criterion | Official answer fields |
|---|---|---|
| Noul | One yes/no proposition; optional true/false descriptions | `type: "noul"`, `noul` in [0,1] |
| Choice | Map of options to descriptions; at most 255 options | `type: "choice"`, `choice`, full `probabilities`, `confidence` |
| Score | Ordered array of 2–10 descriptive levels | `type: "score"`, `score`, `legend`, full `probabilities`, `confidence` |

A Choice selects a maximum-probability option; every supplied option must be
present, and confidence must be a finite number in [0,1]. Choice and Score
probability sums must be within `max(1e-6, option_count * 5e-5)` of one.
The API reference and primitive pages require a sum of one but do not specify
precision ([API](https://docs.typesafe.ai/api), saved `api.md:255`;
`primitives_choice.md:346`, `primitives_score.md:662`). The tolerance budgets
half a rounding unit at four fractional decimal places per option. It is an
application allowance, not a claim about the provider's actual precision.
All values still require [0,1] bounds, complete keys and a selected maximum;
clearly malformed sums remain unavailable. A Score is the probability-weighted position on
zero-based levels, in [0, number of levels minus one]; the validator checks its
weighted value and legend against the rubric. Structured level descriptions
are supported. Noul has no separate confidence: near 0.5 means uncertainty,
not medium intensity. Score/Choice confidence summarizes a distribution; it
is not the score or the selected option's probability.

Missing/wrong answer types, partial or extra answer sets, absent model/usage,
numeric strings/booleans, out-of-range values, duplicate JSON members,
malformed distributions and non-JSON output make the **whole batch unavailable**.
No missing answer becomes zero. The adapter preserves official answer fields
and strips unrelated provider extras. The guide uses complete decision text or
reports uncovered input before sending. See [the decision dial](decisions.md#the-dial).

HTTP 401/422 errors give no answer. HTTP 429/529 receive at most two exponential
backoff retries (100 ms, then 200 ms) inside the original overall timeout;
network errors, exhausted retries and malformed success bodies remain
unavailable. Error bodies and credentials are not printed. A retry repeats the
same batch and does not split its independent questions.

The official fixtures in `internal/typesafe/testdata` and the adapter's HTTP
rows include Noul, Choice and Score. Invalid variants are checked before their
valid controls. Run executable checks on an authorized disposable Linux machine:

```sh
go test ./internal/typesafe ./internal/judge ./internal/orghook ./examples/judges/typesafe_jev
python3 -m unittest discover -s e2e-rows -p test_typesafe_jobs.py -v
sh e2e-rows/check-decision-guide.sh
sh e2e-rows/check-job-hook.sh
```

The stand-ins verify wire shape, request content, batching and advisory policy.
They provide no authenticated AI-service test or domain-calibration evidence.

### How the launcher reads the contract

- **The request.** Sent as one line of UTF-8 JSON ending in a newline. The members are in the order shown. When texts
  were held back, two more members follow `subject`: `"cut": ["name", ...]` lists the texts that were cut to their
  first 4000 characters, and `"withheld": ["name", ...]` lists the texts that were replaced by the string
  `[withheld]` (the prompt is listed as `prompt`). Each member is left out when its list is empty. The launcher sends
  the whole request and closes the judge's standard input; a judge that does not read its input is not an error.
- **The answer.** Standard output is read up to 64 KiB. It must be UTF-8 text holding exactly one JSON object
  (whitespace around it is fine) with a `probability` that is a JSON number from 0 to 1 (not a string, not `true`,
  not `NaN` or `Infinity`), and optionally `model` and `request`. Any other member, a repeated member, a second
  object, or text before or after the object is no answer. The exit status must be 0: a judge that exits with another
  status gives no answer even when it printed a valid one.
- **The probability is the number that was written.** It is read exactly, as a decimal, and checked against 0 and 1
  before it becomes a floating-point number: `1.0000000000000001`, `-1e-999` and `1e400` are not answers, whatever
  they would round to. A number that is in range and has more digits than a double holds is an answer, rounded after
  the check.
- **`model` and `request` are identifiers or nothing.** Each is `null`, left out (read as `null`), or a string that
  matches `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` and that the credential detector does not refuse. Anything else, a
  credential-shaped value included, makes the whole answer no answer (the reason is `output`), so nothing of it is
  printed or logged.
- **Standard error.** The first non-empty line of what a judge writes on standard error is shown by `judge ask` when
  there is no answer, cut to 300 characters, with control characters replaced by `?`. The whole line and the 300
  characters that would be shown are both screened by the credential detector, and either one that it refuses is
  replaced by `[withheld]`. It is never written to the egress log.

## Configuration

Judges are named in the configuration (schema version 1 stays; keys are validated strictly, and errors name the key
path, never a value):

    [judges.NAME]
    description = "free text"                  optional, through the credential detector like other descriptions
    command = ["/abs/or/on/PATH", "arg", ...]  required; no placeholders in version 1
    timeout_seconds = 10                       optional, 1 to 60, default 10

| Key | Type | Required | Meaning |
|---|---|---|---|
| `description` | string | no | Free text. |
| `command` | array of strings | yes | The argument vector the launcher runs, without a shell. The first element is a command name or an absolute path. Version 1 has no placeholders, so an element with a brace is refused instead of being passed on as written. |
| `timeout_seconds` | integer 1 to 60 | no | How long one question may take; default 10. |

`NAME` follows the grammar of runner names (`[a-z0-9][a-z0-9-]{0,31}`). Nothing else is accepted under a judge. Like the
rest of a configuration, a judge never holds a secret: a credential in a description or an argument is refused. A
judge that needs a key reads it from its own environment or files (see "Known limits").

## Asking

`judge.AskContext` in `internal/judge/ask.go` implements scalar asks; `AskNoulsContext` in `internal/judge/batch.go` implements guide batches, and `AskJobsContext` implements catalog asks. They share bounded process execution, configuration binding and egress locking. For scalar asks, in order:

1. **Screens the names.** The judge name, the question, the lane and every subject name go through the credential
   detector (`docs/architecture.md`, "Credentials") before anything else is done with them. One that it refuses is
   refused (exit 2): the message says which argument it was (`--judge`, `--question`, `--lane` or a `--subject` name)
   and never repeats it, and nothing is run or logged. A name can pass its grammar and still look like a credential;
   a judge name that is merely unknown is repeated in the message unless the detector matches it.
2. **Validates.** The judge is defined in this configuration; the question is an identifier (lower-case words joined by
   dots and hyphens, at most 64 characters); the lane, when given, has the lane grammar; the prompt is text that is
   not empty and at most 4000 characters; the subject names 1 to 8 texts, each name `[a-z][a-z0-9_-]{0,31}` and not
   `prompt`, each text a string (it may be empty); the state directory is the configuration's own. Anything else is
   refused (exit 2) before anything is run or written.
3. **Screens and cuts the texts.** The prompt and every subject text, as a whole, go through the credential detector.
   A text it refuses is replaced by `[withheld]` and its name is listed in `withheld`, so a secret never leaves the
   machine through a judge. A text that passes and is longer than 4000 characters (characters, not bytes) is cut to its
   first 4000, **the cut text is screened again**, and its name is listed in `cut`; when the cut made it a credential
   (a key with one character too many is no key, and the cut leaves it whole) it is replaced and listed in `withheld`
   instead. A text is screened before it is cut as well, so a secret that would straddle the cut withholds the whole
   text.
4. **Records the owner and logs the attempt.** An ask for a state directory that has no ownership marker yet (the first
   ask) records it, so that judge-only state belongs to its configuration like all other state (a copy of it in another
   configuration's place is refused). Recording takes the state directory's lock and **waits for it, without a bound of
   its own,** while another command holds it (the judge's time-out has not started yet); an ask for a state directory
   that has a marker does not take that lock. Then the state directory is synced, once, and the **sent line** of the
   egress log (below) is written: it records an **attempt**, because it is written before the command is started. If
   anything here cannot be done, or the log was not written by this version or has no room left, nothing is asked:
   exit 7.
5. **Runs the command.** With the request on standard input, without a shell, in a session of its own, with the
   launcher's environment minus every `LANEBOSS_` variable, and the configured time-out. When the time-out passes, the
   command's whole process group gets SIGTERM and, a second later, SIGKILL; the launcher does not wait for it beyond
   two seconds in all. When the command ends by itself, **what its pipes still hold is read first**, and **then** the
   process group is ended (SIGKILL, without waiting): the read stops at the ask's time-out, when standard output passes
   64 KiB (no answer) and after 64 KiB of standard error from a pipe; it takes whole chunks of up to 64 KiB, so **one
   last chunk may be read past the bound**, and a child that keeps writing is not read beyond that.
6. **Reads the outcome.** Either the validated answer, or an unavailable result with one reason: `timeout` (no end
   within the time-out), `exit` (a non-zero exit status or an end by a signal), `output` (an exit status of 0 but
   standard output that is not one answer object, or more than 64 KiB of it) or `not-found` (the program does not exist
   or cannot be started).
7. **Logs the outcome.** The **outcome line** is written; only then is the result returned. If it cannot be written
   the sending is logged and the outcome is not: exit 7, with a message that says so, and no result.

It never raises for a judge's fault and never returns a made-up probability. It returns a refused-input error for invalid input or
a state directory that is not the configuration's, and an egress error (exit 7) when the ask cannot be logged. While
a judge runs, the launcher holds no lock: not the lanes lock, and not the state directory's lock, which is taken only to
record the owner, before the sent line (step 4). The egress log has a lock of its own that is held only while a line is
written.

## Commands

All are bound to one configuration (`--config NAME` or `LANEBOSS_CONFIG`, as for every state command), and a judge of
another configuration is refused.

| Command | Result |
|---|---|
| `laneboss judge list --config N` | One JSON array, sorted by name: `name`, `description` (or null), `program` (the command's first element as written) and `timeout_seconds`. Creates nothing. |
| `laneboss judge ask --config N --judge NAME --question ID --prompt-file F --subject NAME=FILE [--subject ...] [--lane L]` | Asks once and prints one JSON value: `judge`, `question`, `outcome` (`answered`, or the reason there is no answer), `probability` (or null), `model`, `request`, `withheld`, `cut` and `duration_ms`. Texts come from files, never from arguments; a file must be UTF-8 text of at most 1 MiB. |
| `laneboss judge egress --config N [--since TIME]` | Prints the egress log's lines, one JSON object a line, as they are: the sent lines and the outcome lines alike. With `--since` (a timestamp such as `2026-10-09T09:00:00Z`) only the lines whose own `at` is at or after that time. Read-only: it creates nothing, and prints nothing when there is no log. Every line is checked first, and nothing is printed until all are. |

`judge ask` exit codes:

| Exit code | Meaning |
|---|---|
| 0 | Answered. |
| 1 | Unavailable: the printed value says why in `outcome`, and a line on standard error says what the judge did. |
| 2 | Invalid input or a refused request: an unknown judge, a bad or credential-shaped question, subject name, lane or judge name, a missing or unreadable file, a configuration that is not bound, a state directory that belongs to another configuration. Nothing was run and nothing was logged. |
| 7 | The ask could not be logged. If the owner, the state directory or the sent line cannot be written, or the log is full, or the log was not written by this version, the message says `nothing was asked` (and, for the last two, names the file and says to move it aside) and the judge is not run. If the outcome line cannot be written, the message says that the sending is logged and the outcome could not be logged, and no result is printed. The message starts with `egress problem:`. |
| 70 | An unexpected internal error. |

`judge egress` exits 2 for a `--since` that is not a time (an hour, a minute or a date that does not exist, an offset
such as `+00:60`) and 3 (integrity problem) when a line of the log is not a line of the log: not an object, a repeated
or missing or extra member, a field of the wrong type or form, or a time that does not exist.

## The egress log

`judges/egress.jsonl` in the configuration's state directory (the directory is mode 0700 and the file 0600; both are
made by the first ask). Every ask writes two whole lines that share an `ask` identifier (32 hexadecimal characters),
answered and unavailable alike.

**The sent line**, written before the command is started, with these members:

| Member | Meaning |
|---|---|
| `at` | When the line was prepared (UTC, `YYYY-MM-DDTHH:MM:SS.ffffffZ`): before the wait for the log's lock and the write, so before the command is started. |
| `ask` | The ask identifier. |
| `event` | `"sent"`. |
| `judge` | The judge's name. |
| `question` | The question identifier. |
| `lane` | The lane given with `--lane`, or null. |
| `request_sha256` | The SHA-256 of the request the launcher **prepared** and offered to the command. |
| `request_bytes` | How many bytes that was. |
| `withheld`, `cut` | The two name lists of the request. |
| `outcome_reserve` | Present only for a guide batch: `4096`, the bytes reserved for its outcome. Its absence means the scalar reserve of 1024 bytes. No other value is valid. |

**The outcome line**, written after the command ended, with exactly these members:

| Member | Meaning |
|---|---|
| `at` | When the line was written. |
| `ask` | The ask identifier. |
| `event` | `"outcome"`. |
| `outcome` | `answered`, or `timeout`, `exit`, `output` or `not-found`. |
| `probability` | The scalar probability, or null. An answered guide batch has null here and an additional `probabilities` map of question ID to yes probability. |
| `model` | What answered, or null: an identifier, as "How the launcher reads the contract" says. |
| `request` | The provider's own request identifier, or null: the same. |
| `duration_ms` | How long the command ran, in milliseconds. |

**What the hash describes.** `request_sha256` and `request_bytes` describe the request the launcher prepared and
offered. A judge may read less than all of it (it may close its input, ignore it or read a prefix); the log does not
claim what it read. The log never holds a text the launcher sent, a prompt or a judge's standard error, and of a judge's
answer only validated scalar/batch probabilities and identifiers. A judge that echoes a short text
into `model` or `request` is no answer unless the text is itself an identifier; an identifier that happens to equal a
short text is logged.

**A sent line records an attempt.** It is written before the command is started, so it is not proof that the command
ran or that anything was delivered: a launcher killed between the two leaves a sent line for a judge that never ran.

**An unfinished ask.** A sent line without an outcome line of the same `ask` is an unfinished ask: the launcher was
killed (SIGKILL, a power cut) before or while the judge ran, or the outcome could not be logged (exit 7). `judge egress`
prints both kinds of line as they are, and the person decides what an unfinished ask means. An interrupt while the judge
runs (SIGINT, SIGTERM or SIGHUP) ends the judge's process group and writes the outcome line, as `exit`, when it can; an
interrupt at another moment, or one that arrives while the outcome line is written, can leave the sent line alone.

**An unlogged egress is not allowed.** The sent line is written before the command is started, so an ask that cannot
be logged (the state directory or the log cannot be written, the log is unreadable, full, or not written by this
version) is not made: exit 7, `nothing was asked`. Whether there is room for the line is settled by writing it, not by a
probe. If the outcome line cannot be written after the judge ran, the ask fails with exit 7 and a message that says the
sending is logged and the outcome is not; the result is not printed.

**What survives.** The first things an ask creates, the ownership marker and the `judges` directory, are made durable by
syncing the state directory once, before the sent line is written, and the sent line is written whole, synced and renamed
into place before the command starts: it survives the launcher being killed, and after a power cut it is there when the
file system kept what was synced. Directories above the state directory that the same command had to create are not
synced by it.

**The log never grows past what its own reader accepts.** `judge egress` reads at most 64 MiB. Before a sent line is
written, the log's size plus that line plus the reserves for every unfinished ask (this
one included) must fit in that limit. Each scalar ask reserves 1024 bytes; each guide batch reserves 4096 bytes,
recorded in its sent line. Otherwise the ask is refused (exit 7, `nothing was asked`) with a message that says
the egress log is full and names the file, which is to be moved aside (renamed: nothing rotates it). Move it aside only
when no ask is running: stop issuing asks and let the launcher commands that are asking finish first, because an ask in
flight writes its outcome line to whatever file has the log's name then, apart from its sent line. A scalar outcome fits
inside 1024 bytes; a bounded guide batch fits inside 4096 bytes, so the log stays readable by `judge egress` after a
refused ask and after every outcome. Only an outcome with the same `ask` releases a sent line's reserve. An unfinished
or killed ask keeps the reserve of its own class for as long as its unmatched sent line is in the log.

**A log this version did not write is not appended to.** Before a sent line is written, the last line of the log must be
a line of this version (the check `judge egress` makes on every line). Otherwise the ask is refused (exit 7, `nothing was
asked`) and the message names the file and says to move it aside. Logs written by earlier, unreleased builds (one line
per ask, without `event` and `ask`) are such logs: move `judges/egress.jsonl` aside before the first ask of this version,
or `judge egress` refuses it too (exit 3). Only the last line is checked on an ask; `judge egress` checks them all.

Lines are written whole, the way the launcher writes its other state files: under a lock on the directory the log is
read, the new line is added, and the log is written anew under a temporary name, synced and renamed over the old one. It
is never appended to in place, so a crash leaves the old log or the new one, and two asks at once keep all their lines.

## Doctor

`laneboss doctor` has one line `judge.NAME` for each configured judge. It passes when the program of the judge's
`command` is found (on `PATH`, or an executable absolute path). Doctor never calls a judge and writes no log.

## Known limits

- **The detector is the only screen.** The credential detector recognises secret shapes and assignments to names such
  as `token` or `password` (`docs/architecture.md`, "Credentials"). A secret with no shape and no name (a bare random
  string in a tool result, a private note) goes to the judge.
- **A judge inherits the whole environment except `LANEBOSS_` variables.** An adapter has to find its provider key
  somewhere, so everything else in the launcher's environment reaches the command, proxy settings (`http_proxy`,
  `https_proxy`, `no_proxy` and their upper-case forms) included. A judge that sends the request over the network goes
  where those settings send it.
- **What a judge does with the request is its own business.** The log records what the launcher offered, not what the
  judge read or where it sent the request on.
- **Only the process group is ended.** A descendant of a judge that starts a session or a process group of its own
  survives the time-out and the clean-up; when the judge has ended by itself, what it keeps writing is read only up to
  the bounds of step 5 of "Asking" (the ask's time-out, 64 KiB from each pipe and one last chunk), and then its pipe is
  closed.
- **A killed launcher.** A launcher ended with SIGKILL while an ask is in flight leaves the judge running (it is in a
  session of its own) and the ask unfinished: the sent line is in the log, the outcome line is not. SIGINT, SIGTERM and
  SIGHUP end the judge and write the outcome line when they arrive while it runs. A launcher killed before it starts the
  command leaves a sent line for a judge that never ran, which is why a sent line is an attempt and not proof of
  execution.
- **The log is rewritten whole, and has a size.** Every ask reads the log and replaces it, so the cost grows with its
  size. An ask that would take the log, with its reserve, past 64 MiB is refused (exit 7) until the file is moved aside.
  Nothing rotates it.
- **The state directory's lock.** The first ask for a state directory waits for it, without a bound of its own, while
  another command holds it; the judge's time-out starts only after that wait and the sent line.
- **A stopped launcher holds the log's lock.** The lock is held only while a line is written. A launcher process that
  is stopped (SIGSTOP, not killed: a killed one releases the lock) in that moment makes other asks wait for it
  before they can log: an ask waiting to write its outcome line has already run its judge, and an ask waiting to write
  its sent line has not started it.
- **The log is not verified.** `state verify` does not know it. `judge egress` refuses a line that is not a line of
  the log (exit 3), but a careless edit of a well-formed line goes unnoticed.
- **Line order.** Each line is written when its moment comes, so the lines of asks that overlap are interleaved, and
  the two lines of one ask are not always next to each other; the `ask` identifier joins them.
- **Texts.** `judge ask` reads at most 1 MiB per file and the judge sees at most 4000 characters of each text. A
  prompt longer than 4000 characters is refused, not cut. The detector reads each text whole, so screening takes time
  in proportion to its size.
- **The answer is not authenticated.** The launcher trusts the command it was configured with.

## A stand-in judge

This judge of six lines answers 0.9 when the subject mentions a refusal-like word and 0.1 otherwise. It is only a
shape to start from:

    import json, sys

    request = json.load(sys.stdin)
    words = ("denied", "blocked", "not permitted", "refused")
    text = " ".join(request["subject"].values()).lower()
    probability = 0.9 if any(word in text for word in words) else 0.1
    print(json.dumps({"probability": probability, "model": "stand-in-1", "request": None}))

Name it in the configuration and ask it a question:

    [judges.stand-in]
    command = ["python3", "/path/to/stand_in.py"]
    timeout_seconds = 5

    laneboss judge ask --config NAME --judge stand-in --question refusal.is-refusal \
        --prompt-file prompt.txt --subject result=result.txt --subject command=command.txt

`laneboss judge egress --config NAME` then shows the two lines of that ask, the sent line and the outcome line.
