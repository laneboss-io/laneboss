# Historical lane communication rows

Run these rows only on the authorized disposable Linux test machine with
Python 3, Git and tmux. The supplied executables are built before this procedure.
The development Mac runs only authorized static checks. No machine launch or
authenticated model request is part of this procedure.

`LANEBOSS_BIN` names the release CLI and `LANEBOSS_FAULTS_BIN` names the CLI
built with `-tags laneboss_faults`, both by absolute path. Historical fixtures
start real runners through that tagged CLI. Historical fixtures do not write
lifecycle events through `event append`, import product modules or modify SQL. Their fixture
markers and original start fields are asserted. The stand-in saves its exact
stdin prompt before readiness; turn rows compare those bytes with the kept
rendered prompt and hash, require an actual successful end and zero survivors,
and inspect delivery sequences. Keep source revision, inputs, binary bytes
and hashes, transcripts, exits and markers outside the checkout.

A missing binary, failed setup, timeout or failed cleanup is incomplete
evidence. No skip or substituted product output is accepted. Every test name
is under 40 characters. The commands below run unchanged assertions.

First demonstrate the review regressions with retained pre-fix binaries. Use
the release head for the append row, and the tagged CLI from b41ffa7 for the
turn row. The new provenance rows and their separate base failures are described
in [PROVENANCE.md](PROVENANCE.md).

```sh
LANEBOSS_BIN="/absolute/path/to/pre-fix-laneboss" \
  python3 -m unittest discover -s e2e-rows -p test_legacy_lanes.py \
  -k test_append_grants_no_legacy -v
LANEBOSS_BIN="/absolute/path/to/pre-fix-laneboss" \
  LANEBOSS_FAULTS_BIN="/absolute/path/to/pre-fix-faults" \
  python3 -m unittest discover -s e2e-rows -p test_legacy_lanes.py \
  -k test_legacy_turn_delivery -v
```

On the release head the append row fails because the starter-less resume is
refused before payload validation. On a build before lifecycle protection it
fails because the accepted event lacks external provenance. The turn row fails at the real turn's success
assertion with the strict relationship refusal after mail was queued.
A setup or fixture-marker failure is not the expected regression. The old
tagged binary must support `legacy-start-without-starter`.

Challenge the current tagged build with these mutants before running controls.
Each must exit 1 at the named action's assertion, with its marker present:

```sh
LANEBOSS_BIN="/absolute/path/to/laneboss-faults" \
  LANEBOSS_REPORT_MUTANT="event-allow-started" \
  LANEBOSS_REPORT_MARKER="/absolute/path/to/append-marker" \
  python3 -m unittest discover -s e2e-rows -p test_legacy_lanes.py \
  -k test_append_grants_no_legacy -v
LANEBOSS_BIN="/absolute/path/to/laneboss" \
  LANEBOSS_FAULTS_BIN="/absolute/path/to/laneboss-faults" \
  LANEBOSS_REPORT_MUTANT="legacy-turn-strict-only" \
  LANEBOSS_REPORT_MARKER="/absolute/path/to/turn-marker" \
  python3 -m unittest discover -s e2e-rows -p test_legacy_lanes.py \
  -k test_legacy_turn_delivery -v
LANEBOSS_BIN="/absolute/path/to/laneboss" \
  LANEBOSS_FAULTS_BIN="/absolute/path/to/laneboss-faults" \
  LANEBOSS_REPORT_MUTANT="legacy-relationship-disabled" \
  LANEBOSS_REPORT_MARKER="/absolute/path/to/send-marker" \
  python3 -m unittest discover -s e2e-rows -p test_legacy_lanes.py \
  -k test_legacy_supervisor_delivery -v
LANEBOSS_BIN="/absolute/path/to/laneboss" \
  LANEBOSS_FAULTS_BIN="/absolute/path/to/laneboss-faults" \
  LANEBOSS_REPORT_MUTANT="peers-allow-all" \
  LANEBOSS_REPORT_MARKER="/absolute/path/to/sender-marker" \
  python3 -m unittest discover -s e2e-rows -p test_legacy_lanes.py \
  -k test_changed_sender_not_delivered -v
```

The first mutant omits the stored external-origin mark for appended starts.
The second refuses fallback at
the real turn delivery boundary. The third removes send-time fallback. The
fourth disables the shared permission decision so a now-lower-level sender
reaches a turn despite its old marker. None manufactures product output.
The append mutant can create a phantom run; retain any collection failure
and its state instead of deleting claims or claiming a clean collection.

Finally run the normal rows with no mutation selector. Require exit 0:

```sh
LANEBOSS_BIN="/absolute/path/to/laneboss" \
  LANEBOSS_FAULTS_BIN="/absolute/path/to/laneboss-faults" \
  python3 -m unittest discover -s e2e-rows -p test_legacy_lanes.py -v
```

`CurrentLaneRows` uses the release CLI. Historical rows use the tagged CLI
to create genuine historical starts and then exercise its real mail/turn path.

| Row | What makes its assertions fail |
| --- | --- |
| `test_legacy_supervisor_delivery` | Higher-level local mail is refused; bytes, identity, hash or marker differ; another local supervisor is excluded; lifecycle or dashboard readers lose the mail. |
| `test_legacy_human_delivery` | Human mail is refused or loses its marker or human message grouping. |
| `test_foreign_configuration_refused` | A pipe-only session registered only in another configuration sends without a binding variable; its refusal does not identify missing local identity; mail or state changes. |
| `test_legacy_turn_delivery` | A real turn is refused; the runner's prompt loses either sender's bytes or marker; mail is not delivered or processes survive. |
| `test_changed_sender_not_delivered` | A queued sender whose level was reduced reaches a prompt, changes state or loses queued mail; restoring its qualifying level fails to deliver the same bytes. Its L6-to-L5 send is a positive recorded-level control. |
| `test_legacy_cannot_raise_level` | An unnumbered historical runner starts an L4 child; the level-rule refusal or unchanged-event assertion fails; an authorized L6 supervisor cannot start the control child. |
| `test_lower_or_equal_level_refused` | L4/L5 senders reach a historical L5 lane or leave mail/state. |
| `test_unidentified_or_forged_refused` | An unregistered pipe caller or impersonating sender sends, or the refusal changes mail/state. |
| `test_current_relationship_stays_strict` | An unrelated supervisor reaches a current lane, its real starter is refused, or normal mail acquires a legacy marker. |
| `test_append_grants_no_legacy` | A starter-less resume is refused, is stored without external provenance, changes the current lane's permissions, or makes ordinary delivery legacy. |
| `test_legacy_reports_reach_supervisors` | A historical reporter omits a configured supervisor, changes bytes/identity, loses markers/outcomes or disagrees with actual file/dashboard output. |

The Go regressions fail if the original run line can be overwritten or reopened
(`TestRunLineIsImmutable`), an unnumbered lane raises a child's level
(`TestLegacyStarterCannotRaiseLevel`), permission or marker decisions differ
(`TestMessageDecision`), an authenticated lifecycle input cannot reach payload validation
(`TestLifecycleAppendAuthorized`), a protected message kind reaches append
(`TestMessageAppendStillRefused`), or Discord loses its marker or original text
(`TestDiscordLegacyText`). Run these packages under both tag sets on Linux:

```sh
GOTOOLCHAIN=local go test ./internal/caller ./internal/event \
  ./internal/peers ./internal/report ./internal/laneturns
GOTOOLCHAIN=local go test -tags laneboss_faults ./internal/caller \
  ./internal/event ./internal/peers ./internal/report ./internal/laneturns
```

The existing identity source row now needs `LANEBOSS_FAULTS_BIN` for its
`historical-supervisors` real-start fixture; its source/graph assertions remain.
R5 in the report message rows still uses its tagged loopback Discord probe.
These rows do not claim an authenticated AI-service test.
