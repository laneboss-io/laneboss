# Turn and analytics provenance

These checks are for the disposable Linux test host with supplied release and
tagged binaries. They were authored on the development Mac, where only static
checks are authorized. No red/green or canary result is claimed here.

Turn actions reconstruct their state and previous payload from launcher events.
Appended events retain their display projection, but supply no worktree,
session, project, claim registry or report line to a turn. An external-only
adoption with no mail acknowledges the empty turn without resolving its runner.
Mail permission checks use the configuration's existing relationship rules,
then `lane send` requires a launcher-made run. An external-only adoption takes
no mail: send exits 2, with no event or mail-directory change. An appended runner
that cannot take turns selects `lane X cannot take mail: runner R cannot take
turns, because …`; otherwise the refusal is `lane X has not run yet, so it takes
no mail` followed by `Instead: lane adopt the running session, or lane start
--turns`. An ordinary empty turn still succeeds without execution, and an idle
turn refuses with `Instead: lane adopt`, including after a refused send.
Differing observed and launcher run numbers
refuse before launch. The turn loop also schedules from launcher records.
Run-advancing appends for an existing launcher life now refuse before any
projection change, with `Instead: use lane start, resume or turn`. The forged
turn row requires this refusal and unchanged runner/state. Only the exact old
release refusal enables its base-only append fault seam; that path reconciles
the dead record and attempts the redirected turn. The release head refuses that
turn with its directory-claim guard (`the working directory no longer carries
lane current's claim`), so the forged turn was never open there and the row
fails on it at `the base must reach its redirected turn`. Without the advance
gate the fix path fails at `run-advancing append was accepted`.
Both lane command groups share the same mismatch message and recovery text.

The external end/loss residual is withdrawn. Ended, lost and gone appends
for launcher-recorded names refuse; use lane stop or lane check instead.
Never-launched observation names keep their event contract. The existing
external-target rows require no-run send refusals. The forged-starter and
forged-level L3 checks retain their permission refusals, with an additional
`may not message` control from that same L3 sender to a launcher-made lane
under a different supervisor.

Analytics omit appended events before run association, counts and usage reads.
An appended project cannot select a lane into an instance ledger. Independently
selected ledger observations remain marked. Settings keep the observed values
and add `externally_appended: true`; an external scalar `get` is wrapped as
`{value, externally_appended}` so it can carry that mark. Genuine scalar output
is unchanged. Event tail adds an origin boolean to its display copies and only
a launcher-made event satisfies `--until`.

| Check | Required failure without the repair |
| --- | --- |
| `laneturns.TestTurnAuthority` | The latest payload selects a forged directory, session, project, registry or ancestry; the reconstructed run changes; a differing run is accepted; the scanner reads appended paths; or loop backoff uses an appended end. The real-life and display controls must still succeed. |
| `laneturns.TestTurnExternalOnly` | An appended adoption becomes a previous run, empty-turn behavior is lost, execution lacks the adoption refusal, or an external-only target receives mail. An appended runner may select a refusal explanation but cannot authorize queuing. |
| `laneturns.TestTurnLiveEvidence` | An appended ended/gone event serves as proof that an open launcher run without a process record is safe. It must keep the missing-record refusal. |
| `laneturns.TestTurnCleaned` | Reconstructing launcher state loses a real cleanup record. |
| `dashboard.TestAnalyticsExternal` | Appending a real stored start and failing end changes any analytics output. The genuine run must count before that comparison. |
| `ledger.TestSelectionExternal` | An appended project pulls an unrelated real task into an instance ledger. A later genuine project association must select two real tasks and retain two marked observations. |
| `settingscli.TestSettingsExternal` | Any of get/list, with/without explain, loses the external mark or the actual observed model. The genuine scalar control must keep its original value and shape. |
| `event.TestTailExternalUntil` | Tail stops on an appended state, passes the later launcher state, or omits either origin boolean. The events are appended through the actual store. |
| `TurnOriginRows.test_external_no_mail` | Actual CLI empty-turn output changes, idle execution lacks the adoption refusal before or after rejected mail, send does not exit 2 with the exact no-run refusal and recovery text, or events/mail change. A rejected send must leave the ordinary turn empty. |
| `TurnOriginRows.test_forged_turn` | After a real successful mailed turn, the next-life append must refuse without changing events or the real prompt. On the release head the fault path's turn is refused by the directory-claim guard (`the base must reach its redirected turn`); without the advance gate the fix path fails `run-advancing append was accepted`. The spare directory and session are distinct from the genuine control. |

The old release head refuses some lifecycle inputs, so such setup failures are
not evidence that the security assertions work. Use the following exact
one-line mutations of this repair, one at a time, retaining the assertion
failure and the complete inputs. Compilation or setup failure is not a kill.

1. In `internal/laneturns/provenance.go`, replace `return owned, nil` with
   `return events, nil`. The authority, external-only and live-evidence units
   must fail their metadata or safety assertions.
2. In its `checkLaunchProjection`, replace
   `if integer(observed["run"]) != integer(row["run"]) {` with
   `if integer(observed["run"]) < integer(row["run"]) {`.
   The genuine control passes, then `TestTurnAuthority` must fail its divergent
   run assertion. The CLI forged-life row now stops at the stronger append
   boundary; removing the advance gate fails its append-refusal check.
3. In `internal/laneturns/scan.go`, replace
   `events, err := s.events(lane, "")` with
   `events, err := s.store.events(lane, "")`.
   `TestTurnAuthority` must fail its scanner assertion.
4. In `internal/laneturns/projection.go`, replace
   `row["cleaned"] = true` with `row["cleaned"] = false`.
   `TestTurnCleaned` must fail its cleanup assertion.
5. In `internal/dashboard/analytics.go`, replace its new external filter with
   `if eventstore.ExternallyAppended(e) && e["kind"] == "demo.note" {`.
   The real analytics control passes; the appended-output comparison fails.
6. In the first event loop of `internal/ledger/ledger.go`, replace its new
   external filter with
   `if eventstore.ExternallyAppended(e) && e["kind"] != "lane.started" {`.
   `TestSelectionExternal` must fail its unrelated-task assertion.
7. In `internal/settingscli/settings.go`, replace
   `output.(map[string]any)["externally_appended"] = true` with
   `output.(map[string]any)["externally_appended"] = false`.
   The genuine scalar control passes; the external-mark assertion fails.
8. In event tail, replace its new until condition with
   `if o.Until != "" && e["kind"] == o.Until {`.
   `TestTailExternalUntil` must fail its event-count assertion. Separately,
   replace `display["externally_appended"] = eventstore.ExternallyAppended(e)`
   with `display["externally_appended"] = false`; its origin assertion fails.

On Linux, run the changed packages with and without `laneboss_faults` and run
the two CLI rows separately against the supplied release binary. Retain the
fixture via an absolute `LANEBOSS_ROW_EVIDENCE` outside the checkout. Do not
import or execute these rows on the development Mac.

```sh
go test ./internal/laneturns ./internal/dashboard ./internal/ledger ./internal/settingscli ./internal/event
go test -tags laneboss_faults ./internal/laneturns ./internal/dashboard ./internal/ledger ./internal/settingscli ./internal/event
python3 -m unittest discover -s e2e-rows -p test_turn_origin.py -v
```

The existing private adoption no-mail test, the external-target refusal row in
`test_legacy_lanes`, and the integration security read
are also required before acceptance. These stand-in rows do not authenticate
to an AI service.
