# Human-issued registration-ticket rows

The issued level/role and replay contract is [docs/TICKET.md](../docs/TICKET.md).
R39 adds five `test_r39_*` rows, all with names shorter than 40 characters.
Three `test_s*` rows cover the release security delta. No setup error or skip
counts as a passing row.

Run only on the authorized disposable Linux box. Nothing here authorizes a box
launch or a runtime/build on the Mac. LANEBOSS_BIN names the already built real
unified binary. T0 runs without a service and requires successful open legacy
registration plus exactly one R25-not-enforced notice on stderr. Before that
allowed control, T0 requests an undefined role in both text and JSON forms and
requires the exact refusal with no notice, success output or registration state.

T1–T8 and R39 rows provision their own credential-free service and attested owner PTY under
separate OS accounts through ticket_fixture.py. The root test driver must have
useradd/groupadd, Git, tmux and Python 3.11 or later. The service creates its own
private database. No verifier, ticket, registration record or launcher result is
seeded. The owner terminal runs the actual ticket issue CLI. Raw tickets stay in
memory and private handoff files, never fixture logs. Services and owner terminal
controllers are collected by PID after lane/controller cleanup.
Configurations sharing the source org receive separate protected homes at
`policy/CONFIG`, with `configs/CONFIG` and canonical `orgs/ORGANISATION` inside.
Both explicit org_dir and the historical named-org lookup reach that binding's
same real protected copy. The old shared destination raised FileExistsError on the
second binding, before T1–T8 ran. That box log proves the fixture failure only.

```sh
LANEBOSS_BIN='/tmp/lb-svc-ticket' python3 -m unittest discover -s e2e-rows -p 'test_ticket.py' -v
```

T1 and T2 must register, start a real lane through the ordinary CLI, wait for its
actual runner, and adopt another lane. They require the supervisor as starter,
the runner's retained prompt/session record, and no local supervisor sessions or
role tickets. A service status response alone cannot pass them.
The adoption record's filesystem mtime models an existing quiet session;
the JSON timestamp alone does not satisfy the runner's quiet-period check.
After adoption each row sends a file and runs a real first turn, requires the
retained continuation, and checks that settings delegation names the immutable
recorded supervisor starter. Starter and level checks remain active.

The stand-in runner emits a receipt only after reading and retaining the real
prompt, including its observed byte count and session. Collection archives this
actual output through ordinary lane clean. The rows supply no invented report
or archive receipt. T8 also emits this receipt before its actual detach probe.
The runner stays alive while a separate probe parent exits and the orphan
retains its real verdict; this prevents the supervisor's normal descendant
collection from racing the probe. The pidfd parent-exit proof, double fork,
reparenting check, marker and issuance assertion remain required. The outer
probe deadline stays 60 seconds. A timeout includes bounded lane output and
daemon stderr tails, both bearer-redacted through safe_diagnostic; daemon stderr
is retained in a private file instead of an undrained pipe.
Command and owner-issuance failures include their real stderr with bearer text
redacted; raw issuance stdout is never included in diagnostic messages.

T8 starts a real stand-in lane. The probe runs with the configured owner's
unprivileged UID, double-forks, uses a real pidfd to prove its original parent's
exit, opens a new PTY and invokes ticket issue. It requires the exact first line
`refused: only the human at a real terminal may issue a registration ticket`,
an Instead route and no issued bearer. The separate attested owner remains its
allowed control. No environment label supplies its identity or authorization.

With the fault-tagged real binary, demonstrate the expected failures before
controls, each as its own retained command. A setup/cleanup error, timeout,
missing marker or unrelated failure is not a mutation kill.

```sh
LANEBOSS_FAULTS='{"point":"ticket-reuse","marker":"/tmp/lb-ticket-unit-reached"}' GOTOOLCHAIN=go1.26.0 go test -tags laneboss_faults ./internal/identityd/ticket -run '^TestSingleUse$' -count=1 -v
LANEBOSS_BIN='/tmp/lb-svc-ticket-faults' LANEBOSS_TICKET_MUTANT='ticket-reuse' python3 -m unittest discover -s e2e-rows -p 'test_ticket.py' -k test_t2 -v
LANEBOSS_BIN='/tmp/lb-svc-ticket-faults' LANEBOSS_TICKET_MUTANT='ticket-human-pty' python3 -m unittest discover -s e2e-rows -p 'test_ticket.py' -k test_t8 -v
LANEBOSS_BIN='/tmp/lb-svc-ticket-faults' LANEBOSS_TICKET_MUTANT='ticket-level-unchecked' python3 -m unittest discover -s e2e-rows -p 'test_ticket.py' -k test_r39_wrong_level -v
```

The fixture places LANEBOSS_FAULTS in the daemon, not the client. The real
ticket-reuse call site removes the consumed-status guard and SQL unused predicate: TestSingleUse and
T2 must fail at `a registration ticket verified twice`. The ticket-human-pty
call site restores the old unknown-plus-PTY rule: T8 must fail at
`a detached lane with a PTY minted a registration ticket`. Inspect the actual
fixture marker before treating either as a kill. Run the selectors absent for
their controls and run the release with selectors to prove they are inert.

The `ticket-level-unchecked` site skips the requested-level comparison inside
the real store's atomic redemption. Its reach marker must exist, and
`test_r39_wrong_level` must fail at `WrongLevel: L4 ticket requested as L5 top`.
Role comparison remains active, so the mutant produces WrongRole. Setup errors,
missing markers or another assertion's failure do not count. Run the same row
without the selector as its control, and with the selector on the release
binary to prove it is inert. Add this selector alongside the two existing
mutants in the supervisor's ticket suite.
Its release-inert runs also set LANEBOSS_TICKET_EXPECT_INERT=1: the same row
requires the real marker to be absent while keeping the behavioral assertions.
Fault-mutant runs require the marker to exist before their named assertion;
neither mode skips a probe or replaces a product result.

For RED on `52c60e1`, copy the current Python row/helper bytes alongside that
built binary and select each of the five original R39 rows listed below (the
later `test_r39_demoted_refused` belongs to the 1e99aa6 delta). The fixture discovers supported level
syntax from the actual issue help before issuance. This lets the old command
reach the semantic assertions; it does not retry refusals or weaken assertions.
On current help, every helper passes `--level` explicitly. Retain the real
help, command exits and red/green logs. The expected failures are:

| Row | Expected failure on 52c60e1 |
|---|---|
| `test_r39_issued_scope` | `GrantedLevel: CLI identity differs from the issued level`: protected policy reload changes the old grant from the issued L4 to L5. |
| `test_r39_wrong_level` | `WrongLevel: L4 ticket requested as L5 top`: old code returns WrongRole. |
| `test_r39_wrong_role` | `WrongRole recovery must issue the desired level and role`: the old route omits level. |
| `test_r39_reuse_scopes` | `Used: consumed status must precede requested scope`: changed-scope replays return WrongRole; matching replay already refuses. |
| `test_r39_explicit_issue_level` | `IssueLevel: omission of the issued level was admitted`: the old command issues without level. |

Each refused registration also checks actual service identity remains absent,
with no local session/role records. The allowed control checks the CLI identity
is exactly L4 `supervisor:supervisor`. The policy reload changes only the real
protected configuration and restarts the daemon; it never edits tickets or
registration records.

For the security delta, run current Python rows/helpers against 0633e60 with
the per-configuration org-copy fixture fix, then against the current product.
This isolates security assertions from the observed setup failure. Retain the
exact source delta and both runs.

| Row | Expected RED before the product fix |
|---|---|
| `test_s1_issue_untrusted_role` | The unprivileged owner rewrites a mode-0666 instance from L4 to L6, and issuance succeeds: `UntrustedIssue: caller-writable instance policy issued a ticket`. |
| `test_s2_redeem_untrusted_role` | The same unprivileged policy write permits a registration: `UntrustedGrant: caller-writable instance policy authorized registration`. Restored protected policy must allow the same ticket on the fixed product. |
| `test_s3_parent_not_session_leader` | A kernel-proven non-leader parent registers: `DedicatedParent: a non-leader parent authorized registration`. The allowed control is a dedicated session. |
| `TestMalformedServiceNeverLegacy` | Invalid service input selects legacy mode: `MalformedService: a present invalid service selected legacy registration`. Empty-table and absent-table selections are controls. |

The instance policy comes from the real org CLI. The write probe runs under the
separate unprivileged human UID and verifies real file contents; it creates no
ticket, grant or product result. The security findings remain suspected until
the Linux canary and control run. A separate caller/tickets.go bypass with valid
configuration is ruled out by its ticket gate and independent core checks.
Instance identity lookup and service trust checks honor explicit org_dir, so
they read the per-binding protected copy. TestInstanceRoleUsesExplicitOrg uses
two real instance files with different levels; the old implementation selects
the named org despite the override and fails its ExplicitOrg assertion. The
no-override case and invalid-override refusal are controls. S1/S2 still issue
real L4 instance tickets in their protected allowed controls.

The exact-stderr `test_agreeing_lane_cannot_claim_human` is unchanged. The product
role gate restores `refused: Instead:`. The broader plain-Instead change came
from release commit 08e365b (setup formatting), before the ticket integration;
setup/service recovery lines retain their plain format. Other full-stderr
report rows compare the one-line level rule and report peer refusal and do not
share this role-gate path.

Run the existing modules twice. The first pass leaves no service configured;
the second sets LANEBOSS_TICKET_SERVICE_ROWS=1. Their registration helpers then
issue actual tickets and pass the explicit configured level plus --ticket-file to the same start command. They do
not replace registration with status or preseed sessions.
In service mode, human steps use the separately attested owner terminal. Each
registered role has its own persistent controller; clearing a role label does
not turn that controller into the human. Client controllers share the fixture's
unprivileged human UID so local state ownership remains consistent, while the
service and its protected policy/state retain a different UID and protected
copy. Public copies of the real launcher and runner source bytes are used when
the checkout's parent directories are private. The root test driver prepares
only the disposable client tree for that UID, never the service policy tree.
Both human and role results still come from actual CLI subprocesses.
Protected service fixtures are created directly under root-owned /tmp, even
when caller evidence uses another TMPDIR; an unprivileged suite-owned ancestor
cannot protect service state or policy. The public interpreter alias preserves
the configured driver basename while resolving the actual interpreter outside
private venv ancestry. Changing python3 to python3.12 in a command array would
fail the org's real driver allowlist before service readiness. Early daemon
exit reports its observed exit code and bearer-redacted stderr tail; the real
owner PTY and daemon readiness checks remain required.
The service fixture prepares ownership across the disposable client tree before
requests. Results that depend on original file ownership therefore are not
established by this service pass; retain the no-service ownership rows and the
separate cross-account ticket security canaries for those claims.

```sh
LANEBOSS_TICKET_SERVICE_ROWS=1 sh e2e-rows/check-roles.sh
LANEBOSS_BIN='/tmp/lb-svc-ticket' LANEBOSS_TICKET_SERVICE_ROWS=1 python3 -m unittest discover -s e2e-rows -p 'test_headless.py' -v
LANEBOSS_BIN='/tmp/lb-svc-ticket' LANEBOSS_TICKET_SERVICE_ROWS=1 python3 -m unittest discover -s e2e-rows -p 'test_report_identity.py' -v
LANEBOSS_BIN='/tmp/lb-svc-ticket' LANEBOSS_TICKET_SERVICE_ROWS=1 python3 -m unittest discover -s e2e-rows -p 'test_report_dashboard.py' -v
LANEBOSS_BIN='/tmp/lb-svc-ticket' LANEBOSS_TICKET_SERVICE_ROWS=1 python3 -m unittest discover -s e2e-rows -p 'test_report_messages.py' -v
LANEBOSS_BIN='/tmp/lb-svc-ticket' LANEBOSS_TICKET_SERVICE_ROWS=1 python3 -m unittest discover -s e2e-rows -p 'test_orghook_lane_boundary.py' -v
LANEBOSS_INIT_BINARY='/tmp/lb-svc-ticket' LANEBOSS_INIT_FAULTS='/tmp/lb-svc-ticket-faults' LANEBOSS_INIT_EVIDENCE='/var/tmp/ticket/service-init/cases' LANEBOSS_TICKET_SERVICE_ROWS=1 python3 -m unittest discover -s e2e-rows -p 'test_init.py' -v
```

check-roles.sh supplies its own installed/fault builds and retained evidence.
For an already supplied pair, test_roles.py instead requires the exact
LANEBOSS_ROLES_BINARY, LANEBOSS_ROLES_FAULTS_BINARY and LANEBOSS_ROLES_EVIDENCE
contract. Other report modules retain their documented LANEBOSS_FAULTS_BIN,
Playwright and mutation inputs; this actor change does not replace them.

The 1e99aa6 policy/binding delta must also run the new rows below. Every refusal
requires its exact scoped first line, no success output and the Instead route.
No expiry or unrelated setup error counts as the stale-policy RED.

| Row | Expected RED on 1e99aa6 |
|---|---|
| `test_r39_demoted_refused` | An unexpired issued L4 instance registers after its protected source lowers it to L3, failing StalePolicy. Current L3 succeeds; restoring policy redeems the original ticket from another dedicated session to prove it was not burned. |
| `test_policy_revokes_live_session` | Removing a configured role leaves its old live registration identified. Fixed status, next start and next adoption all refuse with the same issued/removed scope. |
| `test_policy_demotes_live` | Lowering the protected role without restarting leaves its old L5 identity active. A new L4 ticket must replace the revoked scope on the fixed product. |
| `test_binding_survives_stop` | With a persistent marker retained, stop the real service and remove its volatile directory; the old selector falls back to successful legacy registration. |
| `test_binding_unreadable` | Mode-000 runtime data loses the exact binding refusal on the old selector. The known no-service T0 control remains open and unchanged. |
| `test_plugin_ticket_route` | The old plugin gives a different four-word refusal, failing `PluginArguments: extra words or empty names lost the exact two-argument refusal`. The restored plugin rejects three/four words and empty names exactly, accepts only configuration/role, and transports the real missing-ticket refusal. A separate CLI call through a live shell parent requires the owner-terminal/dedicated-process refusal, then the supported controller redeems the unconsumed ticket. |
| `test_briefing_uses_granted_level` | A higher client copy replaces the actual service-granted L4 in the old briefing. The fixed briefing and real identity both report L4. |

test_service_actors_separate pins the model itself: real ticket registration
must leave the attested human human and identify a separate role controller.
Its baseline comparison uses the old actor helpers, since copying the fixed
helpers already repairs that model. The existing modules' original human/role
and semantic assertions remain required. S1 now runs its protected allowed
control before the writable-file probe, preventing a missing root from making
the attack refusal vacuously pass.

test_init.py retains its documented LANEBOSS_INIT_BINARY, LANEBOSS_INIT_FAULTS
and evidence settings in both passes. Its wrapper now uses the same issuance
helper for role registration. Run docs/check-bootstrap.sh on a clean Linux box;
it checks the credential-free no-service notice and ordinary walkthrough. These
commands do not run on the development Mac.

The supervisor's lb-ticket-suite.sh schedules both passes of these seven
modules as root, using check-roles.sh and the documented fault/init inputs. It
installs the pinned Playwright package and Chromium for the dashboard row. It
also builds all three supplied base tars, runs each of the 15 historical product
rows separately, and accepts RED only for the named AssertionError with no
setup/cleanup error or skip. Missing tars fail the suite. The baseline keeps its
own plugin script and product source while receiving current Python rows and
helpers. The plugin row stays a historical RED: 1e99aa6 accepts three arguments
and uses a different message for four, so it fails the restored exact argument
contract before the CLI probes. The suite requires that named assertion rather
than its former level/path-forwarding assertion. All three mutant rows require their marker and named failure, fault
controls and selector-inert release controls. The bootstrap check must exit 0
and print PASS: getting-started walkthrough.

| Row/check | What makes it fail |
|---|---|
| T0 | No-service registration is refused, the real local record is absent, or the notice is missing/repeated. This is red on 1b162a3's nil-service path. |
| T1/T2 | Actual issuer/registration fails, the real lane start or adoption is refused, the starter changes, or local supervisor files appear. The prior handoff cannot issue or supply caller identity. |
| T2/TestSingleUse | A ticket verifies twice; the SQL reuse mutant must trigger this assertion. |
| T3/T4 | Wrong role/configuration is accepted, its exact refusal changes, the bearer leaks or the valid control burns. |
| T5 | Expiry is admitted or a fresh control fails. |
| T6 | Unknown/absent tickets register or lose their first line/Instead route. |
| T7 | A recorded principal with a PTY issues. |
| T8 | The real detached lane issues; the old PTY rule deliberately admits it. |
| Headless service cases | Local forged session bytes authorize a stranger, revoke the real service identity, or adoption writes a local identity. No-service cases retain their original checks. |
| TestConsumerAndRetention | The persisted consuming peer differs, old rows are not pruned during issue, or cleanup burns the new control. |
| TestIssuedLevelAndUsedPrecedence | Persisted/granted scope differs, editing the embedded level retains authority, or changed-scope replay loses Used. |
| TestLegacyTicketHasNoIssuedLevel | Schema migration infers a missing level, accepts a legacy unscoped ticket, or prevents explicitly scoped fresh issuance. |

The prior hash, concurrency, exact expiry, scope-forgery, handoff-file and parser
unit checks remain. Their assertions operate on actual random inputs and SQLite.
Keep binary/source bytes, commands, exits, red and green logs and real markers.
The Mac static checks establish none of these runtime outcomes. Linux red at
1b162a3 with prior rows, R39 red on 52c60e1, current controls, all three mutants and an independent gate
review remain required before acceptance.
