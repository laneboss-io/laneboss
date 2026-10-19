# Human-issued registration tickets

R39: a ticket is single use, and the level and role granted at registration are
exactly those specified when the human issued it. Nothing is chosen at use time.
For 1.0.0, R25 is enforced for Linux identity-service deployments. Without a
service, registration stays open with its one-line R25-not-enforced notice.
macOS service mode is not yet supported for registration. In service mode no
shipped harness can register a supervisor: the plugin and shell-tool agents
are refused. Only a custom persistent process that leads its own OS session
and invokes the CLI directly can register. Their refusal
names the owner-terminal ticket route and the supported direct invocation from
a dedicated persistent agent process. No-service plugin registration remains
available. The plugin accepts at most two words: configuration and optional
role. It accepts no level or ticket-file argument and cannot carry this handoff.
These are the shipped limits, not a claim of universal enforcement.

## Issue and redeem

From the separately attested human terminal, issue to a private handoff file:

```sh
umask 077
laneboss ticket issue --config example --level 4 --role supervisor --ttl 10m > supervisor.ticket
```

The protected configuration must define `supervisor` at L4 when it is issued.
`--config`, `--level` and `--role` are required on issue. There is no level or
role default. Only the lifetime has a default: ten minutes, also its maximum.
Configured supervisors support L4–L6; org instances can also use L3.

The intended dedicated persistent session registers with that exact scope:

```sh
laneboss start --config example --level 4 --role supervisor --ticket-file supervisor.ticket
```

`--level` is required with `--ticket-file`. It requests a comparison with the
ticket, not a new authority. The service reads configuration, level and role
from the digest-matched database record under SQLite's writer lock. It compares
the request, resolves a dedicated live parent from the kernel peer, constructs
the grant using that stored issued scope, and conditionally consumes the ticket.
The grant is returned only after consumption commits. Invalid scope or a denied
grant does not consume it; a later core registration failure does burn it.

Changing protected role policy never substitutes another grant level. If policy
lowers or removes the role after issue, redemption refuses with the issued and
current scope and an Instead route to issue a new ticket for the current scope.
That refusal does not consume the ticket. A higher current level still grants
only the issued level. The service reloads protected policy on each check;
lowering or removing a role also refuses a live registration on its next use.
The next service status, lane start or adoption refuses with the same scoped
policy diagnostic. A fresh current-scope ticket may replace the revoked record.
This is a current-policy suspension, not a durable revocation record: restoring
the role at or above its recorded level reinstates a still-running session
without another ticket. A policy change undone before the next use leaves no
revocation record. Refusals and reinstatements currently write no policy-transition
audit line to the service journal; exactly one actor/registration record per
transition remains a known limit. Commands that already passed identity resolution can finish.

Lanes already started under that role keep their recorded level and starter
and run until they end; an existing supervising lane can still start lower-level
lanes. Demoting or removing the role does not stop those lanes. The human stops
each affected lane with `laneboss lane stop --config NAME --lane LANE` from the
attested terminal. If the service or its binding is unavailable, this CLI stop
also refuses. Restore the service/binding first, or have the human use OS tools
to stop the supervised processes by their verified PIDs, never by a command-line
pattern.

The core still enforces session ancestry and escalation limits. Request fields
and a role's newly derived level never supply the granted level. A successful
registration of an L4 `supervisor` ticket is recorded as `supervisor:supervisor`
at level 4, which the real `service status --config example` must resolve from
that persistent session.

## Exact refusals

All refusals below exit 2, emit no success document or bearer, and retain a
separate `Instead:` route.

| Condition | First stderr line |
|---|---|
| WrongLevel | `refused: the registration ticket is for another level` |
| WrongRole | `refused: the registration ticket is for another role` |
| Used | `refused: the registration ticket has already been used` |
| Policy demotion example | `refused: the registration policy changed: issued example L5 top; current example L4 top` |
| Policy removal example | `refused: the registration policy changed: issued example L4 supervisor; current removed example supervisor` |
| Source unreadable example | `refused: the registration policy changed: issued example L4 supervisor; current unavailable example supervisor` |
| Binding lost or unreadable | `refused: the configured identity service binding is unavailable` |
| macOS service registration | `refused: identity service registration is unsupported on macOS` |

For an unused L4 supervisor ticket requested as L5 top, WrongLevel precedes
WrongRole. A different L4 role receives WrongRole. Both recovery routes direct
the human to issue a fresh ticket for the configuration, level and role they
want with `laneboss ticket issue --config NAME --level LEVEL --role ROLE`, then
register with that exact scope and `--ticket-file PATH`.

A known consumed ticket receives Used for matching scope, a different level and
role, or a different role at the same level. The recovery route asks the human
to inspect the consuming peer through service status before issuing a fresh
ticket for the desired level and role. Changing the request cannot reuse or
reset the ticket. Expired records retain the existing one-day diagnostic window.

## Token and upgrade

The canonical token is `lbt2.CONFIG.LEVEL.ROLE.NONCE`. LEVEL is a single decimal
digit 3–6, and NONCE encodes 32 random bytes as canonical unpadded base64url.
SHA-256 covers the entire token, including level and role. Only the digest and
issued scope are persisted. Instance roles use the shared 96-character name
grammar, including case, underscores and dots; the final dot always separates
the nonce. The token is at most 180 bytes and the private regular handoff file
is bounded at 256 bytes with an optional single final newline. Existing lbt2
tickets remain canonical and keep their issued scope.

The service migrates older databases by adding a level column. Existing rows
remain without an issued level; it never fills them from role policy. Old
`lbt1` tokens are refused as unknown and require new human issuance. Previously
registered sessions keep their journaled identities only while current protected
policy still authorizes their recorded scope.

## Trust checks before the release gate

Only absence of both service configuration and persistent selection permits legacy
mode. Malformed tables or paths are errors through caller resolution,
registration and the service client, and never select local identity files.
Every Linux service deployment must provision a root-owned mode-0644 persistent marker
at `/etc/laneboss/identity/NAME`. A volatile runtime directory alone is not a
service configuration. Runtime-directory loss or unreadability leaves selection
in force and produces the exact binding refusal, with no legacy notice or files.
The documented empty table enables the default service root. The selector
also validates configurations assembled in memory by other command groups.
The marker is required even with an explicit service table: a lane-editable
client table alone is not an OS boundary and can be removed from that view.

Issuance authenticates the socket's kernel peer UID and full process identity,
controlling terminal, rechecked ancestry and the attested live terminal session
leader. It refuses recorded agent identities. The request configuration must
match the service. Level and role must match protected policy at issue and the
digest-matched stored scope at redemption. The grant parent comes from kernel
ancestry and must lead its OS session; core authorization independently checks
ancestry, root collisions and escalation.

At issue and redemption the service rechecks config policy protection. For an
org instance it also checks every ancestor of the instance directory and the
bounded regular `instance.toml` file's ownership and write permissions. A
protected org root cannot make a writable instance file trusted. A refused
grant rolls back without consuming the valid ticket.

Keep the attested human terminal for issuance, and run agents outside that
login's ancestry. An unregistered interactive agent under that login otherwise
meets the same kernel human checks. Handoff files remain bearer secrets;
processes sharing their UID may read them. CLI lane identities are not yet
recorded in the service's lane registry, so direct-socket use of a stolen ticket
is a suspected residual not closed by the client's lane check. Escalation or
other core refusals after consume burn the ticket. Consumer audit supports
investigation; it is not theft prevention. Multiplexer/shared-parent detection
still has name-based limits; registration through such roots is unsupported.

An independent bypass in `caller/tickets.go` with valid service configuration
is ruled out by the control path: configured service selection wins over a
registrar probe, empty tickets and absent registrars refuse, the executable
installs the authenticated client, and core authorization independently refuses
a grant above the recorded caller level. Legacy open registration is intentional
no-service compatibility. Malformed selection and incomplete policy/session
checks are separately hardened. Runtime canaries are still required before
claiming the suspected gaps were exploitable.

## Verification contract

The disposable-Linux rows live in `e2e-rows/test_ticket.py`; execution and retained
evidence instructions are in [the row guide](../e2e-rows/TICKET.md). No Mac
static check establishes a runtime pass or a mutation kill.

| Row | Required observation; expected red on 52c60e1 |
|---|---|
| `test_r39_issued_scope` | Issue L4 supervisor, reload its protected policy as L5, register as L4 supervisor, and inspect actual CLI identity. The old grant derives L5 at use and fails `GrantedLevel`. |
| `test_r39_wrong_level` | L4 supervisor requested as L5 top gets exact WrongLevel and no registration; the issued scope still works. The old verifier reports WrongRole, failing `WrongLevel: L4 ticket requested as L5 top`. A same-role L5 request is also refused. |
| `test_r39_wrong_role` | Another L4 role gets exact WrongRole, no identity, and an issuance recovery specifying both level and role. The old recovery lacks the issued level and fails `WrongRole recovery must issue the desired level and role`. |
| `test_r39_reuse_scopes` | Consume once; matching, changed-level/role and changed-role replays from fresh controllers all get Used and no identity. Old matching replay is already refused, but changed-scope replay reports WrongRole and fails `Used: consumed status must precede requested scope`. |
| `test_r39_explicit_issue_level` | Omitting issue level fails `IssueLevel: omission of the issued level was admitted` on the old command, which issues instead. Explicit issuance supplies the allowed control. |

The fixture reads real issue help before any issuance to select the supported
CLI grammar for comparison with the old binary. Only grammar changes; every
semantic assertion is identical. It never retries a refusal, edits a ticket
database, seeds a grant or manufactures a CLI result. On the current binary all
issuance and registration helpers pass the explicit level.

`ticket-level-unchecked` skips the store's requested-level comparison only in a
fault build and writes a real reach marker. It leaves role comparison intact,
so L5 top receives WrongRole and the WrongLevel row fails its named assertion.
The release build must ignore this selector. Keep the failing log, passing
control, release-inert run, marker and tested binary/source bytes before claiming
a kill. The existing reuse and human-PTY mutants remain required.

The release-fix fixture gives each configuration a separate protected org copy,
fixing the observed FileExistsError that stopped T1–T8 in setUp. No row is
skipped. `test_s1_issue_untrusted_role` and `test_s2_redeem_untrusted_role` make
an actual unprivileged write to a writable instance file and require refusal at
issue and redemption. `test_s3_parent_not_session_leader` proves the parent is
not a session leader and requires refusal. Each has a protected/dedicated
allowed control and checks actual CLI identity. `TestMalformedServiceNeverLegacy`
requires malformed selection to refuse before any registrar call or local
identity write. RED/GREEN results remain pending disposable-Linux execution.

Instance lookup uses the explicit configured org_dir when supplied, matching
role policy and the service's protected-source checks. It falls back to the
organisation's named directory only when no override exists; an invalid
override cannot silently select another org. A regression fixture gives the
two orgs different instance levels to detect the wrong source.

The service-backed T1/T2 workflow also executes a real turn of the adopted
session and verifies that the merged settings code derives delegation from
the recorded starter. Its source record must satisfy the filesystem quiet
period. The stand-in runner prints an input-derived completion receipt for
ordinary archive collection; no report or product result is fabricated.

## Policy and deployment delta rows

The policy rows use normal ten-minute tickets and require the exact policy
diagnostic, so expiry or another refusal cannot satisfy them. All results still
require disposable-Linux execution.

| Row | Expected RED on 1e99aa6 |
|---|---|
| `test_r39_demoted_refused` | An unexpired L4 instance ticket registers after policy lowers it to L3; `StalePolicy` fails. The current L3 control succeeds, and restoring policy proves the old refusal did not burn its ticket. |
| `test_policy_revokes_live_session` | A removed role remains identified. The fixed row also requires next start/adopt to refuse with the same scope diagnostic. |
| `test_policy_demotes_live` | Without a daemon restart, an L5 registration retains authority after the config lowers it to L4. A new L4 ticket is the replacement control. |
| `test_binding_survives_stop` | After a real service stop and runtime removal, binding-only registration silently falls back to legacy and exits 0. The persistent marker remains. |
| `test_binding_unreadable` | An unreadable runtime binding loses the exact binding refusal. |
| `test_plugin_ticket_route` | The old plugin's four-word refusal differs from the restored exact two-argument message and fails `PluginArguments`. The current plugin rejects three/four words and empty names, transports the real missing-ticket refusal for two words, and accepts no ticket handoff. A separate shell-parent CLI call retains the owner-terminal/dedicated-process refusal; the supported direct controller redeems the same unconsumed ticket. |

The existing-module service pass now uses the separately attested owner terminal
for human commands and a separate persistent controller for each role. Client
actors share an unprivileged UID for the launcher's state ownership checks;
service policy/state remain separately owned. `test_service_actors_separate`
checks real ticket registration leaves the human actor human and the role actor
identified. This detects the baseline row-model bug when run with baseline
helpers; copying the fixed actor helpers already applies that fixture repair.
