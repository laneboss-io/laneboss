# Dedicated-user identity service

The additive service core exposes `laneboss service run --config NAME` and
`laneboss service status --config NAME`. It keeps identities and appended
observations under a different OS account from the callers. A lane cannot turn
a file in its own home, an environment label, an argument, or a JSON actor field
into a service-owned identity record. This is the additive identity service core;
the CLI now resolves supervisor registrations through this service when it is
configured. Existing lane-run identity machinery remains in place.

Configure the client with `[identity_service]` and an optional absolute
`runtime_root`. Binding-only installations need a persistent root-owned mode-0644
marker at `/etc/laneboss/identity/NAME`; it selects the protected runtime binding
under `/var/run/laneboss/NAME/` even after the volatile directory disappears.
A missing/unreadable selected runtime directory refuses with
`the configured identity service binding is unavailable`. A volatile directory
without a table or persistent marker must be migrated before registration.
No-service configurations retain open 0.7.0 registration and print one notice
that R25 is not enforced. They are not silently upgraded to a broken ticket path.
For 1.0.0, R25 is enforced for Linux service deployments; macOS service
registration is not yet supported. Plugin and shell-tool parents retain their
service-mode refusal with the owner-terminal ticket-file route. Direct calls
from dedicated persistent agent processes remain the supported service route.

For issuance, the protected service definition supplies `--config-home PATH`,
`--human-uid UID` and `--human-session PID:START`. The configuration and org role
policy must be owned by the administrator or service and not caller-writable.
The human session is attested out of band: the service checks its full kernel
generation, live terminal session leadership, same-UID ancestry and the issuing
peer's real terminal. Unknown peers do not become human merely by opening PTYs.
The `issue` operation applies this check inside the service, including when a
client sends JSON directly. Its payload is exactly `{"level":4,"role":"ROLE","ttl":"10m"}`;
its response contains a transient `ticket`, never a journal record of that value.

The CLI presents `{"level":4,"role":"ROLE","value":"TICKET"}` as the register ticket.
Trusted role policy and peer ancestry supply the grant and dedicated persistent
parent attestation. Current protected policy is reloaded at redemption and on
each use of a live registration. Lowering/removal refuses with issued/current
scope and a fresh-current-scope ticket route; it never grants stale privilege.
The service preserves typed ticket refusal first lines and
their Instead routes. Successful consumption records PID/start/UID atomically;
the attested human's `service status` includes `last_ticket_consumer`. A replay
warning asks the human to inspect that peer before issuing a replacement.

At activation, `--legacy-state PATH` accepts a protected administrator-frozen
`LegacySnapshot` containing the configuration and existing live role/process
entries. Their full kernel identities are validated and imported once; a stored
fingerprint prevents later snapshot replacement. Existing processes keep their
roles subject to the same current-policy checks. New local `sessions/` and `roles/` files are ignored by service
resolution, and new service-backed starts/adoptions write none. See
[configuration.md](configuration.md) for the mode and migration rules.
CLI integration is a separate step. Installing this core does not silently
upgrade those commands' security guarantees.

The service observes and records. It does not launch agents, restrict their
ordinary tools, change their communication channels, merge work, or send owner
messages. `append` durably records an event, report or send request; channel
delivery and the existing CLI event store are not wired to it in this part.

## Ownership and paths

Use one dedicated, unprivileged service user per configuration and one OS group
for its callers. The service's primary group is that configuration group. The
service user must never be used to execute lanes or supervisor tools.

| Item | Default path | Owner and access |
| --- | --- | --- |
| Private identity directory | `/var/lib/laneboss/NAME` | Service user, configuration group, **0700**. |
| Journal | `/var/lib/laneboss/NAME/records.jsonl` | Service user, configuration group, **0600**, regular file with one link. |
| Writer lock | `/var/lib/laneboss/NAME/identityd.lock` | Service user, configuration group, **0600**; exclusive kernel flock. |
| Socket directory | `/var/run/laneboss/NAME` | Service user, configuration group, **0750**; callers can traverse but cannot replace entries. |
| Unix socket | `/var/run/laneboss/NAME/service.sock` | Service user, configuration group, **0660**. |

Root or the service user must own ancestor directories. Group/other write access
is refused, except for a root-owned sticky scratch ancestor used by isolated
fixtures. The leaf directories may not be symlinks. System aliases such as
macOS's `/var` are resolved once and subsequent operations use that canonical
path. A directory with unsafe permissions is refused rather than repaired by
the daemon. Its record files reject symlinks, FIFOs, foreign owners and hardlinks.

`--state-root PATH` and `--runtime-root PATH` override the provisioned roots for
an installation or fixture. They do not confer identity. The service does not
read identities from `LANEBOSS_HOME`, `LANEBOSS_STATE_HOME`, `LANEBOSS_LANE`,
`LANEBOSS_SESSION`, `LANEBOSS_ROLE`, `LANEBOSS_INSTANCE` or portable-process
settings. The CLI still checks its existing configuration binding and requires
an explicit `--config`; it does not load a caller-owned configuration to grant
a role. Part 2's verifier must bind its trusted role policy to that name.

Group membership permits connecting, including supplementary group membership;
the peer's primary GID need not be the socket's group. Membership alone grants
no principal. Unknown callers can use `whoami` and status, but cannot append or
record a lane. The status client checks directory ownership, the socket mode,
the server's kernel credentials and the response's matching server identity.
It refuses a service socket owned by its own caller UID or by root.

## Kernel identity and the ticket boundary

On Linux the accepted socket supplies PID, UID and GID via `SO_PEERCRED` and a
reference to that connecting process through `SO_PEERPIDFD` (Linux 6.5 or later).
The service keeps the pidfd for the connection's lifetime, obtains it before
reading `/proc`, and checks its kernel exit notification at accept and before
writes. Signal zero sends no signal; when the different service UID receives
`EPERM`, polling the same pidfd still observes exit without granting signal rights.
The service reads `/proc/PID/stat` and `/proc/PID/status`, checks the stat again, and
uses the boot ID plus the kernel start ticks as `start`: `BOOT_ID:TICKS`. The
boot ID prevents a record from accidentally matching after reboot. The process
name's parentheses do not shift the stat fields.

On macOS the socket supplies UID/groups through `LOCAL_PEERCRED` and PID through
`LOCAL_PEERPID`. `kern.proc.pid` supplies its start seconds and microseconds as
`SECONDS.MICROSECONDS`, effective credentials and parent PID. No shell command,
`ps` output, environment-selected process reader or caller file supplies these
values. Darwin responses say `peer_lifetime: snapshot-readonly`: these are
diagnostic snapshots, not a verified binding to the connecting process's lifetime.
Every Darwin mutation is refused on both server and client until
`LOCAL_PEERTOKEN`/live pidversion comparison is verified. Unreadable kernel
processes are refused; a later holder of a reused PID is not authenticated by a
Darwin snapshot.

### Older Linux kernels

This implementation deliberately has no PID-only fallback, including for
`whoami`. A Linux kernel without usable `SO_PEERPIDFD` refuses connections with
exit/code 2 and the explicit route to Linux 6.5 or later. `service status`
preserves that lifetime-binding diagnostic rather than reporting an owner mismatch.
The daemon may have opened its socket, but readiness alone is not proof of usable
identity operations. The existing CLI doctor checks do not probe this service
capability; run `service status --config NAME` separately. No registration,
append or lane record is accepted by weakening peer identity on an older kernel.
The ordinary CLI is still independent of this core. A read-only older-Linux mode
would need an explicit future policy and a visible snapshot designation.

The service captures the connected process before reading the request. It walks
kernel parents, compares PID, UID, GID and start time, and rechecks every ancestry
edge included in the walk. The walk stops at the first ancestor whose effective
UID differs from the caller's; nothing above that cut identifies the caller.
It repeats liveness checks and re-resolves the principal before a write.
The identity must agree with the initial resolution. Lane records take precedence
over supervisor sessions, as in `caller.Resolve`; overlapping lane identities
are refused. A nearest recorded supervisor ancestor resolves a headless session
without requiring an OS session ID or a role label. Unknown terminal users do
not automatically become the human principal through this core.

`internal/identityd.TicketVerifier` is the part 2 interface:

```go
Verify(ctx context.Context, config string, peer Peer, ticket json.RawMessage) (Grant, error)
```

`Grant` contains a validated `Principal`, the persistent session's `ProcessRef`
(PID and start time), and a required `DedicatedSession` attestation. The verifier
must authenticate configuration, role and
session authorization, expiration and replay prevention. The service separately
checks that the granted process is the connected caller's live ancestor of the
same UID and a different UID from the service. Lanes cannot register supervisor
roles; a registered session cannot raise its recorded level. Ticket bytes are
neither retained in the journal nor echoed in diagnostics. A new anchor may not
broaden the caller's existing session anchor or contain another live recorded
identity root. Verification runs outside the journal mutex and the kernel identity
is rechecked under that mutex afterwards.

The default `RejectTickets` verifier **refuses every ticket**. Neither the CLI
nor the socket has a flag to replace it with a trusting verifier. A fresh
installation can answer `whoami` but cannot create principals until part 2 is
installed. Linux rows seed a protected baseline as the root-owned fixture; this
is explicitly a test setup and does not test authenticated bootstrap tickets.

An identified launcher records a lane with `lane-started`. The service verifies
the target's live PID/start time and kernel ancestry beneath that launcher,
records its actual credentials and starter, and checks the lane's own lower
level and successive run number. A lane cannot record itself. Later runs remain
bound to the original starter; a handover requires its own authorized operation.
Run N+1 is refused while run N's root is live. Every historical run root remains
in the projection, including after restart, so a still-live old run continues to
resolve as its lane. A proposed root may neither equal nor be an ancestor of a
live recorded session anchor or lane root.

### Launcher detach semantics

`identityd.Launch` creates a gated root beneath a short-lived intermediate, records
it with `lane-started`, exits the intermediate, proves detachment, then releases
the command. `whoami` supplies the matched `identity_root` and a
`detachment_root`, both as PID/start. The latter is the outermost recorded
lane or session root whose PID, start, effective UID and effective GID currently
match, within the caller's **same-UID ancestry line**. The proof compares that
line after detachment with the caller's old line **up to and including that
credential-matched root**. If only one root matches, the two fields agree.
A subreaper at or below that boundary that retains the lane causes refusal
while the command is still gated. This covers an enclosing recorded session
with matching credentials above a nearer anchor in the same-UID line.
Unrecorded ancestors above that boundary remain allowed. The kernel's reaper
search crosses UID changes, and credential drift can hide a root or a retained
ancestor; the exact P2-G windows below remain open before part 2.

Identity resolution still gives a live lane root precedence over session roots.
Ordinary live descendants, including build tools that fork or become subreapers,
continue to resolve and report as their lane. In the stable-credential, same-UID
topologies covered by the rows, an adopted child of an exited detached lane root
has no recorded ancestor and is unidentified. The rows prove
parent exit through a pidfd and kernel reparenting before querying the orphan;
pipe EOF alone can occur before the parent exits and is insufficient evidence.

The helper applies `setsid` to the intermediate and root, preserves environment,
cwd, stdio, rlimits and cgroup, and execs the command without changing its recorded
PID/start. The lane has **no controlling terminal**: `/dev/tty` prompts and normal
pane SIGINT/SIGWINCH/SIGHUP forwarding are not provided. The detached root is not
the starter's waitable child; this handoff currently returns the start record,
not an exit status or stop handle. Process-group/session-based stops do not reach
it, although a containing cgroup stop still does.

There is currently no release CLI caller of Launch; the fault-build probe tests
it. Before wiring it into ordinary lanes, keep a root supervisor that forks and
waits for the command and returns its exit status over a pipe, and a pane relay
that forwards SIGINT, SIGTERM, SIGHUP and SIGWINCH through a pidfd and exits with
that status. Status/stop/terminal integration is pending and must not be replaced
by simply detaching an ordinary CLI lane. Direct `lane-started` callers must also
arrange the gated detach; caller-writable legacy run files are not imported.

## JSON-line protocol, version 1

Every request and response is one UTF-8 JSON object followed by a newline.
Requests carry integer `laneboss_service: 1`, the socket's `config`, and `op`.
Field names are exact lower-case names, both at the top level and inside
`process`; `OP` is not an alias for `op` and `PID` is not an alias for `pid`.
Unknown fields, duplicate keys, invalid Unicode and trailing JSON are refused.
Optional `claim` is arbitrary untrusted JSON and is ignored in release
builds; it never selects a PID, UID, role or actor. Payload is content, not
provenance. There is no top-level client `actor` option.

| Operation | Additional request fields | Result |
| --- | --- | --- |
| `whoami` | None | Kernel `peer`, `peer_lifetime`, whether it is `identified`, and its recorded `principal`, matched `identity_root` and outermost credential-matched `detachment_root` in the same-UID line when identified. No state write. |
| `register` | Opaque `ticket` | Verified session record, or the closed verifier's refusal. |
| `lane-started` | `lane`, positive `run`, `process: {pid,start}`, optional `level` (default 3) | Service-written lane identity rooted in the launcher's actual descendant. |
| `append` | `type: event/report/send`, JSON `payload`; events also need `kind`; sends need principal ID `to`; optional `lane` | Service-written record with the resolved principal as `actor`, kernel peer, timestamp and sequence. |

The root fields can appear on every identified response and describe the
caller resolution before the operation. On a successful future `register`,
`principal` is the new grant while any root fields still describe the caller's
pre-registration projection; query `whoami` again for the new roots. Production
registration remains closed.

For example, a caller queries identity or records a report using these separate
lines on the `example` socket:

```json
{"laneboss_service":1,"config":"example","op":"whoami"}
{"laneboss_service":1,"config":"example","op":"append","type":"report","payload":{"text":"The required checks finished."}}
```

Every append type (event, report and send) is scoped to a lane caller's own lane.
An omitted lane is derived from its principal; naming another lane is refused.
Event kinds use this explicit role allowlist, followed by the CLI envelope,
credential screening and per-kind payload validators:

| Kind | Allowed recorded principals |
| --- | --- |
| `agent.observed`, `lane.refusal`, `lane.workaround_suspected` | Lanes and valid supervisor/instance principals. |
| `lane.refusal_reviewed` | Valid supervisor/instance principals at level 4 or higher. |

Unlisted kinds, including lifecycle decisions, are refused. Report/send types
cannot provide an event kind. Event names inside an append payload never create
identities: only the journal's service-controlled `op` projects identity.
The future adapter must preserve that distinction and must not replay user event
payloads as service registration or lane-started operations.

The request limit is 65,536 bytes including newline; responses and journal
records are limited to 131,072 bytes. Append payloads are capped at **49,152 bytes
after JSON encoding**, including HTML escapes; the complete success envelope is
checked before the durable write. There are at most **32 global connections**,
**2 per kernel peer** (PID, UID, GID and start time), and **8 per UID by default**.
Set the service's `--uid-connection-limit N` to an integer from 1 through 32;
`Options.UIDConnectionLimit` uses 0 for the default. This is a daemon setting,
not a configuration TOML key or a client authority flag. For example:

```sh
laneboss service run --config example --uid-connection-limit 16
```

The refusal names the peer/UID/global cap and, for a UID refusal, the configured
value and how the administrator can adjust it. It occurs before reading request
bytes, without holding the identity mutex. A refusal may close the connection
before the client writes. On EPIPE or ECONNRESET, `Call` still reads a bounded
reply under the same deadline and checks the authenticated service peer,
protocol and configuration. It returns the actual refusal when present. If
the terminal request newline was not sent and no reply arrives, it returns
exit 2 with “the service closed the connection before reading the request” and
an Instead route to retry within the caller's deadline. An unsolicited success
for an incomplete request is an integrity failure. Other write errors keep
their existing handling.

`Call` does not automatically retry or extend the deadline. Size the setting
for expected bursts, or retry an explicit pre-request refusal within the
caller's own deadline. A fully written request followed by a missing response
has no such guarantee; reconcile the journal before retrying a mutation.
There are 64 requests per connection and 128 ancestry steps. Reads and writes have five
second deadlines; connections have a 30 second lifetime. The journal stops at
256 MiB pending administrator archival. A successful response is sent only after
the journal write and fsync. A write/fsync failure stops further writes. Startup
refuses incomplete, malformed, out-of-sequence or cross-configuration records;
it never truncates a tail to manufacture recovery. A response lost after fsync
can leave an already recorded write: there is no automatic retry or idempotency
key in this version. An administrator must reconcile the retained journal.

Responses include `ok`, numeric `code` (0, 2 for refusal, 3 for integrity failure),
`service` and, on refusal, `error`. The error preserves the CLI first line and
Instead route, for example:

```text
refused: the caller has no recorded identity
Instead: run laneboss start --role ROLE from the persistent session that will issue these commands.
```

For an unknown lane-started caller the Instead line includes the CLI's headless
registration and terminal-human routes. Those routes refer to the existing CLI;
service registration itself remains closed pending part 2.

## Linux installation with systemd

The following is an administrator installation example for configuration
`example`, using the invented account `lb-id-example` and group `lb-example`.
Do not perform these host changes merely to inspect the service. Use a released
binary installed by the normal installer in `/usr/local/bin/laneboss`, owned by
root and not writable by callers. Provision the group and dedicated account,
then add the intended caller accounts to that group through the OS's normal
account administration. Start new login sessions for changed memberships.

```sh
groupadd --system lb-example
useradd --system --no-create-home --gid lb-example --shell /usr/sbin/nologin lb-id-example
install -d -o root -g root -m 0755 /etc/laneboss/identity
install -o root -g root -m 0644 /dev/null /etc/laneboss/identity/example
```

Install this complete template as
`/etc/systemd/system/laneboss-identityd@.service` (root-owned, mode 0644):

```ini
[Unit]
Description=Laneboss identity service for %i
After=local-fs.target

[Service]
Type=simple
User=lb-id-%i
Group=lb-%i
UMask=0077
StateDirectory=laneboss/%i
StateDirectoryMode=0700
RuntimeDirectory=laneboss/%i
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
EnvironmentFile=/etc/laneboss/identity/%i.env
ExecStart=/usr/local/bin/laneboss service run --config %i --config-home /etc/laneboss --human-uid ${LANEBOSS_IDENTITY_HUMAN_UID} --human-session ${LANEBOSS_IDENTITY_HUMAN_SESSION}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_UNIX

[Install]
WantedBy=multi-user.target
```

The systemd directory directives provision the default store and socket
directories for the selected user/group. `/var/run` normally resolves to `/run`.
Provision `/etc/laneboss/configs/NAME` and its org as protected policy. The
root-owned mode-0600 `NAME.env` supplies `LANEBOSS_IDENTITY_HUMAN_UID` and
`LANEBOSS_IDENTITY_HUMAN_SESSION` from an independently attested live human
terminal (the latter is `PID:START`). These are service-definition inputs;
never accept them from a client or copy credentials into that file. Refresh
the attestation after the login exits. The separate persistent marker is not
removed when stopping the unit. RuntimeDirectoryPreserve helps across stops;
the persistent marker/table is still required across reboot.
Do not enable `ProtectProc=invisible`, `ProcSubset=pid` or a `/proc` hidepid policy
that prevents this service user reading callers' process identity. Availability
of peer credentials alone does not make unreadable start times safe.

```sh
systemctl daemon-reload
systemctl enable --now laneboss-identityd@<config>.service
laneboss service status --config example
```

Run status as a caller account in `lb-example`. It must exit 0 with `ok: true`
even if `identified: false` during part 1. Use the systemd manager to stop the
service. A refused startup requires inspecting its exact diagnostic; never
change a live configuration binding or replace a foreign socket to force it.

## macOS installation with launchd

Use a **LaunchDaemon**, so the service has its own UID independently of the
logged-in caller. An administrator allocates an unused service UID and a new
configuration group GID according to local account policy. The numeric arguments
below stand for those allocated IDs; they are not authentication secrets.
Use the invented account `_lb-id-example`, with no login shell or agent profile.

```sh
dseditgroup -o create lb-example
dscl . -create /Users/_lb-id-example
dscl . -create /Users/_lb-id-example UniqueID ALLOCATED_SERVICE_UID
dscl . -create /Users/_lb-id-example PrimaryGroupID ALLOCATED_CONFIGURATION_GID
dscl . -create /Users/_lb-id-example UserShell /usr/bin/false
dscl . -create /Users/_lb-id-example NFSHomeDirectory /var/empty
dscl . -create /Users/_lb-id-example IsHidden 1
install -d -o root -g wheel -m 0755 /var/lib/laneboss /var/run/laneboss
install -d -o _lb-id-example -g lb-example -m 0700 /var/lib/laneboss/example
install -d -o _lb-id-example -g lb-example -m 0750 /var/run/laneboss/example
install -o _lb-id-example -g lb-example -m 0600 /dev/null /var/log/laneboss-identityd-example.log
```

The group ID must be the GID assigned to the newly created `lb-example` group.
The administrator adds intended caller accounts to that group and installs the
root-owned binary at `/usr/local/bin/laneboss`. Provision the socket directory
again after reboot if the OS clears `/var/run`; use the same owner and modes.
The daemon requires the parent `/var/run/laneboss` to exist and can create its
own configuration leaf there only when that parent grants it creation rights.
Prefer a managed boot provisioning step for the precreated 0750 leaf.

Install this complete root-owned, mode 0644 plist at
`/Library/LaunchDaemons/io.laneboss.identityd.example.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.laneboss.identityd.example</string>
  <key>UserName</key><string>_lb-id-example</string>
  <key>GroupName</key><string>lb-example</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/laneboss</string>
    <string>service</string><string>run</string>
    <string>--config</string><string>example</string>
  </array>
  <key>WorkingDirectory</key><string>/var/empty</string>
  <key>Umask</key><integer>63</integer>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>StandardOutPath</key><string>/var/log/laneboss-identityd-example.log</string>
  <key>StandardErrorPath</key><string>/var/log/laneboss-identityd-example.log</string>
</dict>
</plist>
```

```sh
launchctl bootstrap system /Library/LaunchDaemons/io.laneboss.identityd.example.plist
laneboss service status --config example
```

Use `launchctl bootout system /Library/LaunchDaemons/io.laneboss.identityd.example.plist`
to stop the installed daemon. Do not run it as a LaunchAgent under the callers'
UID. This part's Darwin unit row checks the real kernel API with one account;
the Linux rows provide the separate-user canary. A production macOS installation
still needs its administrator to verify process visibility across its chosen
accounts and boot-time directory provisioning.

## Evidence

[The service rows](../e2e-rows/IDENTITYD.md) define the exact Linux box command,
22 required mutation kills, an additional S16 proof using the existing UID
mutant, controls, and the Darwin-only test scope. The
Linux fixture really creates service/caller users with `useradd`. It retains
the source archive, binary bytes and hashes, requests, kernel observations,
file-access canaries, journal, logs, exits and manifest. No authenticated model
or owner-channel operation is part of these tests. The additional rows check a
subreaper above the matched same-UID boundary, ordinary forking lane children,
configurable UID caps and an enclosing recorded session above a subreaper. S15's
short-detach mutation must expose the actual orphan inheriting the enclosing
session; the control must keep the command gated. S16 requires 50 real CLI
status calls to preserve a UID-cap refusal and leave the journal unchanged.
The new Linux unit closes a real Unix connection before the request write to
make refusal delivery deterministic. Runtime results must come from the
supervisor's Linux box. These rows do not cover the P2-G UID/GID windows.

## Known limits

Root, the kernel, the dedicated service account, its installed binary and the
future ticket issuer remain trusted. Processes sharing a caller UID are not
isolated from one another: ptrace/injection permitted by the OS, an inherited or
passed connected descriptor, and a cooperating registered ancestor remain
limits. Unix stream credentials describe the connecting process; they do not
authenticate each later write to a descriptor passed to another process. On
Linux with a valid peer pidfd, the connection's mutation authority ends when its
connecting process exits. A live connector can still delegate its descriptor.
Darwin remains snapshot-readonly and provides no equivalent lifetime guarantee. Tools
that are real descendants inherit the ancestor's recorded identity naturally.

The service does not validate the truth of a report's content, cryptographically
sign exported journal copies, enforce a reports-to graph, route owner messages,
or replace the existing CLI state. Deletion/archival, revocation, ticket replay
policy, endpoint request idempotency and launcher/CLI integration need their
own work. A journal parse or write failure is a stopped integrity gate. Do not
edit records or fabricate a successful status to make recovery appear complete.

**P2-C, credential drift (conditional, latent):** roots recorded directly by
`lane-started` without Launch may remain under a broader recorded session. If such
a root re-execs with a different effective GID (`newgrp`, `sg` or a setgid program),
the current PID/start/UID/GID comparison stops matching it and its same-UID tree
can fall through to the enclosing identity. A narrowed session can similarly
fall through to a broader session, and collision checks may skip the drifted root.
Drift of an enclosing recorded root also narrows Launch's detach proof; its
window and possible later credential restoration are described in P2-G below.
Registration is currently closed. Before opening it or attaching direct roots,
match roots first by PID/start and refuse credential differences with an explicit
credentials-changed error; add the actual credential-drift canary. This source
analysis is not a claim that such a canary ran in this lane.

**P2-G, detach proof blind spots (suspected, conditional and latent):** the
boundary lookup matches all four root fields and the ancestry walk stops at a
different effective UID. The overlap proof also compares UID/GID through
`samePeer`. These are three specific windows:

- A different-UID hop followed by a return to the caller's UID lies between a
  recorded outer session/reaper and the launcher's nearer recorded session
  when its boundary is resolved. The outer root is above the UID cut and is
  absent from the old proof line. When the intermediate exits, the kernel can
  adopt the gated root under that outer subreaper because its reaper search
  ignores UID. The proof can pass, and children orphaned when the lane root
  later exits can identify as the outer session.
- An enclosing root has a different effective GID during the final `whoami`
  resolution that returns the launch boundary. Its PID/start still match, but
  `samePeer` skips it and selects a nearer boundary. A subreaper between the
  roots can then retain the released lane. If the skipped outer root's GID
  returns to the recorded value before an adopted child queries, that child
  can identify as the outer principal. The mismatch need only span boundary
  resolution; it need not persist until lane exit.
- A retained ancestor's credentials change between the original launch
  snapshot and the snapshot after intermediate exit. Comparing the two with
  `samePeer` can hide that PID/start match. Another unchanged checked ancestor
  can still refuse the launch; the window matters when no other checked match
  does so. Restored recorded credentials can expose the enclosing identity to
  a later orphan query.

These are source-derived conditions, not measured UID/GID canaries. The verifier
is closed and Launch has no release caller. Closing these windows needs
coordinated identity/proof changes and the actual credential-drift and UID
round-trip rows before part 2. Match roots
first by PID/start in `resolveRoot`, `sessionAnchor` and `rootCollision`, and
refuse changed credentials. Compute the boundary and detach proof over an
unfiltered, per-edge-rechecked kernel chain while keeping principal selection
within its same-UID line. Compare detach overlap by PID/start, and prove a real
different-UID round trip remains gated. Do not treat the current detach rows as
evidence for these untested topologies.

**P2-H, nested different principals (suspected, pre-existing):** the current
registration contract prevents broadening but does not isolate a nested
principal from its enclosing session. An inner anchor can mint an enclosing
principal's process via `clone(CLONE_PARENT)`, or its descendants can reach an
intervening subreaper after that anchor exits. The lane detach boundary does not
protect the nested session itself. Before part 2, refuse cross-principal nesting
and anchors inside another principal's live root, while allowing same-principal
narrowing, and add the authenticated registration canary. No such canary is
claimed here.

**P2-E, projection growth and error propagation:** all run roots remain in memory
until the journal's overall size limit, and resolution scans runs against ancestry
multiple times under the state mutex. Root-collision checks read historical PIDs,
including dead ones. Large histories can make new registration/start operations
reach their deadline. A transient walk failure in another live root also refuses
the operation with a caller-ancestry diagnostic. PID-indexed resolution, caching
observed-dead roots and a bounded retry with a cause-specific diagnostic remain
follow-up work. No history is discarded to hide these limits.
