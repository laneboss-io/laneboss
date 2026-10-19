# Identity service rows

This lane adds a service core without switching the existing CLI to it. Its
Linux runtime evidence must come from the supervisor's disposable test box.
The lane launches no box. Linux 6.5 or later with usable `SO_PEERPIDFD`, Python 3.9
or later with `os.pidfd_open`, Git, the pinned Go 1.26.0 toolchain and its
modules, `groupadd` and `useradd` are prerequisites. No credentials, authenticated
agent profile or AI-service request is needed.

Have the supervisor invoke the sealed kit's named root-owned identityd step
with this exact command, from the transferred checkout:

```sh
python3 e2e-rows/check_identityd.py /var/tmp/lb-svc-core-evidence
```

The evidence destination must be new; the path above is an example, so use a
fresh absolute lane evidence path for each run. The root-owned row fixture uses
`groupadd --system` and `useradd --system --no-create-home` to create a fresh
configuration group and **two different unprivileged users** for each row.
It then drops UID/GID before executing the real service and caller processes.
The service never runs as root. It creates its directory and journal itself; the
root fixture appends the baseline without changing owner/modes and restarts it.
The production ticket verifier deliberately refuses everything.
This exercises service storage and peer resolution; it does not authenticate
part 2's bootstrap tickets. There is no release bootstrap/seed switch.

The checker archives the actual source inputs and revision, saves build and
check logs with their own exits, keeps both binary variants and their hashes,
then runs each mutant **before** any passing row controls. A mutant must return
1 with exactly one assertion failure, its stated reason and its real call-site
marker. A setup error, cleanup error, missing marker, timeout, unrelated failure
or success stops the checker. The entire Go unit suite runs only on the Linux
box, with both release and `laneboss_faults` tags. The 19 row mutants and three
unit mutants must be killed. S16 also first fails under the existing
`identityd-uid-setting` selector, in the separate `identityd-cap-status` proof
action. This is 22 distinct mutation kills plus one reused-selector row proof,
all before any passing controls. Then all row controls run on both
builds, and the release binary repeats S1 with the hostile fault selector present
in the daemon's environment to prove the selector is inert.

Exit 0 **and** this actual line are required:

```text
PASS: identityd Linux rows; 22 mutation kills and both controls
```

| Row | Observable behavior and what makes it fail | Required mutant |
| --- | --- | --- |
| S1 `test_s1_kernel_peer` | An unrelated peer supplies another live PID, forged UID/start/actor and environment role/session/lane labels. Its observed identity must equal its actual kernel process and remain unidentified; the genuine recorded ancestor is the control. It fails if the request selects that other PID. | `identityd-trust-pid`, failure `caller-sent pid replaced kernel peer identity`. |
| S2 `test_s2_separate_account` | The caller actually attempts to read, overwrite and create a service-side record; kernel permission denial and unchanged canary bytes are required. It also writes its own forged CLI session file as the caller UID, which the service must ignore. The genuine service-owned session remains the allowed control. | `identityd-public-store`, failure `caller read the service-owned record`; the mutation admits 0750/0660 private storage so the real canary becomes accessible. |
| S3 `test_s3_lane_actor` | An identified launcher records its actual child. That child's append must persist `lane:NAME` as actor despite a conflicting claim and payload actor; report/send records keep the same actor. The journal bytes, sequences and restarted daemon must agree with the reply. | `identityd-append-actor`, failure `caller-sent actor replaced the identified lane`. |
| S4 `test_s4_unknown_refused` | An unknown peer may whoami but cannot append or record a lane. Exact CLI first lines/Instead routes, unchanged journal and refusal of invented tickets for both unknown/known peers are required. A real identified report append is the control. | `identityd-allow-unknown`, failure `an unidentified peer appended a record`. |
| S5 `test_s5_start_time` | A real descendant PID with an altered start token must be refused without a write. Its exact kernel PID/start token must then record successfully. It fails if PID alone is sufficient. | `identityd-no-start`, failure `a wrong process start time was accepted`. |
| S6 `test_s6_protocol_status` | Wrong protocol/configuration, duplicate JSON fields, oversize, missing newline and idle timeout must be refused without a write. The real CLI status must authenticate the running daemon's kernel identity and return the recorded sequence. | `identityd-ignore-version`, failure `an unsupported protocol version was accepted`. |

S2 now probes the actual service-created journal, with no fixture branch on the
mutant name. Its release control also presents public 0750/0660 storage and
requires startup exit 2 with the unsafe-permissions refusal.

| Row | Behavior and what makes it fail | Required mutant |
| --- | --- | --- |
| S7 `test_s7_owner` | An L4 lane cannot record its own next run; another starter cannot take over its name. The bound starter is the control. | `identityd-lane-owner`: `an L4 lane recorded its own next run`. |
| S7 `test_s7_live` | Run N+1 is refused while N's root is live; N still resolves as its lane. Replacement succeeds once N exits. | `identityd-live-run`: `a live lane run was replaced`. |
| S7 `test_s7_history` | A legacy journal with multiple real roots retains every run before and after restart. | `identityd-forget-runs`: `an older live run became its supervisor`. |
| S7 `test_s7_roots` | A root cannot equal or contain a live session anchor or another lane root. A separate root succeeds. | `identityd-overlap-root`: `a live session anchor was relabelled`. |
| S7 `test_s7_detach` | A gated root is recorded, detached and released. The same child reports as the lane while its parent lives, then becomes unidentified after pidfd-proven parent exit and kernel reparenting. An at-anchor subreaper is refused before command execution. Ordinary forking tools report as the lane. | `identityd-no-detach`: `the launcher left the lane in its session tree`. |
| S8 `test_s8_case` | `OP` and nested `PID` aliases cannot change the operation or select a root. | `identityd-field-case`: `a case alias changed the operation`. |
| S9 `test_s9_scope` | Event, report and send appends derive the caller's lane; a foreign report lane is refused. | `identityd-foreign-lane`: `a lane recorded another lane's report`. |
| S10 `test_s10_events` | Unlisted kinds are refused; allowed kinds still need the CLI envelope/per-kind payload schema. | `identityd-any-event`: `an unlisted event kind was accepted`. |
| S11 `test_s11_slots` | Two connections from one peer are admitted; its third returns exit/code 2 and the per-peer cap text, even if rejection closes before the fixture writes. Another peer remains usable. | `identityd-peer-slots`: `one peer exceeded its connection cap`. |
| S12 `test_s12_size` | Encoded payloads over 49,152 bytes are refused before a write; smaller escaped payloads round-trip. | `identityd-large-payload`: `an oversized encoded payload was accepted`. |
| S13 `test_s13_above_anchor` | A real unrecorded subreaper above every recorded root permits launch; ordinary tools report. After proven parent exit the adopted orphan reaches that subreaper, is unidentified, cannot append and leaves the journal unchanged. | `identityd-wide-detach`: `an above-anchor subreaper refused an ordinary launch`. |
| S14 `test_s14_uid_setting` | Distinct peers measure configured UID caps 2 and 3 and the default 8. Refusal names the configured cap and setting. | `identityd-uid-setting`: `the configured UID connection limit was ignored`. |
| S15 `test_s15_outer_session` | A nearer recorded session below a subreaper cannot hide another recorded session above it. The control refuses launch while gated and preserves the live session's reporting permission. If a launch is released, the row follows a real live lane child through parent exit and reparenting, then checks its actual identity. | `identityd-short-detach`: `an orphan inherited an enclosing recorded session`; it truncates the real detach proof at the nearer root and exposes the orphan's promotion to the enclosing session. |
| S16 `test_s16_cap_status` | One connection occupies the UID cap of 1. Fifty separate same-UID CLI status processes must each exit 2 with the actual per-UID cap text, no integrity diagnostic and unchanged journal. The held connection is refreshed within its request bound. After synchronized collection, an uncapped status succeeds. Every stdout, stderr and exit is retained. | Reuses `identityd-uid-setting` as `identityd-cap-status`: `a capped CLI status lost the UID refusal`; ignoring the configured cap makes the real CLI exit 0. The deterministic write/close loss is covered by the unit below. |

The three Linux-only unit mutation kills also use real Unix sockets/kernel peers:

| Unit | What makes it fail | Mutant |
| --- | --- | --- |
| `TestPeerLifetime` | The connecting child exits normally, and its retained connection must lose its pidfd lifetime proof. | `identityd-no-peer-pin`: `an exited connecting process retained its lifetime proof`. |
| `TestVerifyOutsideLock` | An independent whoami must complete with the actual peer while verification is held at a real synchronization gate. No refused ticket is written. | `identityd-verify-lock`: `verification blocked an independent whoami`. |
| `TestClosedReply` | The real rejection path queues a refusal and closes before any request write. A real write proves EPIPE/ECONNRESET, then the product exchange helper must recover that actual refusal. Empty close gets the explicit incomplete-request refusal; a mismatched kernel-peer header and unsolicited success remain integrity failures. No timing sleep or injected errno selects the order. | `identityd-drop-refusal`: `an early service refusal was lost`; it restores the early return at the actual failed-write boundary. |

`whoami.identity_root` comes from the same projection as the principal.
`detachment_root` is the outermost recorded root whose PID, start, UID and GID
currently match within the same-UID ancestry line. The launcher cuts its old
line at this boundary and refuses a retaining subreaper at or below it, while
allowing unrecorded ancestors above it. A different-UID hop hides ancestors,
and credential drift can hide a root or a retained overlap; the exact P2-G
windows are documented under [Known limits](../docs/service.md#known-limits)
and are not covered by these rows. The short-detach mutant restores the unsafe cut at the
nearest root; the wide-detach mutant restores the unnecessary whole-ancestry
ban. S7 and S13 still run a build tool that becomes a subreaper and forks a
child; both must report as their lane while its root lives.

The orphan helper binds to its parent's pidfd before launch evidence is
published. It records successful whoami/report calls while the parent lives,
waits for both pipe EOF and the actual pidfd exit event, then proves its parent
PID changed and the old parent left kernel ancestry before making either
orphan request. The root retains the pipe until process exit. An early pipe
close alone could let the helper query as an ordinary live child. The retained
`orphan-ready.json` and `orphan.json` contain the same peer before and after,
the parent's PID/start/credentials, actual exit poll events, adopted ancestry
and socket responses. Failure messages include the observed principal.

The helper's detached session has no controlling terminal and currently offers
start acknowledgement, not waitable exit status or a pane stop/signal relay.
Those paths must be implemented before release CLI wiring; see
[service.md](../docs/service.md#launcher-detach-semantics). The existing CLI
remains independent, and the fault probe is Launch's only caller.

The fixture's shared exchange/hold helper reads the bounded answer when a
pre-request refusal is already readable. If closure races with sendall, it
catches only BrokenPipeError/ConnectionResetError and still reads the actual
reply. Missing, malformed or oversized replies fail; no successful result is
substituted. S11 and S14 therefore use the same response path as ordinary rows.

Fault hooks, their selector parsing and their vulnerable branches are compiled
only with `laneboss_faults`. They change real behavior at the relevant boundary;
they do not generate canned successful responses or replace observed results.
Every normal assertion reads the actual socket response, process table, access
result or service-written bytes. Each marker comes from the selected call site.

Each row retains `fixture.json`, requests, binary bytes/hash, seed, journal,
canary results, ready/status output and collection logs. Runtime sockets use
short `/var/tmp/lb-svc-core-runtime-*` paths to fit the kernel's Unix path bound;
the literal runtime directory is recorded in its fixture manifest. Collection
signals only known PIDs and requires exit 0; it removes no evidence or accounts.
Accounts, scratch directories and caches remain on the disposable box until
the supervisor harvests evidence and collects that box. The final manifest
hashes retained artifacts; absence of a manifest means an incomplete run.

## Darwin-only kernel row

`internal/identityd/peer_darwin_test.go` has a `darwin` build constraint and a
single `TestDarwinPeerCredentials`. It runs the actual service listener, reads
`LOCAL_PEERCRED`/`LOCAL_PEERPID`, compares the sysctl UID/GID/parent/start with the
live test process, and then supplies a false parent PID through `claim`. Labels
must remain irrelevant. It fails with `caller-sent pid replaced kernel peer
identity` when the fault build trusts that PID. The plain request is its control.
This test uses one OS account and makes no separate-user macOS canary claim.

The Darwin row checks snapshots only; every mutation is refused pending verified
LOCAL_PEERTOKEN/pidversion support. The current lane brief authorizes local static
checks only. These commands are for a separately authorized Darwin test session,
not permission to run project code on the development Mac:

```sh
GOTOOLCHAIN=local \
  go test -c -tags laneboss_faults -o "$service_evidence/darwin-faults.test" ./internal/identityd
GOTOOLCHAIN=local \
  go test -c -o "$service_evidence/darwin-release.test" ./internal/identityd
LANEBOSS_FAULTS="$(cat "$service_evidence/darwin-fault.json")" \
  "$service_evidence/darwin-faults.test" -test.v -test.run '^TestDarwinPeerCredentials$' -test.count=1
"$service_evidence/darwin-release.test" -test.v -test.run '^TestDarwinPeerCredentials$' -test.count=1
"$service_evidence/darwin-faults.test" -test.v -test.run '^TestDarwinPeerCredentials$' -test.count=1
```

`service_evidence` is the absolute lane evidence directory; create
`darwin-fault.json` with the file-editing tool. It contains
`{"point":"identityd-trust-pid","marker":"ABSOLUTE_EVIDENCE_MARKER_PATH"}`,
with a fresh absolute marker path. Save each command's full output and exit
before checking it. The first runtime command must fail with exit 1 for that
specific peer comparison and create its marker. Both controls must exit 0 with
the named test passing. The retained `/private/tmp/lb-svc-core-darwin-*` fixture
paths are printed by the test; the service must collect its own socket. Keep
those small private journals with the evidence until supervisor collection.

Local static checks are `gofmt -l`, `go vet ./...` with both tag sets using the
brief's GOCACHE and `GOTOOLCHAIN=local`, and Python `py_compile`. The box additionally
checks `bash scripts/scan.sh` with its own exit and `SCAN PASS`. Linux cross-vet
can inspect that platform's files without executing project code. Static checks
and the Darwin row do not count as a passing Linux E2E or authenticated AI test.

Set the service's UID cap with `--uid-connection-limit N` on `service run`, default
8, range 1-32. Independent per-peer/global limits remain 2/32. Older Linux kernels
receive an explicit lifetime-binding refusal from status; there is no weaker
PID-only or read-only Linux fallback. Darwin retains visibly designated snapshot
whoami. Ordinary CLI use remains unchanged until the service is wired in.
