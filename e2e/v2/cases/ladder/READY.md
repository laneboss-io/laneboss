# Installed two-tree ladder readiness

This is the current item-8 handoff for the converged source at 83c3926b.
The harness and its supporting controls were restored as file content from
f64e2ea; no merge, cherry-pick or Git metadata change is needed.

The 22-row plan audits all 102 original dependencies, replaces stale source
references, and adds eight explicit dependencies for the installed vendor,
network, effect-coordinator and scheduler gaps. A landed flag describes a
source port. It does not attest installation, authentication, capacity,
physical presence, a completed case or release acceptance.

## Gate order and remaining work

| Gate | Current behavior and next prerequisite |
| --- | --- |
| 8A | Installed wrapper, case discovery, preparation, verifier, read-session client, row controls and supporting tests are present. Harness tests are separate from live acceptance. |
| 8B | plan.json selects current declarations and explicit refusals by file plus symbol; ready_plan resolves each pin to its current line, so merges that only move lines leave it valid. It rejects a missing, ambiguous or wrong-file symbol, missing rows, inconsistent flags and uncovered instances/owners. Re-audit after another lane renames a symbol or duplicates an anchor. |
| 8C | fixture rejects overlapping store/socket/service UID/lane UID/workspace inventories before dispatch, then checks protected installed bindings. Two actual active installations, profile/runtime/model/project/task grants and fresh L6 tickets remain external prerequisites. |
| 8D | The public reader and protected observer client are present. Native peer/nonce/replay controls exercise the actual Unix transport. The authentic observation producer, durable-commit/parent-receive clocks, privacy/barrier/collection controls and configuration-event source are still open. Missing coverage stops before either root. |
| 8E | Source inventory retains explicit gaps for credential workers, per-run vendor enrollment, controlled network, effect coordinators, renderer, review verifier, presence propagation and automatic scheduler. Fix the owning implementations and rerun the relevant installed controls before changing statuses. |
| 8F | Launch additionally requires sealed independently observed SERVE-STATE, MIGRATE-ROLLBACK and INTEGRATED-RELEASE results on the exact source/binary. Plan-only migration and INTEGRATE-RECORDS cannot satisfy this requirement. The current complete producers remain open. |

There is no native observer server that returns claimed readiness. Unit and
root transport canaries supply no process/timing/collection success facts.
No owner confirmation is produced by the harness.

## Exact installed path

Use these commands only on the separately authorized disposable Linux box.
Prepare the named directories first, using fresh canonical absolute paths.
The service phase consumes retained item-1 evidence; it does not restart the
units collected by that case.

```sh
EVID=/test/evidence
sh scripts/v2-e2e/run-installed-ladder.sh --phase service \
  --serve-evidence "${EVID}/lb-v2-serve-lifecycle" \
  --result "${EVID}/lb-v2-ladder-ready/service-handoff.json"
sh scripts/v2-e2e/prepare-ladder.sh \
  --directory "${EVID}/lb-v2-ladder-inputs" --config tree-a --config tree-b
sh scripts/v2-e2e/run-installed-ladder.sh --phase launch \
  --serve-evidence "${EVID}/lb-v2-serve-lifecycle" \
  --context "${EVID}/lb-v2-ladder-launch/context.json" \
  --result "${EVID}/lb-v2-ladder-launch/result.json"
```

Every step requires its preceding step to succeed. Launch consumes the ordinary
frozen candidate context and inputs/ladder.json. Here inputs is the context's
test_root, not an implicit subdirectory. Result belongs next to test_root.
The direct frozen case entry repeats the source and supporting-evidence gates;
invoking it independently cannot bypass the installed wrapper's preflight.
Keep evidence_root separate. Source/binary pins must match the retained serve
archive and installed binary; consumed serve tickets and closed sessions are
not new launch authority. Nonzero typed waits remain unreached failures.

The older ladder-box.sh source-install route remains unavailable: its proposed
administrator handshake has no producer, and its go1.26.5 compiler contract
conflicts with the current source installer's go1.26.0 pin. The installed
handoff above neither rebuilds nor overrides installer policy.

## Box, installations and account capacity

Use one disposable Ubuntu 24.04 Linux machine for both trees at the same time.
The historical planning floor in ladder/pins.json is 32 available CPUs,
60 GiB measured RAM and 160 GiB free disk (typically at least 64 GiB nominal
RAM). This is an unmeasured planning floor, not a demonstrated capacity result.
Measure task/thread peaks, memory, disk and pids.events before approving the
twenty-agent load. Twenty process slots do not bound vendor threads or helpers.

Install the matched candidate/helper, supported kernel/cgroup-v2/Landlock,
non-setid bubblewrap, systemd, Python, Git and required AppArmor tooling.
Restriction-one controls retain unchanged host user-namespace switches and
must distinguish the enrolled executable from an unprofiled copy. The other
Linux architecture/restriction/ABI cells remain separate acceptance results.

Install tree-a and tree-b with separate state directories, service/helper units,
sockets, service UIDs/groups, lane pools, workspace roots, private homes and
protected bindings. The administrator currently provisions 32 lane accounts
per installation; these are OS identities. The scenario consumes ten active
identities per tree. Allocation templates are requests: occupied identities or
paths must refuse, never reuse another installation's resources.

Each tree is 1 L6, 2 L5, 3 L4 and 4 L3. All six upper instances use
Claudock/Claude; the seeded leaf draw is two Claudock/Claude and two Codex.
Across both trees this requires capacity for 16 concurrent Claudock/Claude
agents and 4 concurrent Codex agents, each completing two credentialed logical
turns. The source specifies no number of distinct paid accounts. The owner
supplies sufficient existing authenticated profile/concurrency/quota capacity,
full approved model names and positive finite budgets. Separate watchdog swap
cells need at least two same-provider profile grants. OS accounts are not
vendor accounts, and inert serve profiles are not authenticated profiles.

The candidate vendor pins are claudock-cli 0.1.0, underlying Claude Code
2.1.296 and codex-cli 0.146.0. Retain immutable executable/runtime bytes and
verify actual help, authentication, resume and capture compatibility. Pins
alone do not establish a supported live mode. No login, purchase, real model
request, new machine, owner message or production D6 change is authorized here.

## Owner-in-person waits

The owner performs any root installation/sealing, profile selection/login and
finite budget approval outside this checkout. For physical approval, the owner
uses the enrolled hardware credential and performs fresh same-endpoint L6
ticket and human.session ceremonies for both installations. A software
authenticator remains simulated and cannot prove hardware presence.

The 6900-second driver deadline requires at least four fresh active read-session
windows per tree, eight across both trees. This is a planning minimum, not
preapproval of eight reusable proofs. Absolute session expiry never resets.
Proof files/tickets stay protected and outside prompts; absent files yield
prerequisite_missing with an explicit owner action. Reused, expired or
foreign-intent proofs are refused. D6 approvals, human sends and browser
gestures required by supporting cases also remain actual owner steps.

The two roots start behind one barrier and must share a measured instant with
all twenty actual vendor agents alive. Parents alone start, review, mark,
archive and clean their children. One tree or sequential trees cannot pass.
Both protected start files, tickets and retained keys are checked before the
barrier is constructed; an absent second ticket preserves its owner wait and
starts neither root.
The 115-minute driver limit already exceeds this repair round's time budget;
setup, owner time, red controls and external review/collection are additional.

## Producer hooks and supporting evidence

No item-1 capture, materialization or agent-launch source was changed.
The item-1 producer must retain its full 78-step report/manifest, exact source
and binary, publication receipts/read-backs, timing journals and collection.

The installed observer implements the protected socket in ladder/README.md:
preflight, sample, finalize and collect. It must add configuration-events
coverage and authority_events in each finalized tree. These are the original
service-origin events without life/run selection (human sessions/proofs/tickets);
they supplement selected public tails and cannot replace a public run event.
Snapshots retain prior exact events, configuration, ID and durable sequence.
The producer must measure commit and actual authenticated parent receipt in
one monotonic domain, plus kernel executable/lifetime brackets, barriers,
privacy, release/archive read-backs and collection. The client grants it no
human proof or arbitrary execution method. This producer is not supplied here.

Public event.tail calls now select each known life and each run with separate
exclusive cursors. A fresh empty installation is checked through lane.list;
there is no invented configuration-wide public event RPC.

The installer/controller supplies test_root/supporting.json with schema
laneboss.ladder-supporting.v1, binary_sha256, source_sha256 and cases. Each
service/migration/integrate entry has id and absolute context, result, observer,
execution paths, each paired with its *_sha256. Seal the manifest, referenced
files and evidence under root-owned non-writable ancestors. Execution retains
the actual exit, timeout and monotonic bracket; observer uses the existing
laneboss.e2e-observer.v2 envelope. Every declared assertion must be reached,
pass and have checked evidence and collection. No caller-authored readiness
Boolean replaces these records. Complete producer implementation and independent
review remain necessary even when decoder/control tests pass.
