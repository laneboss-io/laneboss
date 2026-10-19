# Installed service E2E

The default installed-lifecycle scope uses the installed CLI and service for first
human enrollment, a verified session and two disposable L5 roots: Claudock first,
then Codex. Each root must start, be observed running, expose its status/events,
stop with known zero survivors, be abandoned, archived and cleaned. STEPS.md lists
the exact commands and required observations. Every required row must execute.

On a fresh authorized Ubuntu 24.04 machine, run:

    serve_tree=/test/candidate
    sudo -n bash "$serve_tree/e2e/v2/cases/serve/run.sh" \
      --source /test/candidate \
      --evidence /test/evidence/lb-v2-serve-lifecycle \
      --suite lifecycle

The evidence destination must be new and absolute. The harness now assembles an
owned initial publication during protected install-input preparation, using the
shipped org/L5 sources and actual runtime pins. It also supplies a bounded root
request and unticketed launch proposals, binding issued IDs only after real
grants.root responses. scripts/v2-serve/README documents the complete input,
validators, file modes and current product contract gaps. No store seed or
publication receipt is supplied by the harness.

An explicit external bundle remains supported with paired --config/--boot and
protected --root-grants plus --lane-inputs files. They must select the exact
publication's L5/project/profile/task inputs and contain no copied root tickets.
Missing or rejected inputs remain FAIL/unrun with owner requests.

The driver stages immutable source under /opt, builds the actual release and
separate vendor/authenticator fixtures, installs through the administrator boot
and namespace tools and starts the named installed units. It preserves exact
source/dependency/binary bytes, input files, argv, stdout, stderr, exit codes,
receipts, journals and a hash manifest. The service binary must match installed
bytes and run under its dedicated UID. Public health is read over its real socket.
A separate UID-only direct-open canary is supporting evidence, not lane authority.

Administrator ceremony requests are retained in evidence but consumed from exact
copies in a root-owned 0700 directory under protected /opt. Each actual helper
input is regular, single-link and 0600. Per-call metadata includes the executable,
configuration and both request paths with every ancestor; a private file below
shared /var/tmp is not accepted as a protected helper input. Production ownership,
mode, link and artifact checks remain intact.

Private enrollment refusals carry a typed error and fixed failure_field. The
service journal names only that field/stage, code and owner; it never prints
request values or native paths. Keep both outputs when diagnosing the next
installed failure. The listed frame fields match in source, including a random
39-character nonce. Native prerequisite failures are distinguished from strict
JSON or binding-field refusals without relaxing either gate.

The external root enrollment CLI now uses the fixed installed root daemon. The
daemon verifies that CLI's real mapped artifact and forwards only the two typed
ceremonies to the installed service endpoint. The service verifies its native
daemon PID, stable lifetime, sole control-cgroup membership, protected root-owned
helper socket and actual installed executable digest. It does not need ptrace
access to a root process. Descriptors remain forbidden, and ordinary service
helper callers cannot use the enrollment relay. FORWARD.md records the complete
proof and the remaining initial publication, materialization and briefing store
gates.

Both fixtures are explicitly test-only. The software device stands in for hardware
UP/UV gestures, generates a real private P-256 key and emits genuine WebAuthn packed
self-attestation and signed operation-bound assertions. Its private key/counter
stay outside source, runtime and evidence archives. It never mints a proof, ticket
or successful enrollment. Shared marker policy rejects software credentials in a
production build, including revoked ones during the store's startup inventory.
All dependent observations say presence=simulated and human_approval=not_proven.

The vendor fixture invokes the installed CLI inside the genuinely launched lane.
It records actual identity and session metadata and waits boundedly for real stop.
Its state mode invokes real blob/record operations and requires a real judge
projection rather than treating not_implemented as success. It neither calls an
AI service nor implements identity, grants, storage, workers or native isolation.
Fixture adapters require both laneboss_partial and laneboss_e2e_authenticator,
plus the protected pinned dual-driver runtime declaration. Without enrollment,
assembly calls the real installed vendor constructors. Missing per-run enrollment still refuses every plan/capture operation.

The current composed tree still contains owner gaps listed in REQUESTS.md. In
particular, the initial/full-org source-kind contracts, profile grant enrollment,
service briefing/source readers and native
credential/endpoint projections must land before the complete lifecycle can pass.
The harness does not invent endpoints or convert a real refusal into the desired
not_implemented. Each missing method is a failing step with its actual typed owner;
unreached dependent steps remain FAIL. A missing setup capability is reported as
an unexecuted owner request, not a forged RPC result.

Assembly uses real constructors throughout. Templates, dashboard, migration and
packaging now validate/store dependencies and register their real typed methods;
constructor errors stop startup and no zero-value fallback is supplied. Unfinished
operations keep their owner-named errors. The native backend receives the same
installed wall clock as the service. Real installed runner/policy constructors
separate startup from optional operation enrollment without inventing runtime
pins or an inference budget. The concrete store's private ports remain visible.
STARTUP.md lists every constructor and the separate untagged production startup
test. Public health remains the first E2E RPC after service startup.

summary.txt validates the entire scope catalog independently of the report's
claimed list. A missing row, stored error, erased simulation or unexecuted claim
cannot pass. Original failures survive cleanup; actual operation and unit-journal
refusals retain their owner/code and raw evidence. A refused control is not retried
by another route. Named unit shutdown cannot prove unknown lane collection.

The broader serve-state scope is available with --suite state. Its protected
workspace/capture mapping, lost socket reply, exact mutation counts and restart
recovery are separate required gates and remain unimplemented. A lifecycle result
does not satisfy them. FORWARD.md walks every entry from device creation through the first lane.start
and events. It records endpoint/codec/receipt/selector glue, the remaining owner
implementations and the now-merged administrator data boundary. Requested service stop
now requires actual zero exit status in addition to MainPID zero.
No installed acceptance, unit or mutation outcome is claimed
by this Mac authoring session; run those checks on the authorized Linux machine.
Public health and later commands use separate CLI processes. The service lane
supplies the merged 2a46490 health-socket repair; this harness does not add a
preliminary health call to a command's live client. BriefRender and BriefStart
are real after 7d498c5, with genuine store/source ports still required.
# Installed item cases

The shared contract is [ITEM-CONTRACT.md](ITEM-CONTRACT.md). On the
authorized disposable Ubuntu scope, after the serve suite's own checks,
dispatch grants in the same installed run with:

```sh
python3 -I -B scripts/v2-serve/run.py \
  --source /test/candidate \
  --evidence /test/evidence/lb-v2-grants \
  --item-case grants
```

This creates one fresh configuration and keeps the ordinary serve catalog.
The item context hashes the retained complete source and installed binary.
The actual entry is `e2e/v2/cases/grants/run.sh`, with `--context` and
`--result` files under its private input directory. Exact input bytes,
entry output/exit, assertion evidence and outside collection remain in
the serve evidence scope. The dispatcher uses the frozen result reader;
both GRANT-BOUND and CHILD-CODE must be reached/pass with exit zero.

The grants relay is a declared vendor fixture running as its original
installed actor. Outside metadata supplies no lane authority. Real mail
delivers each instruction and primary capture carries each CLI response.
The observer must collect the worker and both fixtures before unit
teardown; stopping systemd units gives no grants collection credit.

Resource-handle enrollment and child-test worker capture are native owner
gates. A refusal from either remains a failed installed run with its
exact owner/code/output. Never remove the resource requirement, use the
human caller for the child test, or invent successful worker output.
No login or authenticated model request is authorized by this command.
