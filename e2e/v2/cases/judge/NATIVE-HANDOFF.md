# Native judge handoff

The source base is 1d2c9c6b. This continuation implements the native job
and the installed producer. It makes no installed acceptance claim.

Path aliases below are relative to internal/v2: A is admin, C is client,
I is identity, J is judge, H is service, S is store, and B is assembly.
V is scripts/v2-serve relative to the checkout.

S/judge_native.go binds one narrow worker lease, immutable input and
fixed plan to the acquired JudgeExecution. The native claim is retained
in that execution's projection. S/judge_effect.go joins its protected
effect read to the original claim, outside the reclaimable outbox.
There is no replacement send after a crash. Worker grants contain no
lane data, profile, secret, resource or channel. Their service endpoint
is selected by the approved provider.

A/judge_client.go re-reads the exact retained job before launch operations.
A/judge_ctl.go allocates a distinct installed UID/cgroup and retains the
sealed spec before the process attempt. The existing helper gate and
allocation locks and three descriptor handoff remain in force.
I/judge_worker.go joins the immutable descriptor to the exact stored job.
Native peer, executable, boot, containment, policy, grant and cancellation
checks run through the existing identity path before the permit.

A/judge_gate_linux.go uses the existing native bootstrap, private
namespaces, denied general networking, runtime mounts, private endpoint
and measured wait owner. Its one-connection provider relay is pinned to
the matching administrator-owned endpoint and worker UID. It copies
transport bytes, including TLS bytes, without interpreting HTTP or
credentials. The adapter, TLS, provider request and tokenizer run in
the native worker. No arbitrary URL or executable comes from lane input.

J/internal.go consumes the native principal, sealed input and live input
read-back. Worker-only setup carries selected protected material; argv
and retained objects carry no credentials. H/judge.go waits for the
original result and actual successful native exit, then measures
collection. Parent release inventory includes outstanding judge workers.

S/judge_worker.go validates request/raw references and the measured reply
before retaining an acknowledgement. Audit completion still uses real
store checks, CAS and cancellation. S/judge_recovery.go recovers only
the original measured acknowledgement and terminal observation. An
unknown outcome retains its full spend reservation. Public sent/outcome
records distinguish unknown usage.

B/assembly.go constructs both providers with the native worker.
B/judges.go selects protected enrollment after policy resolution and maps
the measured tokenizer into the runtime. TypeSafe stays explicit; a Clef
outage never selects it automatically.

V/case_judge.py exports G0 boot/prepare/abort and independent collection.
The public consumer retains HTTP bytes, bounds controls, exact retries,
actual service process replacement, replay and egress pairs. Its fixture
computes answers from complete input and question ID. This proves no
authenticated AI service or semantic corpus calibration.

The shared selector adds judge. The enrollment hook installs pins and
the positive fixture ceiling before hashing publication. The CLI adapter
restores the fixed binding option consumed by common parsing.
base-cli.go.in is the exact CLI file read from 1d2c9c6b; that base has no
case_judge.py. The red runner uses those inputs and four native removals,
requires reached failures, restores bytes and reruns each candidate.

Commands and limits are in README.md. The lane report lists changed
files and verification evidence.
