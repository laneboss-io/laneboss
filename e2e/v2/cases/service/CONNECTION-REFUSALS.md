# Connection entry refusal privacy

Suspected: the shared service baseline 4e361ce copies the typed cause, including
its message and other fields, into the refusal sent before authentication.
Source inspection identifies the path; runtime disclosure remains unmeasured
until the native canary and its red controls run on the authorized Linux box.

The common connectionRefusal now constructs a new error from the cause's code
and owner and the fixed message `service connection refused at <stage>`.
Cause message, recovery advice, retryability and operation selector are not
copied to the response. The main server and both worker-listener refusal paths
pass the original typed cause separately to the private service journal, whose
message retains that detail. A refusal still closes after its one correlated
response and cannot reach dispatch or state. A normal refusal does not become
a server fault. Journal write failures retain their existing fault behavior.

TestAuthenticationRefusalPrivacy sends identity.self over the real Linux
credential-framed socket to a refusing authenticator. A fresh harmless canary
is placed in the cause's message, advice and operation selector. The test checks
the entire returned frame for that canary before decoding it, then requires
the actual code/owner, fixed authentication-stage message, no copied auxiliary
fields, matching request, empty result/head, one authentication, no state or
authorization, and the connection's final close. It also verifies that creating
the public refusal did not mutate the private cause.

The existing first-method and containment-admission cases now require the fixed
correlated refusal. The first-method control previously expected an immediate
EOF even though the shared server already sends a refusal before closure.

Run the two focused controls only as an unprivileged user on the supervisor's
authorized disposable Linux box, with fresh evidence directories:

```sh
bash e2e/v2/cases/service/run-mutations.sh --source /test/source --evidence /tmp/lb-v2-service-auth-cause --mutation authentication-refusal-cause --variant both
bash e2e/v2/cases/service/run-mutations.sh --source /test/source --evidence /tmp/lb-v2-service-auth-field --mutation authentication-refusal-other-field --variant both
```

Each run must retain the tested source and binary bytes/hashes, exit and exact
assertion. The driver runs the mutant before the unchanged candidate. The first
mutant restores the baseline cause copy; the second discloses only through
`instead`. Each must exit 1 at TestAuthenticationRefusalPrivacy with
`authentication refusal disclosed internal cause`, followed by a candidate
exit 0 on that same test. A compiler failure, unrelated assertion, skip, panic,
race, timeout or missing test is not a red-control result. No red/candidate or
installed result is claimed by this static-only authoring run.

The private journal is diagnostic evidence, not peer-visible RPC data. Keep the
service implementation synchronized with the shared fix when the supervisor
lands this change; no different public cause-bearing field is an acceptable
resolution.
