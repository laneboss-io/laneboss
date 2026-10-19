# Public Health before authentication

The current fix-16 policy and source handoff are in D4FIX16-REPORT.md, based on
5e613b9. Health on an ordinary opened connection is refused; it must use a
fresh public connection. The typed handler requires the transport's private
observation context and has no full-store verification fallback. Client.Call
uses and releases a dedicated health socket, preserving an existing primary
and human read session. The new native second-frame and client reuse controls
await Linux execution. The original fix-4 implementation and validation history
below does not establish current candidate results.

The d4fix4 change starts at 3f1a97b with draft.4 fix 8. The supervisor reports
that the installed candidate 69a3c35 built, installed and opened its socket,
but an unenrolled caller's first Health request exited 69 with
"unavailable: service connection failed". In the base serveConnection,
Authenticate runs at server.go:201-203 before any frame is read. Identity's
documented failure closes that connection, so the later Health exemption
cannot receive the request. This is the supplied installed failure, not a
runtime measurement made by this lane.

Transport now obtains the kernel peer, takes the admission slot keyed by its
UID and reads exactly one first frame through ReadPinnedFrame. Every header
and payload fragment still passes the native SCM_CREDENTIALS checks. A first
Health request invokes only the Health handler with an empty Scope, returns
one framed response and closes. A proof is rejected explicitly. The closed
HealthRequest/envelope decoders reject objects and extra fields before a
snapshot or handler call. Every other valid first method authenticates before
dispatch, and a refusal closes the connection.

Public Health reads the actual service-owned HealthSnapshot once. Private
transport context carries its head/time and native frame observation to the
Health handler. It carries no identity, connection/read authority or object
access. This branch reports snapshot availability, binding/artifact checks and
the native peer; it does not perform full-store Verify or BeginRead. Health's
existing dynamic listener, routes, reconciler, freeze and isolation checks
remain in effect. LastSeq comes from the actual snapshot. Readiness is not
forced true when the fixture or a real dependency is incomplete.

## Regression cases and reasoned base failures

All cases use real Linux Unix sockets and real SQLite state. The explicit
authenticator always refuses and closes the actual ConnectionContext; no
authentication or authorization call can succeed. The fixture's binding and
Health digest describe the actual test executable. A committed fixture record
provides a nonzero journal head, and access counters reject full verification,
scoped reads and object access. These are component controls, not an installed
identity/helper acceptance run.

The table gives source reasoning for failure on the base, as the brief allows.
Neither the base nor candidate unit tests were executed on the authoring Mac.

| Brief case / named test | Candidate assertions | Reasoned failure on 3f1a97b |
| --- | --- | --- |
| 1. TestUnenrolledNativeHealth | Native SO_PASSCRED request receives typed Health with the actual artifact digest and nonzero snapshot head; Scope is empty; authentication, authorization and scoped-state counters stay zero. Exactly one snapshot and Health invocation occur. | The base calls the refusing authenticator at server.go:201-203. It closes before ReadPinnedFrame, so the test cannot write/read its Health exchange and fails before the Health result assertions. |
| 2. TestUnauthenticatedFirstMethod | A valid identity.self first frame invokes the refusing authenticator once, closes, and reaches no handler/state. An invalid non-health first frame receives the protocol refusal without authentication or dispatch. | The valid refusal is an existing control. The invalid-frame cell makes the test red: the base's early Authenticate count is one, failing "first-frame validation ran after authentication". It never reaches the pinned-frame validation stage. |
| 3. TestPublicHealthClosesBeforeSecond | After receiving Health, attempt a second identity.self frame on the same native socket. Require closure, zero authentication/dispatch attempts and exactly one snapshot/Health call. Only errors proving the socket is closed are accepted for the second write. | The first Health result is unavailable because early Authenticate closed the socket. readHealth fails with "unenrolled native peer did not receive health" or the initial write reports closure. No claimed second-frame observation is inferred from that base failure. |
| 4. TestPublicHealthRejectsAuthority | A structurally valid proof, extra Health params, an objects envelope and an extra envelope field each produce invalid_request, no result, no Scope/identity activity and no snapshot/handler invocation. The proof's transport validity is checked before sending it. | The base closes during Authenticate instead of returning the required protocol refusal without identity activity; the write/read or "public health authority refusal was not returned" assertion fails. Mere EOF is not credited as the required typed Health refusal. |
| 5. TestPublicHealthUIDAdmission | Hold eight native Health requests at actual snapshots using channels. Check the kernel-UID key/count, reject and close the ninth before snapshot access, release all eight, and prove a new request can use the returned slot. Final counters require nine completed snapshots/Health calls and no retained admission. | The base closes the first connection before its snapshot. The worker-done branch fails explicitly with "connection closed before public health admission reached its snapshot" rather than receiving timeout credit. |
| Native writer control: TestPublicHealthWriterGate | Fresh connections without SO_PASSCRED and with actual SCM_RIGHTS transfer must never reach Health or a snapshot. Require a typed invalid refusal or closed socket, with zero authentication attempts. | The base calls Authenticate before inspecting native evidence, so assertNoAuthority fails, or the sender sees that premature closure. This separates the required native gate from an identity refusal. |

The post-change tests deliberately retain an incomplete component registry and
no reconciler/launcher. They require Health.Ready to remain false while still
returning the valid public Health result. The composed installed run must
independently prove ready Health with the real dependencies. No constructor,
authentication or readiness bypass is added to the product.

## Validation and remaining gate

Only the brief's static checks ran on the Mac. Whole-tree Linux go vet, Linux
go vet with laneboss_faults and Darwin go vet each exited 0. Formatting reported
no unformatted owned Go files. A read-only source overlay also compiled/vetted
the retained base production files with the unchanged new test file under both
Linux tag variants, each exiting 0. This confirms that the reasoned base
failures do not depend on candidate-only symbols; it does not execute a test.
Exact source, output and exits are retained in protected lane evidence. All
six new test names meet the scanner's 40-character limit.

On the supervisor's disposable Linux machine, run the focused tests under both
variants and retain the reached assertions and candidate passes:

```sh
go test -race -count=1 -run '^(TestUnenrolledNativeHealth|TestUnauthenticatedFirstMethod|TestPublicHealth.*)$' ./internal/v2/service
go test -race -count=1 -tags laneboss_faults -run '^(TestUnenrolledNativeHealth|TestUnauthenticatedFirstMethod|TestPublicHealth.*)$' ./internal/v2/service
```

The unchanged new test file can be added to the retained base source to verify
the reasoned failures without altering the product checkout or its branch.
Runtime tests and the installed serve rerun are pending. Static success and
the reasoned base failures do not establish a candidate E2E pass.
