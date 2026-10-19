# Dashboard draft.4 consumer handoff

The [run-5 review correction](v2-dashboard-run5.md) is the current handoff for
session recovery, projection completeness, provenance and direct attestation.

Run 3's [review/enrollment handoff](v2-dashboard-run3.md) supersedes the transport,
HTTP/SSE, control-count and browser-enrollment details below. It retains the
action-to-owner map and the run-2 session/decision corrections.

Run 1 started at source revision 550f2478; run 2 starts at 97662816 on lb-v2-dashboard and consumes
v2.0-draft.4 fixes 8–11. It changes no frozen RPC, shared DTO or service-store
interface. It has no installed-service acceptance result. The authoring
environment permits static checks only; Linux must compile and run the retained
candidate and every named red control before acceptance.

## 1. Contract adaptation

The dashboard fixture now implements the current StateStore interface, including
AppendCapture, CaptureState, ReserveLaunch, LaunchPlan, LaunchDataStage,
PrepareChannelJob, HumanEnrollments, ReserveEnrollment, EnrollmentChallenge,
WorkerBinding, LaunchRevocation, RefreshReadSession, AwaitGuidance, PolicyAt and
RefreshLanePolicy. These unreached private ports return not_implemented owned by
lb-v2-service. TestDashFixturePorts checks each error; none invents a completed
capture, enrollment, reservation, worker or policy write.

The fixture paths that tests actually use retain connection-bound sessions,
compare session revisions, enforce idle/absolute expiry and revocation, refresh
the same connection, preserve verified presence, consume operation proofs on
the simulated state commit, and retain exact receipt domains for retry. State
changes update the in-memory lane and append causal projection events with real
fixture sequence numbers. They do not measure a native process, signature,
outside capture producer or physical authenticator.

| Correction | Dashboard behavior and deciding regression |
| --- | --- |
| Fix 8: public health | The dashboard does not expose health or implement a public authentication bypass. Root HTML remains inert public assets. The installed first-frame public-health gate, deadline and native writer checks belong to lb-v2-service and the peer owners. |
| Strict decoding | HTTP envelopes, method-specific Params and all eight registered query handlers use the shared exact field maps. Request/correlation keys require 22–128 valid characters. TestDashStrictBodies and TestDashHTTPParams reject duplicate, unknown, case-conflicting and null fields before other gates. |
| Fix 9: launch plans and capture | Fixtures use LaunchReservationRequest, LaunchPlanRecord and the current capture DTOs. A reserved/planned record never creates a live lane. Refused capture produces explicit unknown-ended stdout/stderr gaps with its BindingID and owning error code. TestDashLaunchPlanView and TestDashCaptureRefusal name those assertions. |
| Fix 10: review coverage | Historical complete text without verifier evidence is shown as unknown coverage. TestDashReviewCoverage detects it. Production HTTP never accepts a review locally: lane.review and lane.mark go through the service dispatcher and lifecycle's current evidence/CAS checks. The fixture uses the shared closed review validator and explicit fixture evidence. |
| Fix 11: live session | Each view reloads ReadAuthority from the live connection before authorization and after durable refresh. It reads StoredReadSession by SessionID, compares the complete revision/binding, and keeps PrincipalID distinct. Local event IDs and timers grant no authority. TestDashLiveSnapshot, TestDashStoreRevision and TestDashSessionBoundary cover stale, foreign, revoked, closed and expired authority. TestDashCookieRefresh and TestDashSessionReplay keep cached deadlines and retained reply bytes from invalidating a still-current connection. |
| Fix 11: policy generation | Fresh authorization uses the identity-confirmed current generation. Old lane/launch labels remain historical data. lane.policy advances only the live lane projection and keeps its grant set. TestDashCurrentPolicy and TestDashPolicyEvent distinguish both generations. |
| Fix 11: simulated presence | HTTP results and session-dependent reads retain simulation in response headers. Tables and the aggregate report display presence=simulated and human_approval=not_proven. Resource references inherit their simulated approval/application provenance even when those views arrive later. TestDashPresence, TestDashSessionPresence and web-test.cjs cover nested results, sessions, rows and aggregation. Unmarked data makes no physical-presence claim. |

## 2. Owner checklist item 6: action-to-service map

The routes below are implemented adapters. An adapter's existence does not mean
its service dependency is implemented or that an action succeeded.

| Dashboard action | Route and service RPC | Implementation in this source tree |
| --- | --- | --- |
| Browse org/lane tree | GET /api/v2/tree → dashboard.tree | Dashboard handler exists. StateStore reads and installed transport are lb-v2-service stubs. |
| Browse lanes | GET /api/v2/lifecycle → dashboard.lifecycle | Dashboard projection exists, including lane.policy and natural lane.state. Its store/transport remain lb-v2-service stubs. |
| Read lane status/list | POST /api/v2/rpc → lane.status, lane.list | Dashboard allows them; lifecycle methods are lb-v2-lifecycle stubs. |
| Browse events | GET /api/v2/events → bounded event.tail batches through the service dispatcher | SSE framing, filters, reconnect cursors, limits and session checks exist. Background batches require the service-owned non-refreshing PollEvents capability; ordinary event.tail dispatch is never its fallback. PollEvents/pinned-read wiring is missing in lb-v2-service; the ordinary EventTail method remains an lb-v2-lifecycle stub. |
| Browse raw records, decisions, refusals, plugins, resources and approvals | GET /api/v2/{raw,decisions,refusals,plugins,resources,approvals} → the corresponding dashboard.* RPC | All six handlers exist. They require the service's authorized store/object/record reads; lb-v2-service owns the missing store and transport. |
| Send a human message | POST /api/v2/rpc → mail.send; mail.list reads it back | Messaging.MailSend is implemented by lb-v2-messaging, with authorization, screening, relation and transactional queue checks. The durable store/HTTP transport are still missing in lb-v2-service. Channel worker transport/read-back is a separate lb-v2-messaging barrier when an external channel is selected. |
| Start a root lane | POST /api/v2/rpc → lane.start | Adapter allows the typed StartRequest and its separately issued root_ticket_id. It never substitutes an envelope proof for the ticket. LaneStart/PlanLaunch remain lb-v2-lifecycle stubs; ReserveLaunch and the durable launch/capture pipeline remain lb-v2-service stubs, with the admin/worker/native gate owners also required. |
| Stop a lane | POST /api/v2/rpc → lane.stop | Adapter forwards the exact operation-bound proof/request. LaneStop is an lb-v2-lifecycle stub, with lb-v2-service dispatch and effects still missing. |
| Input/resize a lane | POST /api/v2/rpc → lane.input | Adapter forwards AttachInputRequest with fresh human control proof. LaneInput is an lb-v2-lifecycle stub. Contract gap LP-CAPTURE-IO-1 still requires the lifecycle/admin/identity/runner/service owners' scoped interactive channel. There is no generic stdin or host-path bypass. |
| Resume, review or mark a lane | POST /api/v2/rpc → lane.resume, lane.review, lane.mark | Adapters exist; all three lifecycle methods remain lb-v2-lifecycle stubs. Pending operation replies remain pending. Marking merged remains a recorded state decision. |
| Read operation completion | POST /api/v2/rpc → operation.get | Adapter exists; Store.Operation and service dispatch are lb-v2-service stubs. |
| Authenticate and approve a D6 change | human.challenge → human.confirm → human.session; org.change.approve | Identity and approval component implementations exist. Native connection/enrollment/store/dispatcher wiring is still required from their owners; HTTP must use the same protected connection and exact service receipts. |

The web page browses views, documents the control API and links to the protected
real-device enrollment page. Other browser forms for WebAuthn assertions,
messages, start/stop/input or blob upload are not supplied by this slice;
those user-facing forms remain lb-v2-dashboard work if item 6 requires clicking
them in a browser. Programmatic POST controls require committed BlobRefs where
the request type specifies them. This slice does not add a browser-controlled
file/path resolver or an upload/credential shortcut.

### Installed HTTP handoff

Dependencies.Transport is the dashboard-local HumanTransport port for foreground operations. The service
owner supplies a protected connection/cookie context through Scope and the
ordinary durable service dispatcher through Dispatch; assembly owns wiring that
installed implementation. It must preserve the exact original request frame,
one explicit configuration and the actual authenticated principal/connection.
Scope resolves connection/frame metadata without refreshing activity. Foreground Dispatch must serialize same-session refresh and perform native/current authorization,
pinned reads, receipt reservation/replay and atomic proof/ticket consumption.
An HTTP body must not be labelled as a kernel-verified Unix frame.

Background SSE additionally requires HumanLivenessTransport.PollEvents on that
same installed transport. This private capability preserves normal native/frame,
current credential/session, object ACL and pinned-read checks while making no
RefreshReadSession call, proof use, deadline or generation update. Missing
capability returns lb-v2-service not_implemented. The public event.tail RPC and
its wire DTOs are unchanged. Ordinary foreground event.tail reads may refresh
activity; the browser's passive SSE reader cannot select that path. Cookies
reload and enforce identity's last committed idle/absolute deadlines without
extending them. SSE messages update retained lane/tree data without background
GETs that would count as foreground reads.

This checkout's assembly does not supply Transport. Missing wiring returns the
exact owner-named not_implemented from lb-v2-service. No local mint, event-scan
authorization, local receipt replay, or direct module mutation fallback remains
in production HTTP. The older module dispatch helpers live only in test files.
TestDashSSEDispatch requires the event dispatcher before stream headers. TestDashServiceDispatch requires another service call on an exact retry and
propagates its owning failure. TestDashControlsOwner requires start/input to
reach the lifecycle owner without claiming that either action ran.

## 3. Red controls and Linux acceptance

[controls.json](../../e2e/v2/cases/dashboard/controls.json) contains 37 controls,
each with its own target assertion and diagnostic. The local runner retains a
separate source copy, mutation bytes/hashes, command, stdout, stderr, exit code
and named verdict for each mutant and candidate. It reuses the integration
runner's strict Go run/fail/pass validation. A compile/setup error, skip, panic
or unrelated assertion is not a reached red.

On the already authorized disposable Linux machine, retain the exact source
archive outside the evidence directory and run:

```sh
python3 e2e/v2/cases/dashboard/red-controls.py --source /absolute/candidate --evidence /absolute/lb-v2-dashboard-cx-red
go test ./internal/v2/dashboard ./internal/v2/cli ./web/v2
python3 -m unittest discover -s e2e/v2/cases/dashboard -p test_case.py
node e2e/v2/cases/dashboard/web-test.cjs
```

The web renderer control needs Node with node:vm and modern JavaScript support.
Missing tooling is a failed setup, never a skip or a successful UI check.
These fixture tests do not establish native peers, installed containment,
hardware presence, real model execution or a working installed service.

The installed dashboard case now requires both refusal controls and a positive
authorized request plus service read-back. Supply an absolute
LANEBOSS_DASHBOARD_CONTROLS_FILE for the isolated installed fixture: its JSON
object maps DASH-STOP, DASH-RESUME, DASH-MERGED, DASH-ABANDONED and HUMAN-SEND to
their exact Request envelopes. The fixture owner prepares and confirms those
requests against the same protected human connection, real objects and current
base generations. The driver preserves their exact sent bytes and initial
replies, polls the same pending operation, and reads lane.status or mail.list.
It checks run, state, generation, sequence and mail provenance/content. Refusal
responses alone, missing positive inputs and pending-as-complete cannot pass.
Presence labels remain simulated/not_proven in both dependent evidence and the
aggregate evidence report. Start/input have owner-routing regressions here;
they still need their installed-runtime acceptance rows when their owners land.

No unit tests, renderer execution, red mutants or installed E2E ran on the
authoring Mac. Go vet exited 1 at the cache permission boundary; per the brief,
the remaining Linux/faults/Darwin vet variants were skipped for laneboss to run.
The retained refusal log is external evidence, not a passing compile result.
