# Host2 source and verification report

The source starts at c4acd8e, containing host1 and final draft.4 74354cd.
This report separates supervisor-observed Linux failures, source changes and
permitted static checks. No runtime test, project interpreter execution,
product binary, installation, model request, remote access or Git mutation
was performed in this round. Protected evidence is retained in the lane's
run6 directory; host1 evidence is unchanged.

## Item 1: observed Health panic

The supervisor observed TestHealthTracksHostObservations panic while assigning
into a nil handler map. Production installedServer initializes both route
maps. observedHealth reads those maps and does not assign into them. The
fixture constructor omitted initialization, while this test intentionally
sets serving before checking registration refusal and populating the maps.
The fixture now initializes handlers and streams. The late-registration check,
map writes and observed probe/listener/route/reconciler checks remain. A new
freeze toggle also requires Health to become unready. Linux runtime success
has not been measured here.

## Item 2: closed transaction refusal

The final internal write/event matrix in the contract refuses record.appended
under object_retain during ValidateTransactionShape. The original internal
cell now requires only invalid_request with exact text
"invalid typed transaction shape". A separate internal-authority cell first
asserts structural validity, then submits a different internal emitter actor
and requires only forbidden with exact text
"internal emitter does not cover these writes or events". Both verify that
the failed transaction leaves no partial state. An added mutation removes the
store's actor/emitter gate and must fail the latter cell's accepted-transaction
assertion. This red/candidate comparison remains unrun.

## Item 3: installed host priority and dispatch

The installed construction path was read through assembly and the service
host. Shared assembly and other lanes were not edited. BindRuntime now reads
all incomplete effects, including unexpired claims, through private concrete
store methods rather than treating the first runnable page as the whole
startup inventory. A retained freeze is restored before admission. Health
adds the observed dispatch barrier to its existing observations.

Freeze persists an exact operation-bound receipt and monotonic epoch using
the existing projection/history transaction. It requires a committed active
operation, retained deployment phase/generation and exact committed reason.
It stops new reservations/public work/internal initiation/effect claims and
cancels retained watchdog targets. Existing admitted reservations can finish;
completed replay, reads, capture/claimed completion and cancellation remain
available. Failure after a committed barrier retains that barrier. Exact
thaw revalidates pending executors and the retained receipt/epoch; stale thaw
does not reopen a later epoch. Cleared freeze pointers are omitted in retained
JSON so strict decoding can read the thawed state.

Drain serializes with freeze/thaw, waits for admitted handlers, inventories
retained reservations and all incomplete effects, then explicitly refuses
with not_implemented for measured capture/process inventory. RuntimeServices
does not supply the capture supervisor's backlog. No successful
QuiescenceReceipt or zero backlog/survivor count is invented. New effect
claims, including deployment effects, stop while frozen; the complete frozen
deployment execution and backup handoff are still unfinished.

Five new component tests cover store close/reopen and receipt/epoch checks,
completion of admitted reservations, frozen host reads/replay, host bind and
drain/thaw, and watchdog cancellation failure/retry. Their explicit identity,
watchdog and failed-effect fixtures cannot establish installed process or
authenticated deployment behavior. Eight new mutations bring the inventory
to 60, or 120 targeted red/candidate pairs across the two tag variants.
MUTATIONS.md maps each mutation to its exact required assertion.

## Measured scope and next gate

On the authoring macOS environment, GOOS=linux go vet ./..., the Linux
laneboss_faults variant and GOOS=darwin go vet ./... each exited 0. gofmt
reported no unformatted owned Go files. Python byte compilation, shell syntax
checking and diff whitespace inspection also exited 0. Exact command outputs,
exits, source inputs and hashes are retained outside the checkout. These are
static results only; both the new component controls and installed health/
SERVE-STATE remain unmeasured. The next gate is the supervisor's disposable
Linux component and installed serve run, preserving the intended base failure
and full candidate result. The installed case's outstanding cardinality,
boundary, watcher and outage work is recorded in ACCEPTANCE.md and MATRIX.md.
