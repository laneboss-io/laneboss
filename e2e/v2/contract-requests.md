# Integration request history

Historical record restored from f64e2ea. Current source and installed readiness
are maintained in cases/ladder/READY.md and plan.json; old missing-port claims
and prior test counts below are not current acceptance results.

The active draft.4 owner/symbol/need ledger is [CONTRACT-GAPS.md](CONTRACT-GAPS.md).
The previous preparation slice was merged as f64c2d0 before this port.

Draft.4 resolves the old CLI ceremony defect: InvokeRaw establishes
human.session and the requested read on the same socket when --proof is given.
A new invocation still needs a genuinely fresh proof. Root Ticket now retains
principal/config/endpoint generation; root start consumes its ticket instead of
using a generic operation-proof substitute. Installed bindings require matched
draft.4 artifacts. Committed --content-ref inputs are supported for proof-bound
records/decisions, and every mutation retains its retry key.

Remaining installation, live observer/timing, actual credentials, archive export
and source-installer compiler requests are carried whole in CONTRACT-GAPS.md.
Its receipt/read/transaction observations are proposed E2E normalization, not
new public API fields. Missing authenticated transport remains not_implemented
with its owner; no fixture or management-file read fills that gap.

The box must run the combined normal and laneboss_faults tests, all harness
units/red controls, installed serve E2E and the real mixed ladder. Static Mac
checks and the prior unit count are not that evidence. independent Claude reviewer and Gemini review,
phase hash/read-back, safe collection and actual machine termination remain
supervisor gates before release acceptance.
