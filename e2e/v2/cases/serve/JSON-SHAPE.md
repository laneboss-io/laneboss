# Launch preflight JSON shape and raw frame attribution

Green37's supplied log contains the generic API JSON refusal twice and no
previous gate-readiness or bwrap-failure facts. The live follow-up reports that
the CLI request matches StartRequest and its nested DTOs, and asks for raw
frame attribution. Neither supplied artifact includes the rejecting frame's
bytes or a decoder call-site trace. Candidate native acceptance remains pending.

## Concrete source mismatch

The isolation proof producer declares Limits as `[][2]string`. Its measured
limit read-back writes six name/value pairs, including pids.max and memory.max.
The v1 proof format therefore contains an array of exact two-string arrays.
The proof is retained and pinned without dropping those values.

The source trace is LaneStart → spawnPreflight → launchAvailability → Probe →
the installed helper's IsolationEvidence/measureIsolation. The helper starts
and collects its native probe gate, validates the measured proof in memory,
retains the proof bytes and returns an isolationPacket inside helperResponse.
The service-side admin client strictly decodes that returned proof before
verifyIsolationHost and isolationCapabilities. This occurs before ReserveLaunch
for the requested agent life. A gate failure inside measureIsolation returns
early and never reaches the returned-proof decode.

At c9662bb1, API checkShape has no reflect.Array case. It therefore rejects the
first Limits member at `$.Limits[]`, even though the real producer emitted its
declared pair shape. The wire reader has the same missing case. Retained source
at bec6bf14, merge 2a6d6ecc and c9662bb1 confirms the pair declaration and absent
array cases at all three revisions. This is a deterministic source mismatch;
the plain installed message alone does not prove its runtime location.

Both readers now validate the declared array's exact length and recursively
validate every element. Existing v1 fields, values, omission rules and type
declarations are unchanged. No pair is truncated, padded or removed; no null,
duplicate, case alias, unknown field or invalid Unicode becomes acceptable.

## Raw producer and decoder path

The base API uses invalidJSON for both raw parsing and shape failures. The same
message cannot by itself distinguish those stages. The additional live report
of a raw failure remains a separate observation requiring a deciding frame and
reason; it is not replaced by the source finding above.

The shared parser now preserves specific raw reasons: empty, frame_limit,
utf8, surrogate, duplicate, depth, syntax, trailing and nonfinite. Request digest
encoding adds encoding. Helper request/response/result, isolation proof/canary,
gate input, canonical JSON and stored-object boundaries use fixed frame kinds.
Shape errors also identify the compiled object and complete schema path. Array
positions are `[]`; unknown keys are `*`, never a caller's key text. A bounded
secondary diagnostic walk can locate a duplicate but cannot accept input or
replace the strict parser's decision. Error DTO fields and budgets are unchanged.

The helper producer now checks the complete encoded request/response envelope
before any prefix or payload byte is written. This catches invalid RawMessage
content that json.Marshal alone can preserve, including duplicate keys, bad
Unicode and envelope size overflow. The server preflights its complete success
response before entering the writer; a refused producer result uses the existing
correlated typed-error reply with the same protocol/revision/nonce. There is no
retry after partial transport output, no input rewrite and no frame-limit increase.
Undelivered-refusal journals add only allowlisted frame/reason words and retain
their existing code/owner filtering. Raw messages and input values are never logged.

## Regressions and deciding controls

TestIsolationProofTransport uses the real proof DTO, limitValues producer,
isolationPacket, helperResponse and four-byte frame. Both strict readers must
preserve the entire header, proof value, pin and exact raw bytes, then satisfy
the existing nine-check proof validator. This is a synthetic transport test,
not an installed kernel observation. TestIsolationProofShapeRefusal requires
the exact Limits path for short/long/null/wrong-type pairs.

TestFixedArrayJSON and TestFixedArrayShape cover exact array round trips and
refuse inexact lengths, null elements, wrong types, unknown fields and duplicates.
TestShapeDiag varies paths/reasons and randomized private keys/values.
TestRawJSONDiagnostic independently reaches each raw rejection, using otherwise
valid payloads for size, Unicode, depth and finite-number guard controls.
Canonical/stored paths must retain their own frame kinds. Failure-fact tests
reject arbitrary frame/reason text from private messages.

TestHelperJSONProducer requires zero output bytes on malformed RawMessage or
oversize envelopes and preserves valid framing. An independent native marshal
result distinguishes encoding refusal from a later raw-parser refusal.
TestHelperJSONJournal permits only the closed facts. TestHelperJSONRefusal uses
a real bounded pipe exchange to require a correlated strict error frame and
requires the sender to report refusal after delivery.

The catalog retains all 586 prior IDs and adds 30 controls, for 616. The old
helper-diagnostic edit follows its extended journal literal; its deciding test
and condition remain. New controls restore either unsupported-array reader,
drop the producer's Limits field, disable exact lengths/element checks or raw
guards, lose schema/frame/reason attribution, disclose private key/reason text,
or bypass producer preflight. Only the two exact API source files and API test
package are added to the mutation runner's existing allowlists. Roots, account,
root/integration gates and timeout/kill rules remain unchanged.

Every new ordinary/faults reached-red/candidate pair must run on disposable
Linux. A build error, skip, timeout, wrong failure or surviving control is
incomplete evidence. The next installed green must retain the actual frame,
reason and field/object when applicable, and complete the native isolation
proof before any lane-start success is claimed. No runtime test or control
overlay ran on the Mac. Presence stays simulated; human approval stays not_proven.
