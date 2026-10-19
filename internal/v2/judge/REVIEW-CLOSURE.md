# Wave-0 judge review disposition

This ledger consumes the complete wave-0 `lb-v2-judge-read/REVIEW-tail.md` and
`lb-v2-judge-gread/REVIEW.md` supplied by the supervisor. The item numbers below
are those reviews' numbers. “Closed in port” describes the v2 source and its
canaries; the new draft.4 candidate still requires the supervisor's Linux
normal/fault/race, differential, benchmark, mutation, scanner and review gates.
The supplied `f9bf8cf` normal/fault/long/mutation passes do not cover new code.
No claim is made that the unchanged legacy package/evaluator is repaired here.
The supervisor subsequently removed sixteen wave-0 additions at 36753879.
Fix 8's schema-based caller scopes were then flagged as a suspected egress
regression. Fix 9 joins caller text by default and restricts exclusions to the
exact producer-owned paths in CONTRACT.md. The reference omission is narrowed
to an independent caller projection with no hit; six new actual-adapter split
canaries and three unknown-field frames protect that boundary. Runtime red/green
evidence remains required; thirty-five mutation controls are now defined.

| Review item | Disposition in this lane |
| --- | --- |
| Read 1, outgoing credential screening | Closed in port: complete pre-retention/pre-fit/pre-HTTP string/key/value and embedded-JSON screening; zero-HTTP canaries retain all positions and the unchanged 90,000-CJK suffix. Runtime regression gate remains required. |
| Read 2, rule/decision batching | Complete single batches are implemented: named lists, indexed trusted Noul questions and semantic cache keys covering every entry. Preview above twelve remains explicitly unscored; aggregation/per-batch receipts remain open in CONTRACT-GAPS.md. No list is silently cut. |
| Read 3, scored result without probability | Closed for the frozen Noul interface: complete atomic per-ID probabilities only. No Choice/Score cast or synthetic zero. Choice execution remains open under Read 5 / Gemini 8. |
| Read 4, Python/Go request-byte mismatch | Open with evaluator owner. This adapter retains exactly the body it sends, but this lane neither edits nor certifies scripts/judge-eval. |
| Read 5, Choice position bias | Open with evaluator/corpus owner. Twenty Choice rows receive structural checks only; the current normalized contract has no Choice distribution. No calibration success is claimed. |
| Read 6, tautological over-budget canaries | Closed for this port's transport bounds: byte and token boundary tests plus a below-byte-cap token-overflow public canary. Evaluator aggregation/calibration remains open with its owner. |
| Read 7, Python malformed replies/deadline error | Open with evaluator owner. Go adapter malformed/duplicate/partial/timeout paths remain explicitly unscored and bounded by the request context. |
| Read 8, remote plaintext Clef | Closed in port: HTTP requires literal loopback 127.0.0.1 or ::1; redirects refuse. |
| Read 9 / Gemini 1, escaped key echo | Closed in port: strict decoded recursive key/value screening before raw retention, with quote/backslash/slash/Unicode echo controls. Evaluator side remains open/unverified here. |
| Read 10, key through formatting/JSON | Closed in port: nonserializing material and redacted String/GoString on constructor dependencies and services; canaries check both text and byte-array recovery. |
| Read 11, combined/generic refusals | Closed for protected constructor conditions: separate fixed typed messages without request/key echo. Generic malformed-request diagnostics remain intentionally fixed and do not expose input. Evaluator changes are outside ownership. |
| Read 12, provider request ID dropped | Open in normalized contract. The screened raw response preserves the ID; JudgeReply has no dedicated provider-request-ID field. Raw preservation alone is not full accounting closure. |
| Read 13, cache bytes/expiry/concurrent misses | Closed in port source: bounded serialized charge, expiry ordering, coalesced identical misses and copied probability/object references. Fix 8 excludes per-ask ID/deadline/cost ceilings and tests cross-ID hits. New runtime evidence remains required. The charge is not a measured RSS bound. |
| Read 14, replaced/typed-nil transport panic | Closed in port: no assertion on ambient DefaultTransport, explicit nil checks, cloned standard transport and real transport controls. |
| Read 15, long test literals | Open pending the supervisor's staged scanner/review. Owned test names and new messages stay short; this lane does not stage or run the publication scan. |
| Read 16, corpus/docs/red evidence | Corpus text and evaluator documentation remain open with their owners. The owned fixture is a byte-identical copy with no external corpus dependency. The supplied fb25f5b report passes twenty mutations; fix 8 corrects the benign metadata join and adds seven controls. Candidate red/green evidence for twenty-seven controls remains open until the Linux runner returns it. |
| Read 17, fit process environment/trickled headers | Open with evaluator/serving owners for the real formatter/tokenizer. Go transport has no ambient proxy and a total context/header bound. Fixture fit is explicitly synthetic; no serving fidelity is claimed. |
| Gemini 2, empty/incomplete evaluator summary and false over-budget safety | Open with evaluator owner; unchanged by this lane. |
| Gemini 3, second monotonic call / expired subprocess | Open with evaluator owner; Go provider uses one nonresetting context deadline. |
| Gemini 4, missing comparison pairs | Open with evaluator owner; this port does not certify comparison metrics. |
| Gemini 5, ambient proxy/whitespace pins/trailing-dot hosted endpoint | Closed in port: Proxy nil on owned/cloned HTTP transport, strict pins, normalized hosted-host refusal and paired transport controls. Evaluator side remains open/unverified here. |
| Gemini 6, failed/oversized Python artifacts retained | Open with evaluator owner. The Go adapter withholds undecodable/credential-bearing bytes and limits raw responses; its retained failure bytes are screened protected objects. |
| Gemini 7, probability pointer alias | Closed for v2: distinct per-ID probability allocations and copied cache/audit results. There is no duplicate top-level match pointer in the frozen reply. |
| Gemini 8, corpus not built through payload / invalid Choice IDs | Closed for 282 Noul corpus rows, all constructed through Payload, and Choice structural IDs/labels. Full Choice runtime evaluation remains open because its typed probability union is absent. |

The later screening performance gate remains open until the candidate's actual
`many-fields-deep` and `assignment-tails` observations each pass 500 ms at
262,144 bytes on Ubuntu 24.04/c5.large/2 vCPU amd64. The earlier supplied failures
establish red latency evidence, without a measured causal profile. Necessary
literal prefilters, equivalent assignment search and fewer placeholder helper
passes target that cost while preserving the immutable reference and all caps.
The latest supplied fb25f5b base run passed at 120.6 / 163.0 max-ms; it does not
measure this fix-8 candidate. The frozen reference is still unchanged. Its
whole-envelope false positives now have one independent named omission,
structured-join, and individual scored realistic-ID/path/hash controls.
All original split canaries and the three named assignment extras remain.
DEPENDENCIES.md lists every reviewed legacy path as unnecessary to this lane;
the supervisor owns removal and the legacy callers' integration consequences.

Draft.4 audit completion writes are now consumed under their internal matrix;
the isolated fixture verifies actual request/raw bytes, fit, scores and committed
readback. Production dispatch/reservation/recovery, unknown usage/cost, protected
provider wiring and composed service/store/client remain open as described in
CONTRACT.md. A typed dependency error is an honest failing gate, never a passing
JUDGE-WIRE, JUDGE-BOUNDS or JUDGE-AUDIT observation.
