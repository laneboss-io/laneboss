# Wave-0 review disposition

The current draft.4 FIXES-NEEDED cross read and d4fix1 corrections are tracked
item by item in [REVIEW-FIXES.md](REVIEW-FIXES.md). Its production-route P0 is
explicitly deferred to the supervisor's fix-9 handoff; source corrections do
not claim that installed gate is closed. The supplied base already removes
the wave-0 package. This older review ledger remains historical context.

Both supplied review files were read completely. The Fable review is marked
FIXES-NEEDED with 14 findings; the gemini review is marked APPROVE with six
verification areas. Their source scope was the wave-0 legacy package at
997c537, not this draft.4 installed path. No new reviewer approval is claimed.

Closed below means the correction and its supporting component controls exist
in this owned port. The supervisor reported the restriction-off component tree
38ac17c passing both variants/all three runs. Installed closure remains open
until the real root/helper/CLI path runs these same boundaries. The supervisor's
a38bebf restriction-on admin setup passed; Linux then failed on its root-only
profile-registry read. The new unprivileged behavioral prerequisite and its
decision tests still need restriction-on execution. No tests have executed on
the authoring Mac.

| Fable finding | Implementation disposition and evidence | Remaining installed gate |
| --- | --- | --- |
| 1. Host network sharing | Closed: unconditional --unshare-net, controlled_egress without lease, private-loopback/native controls. Draft.4 validates lease bindings. | Open: admin forwarding/packet ownership and positive leased-egress canaries. |
| 2. Helper/runtime writable overlap | Closed: checkExportOverlaps and root-controlled helper/runtime pins; disjoint/overlap controls. | Open: installed materialization/runtime resolver must use these constraints. |
| 3. Name-to-mount race | Closed: openat2/O_PATH identity and FD binds, real ancestor-swap controls. | Open: root gate must invoke the same pinned construction. |
| 4. Named environment payload | Closed: sealed inherited fd 3, seal checks, no named payload, selected-byte control. | Open: installed selected-slot delivery and capture wiring. |
| 5. Raw regular-file streams | Closed: stream admission refuses regular files/directories; real truncation control. | Open: installed outside pipes must reach the same check. |
| 6. Immediate close_range | Closed: CLOSE_RANGE_CLOEXEC, actual event descriptor and fd-200 controls. | Open: same bootstrap dispatch in installed artifact. |
| 7. Missing seccomp/false readiness | Closed: deny filter and disabled nested namespaces, actual syscall controls; production probe requires retained evidence. | Open: installed helper probe/backend proof; no ready flag may substitute. |
| 8. Lost causes/diagnostics | Closed in source: named prerequisite/OS causes, bounded diagnostic tail, protected AppArmor bytes plus fresh unprivileged bwrap/unshare observations without securityfs reads. | Open: corrected restriction-on kernel and installed failure/recovery evidence. |
| 9. Protected dangling/XDG roots | Closed: resolved dangling targets and conventional protected roots, paired root tests. | Open: installed resolver must preserve the protected-root inventory. |
| 10. Lane UID/GID pool trust | Closed: full pool exclusion and missing/invalid inventory refusal controls. | Open: admin supplies real installed account inventory and UID separation. |
| 11. Future Landlock ABI refusal | Closed: known-rights clamp and real ABI retention with independent masks. | Open: ABI 3 floor and supported installed kernels. |
| 12. Probe per launch | Host basics and pinned FD behavior retain success caches per boot and identity; mutable AppArmor readiness is remeasured for the unprivileged caller. | Open: installed path latency and invalidation measurement. |
| 13. Vacuous FD/truncate checks | Closed: real planted non-CLOEXEC fd 200 with controls and truncate-only kernel observation. | Open: public CLI mutation artifacts reach the same effects. |
| 14. Long source tokens | Closed: owned source token checks and split literals/paths. | Open: supervisor's whole staged publication scan. |

Gemini's six areas remain supported and are strengthened by the Fable fixes:

| Gemini area | Disposition |
| --- | --- |
| Mounts/ownership | Closed in component construction; production root resolver and live grants remain open. |
| Environment | Closed in sealed payload construction; installed secret-slot integration remains open. |
| Descriptor hygiene | Closed with CLOEXEC and real descriptor controls; the reviewed old immediate-close behavior is replaced. |
| Landlock/floor | Closed in construction and masks with future-ABI clamp; separate ABI 3 runtime evidence remains open. |
| Network/runtime ownership | Closed for private offline construction and ownership refusal; controlled forwarding remains open. |
| Real tests/platform gates | Existing syscall/read-back controls retained without skips; draft.4 installed/serve, restriction-on and new mutation results remain open. |

The new helper-backed public methods preserve these corrections rather than
replacing confinement with a test stand-in. They never manufacture a process,
gate, zero-survivor count, release receipt or effect completion. CONTRACT-GAPS.md
names the exact construction and backend owners still required for serve.
