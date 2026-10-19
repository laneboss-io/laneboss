# Migration draft.4 port audit

This audit covers the migration-owned changes on source revision `42d077b`,
which already contains the reviewed draft.4 integration revision `74354cd`.
It is a static port checkpoint. Runtime acceptance remains incomplete.

Update for the combined `d60bd08` tree: the fix 3 validator registry and
completion catalog are now present. The migration d4fix2 port registers plan
and apply, replaces concrete cross-lane test dependencies with injected typed
failures, and moves CLI tests beside the command adapter to inject a connection.
The table below retains the original checkpoint's inspected locations; current
per-test changes and runtime verification requirements are in
`migration/v2/D4FIX2.md`.

Every migration-relevant correction in contract sections 14 and 15 was checked.
References below name the source locations inspected in this tree.

| Contract change | Checked source | Migration result |
| --- | --- | --- |
| Retained mutation keys and committed file inputs | `internal/v2/cli/commands_migration.go:19`, `:100`, `:152`; `internal/v2/client/prepare.go:52` | Both handlers now call the common Invocation. Apply cannot generate its own mutation key. Manifest upload subkeys bind the retained parent key, submethod and chunk offset. Plan accepts a committed manifest through `--content-ref`; proof-bearing inline upload refuses before uploading. The old `--db` shortcut no longer fabricates successful verification or zero-survivor receipts. |
| Mutations require replies; reads cannot write state | `internal/v2/migration/apply.go:84`, `:131`; `internal/v2/migration/stub.go:99`; `internal/v2/api/validation.go:64` | Public apply commits a typed pending Operation reply with its proof guard and deployment/effect intent. Missing or unrelated backend replies return integrity instead of a synthesized success. Plan performs no StateStore transaction. Tests inject a missing reply and forbidden writes into a read. |
| Ticket issuer/config/endpoint and MutationReceipt.Config | `internal/v2/api/identity.go:38`; `internal/v2/api/transactions.go:81`, `:104`; `internal/v2/migration/apply.go:102`; `internal/v2/migration/relaunch.go:211` | Replay checks the retained configuration, method, key, digest, actor kind, principal and life after both lookup and await. Fixture receipts retain the original commit metadata and use the full domain. Migration creates no Ticket or TicketUse; relaunch forwards only RootTicketID to normal lane adoption, whose identity/lifecycle owners consume the actual ticket. No parallel ticket decoder or issuer reconstruction was needed. |
| Human reads use human.session on the shared connection | `internal/v2/cli/commands_migration.go:19`, `:152`; `internal/v2/cli/cli.go:286`, `:362`; `internal/v2/cli/integrate_test.go:80`, `:181` | The separate migration client/open/close/envelope path was removed. Plan and all subcalls use the shared Invocation, preserving explicit binding selection and borrowed-client ownership. A read proof therefore establishes human.session through the common path; it is not attached as a migration.plan operation proof. CLI regression inputs include a real session-intent digest, and ergonomic manifest/reference/proof files retain non-symlink checks. |
| Public migration.apply and internal migration_apply matrix; fix 3 completion guards | `internal/v2/api/write_catalog.go:60`, `:85`; `internal/v2/migration/apply.go:84`, `:159`; `internal/v2/migration/import.go:14` | Public apply writes only Deployments and a causally bound Migration effect. Internal completion writes retained Objects/Deployments and inert record.appended history. It requires the retained current effect claim, measured freeze/drain and matched backup. It has no RPC reply, ProofUse or ApprovalUse; original human authority stays on the parent operation. The current catalog still permits Approval on this completion row, so the integration owner's fix 3 removal remains outstanding. These completion transactions already consume no such guard and remain compatible with its removal. |
| TurnStore.Decision and append-only supersession | `internal/v2/api/turns.go:163`; `internal/v2/migration/import.go:71`; `internal/v2/migration/readback.go:164` | Legacy decisions now remain legacy_import records. A copied human/authoritative label never emits decision.changed or writes Decisions. Original decision / status / provenance / vector / egress bytes remain retained; an explicit new human/D6 commit is required for current authority. Read-back uses TurnStore.Decision, including its superseded-history lookup contract, to require that migration created no canonical projection. Migration does not supersede a current v2 decision, so it has no old-generation authority to reconstruct. |
| CLI file-input validator hook | `internal/v2/cli/cli.go:210`, `:286`, `:295`; `internal/v2/cli/commands_integrate.go:72`; `internal/v2/cli/commands_migration.go:122` | The fix 3 validator registry is absent in this tree. The common exact-file path invokes only DecodeObject and the integration alias validator. Migration supplies migrationValidateFileInput and uses it for ergonomic handlers. Registration on the exact-file path requires the integration-owned registry; no common dispatch file was changed by this lane. |
| ConnectionContext authentication order and InstalledBinding peer verification | `internal/v2/api/interfaces.go:96`; `internal/v2/api/peer.go:26`; `internal/v2/migration/stub.go:13`; `internal/v2/migration/apply.go:15` | Migration implements neither Authenticator nor PeerVerifier. It consumes the transport-authenticated Scope and checks its installed human binding and verified proof facts before a new apply. The typed connection fixture was updated. No native peer verification implementation or authentication-order adapter belongs to this lane. |
| Helper.Release receipt, helper kinds and Cause fields | `internal/v2/api/interfaces.go:125`; `internal/v2/migration/stub.go:13`; `internal/v2/migration/apply.go:159` | Migration has no Helper dependency or helper IPC call. Its own effect now carries the complete migration InternalIntent and original requester. It cannot use a lane lease as deployment authority. No ReleaseReceipt decoder or helper Cause producer needed a migration change. |
| ContinuationRequest.Swap | `internal/v2/api/turns.go:132`; `internal/v2/migration/relaunch.go:41`; `internal/v2/migration/import.go:14` | Migration constructs adoption input for a new life, never ContinuationRequest, ProfileSwap or active continuation projections. Old continuation/profile labels remain source history. There is no removed outer continuation field in this lane to port. |
| Clef/TypeSafe providers and approved pins | `internal/v2/migration/stub.go:13`; `internal/v2/migration/import.go:83`; `internal/v2/migration/readers.go:1024` | Migration has no Judge dependency, provider constructor or model request. It preserves verified legacy vector/egress metadata as inert exact bytes. It cannot select a provider or substitute current approved policy, so no provider-field adaptation was needed. |

The import now retains actual bytes atomically with records. Vector and egress
BlobRef hashes describe their full retained JSON bytes; original embedded vector
and chain hashes stay inside those unchanged bytes and the frozen source
manifest. Archive receipts and delivered/queued/returned mail remain history,
without new archive authority or active delivery rows. Read-back checks a pinned
snapshot, exact record IDs, object metadata, provenance and actual object bytes.
It filters events/effects by the actual migration operation so unrelated live
history does not become a false refusal. Source reads validate object identity,
bounded chunks and an exact empty end receipt. Rollback no longer ignores an
event read failure or an incomplete/cycling cursor. Relaunch and rollback also
check their configuration against the authenticated scope.

The existing eleven source mutations are retained. Three targets moved to
`readback.go` and `import.go`. Duplicate-mail and active-authority controls
inspect the constructed internal transaction before store validation, so a
catalog rejection cannot substitute for reaching their own invariant. The
read-back mutation keeps its hash canary and additionally tampers only the
record origin, reaching the metadata predicate even with byte verification
enabled. The checker now requires each named diagnostic, retains source and
binary evidence, and runs the same unmutated test after its red failure.

The following regression conditions must be exercised on the authorized Linux
test machine. None was executed in this Mac round.

| Check | What makes the check fail |
| --- | --- |
| TestMigrationWriteCatalog | A missing reply, state-changing read, public history/canonical write, generic completion, or reconsumed completion authority is accepted. Legitimate public/internal transactions must also pass the real catalog validator. |
| TestMigrationReceiptBinding | A foreign configuration / key / digest / method / principal / life receipt is returned from lookup or await, or a matching exact reply cannot replay before plan/proof preflight. |
| TestMigrationCompletionPrerequisites | Missing backup/freeze phase, a live/unknown process count, a foreign claim or an expired lease reaches import, or it refuses with the wrong typed error. |
| TestMigrationBlobReadIntegrity | A valid full source cannot round trip, a matching prefix hides trailing bytes, or foreign object/end-hash receipts are accepted. |
| TestMigrationRequiresDurableReply | The backend omits its committed reply and migration fabricates an Operation instead of returning integrity. |
| TestMigratePlanAndApplyEndToEnd | Either supported source loses hashes/bytes/history/mail status, public apply imports prematurely, internal completion fails read-back, or restart replay duplicates effects/rechecks a consumed proof. Relaunch/rollback remain in-process fixtures, not native isolation acceptance. |
| TestCLIMigrationCommands | Unknown/invalid flags, a missing retained key or a symlink escapes its local gate; a valid committed-reference/session-proof form fails before reaching the typed transport dependency. |
| Eleven named migration controls | The targeted source mutation survives, fails compilation/setup, misses its specific failing diagnostic, or the corresponding unmutated focused test fails. |

Observed local checks were formatting, bash syntax, ShellCheck and Python byte
compilation, each with exit 0 and no diagnostics. Linux go vet was refused at
the default Go build cache; its exact output is retained in the lane evidence.
The brief explicitly permits skipping that check without another cache path.
Linux, Linux with laneboss_faults and Darwin vet are therefore pending the
supervisor's gate. Unit tests in both builds, all red/candidate controls, the
denylist scan, installed serve E2E and independent reviews are also pending.
The previous eleven-killed result at `851feb5` does not establish this revision.

The runtime and integration requests are recorded in
`internal/v2/migration/CONTRACT-GAPS.md`. No authenticated AI-service, human
ceremony, native confinement, live deployment or rollback acceptance was run
or claimed in this round.
