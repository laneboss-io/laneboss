# Migration integration needs after draft.4

The numbered requests below record the historical `42d077b` checkpoint, with
the first two closures from the combined draft.4 fix 3 contract and migration
d4fix2 port on `d60bd08`. They are not an inventory of current stubs. The
current API/assembly catch-up and static verification are recorded in
`migration/v2/CATCHUP1.md`; installed runtime acceptance remains separate.
They are not permission to bypass a missing dependency or to accept migration.

Catch-up 2 adds two mandatory producer integrations, documented precisely in
migration/v2/CATCHUP2.md. The store must provide MigrationEffects for a complete
operation inventory across pending, claimed and completed states in the pinned
read view. It must also provide MigrationQuiescence from actual current frozen
dispatch, helper/process and capture/outbox measurements for rollback. The
optional feature read ports add no public RPC. The module reports a plan
problem or typed refusal when a producer is missing; no pending-only scan or
caller boolean substitutes. Native/installed evidence remains required.

1. Closed: cli.RegisterInputValidator now exists. commands_migration.go
   registers both migration.plan and migration.apply after exact decoding,
   using the same semantic validator as ergonomic commands. The decisions
   migrate alias shares migration.plan's registration. Feature-owned CLI tests
   cover both methods, alias input, early refusals and an injected connection.

2. Closed: api/write_catalog.go:89 now permits only Cancellation guards for
   migration_apply. Migration completion already consumes no new ApprovalUse
   or ProofUse and retains its original public operation's causality.

3. Service/integration must provide a frozen internal completion port and wire
   the migration coordinator. MigrationAPI at api/interfaces.go:326 and
   RuntimeServices.Migration at api/composition.go:25 expose only Plan/Apply.
   CompleteMigration is a concrete migration-owned trusted entry accepting an
   EffectLease; it is deliberately not registered as a public RPC. The service
   must persist freezing / draining / backed_up / staged / migrating phases, correlate
   the original proof-authorized operation and hand off the current immutable
   claim. It must not call public MigrationApply again as an effect executor.
   No new interface was invented in the shared leaf API by this lane.

4. Service/store must implement the receipt, claim, snapshot, object, deployment
   and backup ports. In this tree store.Transact and the contract methods for
   LookupReceipt, AwaitReceipt, CompleteEffect, RetainObject, Deployment and
   FrozenBackup still return typed not_implemented. Internal commits must check
   the actual persisted effect/claim/actor/requester and retained original
   authority, apply CAS, and retain object bytes with record events atomically.
   Completion must reconcile after the activating or complete phase without
   reimporting history. The module follows the same lookup/await replay pattern
   as records; dispatcher reservation ownership must be composed so a fresh
   handler does not await its own newly created reservation as a retry.

5. Packaging/service must agree on the frozen state manifest reference. The
   completion currently requires FrozenBackup.StateManifest to equal the exact
   approved MigrationPlan.SourceManifest, and reads back state/config/release/
   recovery objects. If packaging uses an outer backup manifest, the integration
   owner must define a typed mapping to the exact approved source instead of
   weakening that equality or inferring it from labels.

6. Grants/dataworker and integration must supply the confined legacy-parser,
   selected-history materialization and matched rollback execution contract.
   DataWorker at api/interfaces.go:203 has no migration import/rollback method.
   The existing read-only legacy parsers and relaunch/rollback algorithms are
   not proof that they run in a confined worker. PrepareRelaunch still prepares
   adoption metadata; its private-history/adoption refs must be committed by
   that worker and current grants/ticket must be checked by lifecycle before
   any launch. ExecuteRollback requires independently measured quiescence and
   matched deployment authority; its boolean worker input is not a public
   proof. These helpers are not exposed as a new host-path RPC.

7. Identity/E2E must supply a credential-free verified human ceremony fixture
   for this case through a reviewed harness contract. The existing controller
   actions cover restart, confined canary and fixture clock only. A human
   binding/UID/label alone cannot grant reads or mutation authority. Each human
   mutation needs its own operation proof, and each CLI read proof must open
   human.session on that invocation's live connection. The case must not invent
   bearer sessions, fake WebAuthn assertions or add an undocumented auth bypass.

8. After those ports exist, the migration case must complete installed-CLI
   apply, exact service read-back, inert decision/mail checks, confined relaunch,
   retained new work and matched old-data/binary rollback rows. Its current
   coverage gate reports missing rows and fails; successful plan controls alone
   cannot pass MIGRATE-ROLLBACK. Setup/dependency failures are not mutation kills.

At that historical checkpoint the local Go vet gates were unverified because
the default build cache was refused. The catch-up brief authorizes a shared
cache, and its current vet results are recorded in CATCHUP1.md. The supervising
Linux tests, eleven
red/candidate runs, denylist scan and independent reviews must run on these
actual final bytes before acceptance. No earlier checkpoint result is reused.
