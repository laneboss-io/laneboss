# Move from v1 to v2 — draft outline

**Draft. This is not an executable migration procedure.** It describes the
intended order at revision `d7403ec`. The migration module is landing separately.
Its constructor, plan/apply handlers and CLI adapters still return
`not_implemented` in this snapshot. The reserved CLI spellings `migration plan`
and `migration apply` are not working migration instructions.
<!-- source: internal/v2/migration/stub.go; internal/v2/cli/commands_migration.go; internal/v2/cli/dispatch.go -->

Not yet verified on an installed service.

## What must move

The contract covers 0.7.0 and 1.0.0-candidate inputs. It also preserves older
protocol 1.1.0 and 1.2.0 history. The migration inventory must include:

- Configuration and authored org sources, including roles, prompts, drivers,
  policy text, recovery routes and settings.
- State databases and sidecars, original events, IDs, sequences, timestamps,
  hashes, input files and embedded protocol bytes.
- Decisions, embeddings, reports, ledgers, refusal records, raw captures,
  archive attempts and verified archive receipts.
- Mail, delivery receipts and the owner queue. Already delivered messages
  must not be sent again.
- Unfinished workspaces, base/diff information and selected private conversation
  history needed for an explicit continuation.

Imported history remains history. Copied role labels, parent labels or session
files do not establish live v2 identity. Decision text does not become binding
guidance without verified original authority or explicit human approval.
Vendor auth stores and unrelated private histories are not ordinary import data.
<!-- source: internal/v2/api/manifests.go; docs/design/v2-contracts.md; docs/design/isolation.md -->

## Intended order

1. Inventory the old binary/source revision, configuration, relocated state,
   active work, mail and archives. Keep an exact protected backup and manifest.
   Record names and verdicts without exposing credentials.
2. Freeze old dispatch and automatic turns. Stop old runs through their verified
   identities. Prove actual quiescence and preserve worktrees and evidence.
3. Verify a frozen copy with the old verifier and the new importer's structural
   and hash checks. Corrupt or incomplete input stops migration. Preserve it;
   do not rewrite old events or repair their hashes.
4. Install a separate v2 service, helper, accounts and bindings. Import into new
   service-owned storage. Never let old and new writers share an active store.
5. Import authored org/configuration sources, then render and validate under the
   new owner. Translate external paths into explicit project, data and profile
   handles with owner-reviewed root grants. Do not grant a whole home by default.
6. Import historical records and queues with copy, hash, read-back and receipt.
   Keep original protocol bytes and provenance. Preserve delivery status.
7. Move selected unfinished work through confined data workers. Relaunch it as
   a new verified life. Resume vendor history only if the pinned driver proves
   the exact private session mapping. Otherwise use an explicit continuation
   report in a new lane.
8. Enroll human authority, issue new root grants/tickets and run credential-free
   installation, data, mail, archive and isolation checks. Only then perform any
   separately authorized authenticated service test. Keep the old copy frozen
   until rollback and new-history retention are verified.

Keep the configuration name and any active session binding. Use a separate
isolated migration process. Do not clear a binding to make a conflicting request
succeed. This outline grants no permission to stop production work or migrate it.
<!-- source: docs/design/isolation.md; docs/design/v2-contracts.md; internal/v2/api/manifests.go -->

## Questions for the migration implementation

- Which exact plan/apply CLI forms, request files and output receipts will be
  supported? Which source versions and schema revisions will they accept?
- How does an operator produce a complete `laneboss.migration.v2` manifest,
  including `source_version`, `source_protocol`, `source_revision`, `inventory`,
  `quiescence` and `verification`?
- Which commands freeze old writers and prove that processes, capture, queued
  effects and database sidecars are safe to copy?
- How are relocated state, partial archives and pending owner deliveries
  discovered without exposing private paths or replaying sends?
- Which fields require human review when legacy paths become grants? How is
  original human/D6 decision authority preserved or explicitly promoted?
- How are interrupted imports resumed idempotently without modifying the source?
  Which receipt proves exact event/sequence/hash preservation after restart?
- Which driver versions support private conversation import? What is the
  tested route when a safe session mapping is unavailable?
- What exact rollback bundle and commands retain both histories and restore
  a compatible old binary, configuration and frozen state?

Do not point an old binary at the v2 store. The documented 0.5.0 rollback
boundary already rejects newer configuration and session/mail structures.
Rollback must restore the matched old binary and its compatible frozen data
after preserving new work. Changing only the executable cannot downgrade data.
<!-- source: docs/design/isolation.md; docs/design/v2-contracts.md -->

Return to [the v2 guide](README.md) for a fresh installation. Wait for the
migration lane's installed-service evidence before replacing this outline
with commands.
