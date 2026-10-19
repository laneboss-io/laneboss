# Policy contract note

The current owner requests and draft.4 integration requirements are maintained
in [CONTRACT-GAPS.md](CONTRACT-GAPS.md). The draft.3 note below is retained as
history; use the current note for implementation and acceptance decisions.

# Remaining draft.3 policy integration gaps

This note distinguishes missing contracts from missing implementations/wiring.
No shared API, dispatcher or composition source is changed by the policy lane.
The observations below come from source inspection; runtime effects have not
been measured by the authoring Mac.

1. **Defining warning threshold.** api.Thresholds still has only Match,
   UncertainLow, UncertainHigh and CalibrationID. Add an explicit Warn scalar
   to that shared type and its tagged field map, with defining-source fallback
   and calibration semantics. Policy's retained initial cutoff remains 0.50;
   uncertainty bounds cannot stand in for a warning threshold. Consumers are
   policy, the canonical source loader/store, judge calibration, templates,
   approval render/validation, dashboard and E2E fixtures.

2. **Complete typed configuration projection.** ConfigProjection now defines
   the result object, but StateStore/OrgStore has no context-aware normalized
   read returning it. OrgSnapshot provides approved raw source/derived files;
   ResourceFile.Kind does not define the setting/role/plugin/channel parse and
   merge schema. Add a canonical internal read, for example ConfigProjection
   taking Scope, ConfigReadRequest and an exact OrgSnapshotRef, or explicitly
   assign an existing canonical loader to this operation. It must return the
   screened typed values, defining sources, full catalogs and approved config
   generation without host-state paths or environment discovery. list/path
   are implemented from approved metadata; show/settings/roles/channels/plugins
   remain typed not_implemented. Consumers are policy, store/source loader,
   templates, approval/dataworker, dashboard, CLI and E2E.

3. **Retention emitter and read causality.** Section 14's InternalObjectRetain
   emitter catalog lists templates, judge, grants/dataworker and records, but
   omits policy. Policy owns protected policy-input objects on empty-rule,
   cache, skip and inference paths, plus ConfigProjection outputs on a read.
   Clarify authorization for the explicit lb-v2-policy service component under
   the existing RetainObject port, or supply a sanctioned scoped retention
   capability. Keep original requester/config/life/operation ACLs and actual
   metadata/read-back; never impersonate another emitter. For ConfigRead also
   define the trusted internal retention cause for a public read that has no
   reserved mutation operation, including metadata/read-back visibility with
   that handler's pinned ReadView. A precommitted projection read port avoids
   creating an object after the read snapshot. The code submits structured policy
   intent and propagates a store refusal; its fixture's acceptance does not
   prove the production emitter gate. Consumers are policy, store/service,
   identity/authorization, records/judge and assembly.

Draft.3 resolved the earlier object-port and atomic result-mapping requests:
ObjectStore.RetainObject/ObjectMetadata and Transaction.Reply/Commit.Reply are
used directly. Human target policy reads/evaluation use BriefingInput without
changing the human principal. OrgSnapshot supplies the distinct validation
generation; ValidateSources can bind TemplatesAPI.OrgValidate. That last item
is remaining composition wiring, not a request for another validation RPC.

**Historical CLI note, superseded by the review follow-up.** The common
--request branch returns after InvokeRaw without HookOutcome. Installed hooks
now use --command-file, and the worker keeps the real deny exit assertion.
The current exact-file outcome seam, emitter and assembly requests are in
CONTRACT-GAPS.md. No out-of-scope dispatcher edit or native runtime claim is
made by this historical note.
