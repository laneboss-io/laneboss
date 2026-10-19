# First-install publication handoff

This change adds an explicit protected import; it supplies no production
policy, source, task or profile defaults. The exact installer field/file map
and two-phase installation sequence are in the v2-admin README.

Admin owns the root-only helper modes, immutable installed document loader,
native channel capability, exact input inventory and durable read-back.
PublishInitial requires the actual administrator frame; it does not accept a
public RPC method, a service Actor label or a client-supplied transaction.

The policy owner entry is ValidateInitial. It calls the ordinary validatePolicy
and policyDigest functions and rejects defaults, later generations and asserted
capture-refusal approval. The resolve.go bytes and four grants manifest source
files are restored unchanged from reference revision 741c464 because this base
had stubs for those owners. The grants manifest Root/Object validators validate
inert document structure and exact source-tree closure. They issue no grants.

The templates owner entry is ValidateInitialSources. It validates a fresh
OrgSnapshot, immutable resource pins and source provenance. The import retains
an explicit L5 prompt/driver selection and source manifest. Rendering and
normal role-dependent TemplateSources resolution still belong to templates.

The service/store entries are Server.PublishInitialFrame, Server.PublishInitial
and store.Service.CommitInitial. The latter guards the sealed private
transaction and delegates to the actual Transact. The transaction carries an
empty-org compare and atomically writes the objects, snapshot, policy, marker
and initial event. Read-back must match all of them before returning a receipt.

Admin's own ServeEnrollment dispatch already routes initial_publish. The
composed service uses its separate listener and must add that fixed-method
branch calling PublishInitialFrame with its actual Connection and Frame.
This base retains service/store stubs; no installed listener or SQLite success
is claimed. The service owner must compose that branch and run the real
installed first import, identical retry and restart read-back on Linux.

The root-grant document only retains explicit capability selections. The
protected grants resolver, native credential projections, materialization
service/store ports and templates rendering remain their existing owner gates.
This import does not fabricate those capabilities or launch an agent.

All previous mutation rows are retained. The four new rows nominate exact
component assertions for duplicate submission, semantic policy validation,
durable event binding and the empty baseline. Static vet only compiles those
tests; Linux must still demonstrate their specified red and candidate outcomes.
