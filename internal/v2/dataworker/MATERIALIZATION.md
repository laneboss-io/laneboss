# Fixed materialization worker

The dataworker library consumes fix-11 MaterializationControl; it does not claim
or launch the child effect itself. The service/store/outbox owns the one durable
stage under PlanLaunch. Admin owns held roots and fixed namespace projection;
identity/transport owns native worker bootstrap and every-frame authorization.
Missing owner implementations return their actual typed errors.

The service prepares in this order:

1. Under the current parent claim/CAS/epoch, issue distinct stage, child effect,
   worker lease and narrow grant IDs once. Use MaterializationGrants with those
   issued IDs and an expiry within the source/set/worker lease ceilings. The job
   has one bind_ro, nondelegable /job/source grant and no credentials, profiles,
   network, channels or resources. The result still names the agent grant set.
2. Open the actual helper storage projection. Retain the inert output tree
   manifest candidate with private original-operation provenance. Its content
   is the authorized tree with service-retained artifact refs; possessing this
   candidate is not evidence of copying or read-back.
3. Use EncodeMaterializationInput. This fixed worker's private opaque body is
   schema laneboss.materialize-input.v2 with stage_id, reservation, source,
   storage, grants, output and budget. Nested values use the shared Go types;
   callers use the encoder instead of inventing another wire field map. No host
   path, executable selector or agent credential enters this body.
4. Retain exact canonical bytes as materialize_input; assign that BlobRef to
   WorkerLease.Input and WorkerPlan.Input, and the exact plan to the child effect.
   Retain LaunchPlanRecord.DataStageID. ValidateLaunchDataStage must succeed
   after final hashes/claims are assigned and before actual worker launch.
5. Launch through the genuine helper/identity/permit path, distinct worker UID
   and containment, with the installed laneboss artifact and exact argv:
   laneboss internal worker --binding /runtime/laneboss-worker.json --lease ID.

RunInternal uses that fixed grammar and the actual private client. OpenWorker
obtains the principal over the native credential-pinned endpoint and matches
the exact sealed binding/lease. The entry reads the inherited sealed input at
/runtime/laneboss-worker-input.json, checks its exact length/hash/class against
that principal, and requires the authenticated WorkerInput response to contain
identical bytes, including whitespace. There is no alternate public RPC,
environment identity, input-authorable principal or fabricated native bridge.
For materialization, it validates the input before opening the three fixed
projections through the shared no-link descriptor walk. Each root must have
the helper's exact device/inode, worker UID/GID and private mode. It constructs
os.Root through the retained /proc/self/fd pin and checks its identity again.
Those owned roots and the connection's scoped object reader then reach
RunInternalJob and RunMaterialization. Every exit closes the roots and connection.
The in-process MaterializationJob bundle is not serialized authority. The
worker's roots correspond only to /job/source, /job/workspace and /job/home;
only the native entry opens those fixed projections in its confined namespace.

The job validates actual WorkerInput envelope bytes, stage/lease/cause and its
own zero-level worker principal. It compares held root identities and rejects
shared or nonprivate destinations. Narrow grants must have the exact parent,
generation and distinct member ID, live set/member expiries, and member-to-set
and set-to-worker-lease ceilings. These limits are rechecked before result
acknowledgement, including when a narrower grant expires during copying.

Tree copy uses only granted manifest paths, descriptor-relative opens from the
held os.Root with O_NOFOLLOW/O_NONBLOCK on every component, source
pre-open/opened identity/device/link checks, bounded
streamed content/assembly hashes and exclusive destination creation. It never
executes source content. Linux uses the same fdpath walk as the helper, including
NO_XDEV mount IDs on the fallback route; a same-device bind mount is not a child
of the held root. Darwin retains its separate portable walk and native refusal.
An explicit `.` directory entry in either manifest
must declare mode 0700; any other root mode returns a typed invalid error before
copying. An omitted root retains the held directory's required 0700 mode.
It independently walks and hashes destination files using nonfollowing
directory opens, rejects missing/extra entries and checks modes/links. Directory
permission handoff compares Lstat and opened identities before Chmod. Vendor
home components are created exclusively through held parent descriptors, then
the whole home is walked for exact 0700 directories and no extra entries.
A changed byte, wrong root, external link or raced destination refuses
before a usable acknowledgement. Partial files remain for owner reconciliation.

The job submits exact JCS LaunchData and validates the actual WorkerResultReceipt.
This receipt proves acknowledgement only. The outside owner must independently
observe the retained process exited/zero survivors and read back the projection.
Only committed measured completion may satisfy AwaitMaterialization. The library
validates that result, exact acknowledged bytes and immutable manifest bytes,
compares both output manifest references with the stored granted source tree, verifies
every distinct output content ref's exact committed artifact metadata,
then rechecks current authority/storage/enrollment. A completed stage's historical
claim is not new execution authority; replay reads the same receipt/data and
never runs the copy again.

Reachable Git is explicitly unsupported until admin provides the protected
granted Git export and pinned runtime. No ambient executable, shared object DB
or synthesized Git result is substituted. Additional agent data views need their
own authorized projections. Legacy generic Materialize/Render/Archive and
review/channel execution retain their separate documented boundaries.
Native TestChild now receives the original scoped/proof handoff through the
private testjob.Call. The installed coordinator atomically admits its single
test lease/effect. The trusted confined wrapper copies the exact candidate,
verifies the enrolled executable, runs the actual plan argv, measures both
output pipe identities and captures bounded stdout/stderr and the real exit.
Authenticated result acknowledgement does not complete the job: the native
helper must independently measure known-zero retirement before the writer
publishes the frozen check, capture ranges/EOFs and worker/release events.

The Linux fixture uses actual private files and bootstrap/result bytes. Native
worker/process/claim facts are synthetic and are never installed acceptance.
Mac verification is static only. Every catalog control needs its named reached
assertion followed by the same candidate pass on the authorized Linux machine.
The shared ReadBackSHA256 equality still describes reference consistency;
the separately encoded outside observation remains an API/service owner gap.

Materialization temporarily lends workspace/home ownership and the parent
traversal group to its distinct worker UID; history stays with the agent.
Retries resume the exact retained LaunchDataStage and held projection during
that loan. They do not first invoke the ordinary agent-owned storage resolver.
After the measured child returns those roots, that unchanged resolver checks
all original agent owners, modes and inodes, and its complete binding must
match the stage. Initial opening still validates the agent allocation inside
the helper before lending it. No foreign UID is accepted by the agent guard.

An unpublished preparation can resume its original prepared/gate IDs only when
the nested gate retains the new reserved marker and the journal records no
PID, process generation, permit, identity or result;
the original descriptors remain held; native cgroup and UID inventory show
quiescence; and both destinations are still empty. A live UID, published gate,
lost pin, changed inode or uncertain output refuses. Immediately before native
creation the helper durably advances that marker to preparing; both legacy
preparing records and crossed-barrier attempts remain uncertain, even with a
zero PID. The process-local barrier cannot be supplied through wire input.
Preparation failures now
retain fixed gate_prepare/cgroup_open diagnostics rather than only operation.

TestMaterializationBorrowedStorageRetry exercises the actual dataworker's
deferred-stage ordering and final storage refusal/binding controls.
TestDataPrepareStorageRetry runs with laneboss_root_canary and
laneboss_gate_integration on disposable Linux root. It retains two actual UID
slots, causes a pre-spawn containment refusal, repairs that original native
prerequisite, proves a real live worker UID blocks retry, then resumes the same
lease/token/gate. It executes the fixed dataworker copy in a separate process
under the reserved worker UID/cgroup and uses the production returnData walk
to verify all three agent directories return to their original lease owner.
Its bootstrap/result metadata are explicit fixtures; it does not claim the
complete installed service's identity and result-commit protocol.
