# Draft.4 fix 27 source comparison

Compared base f5736f7 with the pinned serve2
revision 6cd128f. The comparison covers every
Git tree entry in the five requested subtrees, including files absent in one
tree. Identical files were compared by Git blob and mode; changed production
hunks were inspected. Credential feature files are retained, not adopted.

There are 294 compared paths: 9 taken, 249 already equal and 36 not taken.
Taken can mean selected correctness hunks; the reason states each local choice.
The required marker DTO in internal/v2/api/sources.go is one additional adopted
dependency outside those subtrees. The three new local test files are listed
in D4FIX27-REPORT.md. No harness, E2E driver, credential/read-session feature or
other-lane feature tree was copied.

| File | Decision | Reason |
| --- | --- | --- |
| internal/v2/admin/CONTRACT-GAPS.md | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/FIX11-STATUS.md | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/FIX13-STATUS.md | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/FIX14-STATUS.md | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/FIX15-STATUS.md | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/FIX16-STATUS.md | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/FIX17.md | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/FIX9-STATUS.md | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/GATE-NOTES.md | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/INTEGRATION.md | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/REVIEW-FIXES.md | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/abort.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/abort_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/acceptance_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/binding.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/bootstrap_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/capture_io_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/capture_io_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/capture_plan_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / admin / capture_reconcile_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/client_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/collection_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/containment_linux.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / admin / containment_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/containment_types.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/contract_stubs.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / admin / credential_gate_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/credential_stubs.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/data.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/data_access.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/data_ctl.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/data_gc_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/data_identity.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/data_identity_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/data_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/data_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/data_other.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/data_tree.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/doctor.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/doctor_probe.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/doctor_probe_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/doctor_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/enroll_commit.go | not taken | Reference removes the newer complete-read view; retain the reviewed local view binding. |
| internal/v2/admin/enroll_interface_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/enroll_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/enroll_reply.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/enrollment_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/enrollment_types.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/files_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/fix15_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/fix15_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/gate.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/gate_control.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / admin / gate_installed_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/gate_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/gate_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/helper_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/human_enrollment.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / admin / human_enrollment_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / admin / human_enrollment_other.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / admin / human_enrollment_release_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/human_enrollment_test.go | not taken | Credential/enrollment feature test excluded by the brief; no service/store production fix to adopt. |
| internal/v2/admin/initial.go | taken | Took the shared marker DTO at emission/matching only; retained local validators and omitted timing instrumentation. |
| internal/v2/admin/initial_commit.go | not taken | Reference differences are optional timing instrumentation and wrapper names; retain the reviewed merged-name view implementation. |
| internal/v2/admin/initial_fixture_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/initial_inventory.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/initial_linux.go | taken | Took endpoint socket identity and wire.VerifyAdministrator native verification; omitted optional timing wrappers. |
| internal/v2/admin/initial_other.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/initial_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/initial_timing.go | not taken | Optional timing sink/instrumentation; no installed correctness change required by these findings. |
| internal/v2/admin/initial_view_test.go | not taken | Absent in reference; retain the local view/lifetime regression. |
| internal/v2/admin/internal.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/ipc.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/journal.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/journal_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/journal_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/launch_authority.go | not taken | Reference removes the newer complete-read view; retain the reviewed local view binding. |
| internal/v2/admin/launch_capture.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/launch_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/launch_plan_stubs.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/launch_sources.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/launch_storage.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/lease.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/lease_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/module_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/network.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/network_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/open.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/open_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/peer_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/peer_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/platform_other.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/private_dir_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/probe_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/recovery_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/recovery_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/relay_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/relay_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/release.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/release_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/resources_linux.go | taken | Took the complete file: protected control cgroup gets exactly 0755 after the restrictive umask. |
| internal / v2 / admin / restrictions_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/review_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/revoke_damaged_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/revoke_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/runtime_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/runtime_resolve.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/socket_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/spec.go | not taken | Reference removes the newer complete-read view; retain the reviewed local view binding. |
| internal/v2/admin/spec_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/storage_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/storage_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/store_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/stub.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/tree_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/validation.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/wire.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/admin/worker_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/client/wire/admin_darwin.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/client/wire/admin_linux.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / client / wire / admin_unit_linux_test.go | not taken | Absent in reference; retain the local fixed-unit membership controls. |
| internal/v2/client/wire/binding.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/client/wire/credentials.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / client / wire / credentials_darwin.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / client / wire / credentials_linux.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / client / wire / credentials_linux_test.go | not taken | Reference adds component membership tests; retain the existing native writer tests and local TestAdminMembership controls. |
| internal/v2/client/wire/enroll_json.go | not taken | Reference places the same helpers in json.go; retain the separate local file and avoid duplicate declarations. |
| internal/v2/client/wire/fd_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/client/wire/frame.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/client/wire/json.go | not taken | Reference only adds the helper definitions already present in enroll_json.go; no missing production behavior. |
| internal/v2/client/wire/json_test.go | not taken | Reference adds component codec coverage; no new installed production delta, and existing strict/native frame controls remain. |
| internal / v2 / client / wire / materialization_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / client / wire / operation_event_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/client/wire/schema.go | taken | Took the complete file: strict initial-publication marker event decoding with configuration/event/operation binding. |
| internal/v2/client/wire/service_input.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/client/wire/visibility.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/client/wire/visibility_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / admission_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / admission_retry_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/authentication.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/build_auth_regular.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/build_authenticator.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/build_faults.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/build_regular.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/capture.go | taken | Took the complete file: authenticated capture recheck uses the bounded current-connection adapter. |
| internal/v2/service/commit.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/connection.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / connection_refusal_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/connection_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / contract12_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/contract_stubs.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/data_error.go | not taken | Absent in reference; retain the newer typed interruption normalization. |
| internal/v2/service/data_error_test.go | not taken | Absent in reference; retain successful-read/integrity/context regression controls. |
| internal/v2/service/dispatch.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/dispatch_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/dispatch_mutation.go | taken | Took the complete file: pre-reply authentication uses the bounded current-connection adapter. |
| internal/v2/service/dispatch_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/effect_retry.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / enroll_wire_linux_test.go | not taken | Absent in reference; retain local strict dispatch, refusal, expired-write and reply-bound controls. |
| internal/v2/service/enrollment.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/enrollment_listener.go | not taken | Reference inlines the dispatcher and drops the reply size guard; retain the reviewed local dispatcher and bounded fallback. |
| internal/v2/service/fix11_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/fix11_stubs.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/health.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/host.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/host_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/initial.go | not taken | Reference adds timing diagnostics only; retain the native publication entry without an optional diagnostic sink. |
| internal/v2/service/input_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/launch_control.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/launch_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/launch_recovery.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/listener_darwin.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/listener_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/materialization.go | not taken | Reference removes the newer caller/fixed-wait interruption normalization; retain the reviewed local implementation. |
| internal / v2 / service / materialization_linux_test.go | not taken | Reference removes exact retained-input checks around deadline/cancellation; retain those checks. |
| internal/v2/service/mutation_owner.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/owner_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / public_health_linux_test.go | not taken | Reference adds enrollment refusal/journal component tests; retain existing health tests and local native refusal coverage; this is not a missing installed production fix. |
| internal/v2/service/queue.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/queue_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/reconcile.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / reconcile_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/recovery_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/refresh_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/review_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/revocation.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/server.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/server_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/socket_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/stream.go | taken | Took the complete file: per-frame authentication uses the bounded current-connection adapter. |
| internal/v2/service/stub.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / variant_auth_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / variant_both_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / variant_faults_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / variant_normal_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/service/worker_listener.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / worker_listener_darwin.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / service / worker_listener_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/atomic_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/atomic_support.go | not taken | Reference removes failed-read context normalization; retain it. |
| internal/v2/store/authority.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/capture.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/capture_policy.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / challenge_generation_linux_test.go | not taken | Credential challenge-generation feature test belongs to the identity integration excluded by the brief. |
| internal/v2/store/channel_stubs.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/continuation_claim.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/contract_stubs.go | taken | Took the complete file: protected OrgSnapshot reads replace the stub and check configuration/generation. |
| internal/v2/store/credential_stubs.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/current_policy.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / current_policy_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/dispatch.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/dispatch_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/effect_state.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / effect_state_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/effects.go | not taken | Reference removes failed-read context normalization; retain it. |
| internal/v2/store/emitter_catalog.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/enroll_frame_test.go | not taken | Absent in reference; retain strict frame/parameter binding regression. |
| internal/v2/store/enrollment.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/enrollment_ceremony.go | not taken | Reference removes the private strict parser and still omits replay frame binding; retain the parser and add the requested replay guard locally. |
| internal/v2/store/enrollment_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/fd_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / fix11_capture_policy_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / fix11_enrollment_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / fix11_guidance_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / fix11_launch_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / fix11_policy_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / fix11_presence_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / fix11_session_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/fix11_stubs.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / fixture_regression_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / gate_policy_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/guidance.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/guidance_recovery.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/health.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/human_policy.go | not taken | New identity/read-session capability depends on api.HumanPolicySource and identity/session integration absent from this base; excluded other-lane feature, not adopted piecemeal. |
| internal/v2/store/identity_writes.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/initial.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/internal.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/launch_ceiling.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/launch_control.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / launch_delta_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/launch_fences.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / launch_identity_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/launch_issuance.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/launch_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/launch_plan.go | not taken | Reference restores the failed-query/byte-mismatch conflation; retain checkLaunchReceipt. |
| internal/v2/store/launch_receipt.go | not taken | Absent in reference; retain the exact-byte gate with preserved SQL/context causes. |
| internal / v2 / store / launch_receipt_linux_test.go | not taken | Absent in reference; retain actual SQL-boundary and byte-gate controls. |
| internal/v2/store/launch_reservation.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/launch_revalidation.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/list.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/materialization.go | not taken | Reference restores context masking and allocation forbidden masking; retain reviewed local errors. |
| internal / v2 / store / materialization_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / materialization_scope_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / materialization_verify.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/natural_completion.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / object_cache_linux_test.go | not taken | Absent in reference; retain private-load, cache bounds and eviction controls. |
| internal/v2/store/object_read.go | not taken | Reference drops visibility-before-load and retained-cache limits; retain the reviewed bounded cache. |
| internal / v2 / store / object_read_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/objects.go | not taken | Reference removes failed-read context normalization; retain it. |
| internal/v2/store/owner_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/plan_cleanup.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / plan_cleanup_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/policy_generation.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/presence.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / presence_release_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / presence_tagged_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/projection_reads.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/read.go | taken | Took the complete file: internal configuration-event selection, SQL selection and post-read filtering. |
| internal/v2/store/read_session.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / receipt_integrity_linux_test.go | not taken | Absent in reference; retain actual LaunchPlan receipt-byte corruption control. |
| internal/v2/store/receipts.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/reservation_recovery.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / reservation_recovery_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/review_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/revocation.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/scope_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/snapshot.go | not taken | Reference removes the cache byte counter; retain bounded-cache accounting. |
| internal/v2/store/sql_read_linux_test.go | not taken | Absent in reference; retain real SQL cause and successful-read controls. |
| internal/v2/store/store.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/store_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / testfx / launch_linux.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / testfx / materialization_linux.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/transaction.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/turn_identity.go | already equal | Identical Git blob and mode; retained. |
| internal / v2 / store / turn_identity_linux_test.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/verify.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/verify_atomic.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/verify_launch.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/worker_bootstrap.go | already equal | Identical Git blob and mode; retained. |
| internal/v2/store/worker_objects.go | already equal | Identical Git blob and mode; retained. |
| packaging/v2/linux/laneboss-bwrap.apparmor | already equal | Identical Git blob and mode; retained. |
| packaging/v2/linux/laneboss-helper.service.in | already equal | Identical Git blob and mode; retained. |
| packaging/v2/linux/laneboss-service.service.in | already equal | Identical Git blob and mode; retained. |

| Additional file | Decision | Reason |
| --- | --- | --- |
| internal/v2/api/sources.go | taken | Required shared DTO for the existing initial marker payload used by the adopted wire validator; no identity/credential API feature was copied. |
