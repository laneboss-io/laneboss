"""Linux component mutation checks; never credits installed SERVE-STATE."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys


PACKAGES = {
    "wire": "./internal/v2/client/wire",
    "client": "./internal/v2/client",
    "service": "./internal/v2/service",
    "store": "./internal/v2/store",
    "cli": "./internal/v2/cli",
    "admin": "./internal/v2/admin",
    "identity": "./internal/v2/identity",
}
# Keep every mutation target; package dependencies come from Go, not this list.
ROOTS = ["internal/v2"]
VARIANTS = [("normal", []), ("faults", ["-tags", "laneboss_faults"])]
# Full race-instrumented package suites exceeded 90 seconds as coverage grew.
# Tests and mutants share a ten-minute bound; the parent allows bounded cleanup.
TEST_TIMEOUT = "10m"
TEST_PROCESS_TIMEOUT_SECONDS = 660
PACKAGE_FILES = (
    "GoFiles", "CgoFiles", "TestGoFiles", "XTestGoFiles",
    "CFiles", "CXXFiles", "MFiles", "HFiles", "FFiles", "SFiles",
    "SwigFiles", "SwigCXXFiles", "SysoFiles",
    "EmbedFiles", "TestEmbedFiles", "XTestEmbedFiles",
)
STEP = {"variant": "setup", "mutation": "none", "stage": "inputs", "exit": None}
LAST_FAILURE = None


def step(**fields):
    STEP.update(fields)


def failure_diagnostic(output):
    limit = 12000
    if len(output) <= limit:
        return output
    lines = output.splitlines(keepends=True)
    failed = [i for i, line in enumerate(lines)
              if re.match(r"^[ \t]*--- FAIL: |^FAIL(?:[ \t\r\n]|$)", line)]
    if not failed:
        return output[-limit:]
    # Verbose Go assertions precede their FAIL header; nonverbose assertions
    # follow it. Retain both sides before the tail can displace an early failure.
    context = set()
    for index in failed:
        context.update(range(max(0, index - 8), min(len(lines), index + 9)))
    context.difference_update(failed)
    excerpt = ("FAIL lines (bounded; complete output is in the retained log):\n" +
               "".join(lines[i] for i in failed)[:4000] +
               "\nFailure context (bounded):\n" +
               "".join(lines[i] for i in sorted(context))[:4000])
    separator = "\nOutput tail (bounded):\n"
    return excerpt + separator + output[-(limit - len(excerpt) - len(separator)):]


def failure(reason, output=""):
    global LAST_FAILURE
    if output:
        diagnostic = failure_diagnostic(output)
    elif LAST_FAILURE is not None and LAST_FAILURE["step"] == STEP:
        diagnostic = LAST_FAILURE["diagnostic"]
    else:
        diagnostic = str(reason)
    LAST_FAILURE = {"step": dict(STEP), "diagnostic": diagnostic}
    record = {"verdict": "fail", **STEP, "reason": str(reason),
              "diagnostic": diagnostic}
    print(json.dumps(record, sort_keys=True), flush=True)
    return record


def mutation(name, file, old, new, package, test, message, extra_edits=(), subtest=None):
    return {"id": name, "file": file, "edits": [(old, new), *extra_edits],
            "package": package, "test": test, "message": message, "subtest": subtest}


MUTATIONS = [
    mutation("completed-process-observation", "internal/v2/service/launch_control.go", "\tif !completed {\n", "\tif completed || !completed {\n", "service", "TestCompletedLaunchObservation", "completed launch lost read-only observation authority", subtest="running"),
    mutation("uncompleted-process-stage", "internal/v2/service/launch_control.go", "\tif !completed {\n", "\tif !completed && handle.ID == \"\" {\n", "service", "TestUncompletedObservationStillClaims", "uncompleted launch bypassed its stage claim"),
    mutation("process-live-run", "internal/v2/store/process_observation.go", "lane.Run != r.Target.Run || ", "", "service", "TestProcessObservationRunOwnership", "process observation accepted a foreign or stale run", subtest="stale_run"),
    mutation("process-live-launch", "internal/v2/store/process_observation.go", "lane.LaunchID != r.ID || ", "", "service", "TestProcessObservationRunOwnership", "process observation accepted a foreign or stale run", subtest="foreign_launch"),
    mutation("process-cleaned-run", "internal/v2/store/process_observation.go", " || lane.Cleaned", "", "service", "TestProcessObservationRunOwnership", "process observation accepted a foreign or stale run", subtest="cleaned"),
    mutation("process-current-owner", "internal/v2/store/process_observation.go", "if !sameValue(current, r) {", "if !sameValue(current, r) && current.ID != r.ID {", "service", "TestProcessObservationRunOwnership", "process observation accepted a foreign or stale run", subtest="launch_owner"),
    mutation("cleanup-missing-port", "internal/v2/service/host.go", "\t\t\t\treturn api.NotImplemented(\"lb-v2-admin\", \"installed protected cleanup native ports\")\n", "\t\t\t\treturn nil\n", "service", "TestCleanWithoutNativePort", "clean without native port escaped its installed refusal"),
    mutation("session-dispatch-finalize", "internal/v2/service/dispatch_mutation.go", "actual, err := finalizer.FinalizeHumanSession(ctx, scope)", "actual, err := retained, error(nil)", "service", "TestSessionDispatchFinalization", "successful session receipt bypassed connection finalization", subtest="new", extra_edits=[['finalizer, ok := s.deps.Authenticator.(humanSessionFinalizer)', '_, ok := s.deps.Authenticator.(humanSessionFinalizer)']]),
    mutation("session-dispatch-post-commit", "internal/v2/service/dispatch_mutation.go", '\t\t\t\tif request.Method == "human.session" {\n\t\t\t\t\t// A session can commit before its connection finalization fails.\n\t\t\t\t\t// Preserve that failure for this invocation; never reload the\n\t\t\t\t\t// successful durable receipt over it or retry the bind here.\n\t\t\t\t\tcommitted, lookupErr := s.deps.Store.LookupReceipt(ctx, scope, key)\n\t\t\t\t\tif lookupErr != nil {\n\t\t\t\t\t\treturn nil, scope, errors.Join(err, lookupErr)\n\t\t\t\t\t}\n\t\t\t\t\tif committed.Reply != nil && committed.Reply.Error == nil {\n\t\t\t\t\t\treturn nil, scope, err\n\t\t\t\t\t}\n\t\t\t\t}\n', "", "service", "TestSessionDispatchPostCommitError", "successful durable receipt masked the post-commit finalization error"),
    mutation("session-read-proof-use", "internal/v2/store/session_commit.go", "proof.ConsumedBy != receipt.Operation.ID ||", "", "store", "TestSessionCommitRefusals", "private session read accepted proof_used", subtest="proof_used"),
    mutation("session-read-raw-frame", "internal/v2/store/session_commit.go", " || !bytes.Equal(receipt.RawRequest, raw)", "", "store", "TestSessionCommitRefusals", "private session read accepted raw", subtest="raw", extra_edits=[[' || !bytes.Equal(retainedRaw, raw)', ""]]),
    mutation("enroll-shared-proof", "internal/v2/admin/enroll_native_linux.go", "\treturn wire.VerifyAdministrator(ctx, endpoint, c, frame)\n", "\treturn nil\n", "admin", "TestEnrollmentSharedVerifier", "enrollment lost shared administrator proof"),
    mutation("worker-entry-window", "internal/v2/service/worker_listener.go", "\t\tcallCtx := context.WithValue(ctx, authenticationReplyKey{}, closeWindow)\n", "\t\tcallCtx := ctx\n", "service", "TestWorkerRefusalFlush", "worker recheck lost its correlated refusal", subtest="entry"),
    mutation("worker-delivery-window", "internal/v2/service/worker_listener.go", "\t\tcallCtx := context.WithValue(ctx, authenticationReplyKey{}, closeWindow)\n", "\t\tcallCtx := ctx\n", "service", "TestWorkerRefusalFlush", "worker recheck lost its correlated refusal", subtest="delivery"),
    mutation("worker-later-window", "internal/v2/service/worker_listener.go", "\t\tcallCtx := context.WithValue(ctx, authenticationReplyKey{}, closeWindow)\n", "\t\tcallCtx := ctx\n", "service", "TestWorkerRefusalFlush", "worker recheck lost its correlated refusal", subtest="later"),
    mutation("stream-refusal-window", "internal/v2/service/stream.go", "\t\t\tcurrent, err := s.authenticateConnection(authCtx, scope.Connection)\n", "\t\t\tcurrent, err := s.authenticateConnection(streamCtx, scope.Connection)\n", "service", "TestStreamRefusalFlush", "stream recheck lost its terminal refusal", extra_edits=[["\t\t\tauthCtx := context.WithValue(streamCtx, authenticationReplyKey{}, closeWindow)\n",""]]),
    mutation("stream-refusal-close", "internal/v2/service/stream.go", "\t\t\t\tif closeWindow.closeRequested.Load() {\n\t\t\t\t\ts.closeResource(scope.Connection)\n\t\t\t\t}\n", "", "service", "TestStreamRefusalFlush", "stream recheck refusal did not close"),
    mutation("current-scope-rebind", "internal/v2/identity/service.go", "\tif nilDependency(connection.Peer()) {\n\t\treturn scope, refusal(api.CodeUnauthenticated, \"current connection requires its original verified peer\")\n\t}\n\treturn s.connectionScope(ctx, connection)\n", "\tif nilDependency(connection.Peer()) {\n\t\treturn scope, refusal(api.CodeUnauthenticated, \"current connection requires its original verified peer\")\n\t}\n\treturn s.Authenticate(ctx, connection)\n", "identity", "TestCurrentScopeRecheck", "bound scope recheck acquired or rebound a peer"),
    mutation("current-scope-close", "internal/v2/identity/service.go", "\tdefer func() {\n\t\tif resultErr != nil {\n\t\t\tresultErr = errors.Join(resultErr, connection.Close())\n\t\t}\n\t}()\n", "", "identity", "TestCurrentScopeRecheck", "failed current scope did not close its connection"),
    mutation("auth-close-transport", "internal/v2/service/authentication.go", "\treturn c.ConnectionContext.Close()\n", "\treturn nil\n", "service", "TestAuthClosePropagation", "authentication close did not reach the transport"),
    mutation("capture-auth-close", "internal/v2/service/authentication.go", "\treturn c.ConnectionContext.Close()\n", "\treturn nil\n", "service", "TestCaptureAuthClose", "failed capture authentication kept its transport open"),
    mutation("auth-bound-fallback", "internal/v2/service/authentication.go", "\t\t\terr = errors.Join(serviceError(api.CodePrerequisite, \"bound connection requires current-scope revalidation\"), entry.Close())", "\t\t\tscope, err = s.deps.Authenticator.Authenticate(ctx, entry)", "service", "TestBoundScopeRequiresPort", "bound connection attempted fresh authentication", extra_edits=[["\t\"errors\"\n",""]]),
    mutation("cgroup-read-mode", "internal/v2/admin/cgroup_mode_linux.go", "os.Chmod(path, 0755)", "os.Chmod(path, 0700)", "admin", "TestCgroupReadMode", "cgroup facts lost exact read-only traversal mode", subtest="lanes"),
    mutation("cgroup-mode-wide", "internal/v2/admin/cgroup_mode_linux.go", "os.Chmod(path, 0755)", "os.Chmod(path, 0777)", "admin", "TestCgroupReadMode", "cgroup facts lost exact read-only traversal mode", subtest="lanes"),
    mutation("config-events-internal", "internal/v2/store/read.go", "configurationEvents := request.LifeID == \"\" && request.Run == 0 && internalScope(scope)", "configurationEvents := false", "store", "TestConfigurationEvents", "internal configuration event read was refused or changed"),
    mutation("config-events-public", "internal/v2/store/read.go", "configurationEvents := request.LifeID == \"\" && request.Run == 0 && internalScope(scope)", "configurationEvents := request.LifeID == \"\" && request.Run == 0", "store", "TestConfigurationEvents", "public event reader acquired configuration selection"),
    mutation("config-events-query", "internal/v2/store/read.go", "coalesce(json_extract(data,'$.life_id'),'')=? AND coalesce(json_extract(data,'$.run'),0)=?", "(? IS NOT NULL AND ? IS NOT NULL)", "store", "TestConfigurationEvents", "internal configuration event read was refused or changed"),
    mutation("org-snapshot-generation", "internal/v2/store/contract_stubs.go", "\tif result.Ref.Generation != request.Generation {\n\t\treturn api.OrgSnapshot{}, fault(api.CodeConflict, \"current org snapshot generation differs from the requested publication\")\n\t}\n", "", "store", "TestOrgSnapshotRead", "org snapshot accepted a foreign selection", subtest="generation"),
    mutation("org-snapshot-config", "internal/v2/store/contract_stubs.go", "\tif result.Config != s.deps.Config || result.Ref.OrgID != request.OrgID {\n\t\treturn api.OrgSnapshot{}, fault(api.CodeIntegrity, \"retained org snapshot differs from its configuration\")\n\t}\n", "", "store", "TestOrgSnapshotRead", "org snapshot accepted a foreign selection", subtest="config"),
    mutation("org-snapshot-stub", "internal/v2/store/contract_stubs.go", "result, err := scopedProjection[api.OrgSnapshot](ctx, s, scope, \"org\", request.OrgID)", "result, err := api.OrgSnapshot{}, api.NotImplemented(\"lb-v2-service\", \"store.OrgSnapshot\")", "store", "TestOrgSnapshotRead", "published org snapshot did not read back"),
    mutation("enrollment-replay-params", "internal/v2/store/enrollment_ceremony.go", "\tif err := checkEnrollmentFrame(raw, *s.deps.Enrollment, request); err != nil {\n\t\treturn result, err\n\t}\n", "", "store", "TestEnrollmentReplayFrame", "replay accepted an unrelated administrator frame", subtest="params"),
    mutation("enrollment-replay-method", "internal/v2/store/enrollment_ceremony.go", "\tif err := checkEnrollmentFrame(raw, *s.deps.Enrollment, request); err != nil {\n\t\treturn result, err\n\t}\n", "", "store", "TestEnrollmentReplayFrame", "replay accepted an unrelated administrator frame", subtest="method"),
    mutation("initial-event-schema", "internal/v2/client/wire/schema.go", "if event.Kind == \"org.bootstrapped\" {", "if event.Kind == \"org.bootstrapped\" && false {", "wire", "TestInitialMarkerEvent", "exact initial marker event was refused"),
    mutation("initial-event-config", "internal/v2/client/wire/schema.go", "marker.Config != event.Config ||\n\t\t\t\t", "", "wire", "TestInitialMarkerEvent", "initial marker event lost its closed binding", subtest="config"),
    mutation("initial-event-operation", "internal/v2/client/wire/schema.go", "event.OperationID != api.ID(\"initial-op-\"+string(marker.ID)) || ", "", "wire", "TestInitialMarkerEvent", "initial marker event lost its closed binding", subtest="operation"),
    mutation("sql-success-context", "internal/v2/store/objects.go", "\tif observe, ok := ctx.Value(objectVerificationKey{}).(func(api.ID, int64)); ok {\n\t\tobserve(id, int64(len(data)))\n\t}\n", "\tif observe, ok := ctx.Value(objectVerificationKey{}).(func(api.ID, int64)); ok {\n\t\tobserve(id, int64(len(data)))\n\t}\n\tif cause := ctx.Err(); cause != nil { return metadata, nil, cause }\n", "store", "TestSQLSuccessAfterCancel", "successful SQL read was replaced by context expiry"),
    mutation("enroll-reply-bound", "internal/v2/service/enrollment_listener.go", "\tif encodeErr == nil && len(data) > api.MaxFrameBytes {\n\t\tencodeErr = serviceError(api.CodeIntegrity, \"administrator enrollment response exceeds its frame bound\")\n\t}\n", "", "service", "TestEnrollmentReplyBound", "administrator reply exceeded its bound"),
    mutation("sql-context-parent", "internal/v2/store/materialization.go", "\tif err != nil {\n\t\tif cause := ctx.Err(); cause != nil {\n\t\t\treturn api.EffectLease{}, cause\n\t\t}\n\t}\n", "", "store", "TestSQLReadCauses", "failed SQL read lost its context cause", subtest="parent/cancelled"),
    mutation("sql-context-budget", "internal/v2/store/materialization.go", "\t\tif cause := ctx.Err(); cause != nil {\n\t\t\treturn api.Budget{}, cause\n\t\t}\n", "", "store", "TestSQLReadCauses", "failed SQL read lost its context cause", subtest="budget/cancelled"),
    mutation("enroll-refusal-reply", "internal/v2/service/enrollment_listener.go", "\ts.writeEnrollmentReply(connection, response, field, err)\n", "\tif err == nil { s.writeEnrollmentReply(connection, response, field, err) }\n", "service", "TestEnrollmentReplies", "administrator refusal reply was silent", subtest="old_frame"),
    mutation("enroll-initial-dispatch", "internal/v2/service/enrollment_listener.go", "case \"initial_publish\":", "case \"initial_disabled\":", "service", "TestEnrollmentDispatch", "administrator method did not reach its typed decoder"),
    mutation("enroll-expired-reply", "internal/v2/service/enrollment_listener.go", "connection.SetWriteDeadline(time.Now().Add(time.Second))", "connection.SetWriteDeadline(time.Now().Add(-time.Second))", "service", "TestEnrollmentExpiredWrite", "expired read deadline made the refusal silent"),
    mutation("enroll-frame-params", "internal/v2/store/enrollment_ceremony.go", "frame.Method != \"enroll_complete\" || !wire.SameJSON(exact, frame.Params)", "frame.Method != \"enroll_complete\" || len(exact) == 0", "store", "TestEnrollmentFrameBinding", "enrollment retained a foreign frame", subtest="params"),
    mutation("admin-helper-unit", "internal/v2/client/wire/admin_linux.go", "line != \"0::\"+expected", "len(expected) == 0", "wire", "TestAdminMembership", "administrator accepted foreign helper membership", subtest="unit"),
    mutation("admin-helper-sole", "internal/v2/client/wire/admin_linux.go", "len(processes) != 1 || processes[0] != strconv.Itoa(pid)", "len(processes) < 1 || processes[0] != strconv.Itoa(pid)", "wire", "TestAdminMembership", "administrator accepted foreign helper membership", subtest="shared"),
    mutation("initial-object-view", "internal/v2/admin/initial_commit.go", "func initialReadBytes(ctx context.Context, store api.StateStore, scope api.Scope, ref api.BlobRef) (result []byte, resultErr error) {\n\tscope, release, err := objectread.Bind(ctx, store, scope)", "func initialReadBytes(ctx context.Context, store api.StateStore, scope api.Scope, ref api.BlobRef) (result []byte, resultErr error) {\n\tscope, release, err := objectread.Bind(ctx, struct{}{}, scope)", "admin", "TestInitialReadView", "initial chunks did not share a released view"),
    mutation("initial-snapshot-view", "internal/v2/admin/initial_commit.go", "\tvar empty InitialReceipt\n\tscope, release, err := objectread.Bind(ctx, store, scope)", "\tvar empty InitialReceipt\n\tscope, release, err := objectread.Bind(ctx, struct{}{}, scope)", "admin", "TestInitialSnapshotView", "initial read-back did not share one view"),
    mutation("sql-context-projection", "internal/v2/store/atomic_support.go", "\tif err != nil {\n\t\tif cause := ctx.Err(); cause != nil {\n\t\t\treturn cause\n\t\t}\n\t}\n", "", "store", "TestSQLReadCauses", "failed SQL read lost its context cause", subtest="projection/cancelled"),
    mutation("sql-context-object", "internal/v2/store/objects.go", "\tif err != nil {\n\t\tif cause := ctx.Err(); cause != nil {\n\t\t\treturn metadata, nil, cause\n\t\t}\n\t}\n", "", "store", "TestSQLReadCauses", "failed SQL read lost its context cause", subtest="object/cancelled"),
    mutation("sql-context-effect", "internal/v2/store/effects.go", "\tif err != nil {\n\t\tif cause := ctx.Err(); cause != nil {\n\t\t\treturn record, cause\n\t\t}\n\t}\n", "", "store", "TestSQLReadCauses", "failed SQL read lost its context cause", subtest="effect/cancelled"),
    mutation("sql-context-allocation", "internal/v2/store/materialization.go", "\t\tif cause := ctx.Err(); cause != nil {\n\t\t\treturn api.HelperLease{}, cause\n\t\t}\n", "", "store", "TestSQLReadCauses", "failed SQL read lost its context cause", subtest="allocation/cancelled"),
    mutation("sql-allocation-error", "internal/v2/store/materialization.go", "\t\treturn api.HelperLease{}, err\n\t}\n\tvar record api.EffectRecord", "\t\treturn api.HelperLease{}, fault(api.CodeForbidden, \"materialization has no completed agent allocation\")\n\t}\n\tvar record api.EffectRecord", "store", "TestSQLReadCauses", "SQL read failure was relabeled as authority", subtest="allocation"),
    mutation("materialize-context", "internal/v2/service/data_error.go", "\tif cause := ctx.Err(); cause != nil {\n\t\treturn contextError(cause)\n\t}\n", "", "service", "TestMaterializeErrors", "materialization lost the interrupted context", subtest="deadline"),
    mutation("materialize-success", "internal/v2/service/data_error.go", "\tif err == nil {\n\t\treturn nil\n\t}", "\tif err == nil {\n\t\treturn contextError(ctx.Err())\n\t}", "service", "TestMaterializeErrors", "materialization changed a successful read", subtest="cancelled"),
    mutation("object-cache-visible", "internal/v2/store/object_read.go", "\t\tif !objectVisible(scope, visible.ACL) {\n\t\t\treturn api.ObjectMetadata{}, nil, fault(api.CodeNotFound, \"object is absent or not visible\")\n\t\t}\n", "", "store", "TestObjectCacheVisibility", "unauthorized object entered the read cache", extra_edits=[["\t\tif !objectVisible(scope, metadata.ACL) {\n\t\t\treturn api.ObjectMetadata{}, nil, fault(api.CodeNotFound, \"object is absent or not visible\")\n\t\t}\n",""]]),
    mutation("object-cache-entries", "internal/v2/store/object_read.go", "len(view.objects) >= objectCacheEntries || ", "", "store", "TestObjectCacheBounds", "object read cache exceeded its retained bounds", subtest="entries"),
    mutation("object-cache-bytes", "internal/v2/store/object_read.go", " || view.objectBytes+int64(len(data)) > objectCacheBytes", "", "store", "TestObjectCacheBounds", "object read cache exceeded its retained bounds", subtest="bytes"),
    mutation("object-cache-release", "internal/v2/store/object_read.go", "\tv.objects = nil\n\tv.objectBytes = 0", "\tv.objects = nil", "store", "TestObjectCacheBounds", "closed view retained cache bytes", subtest="entries"),
    mutation("launch-receipt-deadline", "internal/v2/store/launch_receipt.go", "\t\tif contextErr := ctx.Err(); contextErr != nil {\n\t\t\treturn contextErr\n\t\t}\n", "\t\tif contextErr := ctx.Err(); contextErr != nil {\n\t\t\treturn fault(api.CodeIntegrity, \"launch request is not the exact original receipt bytes\")\n\t\t}\n", "store", "TestLaunchReceiptRead", "receipt read lost its context failure", subtest="deadline"),
    mutation("launch-receipt-cancelled", "internal/v2/store/launch_receipt.go", "\t\tif contextErr := ctx.Err(); contextErr != nil {\n\t\t\treturn contextErr\n\t\t}\n", "\t\tif contextErr := ctx.Err(); contextErr != nil {\n\t\t\treturn fault(api.CodeIntegrity, \"launch request is not the exact original receipt bytes\")\n\t\t}\n", "store", "TestLaunchReceiptRead", "receipt read lost its context failure", subtest="cancelled"),
    mutation("launch-receipt-byte-gate", "internal/v2/store/launch_receipt.go", "\tif !bytes.Equal(raw, original) {\n\t\treturn fault(api.CodeIntegrity, \"launch request is not the exact original receipt bytes\")\n\t}\n", "", "store", "TestLaunchReceiptRead", "receipt read lost its exact byte integrity gate", subtest="changed", extra_edits=[['\t"bytes"\n', ""]]),
    mutation("launch-receipt-missing", "internal/v2/store/launch_receipt.go", "\t\tif errors.Is(err, sql.ErrNoRows) {\n\t\t\treturn fault(api.CodeIntegrity, \"launch request is not the exact original receipt bytes\")\n\t\t}\n", "\t\tif errors.Is(err, sql.ErrNoRows) { return nil }\n", "store", "TestLaunchReceiptRead", "receipt read lost its exact byte integrity gate", subtest="missing"),
    mutation("launch-receipt-sql-error", "internal/v2/store/launch_receipt.go", "\t\treturn err\n\t}\n\tif !bytes.Equal(raw, original)", "\t\treturn fault(api.CodeIntegrity, \"launch request is not the exact original receipt bytes\")\n\t}\n\tif !bytes.Equal(raw, original)", "store", "TestLaunchReceiptRead", "receipt query failure became a byte mismatch", subtest="read_error"),
    mutation("launch-receipt-call", "internal/v2/store/launch_plan.go", "\t\tif err := checkLaunchReceipt(ctx, db, r.OperationID, data); err != nil {\n\t\t\treturn err\n\t\t}\n", "", "store", "TestLaunchReceiptIntegrity", "launch plan accepted changed receipt bytes"),
    mutation("object-read-linear", "internal/v2/store/read.go", "metadata, data, err := s.readObjectRow(ctx, scope, db, request.ObjectID)", "metadata, data, err := objectRow(ctx, db, request.ObjectID)", "store", "TestObjectReadLinear", "multi-chunk read repeated full verification"),
    mutation("object-read-tamper", "internal/v2/store/objects.go", "metadata.Ref.ID != id || metadata.Ref.Bytes != int64(len(data)) || metadata.Ref.SHA256 != api.Digest(hash(data))", "metadata.Ref.ID != id || metadata.Ref.Bytes != int64(len(data))", "store", "TestObjectReadTamper", "verified read accepted tampered object", subtest="byte"),
    mutation("object-read-metadata", "internal/v2/store/objects.go", "metadata.Ref.ID != id || metadata.Ref.Bytes != int64(len(data)) || metadata.Ref.SHA256 != api.Digest(hash(data))", "metadata.Ref.ID != id || metadata.Ref.Bytes != int64(len(data))", "store", "TestObjectReadTamper", "verified read accepted tampered object", subtest="metadata"),
    mutation("object-read-request", "internal/v2/store/object_read.go", " || view.objectBinding != bindObjectRead(scope)", "", "store", "TestObjectReadScope", "verified read crossed request binding", subtest="request"),
    mutation("object-read-metadata-copy", "internal/v2/store/object_read.go", "\tmetadata.ACL.Participants = slices.Clone(metadata.ACL.Participants)\n", "", "store", "TestObjectReadScope", "metadata caller mutated the verified pin", subtest="metadata_copy", extra_edits=[['\t"slices"\n', ""]]),
    mutation("object-read-chunk-copy", "internal/v2/store/read.go", "Data: append([]byte{}, data[request.Offset:end]...)", "Data: data[request.Offset:end]", "store", "TestObjectReadScope", "chunk caller mutated verified bytes", subtest="chunk_copy"),
    mutation("object-read-release", "internal/v2/objectread/read.go", "func(resultErr *error) { *resultErr = errors.Join(*resultErr, view.Close()) }", "func(*error) {}", "store", "TestObjectReadLinear", "whole object read retained request view", extra_edits=[['\t"errors"\n', ""]]),
    mutation("object-read-revocation", "internal/v2/store/read.go", "\tif err := s.readScope(ctx, scope); err != nil {\n\t\treturn chunk, err\n\t}\n\tif request.Offset < 0", "\tif request.Offset < 0", "store", "TestObjectReadRevocation", "verified read reused revoked authority"),
    mutation("failed-plan-private-copy", "internal/v2/store/plan_cleanup.go", "if err := decodeStored(raw, &retained); err != nil {", "if err := wire.Decode(raw, &retained); err != nil {", "store", "TestFailedPlanAtomic", "private cleanup copy rejected retained selectors", subtest="commit"),
    mutation("authentication-refusal-cause", "internal/v2/service/authentication.go", '\treturn &api.Error{Code: cause.Code, Owner: cause.Owner,\n\t\tMessage: "service connection refused at " + stage}\n', '\trefusal := *cause\n\trefusal.Message = "service connection refused at " + stage + ": " + cause.Message\n\treturn &refusal\n', "service", "TestAuthenticationRefusalPrivacy", "authentication refusal disclosed internal cause"),
    mutation("authentication-refusal-other-field", "internal/v2/service/authentication.go", '\treturn &api.Error{Code: cause.Code, Owner: cause.Owner,\n\t\tMessage: "service connection refused at " + stage}\n', '\treturn &api.Error{Code: cause.Code, Owner: cause.Owner, Instead: cause.Message,\n\t\tMessage: "service connection refused at " + stage}\n', "service", "TestAuthenticationRefusalPrivacy", "authentication refusal disclosed internal cause"),
    mutation("data-parent-select", "internal/v2/service/materialization.go", "parent, err := s.planningClaimRecord(ctx, plan)", "parent, err := s.inputClaimRecord(ctx, plan)", "service", "TestDataStageDispatch", "materialization dispatch repeated a retained launch", subtest="child_first"),
    mutation("data-parent-completed", "internal/v2/service/materialization.go", "parent, err := s.planningClaimRecord(ctx, plan)", "parent, err := s.inputClaimRecord(ctx, plan)", "service", "TestDataParentClaim", "materialization child replaced a completed planning claim", extra_edits=[["\tif parent.Effect.PlanLaunch == nil || parent.Effect.PlanLaunch.ReservationID != request.ReservationID {\n\t\treturn api.LaunchDataStage{}, serviceError(api.CodeConflict, \"materialization requires the original planning claim\")\n\t}\n", ""]]),
    mutation("failed-plan-atomic", "internal/v2/store/internal.go", "\tif err := s.writePlanCleanup(ctx, tx, input); err != nil {\n\t\treturn commit, err\n\t}\n", "", "store", "TestFailedPlanAtomic", "cleanup append failure left a partial plan", subtest="rollback", extra_edits=[["\tif err := tx.Commit(); err != nil {\n\t\treturn commit, err\n\t}\n","\tif err := tx.Commit(); err != nil {\n\t\treturn commit, err\n\t}\n\tif len(s.cleanupRequests(ctx)) != 0 {\n\t\toutside, outsideErr := s.db.BeginTx(ctx, nil)\n\t\tif outsideErr != nil { return commit, outsideErr }\n\t\tif outsideErr = s.writePlanCleanup(ctx, outside, input); outsideErr != nil {\n\t\t\treturn commit, errors.Join(outsideErr, outside.Rollback())\n\t\t}\n\t\tif outsideErr = outside.Commit(); outsideErr != nil { return commit, outsideErr }\n\t}\n"]]),
    mutation("failed-plan-outbox", "internal/v2/store/internal.go", "\tif err := s.writePlanCleanup(ctx, tx, input); err != nil {\n\t\treturn commit, err\n\t}\n", "", "store", "TestFailedPlanAtomic", "failed plan lost an atomic cleanup request", subtest="commit"),
    mutation("failed-plan-policy", "internal/v2/store/launch_fences.go", "if len(s.cleanupRequests(ctx)) == 0 {", "if len(s.cleanupRequests(ctx)) == 0 || len(input.Writes.LaunchPlans) != 0 {", "store", "TestFailedPlanAtomic", "failed plan and cleanup did not commit together", subtest="policy"),
    mutation("failed-plan-claim", "internal/v2/store/launch_plan.go", "!future(record.ClaimExpiresAt, s.deps.Clock.Now()) || record.Effect.Context == nil", "record.Effect.Context == nil", "store", "TestFailedPlanGuards", "failed-plan cleanup guard accepted claim", subtest="claim"),
    mutation("failed-plan-selector", "internal/v2/store/plan_cleanup.go", "job.ReservationID != r.ID || job.LaunchID != r.LaunchID || cause.EffectID != job.ID", "job.ReservationID != r.ID || cause.EffectID != job.ID", "store", "TestFailedPlanGuards", "failed-plan cleanup guard accepted selector", subtest="selector", extra_edits=[["\t\treturn api.ValidateFailedPlanWrite(input, jobs)\n","\t\treturn nil\n"]]),
    mutation("failed-plan-injection", "internal/v2/store/plan_cleanup.go", "\t\tfor _, selected := range []struct {\n\t\t\tstage string\n\t\t\tref   *api.BlobRef\n\t\t}{{\"input-injection\", job.InjectionIn}, {\"result-injection\", job.InjectionOut}} {\n\t\t\tmeta, _, err := objectRow(ctx, db, cleanupObjectID(r.ID, selected.stage))\n\t\t\tif err == nil && (selected.ref == nil || meta.Ref != *selected.ref) || absent(err) && selected.ref != nil {\n\t\t\t\treturn fault(api.CodeIntegrity, \"cleanup omitted or replaced its protected injection selector\")\n\t\t\t}\n\t\t\tif err != nil && !absent(err) {\n\t\t\t\treturn err\n\t\t\t}\n\t\t}\n", "", "store", "TestFailedPlanGuards", "failed-plan cleanup guard accepted injection", subtest="injection"),
    mutation("failed-plan-projection", "internal/v2/store/plan_cleanup.go", "\t\t\t\tif err := api.ValidateCredentialWithdrawalRequest(projection, *job.Withdrawal); err != nil {\n\t\t\t\t\treturn err\n\t\t\t\t}\n", "", "store", "TestFailedPlanGuards", "failed-plan cleanup guard accepted projection", subtest="projection"),
    mutation("failed-plan-unbound-projection", "internal/v2/store/plan_cleanup.go", " || projected != 0", "", "store", "TestFailedPlanGuards", "failed-plan cleanup guard accepted unbound_projection", subtest="unbound_projection"),
    mutation("failed-plan-generic", "internal/v2/store/plan_cleanup.go", "\treturn api.ValidateTransactionShape(input)\n", "\treturn nil\n", "store", "TestFailedPlanGuards", "failed-plan cleanup guard accepted generic", subtest="generic", extra_edits=[["\tif input.Internal == nil || input.Internal.Kind != api.InternalLaunchPlan || len(s.cleanupRequests(ctx)) != 0 {\n","\tif true {\n"]]),
    mutation("failed-plan-drain", "internal/v2/store/dispatch.go", "SELECT operation_id FROM reservations UNION SELECT json_extract(data,'$.Request.Cause.cause_operation_id') FROM projections WHERE kind='plan_cleanup' AND json_extract(data,'$.State')='pending' ORDER BY 1", "SELECT operation_id FROM reservations ORDER BY operation_id", "store", "TestFailedPlanAtomic", "pending cleanup disappeared from drain inventory", subtest="commit"),
    mutation("failed-plan-target", "internal/v2/store/dispatch.go", "kind IN ('lane','launch','plan_cleanup')", "kind IN ('lane','launch')", "store", "TestFailedPlanAtomic", "pending cleanup lost its original dispatch target", subtest="commit"),
    mutation("failed-plan-replay-bytes", "internal/v2/store/internal.go", "input.Compare, input.Guards, s.cleanupRequests(ctx)})", "input.Compare, input.Guards, nil})", "store", "TestFailedPlanAtomic", "cleanup replay accepted changed request bytes", subtest="commit"),
    mutation("failed-plan-unknown", "internal/v2/store/plan_cleanup.go", "\t\tif err := putGenerated(ctx, tx, \"plan_cleanup\", job.ID, 1, saved); err != nil {", "\t\tif !saved.Request.SlotKnown { saved.Request.SlotKnown = true; saved.Request.Issues = nil }\n\t\tif err := putGenerated(ctx, tx, \"plan_cleanup\", job.ID, 1, saved); err != nil {", "store", "TestFailedPlanAtomic", "failed plan lost an atomic cleanup request", subtest="unknown"),
    mutation("effect-success-state", "internal/v2/store/effect_state.go", 'case "succeeded":\n\t\treturn api.EffectCompleted', 'case "succeeded":\n\t\treturn api.EffectClaimed', "store", "TestStoredEffectStates", "terminal effect confused state and outcome", subtest="succeeded"),
    mutation("effect-failure-state", "internal/v2/store/effect_state.go", 'case "failed":\n\t\treturn api.EffectFailed', 'case "failed":\n\t\treturn api.EffectCompleted', "store", "TestStoredEffectStates", "terminal effect confused state and outcome", subtest="failed"),
    mutation("effect-reclaim-state", "internal/v2/store/effects.go", '\trecord.Generation++\n\tdata, err := encodeEffectState(record)', '\trecord.Generation++\n\tif record.Generation > 2 { record.State = "reconciling" }\n\tdata, err := encodeEffectState(record)', "store", "TestEffectReclaimState", "reclaim left shared claimed state"),
    mutation("effect-lookup-state", "internal/v2/store/effects.go", '\tif err := validateEffectState(record); err != nil {\n\t\treturn record, err\n\t}\n', "", "store", "TestEffectStateRefusal", "store accepted a foreign effect state", subtest="unknown"),
    mutation("effect-dispatch-state", "internal/v2/store/dispatch.go", '\t\tif err := validateEffectState(record); err != nil {\n\t\t\treturn nil, err\n\t\t}\n', "", "store", "TestEffectStateRefusal", "dispatch accepted a foreign effect state", subtest="unknown"),
    mutation("effect-pending-state", "internal/v2/store/read.go", '\t\tif err := validateEffectState(record); err != nil {\n\t\t\treturn nil, err\n\t\t}\n', "", "store", "TestEffectStateRefusal", "pending inventory accepted a foreign effect state", subtest="unknown"),
    mutation("effect-verify-state", "internal/v2/store/verify_atomic.go", '\t\tif err := validateEffectState(record); err != nil {\n\t\t\treturn err\n\t\t}\n', "", "store", "TestEffectStateRefusal", "verification accepted a foreign effect state", subtest="unknown"),
    mutation("current-policy-snapshot", "internal/v2/store/current_policy.go", '\tif err := storedProjection(ctx, s.db, "policy", api.ID(s.deps.Config), &current); err != nil {\n\t\treturn current, err\n\t}\n', '\tdb, err := s.reader(scope)\n\tif err != nil { return current, err }\n\tif err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &current); err != nil {\n\t\treturn current, err\n\t}\n', "store", "TestCurrentApprovedHead", "current policy used the historical snapshot"),
    mutation("current-policy-malformed", "internal/v2/store/current_policy.go", '\tif current.Generation == 0 || current.Generation > 1<<53-1 || !wire.ValidDigest(string(current.SHA256)) {\n\t\treturn api.EffectivePolicy{}, fault(api.CodeIntegrity, "current approved policy head is malformed")\n\t}\n', "", "store", "TestPolicyHeadRefusal", "policy source invented an approved head", subtest="malformed", extra_edits=[['"laneboss.io/laneboss/internal/v2/client/wire"', '_ "laneboss.io/laneboss/internal/v2/client/wire"']]),
    mutation("writer-open-policy-stamp", "internal/v2/store/current_policy.go", '\tif !needed {', '\tif !needed || input.Internal.Kind == api.InternalHelperOpen {', "store", "TestWriterOpenPolicy", "fresh open lost its current policy stamp"),
    mutation("service-current-policy", "internal/v2/service/launch_control.go", 's.deps.Store.CurrentApprovedPolicy(ctx, scope)', 's.deps.Store.Policy(ctx, scope)', "service", "TestCurrentPolicySource", "service hid current policy source failure"),
    mutation("reclaimed-allocation-repeat", "internal/v2/service/reconcile.go", 'recovering := lease.Record.Generation > 2', 'recovering := lease.Record.Generation > 3', "service", "TestReclaimedAllocation", "reclaimed allocation repeated native work"),
    mutation("turn-envelope-snapshot", "internal/v2/store/launch_fences.go", '\tif err := s.validateTurnEvents(ctx, db, input); err != nil {\n\t\treturn err\n\t}\n', "", "store", "TestTurnEnvelopeStore", "turn envelope escaped its real snapshot", subtest="run"),
    mutation("materialize-input-schema", "internal/v2/client/wire/schema.go", "launch_spec materialize_input archive_input worker_result credential_evidence\"", "launch_spec archive_input worker_result credential_evidence\"", "wire", "TestMaterializationSchema", "frozen materialization schema refused", subtest="input"),
    mutation("worker-result-schema", "internal/v2/client/wire/schema.go", "launch_spec materialize_input archive_input worker_result credential_evidence\"", "launch_spec materialize_input archive_input credential_evidence\"", "wire", "TestMaterializationSchema", "frozen materialization schema refused", subtest="result"),
    mutation("materialize-plan-schema", "internal/v2/client/wire/schema.go", 'gateway materialize"', 'gateway"', "wire", "TestMaterializationSchema", "frozen materialization schema refused", subtest="plan"),
    mutation("materialize-grant-schema", "internal/v2/client/wire/schema.go", 'values = "copy mount bind_ro"', 'values = "copy mount"', "wire", "TestMaterializationSchema", "frozen materialization schema refused", subtest="grant"),
    mutation("materialize-generic-non-worker", "internal/v2/store/transaction.go", 'return fault(api.CodeForbidden, "materialization workers must use dedicated job operations")', "_, err := s.dataWorkerScope(ctx, db, scope, api.WorkerInputRead)\n\t\t\treturn err", "store", "TestDataGenericScope", "materialize worker entered generic policy read", subtest="non_worker"),
    mutation("materialize-generic-result", "internal/v2/store/transaction.go", 'return fault(api.CodeForbidden, "materialization workers must use dedicated job operations")', "_, err := s.dataWorkerScope(ctx, db, scope, api.WorkerInputRead)\n\t\t\treturn err", "store", "TestDataGenericScope", "materialize result entered generic read scope", subtest="result_append"),
    mutation("data-stage-grant", "internal/v2/store/materialization.go", "plan.Reservation.GrantSetID != request.GrantSetID || ", "", "store", "TestDataStagePins", "data stage accepted drifted grant selector"),
    mutation("worker-principal-boot", "internal/v2/store/worker_bootstrap.go", 'return empty, fault(api.CodeContainmentUnknown, "worker native generation differs from the retained boot")', "", "store", "TestWorkerPrincipalPins", "worker principal accepted another native boot"),
    mutation("data-stage-current-grants", "internal/v2/store/materialization.go", 'return fault(api.CodeConflict, "materialization retained grants changed")', "", "store", "TestDataStageGrantDrift", "data stage accepted changed issued grants", extra_edits=[['\t\tif err := s.currentLaunch(ctx, s.db, plan); err != nil {\n\t\t\treturn result, err\n\t\t}\n', ""]]),
    mutation("data-registration-pin", "internal/v2/service/materialization.go", 'return api.LaunchDataStage{}, serviceError(api.CodeIntegrity, "materialization helper registration changed its sealed spec")', "", "service", "TestDataRegistrationPin", "materialization accepted a foreign registration receipt"),
    mutation("data-await-process", "internal/v2/service/materialization.go", 'return api.LaunchDataResult{}, serviceError(api.CodeIntegrity, "materialization observed another process")', "", "service", "TestAwaitDataProcess", "materialization await accepted another observed process"),
    mutation("worker-input-own-job", "internal/v2/store/worker_bootstrap.go", 'return api.WorkerJobInput{}, fault(api.CodeForbidden, "worker cannot read another job input")', "", "store", "TestWorkerInputOwnJob", "worker input read another job selector"),
    mutation("worker-result-measurement", "internal/v2/store/worker_bootstrap.go", 'return d, fault(api.CodeIntegrity, "worker result changed the opened source or destination measurement")', "", "store", "TestWorkerResultMeasurement", "worker result accepted a changed source measurement"),
    mutation("worker-result-own-job", "internal/v2/store/worker_bootstrap.go", 'return receipt, fault(api.CodeForbidden, "worker cannot submit another job result")', "submission.LeaseID = p.Lease.ID", "store", "TestWorkerResultOwnJob", "worker result submitted another job selector"),
    mutation("worker-result-replay", "internal/v2/store/worker_bootstrap.go", 'return receipt, fault(api.CodeIdempotencyConflict, "worker result retry changed its exact bytes or input")', "", "store", "TestWorkerResultReplay", "worker result replay accepted changed exact bytes", extra_edits=[['if err := api.ValidateWorkerResult(p, submission, previous.Receipt, s.deps.Clock.Now()); err != nil {\n\t\t\treturn receipt, err\n\t\t}', ""]]),
    mutation("worker-ingress-frame", "internal/v2/service/materialization.go", 'return api.Scope{}, serviceError(api.CodeIntegrity, "worker parameters differ from their authenticated frame")', "", "service", "TestWorkerIngressFrame", "worker ingress accepted changed framed inputs"),
    mutation("state-mode", "internal/v2/store/store.go", "return info.Mode() == os.ModeDir|0700", "return info.IsDir()", "store", "TestRefuseUnsafeDirectory", "wanted prerequisite_missing, got <nil>"),
    mutation("state-owner", "internal/v2/store/store.go", "if !ok || stat.Uid != uint32(os.Geteuid()) {", "if !ok {", "store", "TestPrivateDirectoryOwner", "different-owner metadata accepted"),
    mutation("duplicate-json", "internal/v2/client/wire/json.go", "\t\t\t\tif _, exists := object[name]; exists {\n\t\t\t\t\treturn nil, Invalid(\"duplicate JSON member\")\n\t\t\t\t}\n", "", "wire", "TestRejectJSONAmbiguity", "ambiguous JSON case 0 accepted"),
    mutation("unknown-field", "internal/v2/client/wire/json.go", "\t\tfor key := range object {\n\t\t\tif !known[key] {\n\t\t\t\treturn Invalid(\"unknown JSON field\")\n\t\t\t}\n\t\t}\n", "", "wire", "TestRequiredAndClosedFields", "invalid typed case 0 accepted"),
    mutation("changed-key", "internal/v2/store/transaction.go", "\t\tif previousDigest != string(request.RequestSHA256) {\n\t\t\treturn commit, fault(api.CodeIdempotencyConflict, \"idempotency key has different request content\")\n\t\t}\n", "", "store", "TestReplayAfterReopen", "wanted idempotency_conflict, got <nil>", extra_edits=[["receipt.Key != requestKey(request)","(receipt.Key.Method != request.Method || receipt.Key.IdempotencyKey != request.IdempotencyKey)"]]),
    mutation("revoked-replay", "internal/v2/store/transaction.go", "if record.Revoked || record.Target.LifeID != scope.Actor.LifeID ||", "if record.Target.LifeID != scope.Actor.LifeID ||", "store", "TestReplayRechecksRevocation", "wanted unauthenticated, got <nil>"),
    mutation("ancillary", "internal/v2/client/wire/frame.go", "\tif connection, ok := reader.(*net.UnixConn); ok {\n\t\treader = noAncillary{connection}\n\t}\n", "", "wire", "TestRejectReceivedFD", "descriptor-bearing request accepted"),
    mutation("old-run-end", "internal/v2/service/stream.go", "event.Run == request.Run && event.Origin == \"service\"", "event.Origin == \"service\"", "service", "TestSelectedEnd", "old run ended follow"),
    mutation("watcher-deadline", "internal/v2/service/stream.go", "\tif err := connection.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {\n\t\treturn err\n\t}\n", "", "service", "TestStalledWatcherIsolation", "watcher exceeded its bounded write deadline"),
    mutation("mutation-gate", "internal/v2/service/dispatch_mutation.go", "\treceipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)\n", "\treceipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)\n\tif err != nil { var refusal *api.Error; if errors.As(err, &refusal) && refusal.Code == api.CodeNotImplemented {\n\t\tresult, handlerErr := s.handlers[request.Method](ctx, scope, request.Params); return result, scope, handlerErr\n\t} }\n", "service", "TestMutationCannotBypassReceipt", "wanted not_implemented, got integrity: mutation handler should not run"),
    mutation("scoped-record-read", "internal/v2/store/read.go", "\t\tif record.Collection != request.Collection || request.LifeID != \"\" && request.LifeID != record.LifeID {\n\t\t\tcontinue\n\t\t}\n\t\tvisible, err := s.visibleRecord(ctx, scope, record)\n\t\tif err != nil {\n\t\t\treturn page, err\n\t\t}\n\t\tif visible {\n\t\t\tpage.Records = append(page.Records, record)\n\t\t}\n", "\t\tif record.Collection != request.Collection || request.LifeID != \"\" && request.LifeID != record.LifeID {\n\t\t\tcontinue\n\t\t}\n\t\tif _, err := s.visibleRecord(ctx, scope, record); err != nil {\n\t\t\treturn page, err\n\t\t}\n\t\tpage.Records = append(page.Records, record)\n", "service", "TestSocketScopedRecords", "scoped socket record leaked or changed", extra_edits=[["administrative(scope), string(scope.Actor.LifeID), string(scope.Actor.LifeID), request.Limit+1)","true, string(scope.Actor.LifeID), string(scope.Actor.LifeID), request.Limit+1)"]]),
    mutation("receipt-reservation", "internal/v2/store/store.go", "return scope.Actor.Kind + \":\" + string(scope.Actor.ID) + \":\" + string(scope.Actor.LifeID)", "return scope.Actor.Kind + \":\" + string(scope.Actor.ID) + \":\" + string(scope.Actor.LifeID) + \":\" + string(scope.Request.RequestID)", "store", "TestLiveRetryKeepsOneIntent", "retry duplicated durable intent:"),
    mutation("state-fd-inherit", "internal/v2/store/store.go", "\tif err := unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {", "\tif _, err := unix.FcntlInt(s.lock.Fd(), unix.F_SETFD, 0); err != nil {\n\t\treturn nil, fault(api.CodePrerequisite, \"descriptor mutation failed\")\n\t}\n\tif err := unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {", "store", "TestStateFDExec", "state descriptor survived ordinary exec"),
    mutation("rpc-schema", "internal/v2/client/wire/schema.go", "if request.Protocol != api.Protocol || request.Schema != api.SchemaVersion {", "if request.Protocol != api.Protocol {", "wire", "TestWrongSchema", "wrong schema reached request dispatch"),
    mutation("outage-db-open", "internal/v2/client/client.go", "\tconnection, err := dial(ctx)\n\tif err != nil {\n\t\treturn nil, transportError(err)\n\t}\n", "\tconnection, err := dial(ctx)\n\tif err != nil {\n\t\tstate, openErr := os.Open(c.Options.BindingFile)\n\t\tif openErr != nil { return nil, transportError(openErr) }\n\t\tif closeErr := state.Close(); closeErr != nil { return nil, transportError(closeErr) }\n\t\treturn nil, transportError(err)\n\t}\n", "client", "TestOutageKeepsStateClosed", "socket outage opened direct state"),
    mutation("watcher-frame-limit", "internal/v2/service/queue.go", "make(chan queuedFrame, 256)", "make(chan queuedFrame, 512)", "service", "TestWatcherOverflow", "watcher accepted frame queue overflow", subtest="frames"),
    mutation("watcher-byte-limit", "internal/v2/service/queue.go", "q.queuedBytes+len(encoded) > 4*1024*1024", "q.queuedBytes+len(encoded) > 8*1024*1024", "service", "TestWatcherOverflow", "watcher accepted byte queue overflow", subtest="bytes"),
    mutation("watcher-error-cursor", "internal/v2/service/stream.go", "Index: index + 1, Cursor: cursor, Error: typedError(err)", "Index: index + 1, Error: typedError(err)", "service", "TestWatcherErrorCursor", "watcher overflow lost resumable cursor"),
    mutation("read-entry-auth", "internal/v2/service/server.go", "\tif err := s.deps.Authenticator.Authorize(ctx, scope, request); err != nil {\n\t\treturn nil, scope, err\n\t}\n", "", "service", "TestAuthorityBeforeAndAfterRead", "unauthorized read handler ran", subtest="denied"),
    mutation("read-delivery-binding", "internal/v2/service/server.go", "\tif current.Actor != scope.Actor || current.Config != scope.Config || current.LaunchID != scope.LaunchID || current.EndpointGeneration != scope.EndpointGeneration || current.PolicyGeneration != scope.PolicyGeneration {\n\t\treturn nil, scope, serviceError(api.CodeUnauthenticated, \"peer binding changed before reply\")\n\t}\n", "", "service", "TestAuthorityBeforeAndAfterRead", "wanted unauthenticated, got <nil>", subtest="drift"),
    mutation("required-field", "internal/v2/client/wire/json.go", "return Invalid(\"missing required JSON field\")", "continue", "wire", "TestRequiredAndClosedFields", "invalid typed case 1 accepted"),
    mutation("frame-zero", "internal/v2/client/wire/frame.go", "if length == 0 || length > api.MaxFrameBytes {", "if length > api.MaxFrameBytes {", "wire", "TestFrameBounds", "invalid or truncated frame accepted"),
    mutation("received-fd-close", "internal/v2/client/wire/frame.go", "\t\t\t\tfor _, descriptor := range descriptors {\n\t\t\t\t\tcleanupErr = errors.Join(cleanupErr, unix.Close(descriptor))\n\t\t\t\t}\n", "\t\t\t\tfor range descriptors {}\n", "wire", "TestRejectReceivedFD", "received descriptor leaked:"),
    mutation("call-preparation", "internal/v2/client/client.go", "\tvar err error\n\trequest, err = c.PrepareRequest(request)\n\tif err != nil {\n\t\treturn response, err\n\t}\n", "\tvar err error\n", "client", "TestCallFramedResult", "request preparation failed"),
    mutation("initial-snapshot", "internal/v2/client/client.go", "response: response, stop: stop}", "response: api.Response{}, stop: stop}", "client", "TestStreamInitialPage", "initial snapshot changed"),
    mutation("initial-copy", "internal/v2/client/client.go", "\tresponse.Result = append(json.RawMessage(nil), response.Result...)\n", "", "client", "TestStreamInitialPage", "initial snapshot shares caller storage"),
    mutation("typed-write-gate", "internal/v2/store/transaction.go", "\tif err := api.ValidateTransactionShape(input); err != nil {\n\t\treturn commit, err\n\t}\n", "", "store", "TestDraftFieldsStayClosed", "unsupported draft transaction accepted writes", subtest="writes"),
    mutation("atomic-guard-gate", "internal/v2/store/transaction.go", "\tif err := s.guards(ctx, tx, input, operationID); err != nil {\n\t\treturn commit, err\n\t}\n", "", "store", "TestDraftFieldsStayClosed", "unsupported draft transaction accepted guards", subtest="guards"),
    mutation("exact-reply-gate", "internal/v2/store/transaction.go", "\treply, err := s.finalReply(ctx, tx, input, operation)\n", "\treply, err := input.Reply, error(nil)\n", "store", "TestDraftFieldsStayClosed", "unsupported draft transaction accepted reply", subtest="reply"),
    mutation("raw-frame-match", "internal/v2/store/transaction.go", "\t\tif _, err := wire.DecodeRequest(input.RawRequest); err != nil || !wire.SameJSON(input.RawRequest, requestBytes) {\n\t\t\treturn commit, wire.Invalid(\"raw request differs from authenticated request\")\n\t\t}\n", "", "store", "TestRawRequestMatchesScope", "raw request mismatch accepted"),
    mutation("raw-frame-retention", "internal/v2/store/transaction.go", "\t\trequestBytes = append([]byte(nil), input.RawRequest...)\n", "", "store", "TestRawRequestMatchesScope", "raw request bytes changed"),
    mutation("exact-record-filter", "internal/v2/store/read.go", "\t\terr := projection(ctx, db, \"record\", request.RecordID, &record)\n", "\t\terr := projection(ctx, db, \"record\", request.LifeID, &record)\n", "store", "TestExactRecordLookup", "exact lookup returned unrelated records"),
    mutation("effect-context-count", "internal/v2/store/transaction.go", "value.Type().Field(i).Name != \"Context\" && value.Field(i).Kind() == reflect.Pointer && !value.Field(i).IsNil()", "value.Field(i).Kind() == reflect.Pointer && !value.Field(i).IsNil()", "store", "TestDurableOutboxIntent", "outbox was not pending"),
    mutation("writer-credentials", "internal/v2/client/wire/" "credentials_linux.go", "writer != r.expected", "writer.PID < 0", "wire", "TestPinnedWriterCredentials", "inherited socket writer was accepted"),
    mutation("private-event", "internal/v2/client/wire/visibility.go", "return false, nil\n\t}\n\tswitch event.Kind", "return true, nil\n\t}\n\tswitch event.Kind", "wire", "TestPrivateEventVisibility", "administrative event leaked to lane"),
    mutation("receipt-exact-bytes", "internal/v2/store/receipts.go", "return receipt, nil\n\t}\n\tif !errors.Is(err, sql.ErrNoRows)", "receipt.Reply.Result = nil\n\t\treturn receipt, nil\n\t}\n\tif !errors.Is(err, sql.ErrNoRows)", "store", "TestReservedExactReply", "restart changed exact receipt"),
    mutation("pending-key-digest", "internal/v2/store/transaction.go", "\tif reserveErr == nil && reservedDigest != string(request.RequestSHA256) {\n\t\treturn commit, fault(api.CodeIdempotencyConflict, \"idempotency key has different pending request content\")\n\t}\n", "", "store", "TestPendingKeyRejectsChangedIntent", "pending key accepted changed intent", extra_edits=[["\tif reserveErr == nil {\n\t\tencoded, err := json.Marshal(request)\n\t\tif err != nil || !wire.SameJSON(encoded, reservedRaw) {\n\t\t\treturn commit, fault(api.CodeConflict, \"pending reservation belongs to another request instance\")\n\t\t}\n\t\tinput.RawRequest = append([]byte(nil), reservedRaw...)\n\t} else if err := s.dispatchAllowed(ctx, tx); err != nil {\n\t\treturn commit, err\n\t}\n","\tif reserveErr != nil {\n\t\tif err := s.dispatchAllowed(ctx, tx); err != nil {\n\t\t\treturn commit, err\n\t\t}\n\t}\n"]]),
    mutation("endpoint-class", "internal/v2/service/server.go", "\tif (class == api.EndpointLane || class == api.EndpointWorker) &&\n\t\t(request.Proof != nil || stringsHumanMethod(request.Method)) {\n\t\treturn nil, scope, serviceError(api.CodeForbidden, \"endpoint class cannot use human administration\")\n\t}\n", "", "service", "TestEndpointClassPrecedesActorLabel", "wanted forbidden, got integrity: wrong endpoint invoked handler"),
    mutation("response-head", "internal/v2/service/server.go", "\t\t\tresponse.LastSeq = scope.ReadView.Snapshot().LastSeq\n", "", "service", "TestSocketScopedRecords", "socket response lost committed head"),
    mutation("state-ancestor", "internal/v2/store/store.go", "if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {", "if err != nil || !info.IsDir() {", "store", "TestRejectWritableAncestor", "writable ancestor accepted state writer"),
    mutation("state-hardlink", "internal/v2/store/store.go", "return info.Mode() == 0600 && stat.Nlink == 1", "return info.Mode() == 0600", "store", "TestPostOpenStateHardlink", "post-open state hardlink was credited"),
    mutation("health-probe", "internal/v2/service/health.go", "probe.Available = probe.Available && check.Available", "_ = check", "service", "TestHealthTracksHostObservations", "failed isolation check left health ready"),
    mutation("live-private-event", "internal/v2/service/stream.go", "\t\t\t\tif !visible {\n\t\t\t\t\tcontinue\n\t\t\t\t}\n", "\t\t\t\tif !visible {}\n", "service", "TestLivePrivateEventFiltering", "live private event bypassed visibility policy"),
    mutation("identity-receipt", "internal/v2/store/authority.go", "\t\tif binding.Identity != (api.IdentityCommit{}) && binding.Identity != actual {\n\t\t\treturn fault(api.CodeForbidden, \"caller supplied an uncommitted identity receipt\")\n\t\t}\n", "", "store", "TestIdentityCommitStamped", "forged identity commit was accepted"),
    mutation("foreign-life-event", "internal/v2/store/transaction.go", "if event.LifeID != input.Scope.Actor.LifeID || event.Origin != \"observation\" ||", "if event.Origin != \"observation\" ||", "store", "TestBoundLaneCannotEmitForeignLife", "bound lane emitted foreign-life event", extra_edits=[["event.Actor.Kind == \"lane\" && (record.LifeID != event.Actor.LifeID || record.Origin != \"observation\")","event.Actor.Kind == \"lane\" && record.Origin != \"observation\""]]),
    mutation("human-read-session", "internal/v2/store/snapshot.go", "\tif scope.Actor.Kind != \"human\" {\n\t\treturn nil\n\t}\n", "\tif scope.Actor.Kind != \"human\" || scope.Connection != nil {\n\t\treturn nil\n\t}\n", "store", "TestHumanReadRequiresCurrentSession", "human read without authority exposed state"),
    mutation("measured-operation-status", "internal/v2/store/verify_atomic.go", "if operation.Status != expected || !sameValue(operation.Error, state.failed) {", "if expected == \"\" || !sameValue(operation.Error, state.failed) {", "store", "TestVerifyMeasuredOperationState", "unmeasured pending operation state was credited"),
    mutation("canonical-decisions", "internal/v2/store/read.go", "if record.LifeID == \"\" && record.Collection == \"decisions\" && record.Origin == \"service\" && scope.Actor.Kind == \"lane\" {\n\t\treturn true, nil\n\t}", "if record.LifeID == \"\" && record.Collection == \"decisions\" && record.Origin == \"service\" && scope.Actor.Kind == \"lane\" {\n\t\treturn false, nil\n\t}", "store", "TestCanonicalDecisionsAndFilteredPages", "canonical decision was hidden from lane"),
    mutation("principal-watcher-limit", "internal/v2/service/stream.go", "s.principalWatchers[principal] >= 2", "s.principalWatchers[principal] >= 3", "service", "TestPrincipalWatcherIsolation", "principal watcher limit admitted excess producer"),
    mutation("producer-join-bound", "internal/v2/service/stream.go", "\t\tselect {\n\t\tcase <-done:\n\t\tcase <-time.After(time.Second):\n\t\t\ts.recordFault(serviceError(api.CodeIntegrity, \"stream producer did not drain\"))\n\t\t}\n", "\t\t<-done\n", "service", "TestUncooperativeProducerIsBounded", "uncooperative producer pinned watcher"),
    mutation("object-participant-audience", "internal/v2/store/objects.go", "if acl.Audience == \"participants\" {", "if acl.Audience != \"\" {", "store", "TestObjectParticipantAudience", "owner audience exposed object to an unrelated participant"),
    mutation("human-session-stream", "internal/v2/client/client.go", "connection, c.primary, c.primaryReadSession = c.primary, nil, false", "c.primaryReadSession = false", "client", "TestHumanStreamKeepsSessionSocket", "human stream abandoned its session socket"),
    mutation("internal-actor-gate", "internal/v2/store/internal.go", "\tif !allowedInternal(input) {\n\t\treturn commit, fault(api.CodeForbidden, \"internal emitter does not cover these writes or events\")\n\t}\n", "", "store", "TestDraftFieldsStayClosed", "unsupported draft transaction accepted internal-authority", subtest="internal-authority"),
    mutation("freeze-public-gate", "internal/v2/store/transaction.go", "\t} else if err := s.dispatchAllowed(ctx, tx); err != nil {\n\t\treturn commit, err\n\t}\n", "\t}\n", "store", "TestFreezeSurvivesRestart", "frozen store committed new public work"),
    mutation("freeze-claimed-inventory", "internal/v2/store/dispatch.go", "SELECT data FROM effect_states WHERE json_extract(data,'$.Outcome') IS NULL ORDER BY id", "SELECT data FROM effect_states WHERE json_extract(data,'$.Outcome') IS NULL AND json_extract(data,'$.ClaimID')='' ORDER BY id", "store", "TestFreezeSurvivesRestart", "dispatch inventory lost a claimed effect"),
    mutation("freeze-host-admission", "internal/v2/service/dispatch_mutation.go", "\t\trelease, admissionErr := s.admitDispatch(ctx)\n\t\tif admissionErr != nil {\n\t\t\treturn nil, scope, admissionErr\n\t\t}\n\t\tdefer release()\n", "", "service", "TestFrozenHostKeepsReads", "wanted unavailable, got integrity: frozen mutation reached reservation"),
    mutation("freeze-reserved-completion", "internal/v2/store/transaction.go", "\t// Current authorization and completed replay precede mutable preflight.\n", "\t// Current authorization and completed replay precede mutable preflight.\n\tif err := s.dispatchAllowed(ctx, tx); err != nil {\n\t\treturn commit, err\n\t}\n", "store", "TestFrozenReservationCanFinish", "freeze stranded an admitted reservation"),
    mutation("freeze-watchdog-targets", "internal/v2/service/dispatch.go", "\tfor _, target := range targets {\n\t\tif err := watchdog.Cancel(ctx, target); err != nil {\n\t\t\treturn receipt, err // Durable barrier remains closed for recovery.\n\t\t}\n\t}\n", "", "service", "TestHostFreezeDrainThaw", "host did not cancel observed watchdog targets"),
    mutation("freeze-watchdog-error", "internal/v2/service/dispatch.go", "\t\t\treturn receipt, err // Durable barrier remains closed for recovery.\n", "\t\t\tcontinue\n", "service", "TestFreezeCancelFailureStaysClosed", "wanted unavailable, got <nil>"),
    mutation("freeze-health-observation", "internal/v2/service/health.go", "Name: \"dispatch\", Available: !paused,", "Name: \"dispatch\", Available: !paused || paused,", "service", "TestHealthTracksHostObservations", "durable dispatch freeze left health ready"),
    mutation("service-file-registration", "internal/v2/cli/commands_service.go", "\t\t\"health\", \"operation.get\", \"blob.begin\", \"blob.chunk\",\n", "\t\t\"operation.get\", \"blob.begin\", \"blob.chunk\",\n", "service", "TestServiceFileInputs", "valid service file did not reach transport: health", subtest="health/--request/valid"),
    mutation("containment-admission-transfer", "internal/v2/service/server.go", "nextKey, err := s.authenticatedAdmission(entryCtx, lifetime, expected, admissionKey)", "nextKey, err := admissionKey, error(nil)", "service", "TestContainmentAdmissionIsolation", "same-UID sibling lane was starved"),
    mutation("admission-invalid-first-config", "internal/v2/service/server.go", "\t\tif native && !admitted {\n", "\t\tif native && !admitted && first {\n", "service", "TestAdmissionRetry", "valid second frame did not move UID slot to containment", subtest="wrong_config"),
    mutation("admission-invalid-first-class", "internal/v2/service/server.go", "\t\tif native && !admitted {\n", "\t\tif native && !admitted && first {\n", "service", "TestAdmissionRetry", "valid second frame did not move UID slot to containment", subtest="endpoint_class"),
    mutation("launch-reservation-operation", "internal/v2/store/launch_reservation.go", "receipt.Operation.ID != request.OperationID || receipt.Actor != scope.Actor", "receipt.Actor != scope.Actor", "store", "TestLaunchReserveGuards", "launch reservation accepted foreign_operation", subtest="foreign_operation"),
    mutation("launch-ticket-provenance", "internal/v2/store/atomic_support.go", "\t\t\tif retained.Config != s.deps.Config || retained.PrincipalID != use.PrincipalID || retained.EndpointGeneration != use.EndpointGeneration || ticket.PrincipalID != retained.PrincipalID || ticket.Config != retained.Config || ticket.EndpointGeneration != retained.EndpointGeneration {", "\t\t\tif false {", "store", "TestLaunchReserveGuards", "launch reservation accepted foreign_ticket", subtest="foreign_ticket"),
    mutation("launch-reserved-name", "internal/v2/store/launch_reservation.go", "\tif err == nil {\n\t\tvar prior api.Lane\n\t\tlaneErr := storedProjection(ctx, tx, \"lane\", claimed.LifeID, &prior)\n\t\treleased := laneErr == nil && prior.Cleaned\n\t\tif absent(laneErr) {\n\t\t\tvar failed api.LaunchPlanRecord\n\t\t\tif err := storedProjection(ctx, tx, \"launch_plan\", claimed.ReservationID, &failed); err != nil {\n\t\t\t\treturn nil, err\n\t\t\t}\n\t\t\treleased = failed.Phase == \"failed\" && failed.Reservation.Target.LifeID == claimed.LifeID\n\t\t} else if laneErr != nil {\n\t\t\treturn nil, laneErr\n\t\t}\n\t\tif !released {\n\t\t\treturn nil, fault(api.CodeConflict, \"lane name is already reserved\")\n\t\t}\n\t} else if !absent(err) {\n\t\treturn nil, err\n\t}\n", "\tif err != nil && !absent(err) {\n\t\treturn nil, err\n\t}\n", "store", "TestLaunchReserveGuards", "launch reservation accepted name_claim", subtest="name_claim"),
    mutation("launch-plan-reservation", "internal/v2/store/launch_plan.go", "!sameValue(old.Reservation, next.Reservation)", "false", "store", "TestLaunchPlanAuthority", "launch plan accepted foreign_reservation", subtest="foreign_reservation"),
    mutation("launch-plan-policy", "internal/v2/store/launch_plan.go", "policy.Generation != r.PolicyGeneration", "false", "store", "TestLaunchPlanAuthority", "launch plan accepted stale_policy", subtest="stale_policy"),
    mutation("launch-starter-grants", "internal/v2/store/launch_plan.go", "!sameValue(ceiling, authority.Ceiling) || ceiling.Revoked || !future(ceiling.ExpiresAt, s.deps.Clock.Now())", "false", "store", "TestLaunchPlanAuthority", "launch plan accepted stale_grants", subtest="stale_grants"),
    mutation("launch-claim-expiry", "internal/v2/store/launch_plan.go", "!future(record.ClaimExpiresAt, s.deps.Clock.Now()) || record.Effect.Context == nil", "record.Effect.Context == nil", "store", "TestLaunchPlanAuthority", "launch plan accepted expired_claim", subtest="expired_claim"),
    mutation("launch-replay-comparisons", "internal/v2/store/internal.go", "}{input.Internal, input.Writes, input.Events, input.Effects, input.Compare, input.Guards, s.cleanupRequests(ctx)})", "}{input.Internal, input.Writes, input.Events, input.Effects, nil, nil, s.cleanupRequests(ctx)})", "store", "TestLaunchPlanAuthority", "plan replay accepted changed comparison inputs"),
    mutation("launch-recovery-retention", "internal/v2/store/launch_plan.go", "if result.Record.Actor.Kind == \"lane\" {", "if false {", "store", "TestLaunchMissingRecovery", "restart accepted missing retained recovery"),
    mutation("capture-contiguous-offset", "internal/v2/store/capture.go", "position.NextOffset != request.Offset || ", "", "store", "TestCaptureRangeGuards", "capture range accepted offset_hole", subtest="offset_hole"),
    mutation("capture-revision-cas", "internal/v2/store/capture.go", "state.Generation != request.ExpectedGeneration || ", "", "store", "TestCaptureRangeGuards", "capture range accepted stale_revision", subtest="stale_revision"),
    mutation("capture-replay-hash", "internal/v2/store/capture.go", "!sameCaptureRange(previous.Data, request.Data) || ", "", "store", "TestCaptureRangeGuards", "capture range accepted changed_bytes", subtest="changed_bytes"),
    mutation("capture-worker-endpoint-lease", "internal/v2/store/capture.go", "endpoint.WorkerLeaseID != binding.WorkerLeaseID || ", "", "store", "TestCaptureLeaseFence", "foreign worker endpoint replayed another capture lease"),
    mutation("capture-one-use-pipes", "internal/v2/store/capture.go", "if used != 0 {", "if false {", "store", "TestCapturePipeOwnership", "capture registration reused another binding's one-use pipe"),
    mutation("capture-ingress-principal", "internal/v2/service/capture.go", "\tif request.Intent != (api.InternalIntent{}) {\n\t\treturn api.CaptureAppendReceipt{}, serviceError(api.CodeForbidden, \"capture ingress cannot supply an internal intent principal or cause\")\n\t}\n", "", "service", "TestCaptureAuthenticatedIngress", "capture ingress accepted a body-supplied principal"),
    mutation("launch-required-planner", "internal/v2/service/host.go", "usableDependency(runtime.LaunchPlanner) && usableDependency(runtime.Helper) && usableDependency(runtime.Worker) && usableDependency(runtime.Launcher)", "usableDependency(runtime.Helper) && usableDependency(runtime.Worker) && usableDependency(runtime.Launcher)", "service", "TestLaunchRuntimeReadiness", "pending launch bound without LaunchPlanner"),
    mutation("launch-required-running-jobs", "internal/v2/service/health.go", "launchReady := s.launchConfigured && s.launchJobsActive && s.launchJobsHealthy", "launchReady := s.launchConfigured", "service", "TestLaunchRuntimeReadiness", "bound dependencies advertised launch readiness without active recovery/capture jobs"),
    mutation("capture-actual-recovery-job", "internal/v2/service/launch_recovery.go", "actual, err := runtime.Helper.ReconcileCapture(ctx, plan.Capture)", "actual, err := plan.Capture, error(nil)", "service", "TestLaunchRecoveryJobs", "recovery skipped actual jobs or opened a second gate"),
    mutation("enrollment-absent-baseline", "internal/v2/store/enrollment.go", "if count != 0 {", "if false {", "store", "TestAdminEnrollmentGuards", "administrator enrollment accepted second_baseline", subtest="second_baseline"),
    mutation("enrollment-attestation-bytes", "internal/v2/store/enrollment_ceremony.go", "return challenge, fault(api.CodeForbidden, \"enrollment evidence differs from exact validated registration bytes\")", "", "store", "TestEnrollmentExactBytes", "enrollment validation accepted changed exact registration bytes", subtest="registration_bytes"),
    mutation("enrollment-revoked-inventory", "internal/v2/store/enrollment.go", "\t\tresult = append(result, enrollment)", "\t\tvisible := enrollment\n\t\tvisible.Credentials = nil\n\t\tfor _, credential := range enrollment.Credentials {\n\t\t\tif !credential.Revoked { visible.Credentials = append(visible.Credentials, credential) }\n\t\t}\n\t\tresult = append(result, visible)", "store", "TestHumanEnrollmentInventory", "inventory dropped revoked credentials or recorded registration bytes"),
    mutation("enrollment-inventory-config", "internal/v2/store/enrollment.go", "if config != s.deps.Config {", "if false {", "store", "TestHumanEnrollmentInventory", "inventory read another configuration", extra_edits=[["enrollment.Config != config || enrollment.PrincipalID != id","enrollment.Config != s.deps.Config || enrollment.PrincipalID != id"]]),
    mutation("continuation-claimed-epoch", "internal/v2/store/continuation_claim.go", " || result.CancellationEpoch != request.Intent.CancellationEpoch", "", "store", "TestContinuationLaunchGuards", "continuation claim accepted old_epoch", subtest="old_epoch"),
    mutation("capture-no-generic-ingress", "internal/v2/store/launch_fences.go", "if input.Internal != nil && input.Internal.Kind == api.InternalCaptureAppend && len(input.Events) != 0 {", "if false {", "store", "TestCaptureIngressCannotBeGeneric", "generic transaction forged primary capture provenance", extra_edits=[["if event.Kind == \"capture.appended\" || event.Kind == \"capture.closed\" {","if false {"]]),
    mutation("launch-private-metadata", "internal/v2/client/wire/visibility.go", "\tcase \"launch.planned\", \"capture.bound\", \"capture.refused\":\n\t\treturn false, nil", "\tcase \"launch.planned\", \"capture.bound\", \"capture.refused\":\n\t\treturn true, nil", "wire", "TestLaunchMetadataPrivacy", "private launch or capture metadata leaked to lane"),
    mutation("launch-issued-ceiling", "internal/v2/store/launch_issuance.go", "next.SourceObjectID == parent.SourceObjectID && next.SourceSHA256 == parent.SourceSHA256 && ", "", "store", "TestIssuedLaunchGrants", "planner issued launch grants outside foreign_source", subtest="foreign_source"),
    mutation("launch-issued-request", "internal/v2/store/launch_issuance.go", "\treturn s.launchCeiling(actual, limit, false)\n", "\treturn nil\n", "store", "TestIssuedLaunchGrants", "planner issued launch grants outside request_access", subtest="request_access"),
    mutation("lane-identity-reservation", "internal/v2/store/launch_fences.go", "\t\tif issued == 0 {\n\t\t\t// No historical identity-import emitter is declared in the closed\n\t\t\t// catalog. In particular lifecycle_effect and migration_apply are\n\t\t\t// not exceptions: imported history cannot mint a live identity.\n\t\t\treturn fault(api.CodeForbidden, \"lane identity requires its store-issued launch plan\")\n\t\t}\n", "\t\tif issued == 0 {\n\t\t\tcontinue\n\t\t}\n", "store", "TestLaneIdentityRequiresPlan", "unreserved lane identity accepted service", subtest="service"),
    mutation("lane-identity-historical", "internal/v2/store/launch_fences.go", "\t\tif issued == 0 {\n\t\t\t// No historical identity-import emitter is declared in the closed\n\t\t\t// catalog. In particular lifecycle_effect and migration_apply are\n\t\t\t// not exceptions: imported history cannot mint a live identity.\n\t\t\treturn fault(api.CodeForbidden, \"lane identity requires its store-issued launch plan\")\n\t\t}\n", "\t\tif issued == 0 {\n\t\t\tcontinue\n\t\t}\n", "store", "TestLaneIdentityRequiresPlan", "unreserved lane identity accepted legacy_import", subtest="legacy_import"),
    mutation("launch-failed-name-release", "internal/v2/store/launch_reservation.go", "\t\t\treleased = failed.Phase == \"failed\" && failed.Reservation.Target.LifeID == claimed.LifeID\n", "\t\t\treleased = false\n", "store", "TestFailedLaunchNameReuse", "failed unbound launch kept its lane name reserved"),
    mutation("launch-claimant", "internal/v2/store/effects.go", "\t\tif request.ClaimantID != scope.Actor.ID || scope.Actor.Kind != \"service\" {\n\t\t\treturn lease, fault(api.CodeForbidden, \"launch claimant differs from the authentic execution scope\")\n\t\t}\n", "", "store", "TestLaunchClaimantFence", "foreign claimant acquired a launch effect"),
    mutation("launch-completion-claimant", "internal/v2/store/effects.go", "\tif record.Effect.PlanLaunch != nil && record.ClaimantID != scope.Actor.ID {\n\t\treturn commit, fault(api.CodeForbidden, \"launch completion belongs to another claimant\")\n\t}\n", "", "store", "TestLaunchCompletionClaimant", "foreign claimant replayed measured launch outcome"),
    mutation("launch-foreign-cause", "internal/v2/store/launch_fences.go", "\t\treturn nil, fault(api.CodeForbidden, \"effect differs from its retained launch reservation\")\n", "", "store", "TestLaunchEffectCause", "foreign request cause acquired launch effect"),
    mutation("capture-peer-generation", "internal/v2/store/capture.go", " || facts.ProcessGeneration != binding.ProducerGeneration", " || facts.ProcessGeneration == \"\"", "store", "TestCaptureProducerGeneration", "capture replay accepted changed peer_generation", subtest="peer_generation"),
    mutation("capture-launch-generation", "internal/v2/store/capture.go", "launch.ProcessGeneration != binding.ProducerGeneration || ", "", "store", "TestCaptureProducerGeneration", "capture replay accepted changed launch_generation", subtest="launch_generation"),
    mutation("internal-operation-digest", "internal/v2/store/effects.go", "\t\tdigest = \"\"\n", "\t\tdigest = hash([]byte(operation.ID))\n", "store", "TestOperationDigestProvenance", "internal completion invented a public request digest", subtest="internal"),
    mutation("enrollment-native-commit", "internal/v2/store/internal.go", "return commit, fault(api.CodeForbidden, \"enrollment commit lacks its native administrator capability\")", "", "store", "TestEnrollmentValidationFences", "administrator install accepted direct_internal_commit", subtest="direct_internal_commit"),
    mutation("enrollment-challenge-config", "internal/v2/store/enrollment_ceremony.go", "return result, fault(api.CodeForbidden, \"enrollment challenge belongs to another configuration\")", "", "store", "TestEnrollmentCeremonyFences", "enrollment ceremony accepted foreign_config", subtest="foreign_config"),
    mutation("enrollment-validated-key", "internal/v2/store/enrollment_ceremony.go", "return challenge, fault(api.CodeForbidden, \"enrollment install differs from identity validation\")", "", "store", "TestEnrollmentExactBytes", "enrollment validation accepted a different validated key", subtest="validated_key"),
    mutation("identity-live-kind", "internal/v2/store/launch_fences.go", "return fault(api.CodeForbidden, \"live identity kind differs from its agent or fixed worker authority\")", "", "store", "TestIdentityKindFence", "live identity accepted missing kind", subtest="missing_kind"),
    mutation("proof-enrollment-config", "internal/v2/store/presence.go", "return api.HumanCredential{}, fault(api.CodeForbidden, \"proof enrollment belongs to another configuration\")", "", "store", "TestProofPresenceFences", "proof accepted changed foreign_enrollment", subtest="foreign_enrollment"),
    mutation("proof-current-credential", "internal/v2/store/presence.go", "return key, fault(api.CodeUnauthenticated, \"proof credential was revoked\")", "", "store", "TestProofPresenceFences", "proof accepted changed revoked_credential", subtest="revoked_credential"),
    mutation("policy-history-future", "internal/v2/store/policy_generation.go", "return api.EffectivePolicy{}, fault(api.CodeConflict, \"policy generation is not an approved retained snapshot\")", "", "store", "TestPolicyHistoryIntegrity", "policy history accepted future", subtest="future"),
    mutation("policy-refresh-sequence", "internal/v2/store/policy_generation.go", "return fault(api.CodeForbidden, \"policy refresh sequence differs from its actual journal head\")", "", "store", "TestPolicyRefreshJournal", "policy refresh accepted a caller supplied journal sequence", subtest="journal_head"),
    mutation("natural-state-fields", "internal/v2/store/natural_completion.go", "return fault(api.CodeForbidden, \"natural completion changed unrelated life state\")", "", "store", "TestNaturalCompletionCommit", "natural completion accepted changed_budget", subtest="changed_budget"),
    mutation("natural-measured-process", "internal/v2/store/natural_completion.go", "return fault(api.CodeContainmentUnknown, \"natural completion lacks the actual zero-survivor observation\")", "", "store", "TestNaturalObservationFence", "natural completion accepted a still running observation", subtest="still_running"),
    mutation("session-refresh-credential", "internal/v2/store/read_session.go", "return before, fault(api.CodeUnauthenticated, \"session refresh credential was revoked\")", "", "store", "TestSessionRefreshFences", "durable session refresh accepted revoked_credential", subtest="revoked_credential"),
    mutation("guidance-score-provenance", "internal/v2/store/guidance.go", "return api.NotImplemented(\"lb-v2-service\", \"guidance measured judgment provenance\")", "", "store", "TestGuidanceMeasuredScoreGate", "guidance accepted a score without measured judgment provenance", subtest="missing_judgment"),
    mutation("guidance-unscored-item", "internal/v2/store/guidance.go", "return fault(api.CodeForbidden, \"unscored guidance cannot claim a historical score\")", "", "store", "TestGuidanceMeasuredScoreGate", "unscored guidance accepted a nonbinding historical item", subtest="nonbinding_item"),
    mutation("enrollment-baseline-generation", "internal/v2/store/enrollment_ceremony.go", " || request.ExpectedGeneration != 0", "", "store", "TestEnrollmentCeremonyFences", "enrollment ceremony accepted later_baseline", subtest="later_baseline"),
    mutation("enrollment-expired-nonce", "internal/v2/store/enrollment_ceremony.go", "return result, api.ValidateEnrollmentChallenge(result, result.Ceremony, s.deps.Clock.Now())", "return result, nil", "store", "TestEnrollmentCeremonyFences", "enrollment ceremony accepted expired_nonce", subtest="expired_nonce"),
    mutation("enrollment-consumed-nonce", "internal/v2/store/enrollment_ceremony.go", "return result, api.ValidateEnrollmentChallenge(result, result.Ceremony, s.deps.Clock.Now())", "return result, nil", "store", "TestEnrollmentCeremonyFences", "enrollment ceremony accepted consumed_nonce", subtest="consumed_nonce"),
    mutation("proof-credential-presence", "internal/v2/store/presence.go", "key.SimulatedPresence != proof.SimulatedPresence || ", "", "store", "TestProofPresenceFences", "proof accepted changed credential_mark", subtest="credential_mark"),
    mutation("proof-reference-presence", "internal/v2/store/presence.go", " || proof.Ref.SimulatedPresence != proof.SimulatedPresence", "", "store", "TestProofPresenceFences", "proof accepted changed reference_mark", subtest="reference_mark"),
    mutation("presence-ticket", "internal/v2/store/presence.go", "return false, fault(api.CodeForbidden, \"ticket dropped verified presence provenance\")", "", "store", "TestPresenceWriteFences", "presence propagation accepted dropped ticket", subtest="ticket"),
    mutation("presence-session", "internal/v2/store/presence.go", "return false, fault(api.CodeForbidden, \"session dropped verified presence provenance\")", "", "store", "TestPresenceWriteFences", "presence propagation accepted dropped session", subtest="session"),
    mutation("presence-approval", "internal/v2/store/presence.go", "return false, fault(api.CodeForbidden, \"approval dropped verified presence provenance\")", "", "store", "TestPresenceWriteFences", "presence propagation accepted dropped approval", subtest="approval"),
    mutation("presence-application", "internal/v2/store/presence.go", "return false, fault(api.CodeForbidden, \"application dropped approval presence provenance\")", "", "store", "TestPresenceWriteFences", "presence propagation accepted dropped application", subtest="application"),
    mutation("presence-pending-operation", "internal/v2/store/transaction.go", "operation.SimulatedPresence = operation.SimulatedPresence || retained.SimulatedPresence", "", "store", "TestPendingPresenceSurvives", "pending operation completion dropped retained simulated presence", subtest="pending_operation"),
    mutation("presence-operation-evolution", "internal/v2/store/verify_atomic.go", " && (!before.SimulatedPresence || current.SimulatedPresence)", "", "store", "TestPresenceEvolution", "operation evolution erased retained simulated presence", subtest="retained_mark"),
    mutation("policy-history-hash", "internal/v2/store/policy_generation.go", "return api.EffectivePolicy{}, fault(api.CodeIntegrity, \"approved policy history is ambiguous or corrupt\")", "", "store", "TestPolicyHistoryIntegrity", "policy history accepted hash", subtest="hash"),
    mutation("policy-history-ambiguous", "internal/v2/store/atomic_support.go", "return fault(api.CodeConflict, \"typed projection generation changed\")", "", "store", "TestPolicyHistoryIntegrity", "policy history accepted ambiguous", subtest="ambiguous"),
    mutation("prepared-foreign-commit", "internal/v2/store/authority.go", "return input, fault(api.CodeForbidden, \"prepared binding differs from its exact atomic identity event\")", "", "store", "TestPreparedIdentityBytes", "prepared identity accepted foreign_commit", subtest="foreign_commit"),
    mutation("prepared-missing-event", "internal/v2/store/authority.go", "return input, fault(api.CodeForbidden, \"prepared binding differs from its exact atomic identity event\")", "", "store", "TestPreparedIdentityBytes", "prepared identity accepted missing_event", subtest="missing_event"),
    mutation("plan-read-foreign-record", "internal/v2/service/launch_control.go", "return api.LaunchPlanRecord{}, serviceError(api.CodeIntegrity, \"retained plan read returned another reservation\")", "", "service", "TestPrivatePlanRead", "private plan source accepted a different retained reservation", subtest="foreign_result"),
    mutation("plan-read-current-claim", "internal/v2/store/launch_control.go", "if record.ClaimID != claim || record.Generation != generation || record.Outcome != nil || !future(record.ClaimExpiresAt, s.deps.Clock.Now()) {", "if record.ClaimID != claim || record.Generation != generation || record.Outcome != nil {", "service", "TestPrivatePlanRead", "private plan read accepted an expired durable claim", subtest="expired_claim"),
    mutation("natural-missing-cas", "internal/v2/store/natural_completion.go", "!cas || ", "", "store", "TestNaturalCompletionCommit", "natural completion accepted missing_cas", subtest="missing_cas"),
    mutation("natural-missing-epoch", "internal/v2/store/natural_completion.go", "!epoch || ", "", "store", "TestNaturalCompletionCommit", "natural completion accepted missing_epoch", subtest="missing_epoch"),
    mutation("natural-missing-state", "internal/v2/store/natural_completion.go", " || !state", "", "store", "TestNaturalCompletionCommit", "natural completion accepted missing_state", subtest="missing_state"),
    mutation("natural-foreign-observation", "internal/v2/store/natural_completion.go", "!ended || ", "", "store", "TestNaturalCompletionCommit", "natural completion accepted foreign_observation", subtest="foreign_observation"),
    mutation("natural-end-budget", "internal/v2/store/natural_completion.go", " && sameValue(end.BudgetRemaining, next.BudgetRemaining)", "", "store", "TestNaturalCompletionCommit", "natural completion accepted changed_end_budget", subtest="changed_end_budget"),
    mutation("natural-committed-head", "internal/v2/store/transaction.go", "input.Writes.Lanes[0].LastSeq = head + api.Sequence(len(input.Events))", "", "store", "TestNaturalCompletionCommit", "natural completion lost its actual committed journal head", subtest="valid"),
    mutation("reservation-ticket-grant-set", "internal/v2/store/launch_reservation.go", "if request.Guards[i].Ticket == nil || *request.Guards[i].Ticket != want {", "if request.Guards[i].Ticket == nil {", "store", "TestReservationAuthority", "reservation accepted authority foreign_grant_set", extra_edits=[["want.Target = api.LifeRef{}","want.Target = api.LifeRef{}\n\t\t\t_ = want"]], subtest="foreign_grant_set"),
    mutation("reservation-authority-id", "internal/v2/store/launch_reservation.go", "result.Authority = api.LaunchAuthority{Kind: \"ticket\", ID: guard.Ticket.TicketID}", "result.Authority = api.LaunchAuthority{Kind: \"ticket\", ID: request.OperationID}", "store", "TestReservationAuthority", "reservation lost its actual consumed authority or child pins", subtest="missing_ticket"),
    mutation("session-refresh-expired-idle", "internal/v2/store/read_session.go", "\tif err := api.ValidateReadSessionRefresh(scope, before, after, now); err != nil {\n\t\treturn api.StoredReadSession{}, err\n\t}\n", "", "store", "TestSessionRefreshFences", "durable session refresh accepted expired_idle", subtest="expired_idle"),
    mutation("session-refresh-expired-absolute", "internal/v2/store/read_session.go", "\tif err := api.ValidateReadSessionRefresh(scope, before, after, now); err != nil {\n\t\treturn api.StoredReadSession{}, err\n\t}\n", "", "store", "TestSessionRefreshFences", "durable session refresh accepted expired_absolute", subtest="expired_absolute"),
    mutation("session-refresh-revoked", "internal/v2/store/read_session.go", "\tif err := api.ValidateReadSessionRefresh(scope, before, after, now); err != nil {\n\t\treturn api.StoredReadSession{}, err\n\t}\n", "", "store", "TestSessionRefreshFences", "durable session refresh accepted revoked", subtest="revoked"),
    mutation("transport-refresh-principal", "internal/v2/service/connection.go", "\tif err := api.ValidateReadAuthorityUpdate(*c.authority, update); err != nil {\n\t\treturn err\n\t}\n", "", "service", "TestReadAuthorityRefresh", "transport refresh accepted principal", subtest="principal"),
    mutation("transport-refresh-absolute-expiry", "internal/v2/service/connection.go", "\tif err := api.ValidateReadAuthorityUpdate(*c.authority, update); err != nil {\n\t\treturn err\n\t}\n", "", "service", "TestReadAuthorityRefresh", "transport refresh accepted absolute_expiry", subtest="absolute_expiry"),
    mutation("transport-refresh-stale-revision", "internal/v2/service/connection.go", "\tif err := api.ValidateReadAuthorityUpdate(*c.authority, update); err != nil {\n\t\treturn err\n\t}\n", "", "service", "TestReadAuthorityRefresh", "transport refresh accepted stale_revision", subtest="stale_revision"),
    mutation("transport-session-bind-once", "internal/v2/service/connection.go", "return serviceError(api.CodeForbidden, \"read authority binds once per connection\")", "", "service", "TestReadAuthorityRefresh", "transport rebound a one use read authority", subtest="rebind"),
    mutation("guidance-owner-attempt", "internal/v2/store/guidance.go", "\tif err := api.ValidateGuidanceCompletion(retained, selection, *input.Internal, s.deps.Clock.Now()); err != nil {\n\t\treturn err\n\t}\n", "", "store", "TestGuidanceOwnerFences", "guidance completion accepted foreign attempt", subtest="attempt"),
    mutation("guidance-owner-operation", "internal/v2/store/guidance.go", "\tif err := api.ValidateGuidanceCompletion(retained, selection, *input.Internal, s.deps.Clock.Now()); err != nil {\n\t\treturn err\n\t}\n", "", "store", "TestGuidanceOwnerFences", "guidance completion accepted foreign operation", subtest="operation"),
    mutation("guidance-owner-requester", "internal/v2/store/guidance.go", "\tif err := api.ValidateGuidanceCompletion(retained, selection, *input.Internal, s.deps.Clock.Now()); err != nil {\n\t\treturn err\n\t}\n", "", "store", "TestGuidanceOwnerFences", "guidance completion accepted foreign requester", subtest="requester"),
    mutation("guidance-owner-claim", "internal/v2/store/guidance.go", "\tif err := api.ValidateGuidanceCompletion(retained, selection, *input.Internal, s.deps.Clock.Now()); err != nil {\n\t\treturn err\n\t}\n", "", "store", "TestGuidanceOwnerFences", "guidance completion accepted foreign claim", subtest="claim"),
    mutation("guidance-owner-early-recovery", "internal/v2/store/guidance.go", "\tif err := api.ValidateGuidanceCompletion(retained, selection, *input.Internal, s.deps.Clock.Now()); err != nil {\n\t\treturn err\n\t}\n", "", "store", "TestGuidanceOwnerFences", "guidance completion accepted foreign early_recovery", subtest="early_recovery"),
    mutation("guidance-await-deadline", "internal/v2/store/guidance.go", "\t\t\tdeadline = claimDeadline\n", "", "store", "TestGuidanceAwaitDeadline", "guidance await reset its retained claim deadline", subtest="claim_deadline"),
    mutation("capture-policy-foreign-manifest", "internal/v2/store/capture_policy.go", "return fault(api.CodeForbidden, \"capture policy lacks its actual consumed D6 publication receipt\")", "", "store", "TestCaptureRefusalD6Provenance", "capture refusal accepted unproved D6 foreign_manifest", subtest="foreign_manifest"),
    mutation("capture-policy-foreign-generation", "internal/v2/store/capture_policy.go", "return fault(api.CodeForbidden, \"capture policy lacks its actual consumed D6 publication receipt\")", "", "store", "TestCaptureRefusalD6Provenance", "capture refusal accepted unproved D6 foreign_generation", subtest="foreign_generation"),
    mutation("guidance-one-winner", "internal/v2/store/guidance.go", "\tresult.Acquired = true\n", "\tresult.Acquired = false\n", "store", "TestGuidanceOneWinner", "guidance reservation did not grant exactly one evaluation owner"),
    mutation("guidance-observer-no-acquire", "internal/v2/store/guidance.go", "\tif err == nil {\n\t\treturn result, nil\n\t}\n", "\tif err == nil {\n\t\tresult.Acquired = true\n\t\treturn result, nil\n\t}\n", "store", "TestGuidanceOneWinner", "guidance reservation did not grant exactly one evaluation owner"),
    mutation("session-refresh-binding-config", "internal/v2/store/read_session.go", " || scope.Connection.Binding().Config != scope.Config", "", "store", "TestSessionRefreshFences", "durable session refresh accepted foreign_binding", subtest="foreign_binding"),
    mutation("enrollment-channel-recheck", "internal/v2/store/internal.go", "\t\t\tif err := wire.VerifyAdministrator(ctx, *s.deps.Enrollment, capability.NativeScope.Connection, capability.NativeScope.Frame); err != nil {\n\t\t\t\treturn commit, err\n\t\t\t}\n", "", "store", "TestEnrollmentValidationFences", "administrator install accepted commit_channel_recheck", subtest="commit_channel_recheck"),
    mutation("capture-publication-event", "internal/v2/store/capture_policy.go", "return s.capturePublication(ctx, db, used, receipt)", "return nil", "store", "TestCaptureRefusalD6Provenance", "capture refusal accepted unproved D6 missing_event", subtest="missing_event"),
    mutation("capture-event-receipt", "internal/v2/store/capture_policy.go", "!sameValue(*publication.Receipt, receipt) ||", "", "store", "TestCaptureRefusalD6Provenance", "capture refusal accepted unproved D6 event_receipt", subtest="event_receipt"),
    mutation("capture-event-change", "internal/v2/store/capture_policy.go", "publication.Change.ID != receipt.ChangeID || ", "", "store", "TestCaptureRefusalD6Provenance", "capture refusal accepted unproved D6 event_change", subtest="event_change"),
    mutation("capture-event-origin", "internal/v2/store/capture_policy.go", "event.Origin != \"service\" || ", "", "store", "TestCaptureRefusalD6Provenance", "capture refusal accepted unproved D6 event_origin", subtest="event_origin"),
    mutation("capture-event-approval", "internal/v2/store/capture_policy.go", "return fault(api.CodeForbidden, \"capture publication changed its consumed approval\")", "", "store", "TestCaptureRefusalD6Provenance", "capture refusal accepted unproved D6 event_approval", subtest="event_approval"),
    mutation("reservation-one-owner", "internal/v2/store/receipts.go", "return previous, false, nil", "return previous, true, nil", "store", "TestReservationOneWinner", "identical reservations did not have exactly one winner", subtest="identical_invocations"),
    mutation("reservation-insertion-owner", "internal/v2/store/receipts.go", "return receipt, true, nil", "return receipt, false, nil", "store", "TestReservationOneWinner", "identical reservations did not have exactly one winner", subtest="identical_invocations"),
    mutation("dispatch-await-winner", "internal/v2/service/" "dispatch_mutation.go", "if !won {", "if !won && receipt.Operation.ID == \"\" {", "service", "TestMutationRetryAwaitsWinner", "same request ran mutation preflight twice", subtest="same_request"),
    mutation("mutation-owner-context", "internal/v2/service/mutation_owner.go", "\tif owner == nil || owner.server != s || !owner.active.Load() || owner.config != scope.Config || owner.actor != scope.Actor || owner.launch != scope.LaunchID || owner.endpoint != scope.EndpointGeneration || owner.key != key || owner.operation != operation || owner.request != scope.Request.RequestID {\n\t\treturn false, nil\n\t}", "\tif owner == nil || owner.server != s || !owner.active.Load() || owner.config != scope.Config || owner.actor != scope.Actor || owner.launch != scope.LaunchID || owner.endpoint != scope.EndpointGeneration || owner.key != key || owner.operation != operation || owner.request != scope.Request.RequestID {\n\t\treturn true, nil\n\t}", "service", "TestMutationOwnerFences", "mutation ownership accepted fresh_context", subtest="fresh_context"),
    mutation("mutation-owner-operation", "internal/v2/service/mutation_owner.go", "\tif owner == nil || owner.server != s || !owner.active.Load() || owner.config != scope.Config || owner.actor != scope.Actor || owner.launch != scope.LaunchID || owner.endpoint != scope.EndpointGeneration || owner.key != key || owner.operation != operation || owner.request != scope.Request.RequestID {\n\t\treturn false, nil\n\t}", "\tif owner == nil || owner.server != s || !owner.active.Load() || owner.config != scope.Config || owner.actor != scope.Actor || owner.launch != scope.LaunchID || owner.endpoint != scope.EndpointGeneration || owner.key != key || owner.operation != operation || owner.request != scope.Request.RequestID {\n\t\treturn true, nil\n\t}", "service", "TestMutationOwnerFences", "mutation ownership accepted foreign_operation", subtest="foreign_operation"),
    mutation("mutation-owner-actor", "internal/v2/service/mutation_owner.go", "\tif owner == nil || owner.server != s || !owner.active.Load() || owner.config != scope.Config || owner.actor != scope.Actor || owner.launch != scope.LaunchID || owner.endpoint != scope.EndpointGeneration || owner.key != key || owner.operation != operation || owner.request != scope.Request.RequestID {\n\t\treturn false, nil\n\t}", "\tif owner == nil || owner.server != s || !owner.active.Load() || owner.config != scope.Config || owner.actor != scope.Actor || owner.launch != scope.LaunchID || owner.endpoint != scope.EndpointGeneration || owner.key != key || owner.operation != operation || owner.request != scope.Request.RequestID {\n\t\treturn true, nil\n\t}", "service", "TestMutationOwnerFences", "mutation ownership accepted foreign_actor", subtest="foreign_actor"),
    mutation("mutation-owner-key", "internal/v2/service/mutation_owner.go", "\tif owner == nil || owner.server != s || !owner.active.Load() || owner.config != scope.Config || owner.actor != scope.Actor || owner.launch != scope.LaunchID || owner.endpoint != scope.EndpointGeneration || owner.key != key || owner.operation != operation || owner.request != scope.Request.RequestID {\n\t\treturn false, nil\n\t}", "\tif owner == nil || owner.server != s || !owner.active.Load() || owner.config != scope.Config || owner.actor != scope.Actor || owner.launch != scope.LaunchID || owner.endpoint != scope.EndpointGeneration || owner.key != key || owner.operation != operation || owner.request != scope.Request.RequestID {\n\t\treturn true, nil\n\t}", "service", "TestMutationOwnerFences", "mutation ownership accepted foreign_key", subtest="foreign_key"),
    mutation("mutation-owner-retirement", "internal/v2/service/mutation_owner.go", "\tdefer owner.active.Store(false)\n", "", "service", "TestMutationOwnerFences", "mutation ownership accepted retired", subtest="retired"),
    mutation("dispatch-atomic-port", "internal/v2/service/" "dispatch_mutation.go", "\t\tif !ok {\n\t\t\treturn nil, scope, api.NotImplemented(\"lb-v2-service\", \"atomic mutation reservation ownership\")\n\t\t}", "\t\tif !ok {\n\t\t\tresult, err := s.handlers[request.Method](ctx, scope, request.Params)\n\t\t\treturn result, scope, err\n\t\t}", "service", "TestMutationNeedsAtomicStore", "dispatcher without atomic winner ran preflight", subtest="missing_port"),
    mutation("dispatch-reservation-config", "internal/v2/service/" "dispatch_mutation.go", "return nil, scope, serviceError(api.CodeIntegrity, \"atomic mutation reservation returned another request\")", "", "service", "TestMutationReservationPins", "mutation reservation accepted foreign_config", subtest="foreign_config"),
    mutation("dispatch-reservation-frame", "internal/v2/service/" "dispatch_mutation.go", "return nil, scope, serviceError(api.CodeIntegrity, \"mutation winner lacks its original pending reservation\")", "", "service", "TestMutationReservationPins", "mutation reservation accepted foreign_frame", subtest="foreign_frame"),
    mutation("health-later-frame", "internal/v2/service/server.go", "return nil, scope, serviceError(api.CodeForbidden, \"health requires a new public-health connection\")", "", "service", "TestOpenedConnectionRejectsHealth", "opened connection dispatched health"),
    mutation("health-public-context", "internal/v2/service/stub.go", "return api.Health{}, serviceError(api.CodeForbidden, \"health requires the first-frame public health path\")", "", "service", "TestHealthNeedsPublicContext", "health without public context was accepted"),
    mutation("client-health-release", "internal/v2/client/client.go", "connection, persistent = nil, false", "connection, persistent = nil, c.binding != nil", "client", "TestCallAfterHealth", "health call retained its one-request socket", subtest="success"),
    mutation("client-health-refusal", "internal/v2/client/client.go", "connection, persistent = nil, false", "connection, persistent = nil, c.binding != nil", "client", "TestCallAfterHealth", "health call retained its one-request socket", subtest="refusal"),
    mutation("client-health-session", "internal/v2/client/client.go", "connection, persistent = nil, false", "persistent = false", "client", "TestHealthKeepsSession", "health interrupted the existing read session"),
    mutation("reconcile-claim-forbidden", "internal/v2/service/reconcile_attempt.go", "\tif effectFenceRefused(err) {\n\t\treturn attempt.deferEffect(\"claim\", err, effect.ID, retries)\n\t}\n\tvar typed *api.Error\n", "\tvar typed *api.Error\n", "service", "TestReconcileSkipsEffectFences", "per-effect refusal stopped later work", subtest="claim_forbidden"),
    mutation("reconcile-complete-forbidden", "internal/v2/service/reconcile_attempt.go", "\tif _, err := s.deps.Store.CompleteEffect(ctx, scope, outcome); err != nil {\n\t\tif effectFenceRefused(err) {\n\t\t\treturn attempt.deferEffect(\"complete\", err, effect.ID, retries)\n\t\t}\n", "\tif _, err := s.deps.Store.CompleteEffect(ctx, scope, outcome); err != nil {\n", "service", "TestReconcileSkipsEffectFences", "per-effect refusal stopped later work", subtest="complete_forbidden"),
    mutation("reconcile-run-forbidden", "internal/v2/service/reconcile_attempt.go", "\t\tif refusal != nil {\n", "\t\tif effectFenceRefused(err) {\n\t\t\ts.recordFault(err)\n\t\t\treturn attemptNext\n\t\t}\n\t\tif refusal != nil {\n", "service", "TestReconcileSkipsEffectFences", "per-effect fence latched host fault", subtest="run_forbidden"),
    mutation("reconcile-claim-conflict", "internal/v2/service/reconcile_attempt.go", "\tif effectFenceRefused(err) {\n\t\treturn attempt.deferEffect(\"claim\", err, effect.ID, retries)\n\t}\n\tvar typed *api.Error\n", "\tvar typed *api.Error\n", "service", "TestReconcileSkipsEffectFences", "per-effect refusal stopped later work", subtest="claim_conflict"),
    mutation("reconcile-complete-conflict", "internal/v2/service/reconcile_attempt.go", "\tif _, err := s.deps.Store.CompleteEffect(ctx, scope, outcome); err != nil {\n\t\tif effectFenceRefused(err) {\n\t\t\treturn attempt.deferEffect(\"complete\", err, effect.ID, retries)\n\t\t}\n", "\tif _, err := s.deps.Store.CompleteEffect(ctx, scope, outcome); err != nil {\n", "service", "TestReconcileSkipsEffectFences", "per-effect refusal stopped later work", subtest="complete_conflict"),
    mutation("reconcile-run-conflict", "internal/v2/service/reconcile_attempt.go", "\t\tif refusal != nil {\n", "\t\tif effectFenceRefused(err) {\n\t\t\ts.recordFault(err)\n\t\t\treturn attemptNext\n\t\t}\n\t\tif refusal != nil {\n", "service", "TestReconcileSkipsEffectFences", "per-effect fence latched host fault", subtest="run_conflict"),
    mutation("reconcile-integrity-fatal", "internal/v2/service/reconcile.go", "return failure != nil && (failure.Code == api.CodeForbidden || failure.Code == api.CodeConflict)", "return failure != nil && (failure.Code == api.CodeForbidden || failure.Code == api.CodeConflict || failure.Code == api.CodeIntegrity)", "service", "TestReconcileKeepsStoreFailures", "reconciler lost a store or integrity failure", subtest="claim_integrity"),
    mutation("reconcile-raw-fatal", "internal/v2/service/reconcile.go", "\treturn false\n}\n\nfunc (s *Server) recordFault", "\treturn err != nil\n}\n\nfunc (s *Server) recordFault", "service", "TestReconcileKeepsStoreFailures", "reconciler lost a store or integrity failure", subtest="claim_store"),
    mutation("reconcile-joined-fatal", "internal/v2/service/reconcile.go", "\t\tfor _, cause := range causes {\n\t\t\tif !effectFenceRefused(cause) {\n\t\t\t\treturn false\n\t\t\t}\n\t\t}\n\t\treturn true", "\t\tfor _, cause := range causes {\n\t\t\tif effectFenceRefused(cause) {\n\t\t\t\treturn true\n\t\t\t}\n\t\t}\n\t\treturn false", "service", "TestReconcileKeepsStoreFailures", "reconciler lost a store or integrity failure", subtest="claim_mixed"),
    mutation("reconcile-complete-fatal", "internal/v2/service/reconcile_attempt.go", "\t\treturn attempt.fault(\"complete\", err)\n", "\t\treturn attemptNext\n", "service", "TestReconcileKeepsStoreFailures", "reconciler lost a store or integrity failure", subtest="complete_integrity"),
    mutation("orphan-reservation-finalize", "internal/v2/store/reservation_recovery.go", "\t\tif err := s.failAbandonedReservation(ctx, row); err != nil {\n\t\t\treturn err\n\t\t}\n", "", "store", "TestReservationRecovery", "orphan reservation remained pending", subtest="reopen"),
    mutation("reservation-live-owner", "internal/v2/store/reservation_recovery.go", "\t\tif owner := s.reservationOwners[row.operation]; owner != nil && owner.live {\n\t\t\tcontinue\n\t\t}\n", "", "store", "TestReservationRecovery", "recovery finalized a live or unexpired reservation", subtest="live_owner"),
    mutation("reservation-before-deadline", "internal/v2/store/reservation_recovery.go", "\t\tif s.deps.Clock.Now().Before(deadline) {\n\t\t\tcontinue\n\t\t}\n", "\t\t_ = deadline\n", "store", "TestReservationRecovery", "recovery finalized a live or unexpired reservation", subtest="before_deadline"),
    mutation("reservation-untracked-owner", "internal/v2/store/receipts.go", "\ts.reservationOwners[id] = owner\n", "", "store", "TestReservationRecovery", "recovery finalized a live or unexpired reservation", subtest="untracked_owner"),
    mutation("reservation-effect-handoff", "internal/v2/store/reservation_recovery.go", "\t\tif effects != 0 {\n\t\t\tcontinue\n\t\t}\n", "", "store", "TestRecoveryKeepsEffectHandoff", "reservation recovery discarded a durable effect handoff"),
    mutation("reservation-invocation-retirement", "internal/v2/service/dispatch_mutation.go", "\t\t\tdefer retire()\n", "\t\t\tdefer func() { _ = retire }()\n", "service", "TestMutationRetirementRecovery", "returned mutation kept its reservation live"),
    mutation("reservation-recovery-freeze", "internal/v2/service/reconcile.go", "\tif recovery, ok := s.deps.Store.(interface{ RecoverReservations(context.Context) error }); ok {\n\t\tif err := recovery.RecoverReservations(ctx); err != nil {\n\t\t\treturn false, err\n\t\t}\n\t}\n", "", "service", "TestFrozenReservationRecovery", "deployment freeze prevented reservation recovery"),
    mutation("reservation-recovery-fatal", "internal/v2/service/reconcile.go", "\tif recovery, ok := s.deps.Store.(interface{ RecoverReservations(context.Context) error }); ok {\n\t\tif err := recovery.RecoverReservations(ctx); err != nil {\n\t\t\treturn false, err\n\t\t}\n\t}\n", "\tif recovery, ok := s.deps.Store.(interface{ RecoverReservations(context.Context) error }); ok {\n\t\tif err := recovery.RecoverReservations(ctx); err != nil {\n\t\t\treturn false, nil\n\t\t}\n\t}\n", "service", "TestReservationRecoveryFault", "reservation recovery discarded its store failure"),
    mutation("execution-refusal-terminal", "internal/v2/service/reconcile_attempt.go", "\t\t\toutcome = api.EffectOutcome{EffectID: effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: \"failed\", Error: refusal}\n", "\t\t\treturn attempt.deferEffect(\"run\", err, effect.ID, retries)\n", "service", "TestExecutionRefusalTerminal", "execution refusal remained pending", subtest="plain"),
    mutation("execution-refusal-joined", "internal/v2/service/reconcile.go", "\treturn forbiddenCause(err)\n", "\treturn nil\n", "service", "TestExecutionRefusalTerminal", "execution refusal remained pending", subtest="joined"),
    mutation("effect-retry-backoff", "internal/v2/service/effect_retry.go", "\treturn !now.Before(r[id].after)\n", "\treturn true\n", "service", "TestEffectRetryBackoff", "refused effect retried before its backoff"),
    mutation("effect-retry-reset", "internal/v2/service/effect_retry.go", "\tdelete(r, id)\n", "", "service", "TestEffectRetryBackoff", "completed effect retained its backoff"),
    mutation("health-build-variant", "internal/v2/service/stub.go", "\tcapabilities = append(capabilities, buildCapability())\n", "", "service", "TestHealthBuildVariant", "health omitted the compiled build variant"),
    mutation("lane-stale-recovery", "internal/v2/service/lane_listener_linux.go", "\tif err := recoverLaneSocket(ctx, binding); err != nil {\n\t\treturn nil, err\n\t}\n", "", "service", "TestLaneSocketRecovery", "acceptance: stale service-owned lane socket blocked recovery", subtest="stale"),
    mutation("lane-live-preserved", "internal/v2/service/" "lane_socket_recovery_linux.go", "if !errors.Is(connectErr, unix.ECONNREFUSED) {", "if false && !errors.Is(connectErr, unix.ECONNREFUSED) {", "service", "TestLaneSocketRecovery", "acceptance: lane recovery removed a live, linked or non-socket entry", subtest="live"),
    mutation("lane-inode-preserved", "internal/v2/service/" "lane_socket_recovery_linux.go", "current.Dev != retained.Dev || current.Ino != retained.Ino", "current.Mode != retained.Mode", "service", "TestLaneSocketReplacement", "acceptance: stale recovery unlinked a replaced or foreign inode", subtest="replaced"),
    mutation("lane-owner-preserved", "internal/v2/service/" "lane_socket_recovery_linux.go", "inode.Uid == binding.ServiceUID && inode.Gid == binding.ServiceGID", "true", "service", "TestLaneSocketReplacement", "acceptance: stale recovery unlinked a replaced or foreign inode", subtest="owner"),
    mutation("abandon-target-grammar", "internal/v2/client/wire/json.go", "if t == reflect.TypeFor[api.MarkRequest]() && name == \"review\" {", "if t == reflect.TypeFor[api.MarkRequest]() && (name == \"review\" || name == \"target\") {", "wire", "TestAbandonEmptyReview", "acceptance: abandonment schema admitted malformed or non-abandon empty review", subtest="target-id"),
]


class CheckFailure(RuntimeError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def inventory(root):
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise CheckFailure("source snapshot contains a symlink")
        if path.is_file():
            data = path.read_bytes()
            rows.append({"path": path.relative_to(root).as_posix(),
                         "bytes": len(data), "sha256": sha(data)})
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return {"files": rows, "sha256": sha(encoded)}


def dependency_files(source, evidence):
    """Retain both test graphs, including local packages outside internal/v2."""
    evidence.mkdir(mode=0o700)
    files, directories = set(), set()
    decoder = json.JSONDecoder()
    for variant, flags in VARIANTS:
        step(variant=variant, mutation="candidate",
             stage="dependency-list", exit=None)
        log = evidence / (variant + ".log")
        status, output = command(
            ["go", "list", "-mod=readonly", "-deps", "-test", "-json",
             *flags, *PACKAGES.values()], source, log, split_stderr=True)
        if status != 0:
            failure("dependency discovery failed", output +
                    log.with_suffix(".stderr").read_text())
            raise CheckFailure("dependency discovery failed")
        position = 0
        while position < len(output):
            while position < len(output) and output[position].isspace():
                position += 1
            if position == len(output):
                break
            package, position = decoder.raw_decode(output, position)
            if not isinstance(package, dict) or package.get("Error"):
                raise CheckFailure("invalid dependency package metadata")
            module = package.get("Module") or {}
            if not module.get("Main"):
                continue
            if package.get("ImportPath", "").endswith(".test"):
                continue  # Go generates test mains; they are not source files.
            root = Path(package["Dir"])
            root.resolve(strict=True).relative_to(source)
            if root.is_symlink() or not root.is_dir():
                raise CheckFailure("dependency root is missing or linked")
            directories.add(root.relative_to(source).as_posix())
            # Include other platform Go files as well as this variant's
            # native/embedded inputs. Testdata is runtime input, not a cache.
            files.update(root.glob("*.go"))
            for field in PACKAGE_FILES:
                files.update(root / name for name in package.get(field, []))
            data = root / "testdata"
            if data.is_symlink():
                raise CheckFailure("dependency testdata is linked")
            if data.is_dir():
                files.update(path for path in data.rglob("*")
                             if path.is_file() or path.is_symlink())
    required = {name.removeprefix("./") for name in PACKAGES.values()}
    if not required <= directories:
        raise CheckFailure("dependency graph omitted a component package")
    write_json(evidence / "packages.json",
               {"variants": [name for name, _ in VARIANTS],
                "packages": sorted(directories)})
    return files


def snapshot(source, target, evidence):
    target.mkdir(mode=0o700)
    files = {source / name for name in ("go.mod", "go.sum")}
    for name in ROOTS:
        root = source / name
        if root.is_symlink() or not root.is_dir():
            raise CheckFailure("focused source root is missing or linked")
        files.update(root.rglob("*.go"))
    files.update(dependency_files(source, evidence))
    for path in sorted(files):
        if path.is_symlink() or not path.is_file():
            raise CheckFailure("focused source input is missing or linked")
        relative = path.relative_to(source)
        path.resolve(strict=True).relative_to(source)
        destination = target / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.write_bytes(path.read_bytes())
    return inventory(target)


def group_gone(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def command(argv, cwd, log, *, split_stderr=False, timeout=300):
    process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE,
                               stderr=(subprocess.PIPE if split_stderr
                                       else subprocess.STDOUT),
                               start_new_session=True)
    timed_out = False
    termination = "not_needed"
    try:
        output, diagnostics = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
            termination = "group_killed_by_pid"
        except ProcessLookupError:
            termination = "group_already_gone"
        output, diagnostics = process.communicate(timeout=30)
    log.write_bytes(output)
    step(exit=process.returncode, log=str(log))
    quiescent = group_gone(process.pid)
    observation = {"argv": argv, "exit": process.returncode,
                   "timeout_seconds": timeout,
                   "timed_out": timed_out, "termination": termination,
                   "process_group_quiescent": quiescent,
                   "output": {"path": log.name, "sha256": sha(output),
                              "bytes": len(output)}}
    if split_stderr:
        diagnostics = diagnostics or b""
        stderr_log = log.with_suffix(".stderr")
        stderr_log.write_bytes(diagnostics)
        observation["stderr"] = {"path": stderr_log.name,
                                 "sha256": sha(diagnostics),
                                 "bytes": len(diagnostics)}
    write_json(log.with_suffix(".json"), observation)
    if timed_out or not quiescent:
        failure("command timeout or surviving process group",
                (output + (diagnostics or b"")).decode("utf-8", "replace"))
        raise CheckFailure("command timeout or surviving process group")
    return process.returncode, output.decode("utf-8", "replace")


def build(source, folder, package, flags):
    step(stage="build", package=package, exit=None)
    binary = folder / "component.test"
    status, output = command(["go", "test", "-c", "-race", *flags,
                         "-o", str(binary), PACKAGES[package]],
                        source, folder / "build.log")
    if status != 0 or not binary.is_file():
        failure("test binary build failed; no mutation credit", output)
        raise CheckFailure("test binary build failed; no mutation credit")
    data = binary.read_bytes()
    result = {"path": binary.name, "sha256": sha(data), "bytes": len(data), "flags": list(flags)}
    write_json(folder / "binary.json", result)
    return binary, result


def tests_in(source, package, files=None):
    root = source / PACKAGES[package].removeprefix("./")
    names = set()
    paths = root.glob("*_test.go") if files is None else (root / name for name in files)
    for path in paths:
        names.update(re.findall(r"^func (Test\w+)\(t \*testing\.T\)",
                                path.read_text(), re.MULTILINE))
    if not names:
        raise CheckFailure("candidate has no declared component tests")
    return names


def selected_tests(source, package, flags, folder):
    """Go selects files for the same platform/tags used to build this binary."""
    status, output = command(["go", "list", "-race", "-mod=readonly", "-json", *flags, PACKAGES[package]],
                             source, folder / "test-files.log", split_stderr=True)
    if status != 0:
        raise CheckFailure("cannot select declared component tests")
    selected = json.loads(output)
    files = selected.get("TestGoFiles", []) + selected.get("XTestGoFiles", [])
    if selected.get("Error") or not files or any(Path(name).name != name or not name.endswith("_test.go") for name in files):
        raise CheckFailure("invalid selected component test files")
    names = tests_in(source, package, files)
    write_json(folder / "declared-tests.json", {"flags": flags, "files": sorted(files), "tests": sorted(names)})
    return names


def preflight_mutations(source, selected):
    """Validate every named source edit before any expensive build or test."""
    observations = []
    for case in selected:
        step(variant="preflight", mutation=case["id"], stage="mutation-anchor", exit=None)
        text = (source / case["file"]).read_text()
        for number, (old, new) in enumerate(case["edits"], 1):
            count = text.count(old)
            if count != 1 or old == new:
                raise CheckFailure("mutation edit %d anchor count=%d: %s" % (number, count, case["id"]))
            text = text.replace(old, new, 1)
        if case["test"] not in tests_in(source, case["package"]):
            raise CheckFailure("named mutation test is absent: " + case["test"])
        observations.append({"mutation": case["id"], "edits": len(case["edits"]),
                             "test": case["test"], "subtest": case["subtest"], "anchors": "unique"})
    return observations


def run_test(binary, metadata, source, folder, test=None, marker=None, subtest=None):
    target = test + "/" + subtest if subtest else test
    target_paths = {"/".join(target.split("/")[:end])
                    for end in range(1, len(target.split("/")) + 1)} if target else set()
    step(stage="red-test" if marker else "candidate-test", test=test,
         subtest=subtest, target=target, exit=None)
    expected = {test} if test else selected_tests(source, folder.name, metadata["flags"], folder)
    argv = [str(binary), "-test.v=true", "-test.count=1", "-test.timeout=" + TEST_TIMEOUT]
    if test:
        selector = "^" + re.escape(test) + "$"
        if subtest:
            selector += "/" + "/".join("^" + re.escape(part) + "$" for part in subtest.split("/"))
        argv.append("-test.run=" + selector)
    status, output = command(argv, source, folder / "test.log", timeout=TEST_PROCESS_TIMEOUT_SECONDS)
    if sha(binary.read_bytes()) != metadata["sha256"]:
        raise CheckFailure("executed test binary changed")
    ran = set(re.findall(r"^=== RUN\s+(Test\w+)$", output, re.MULTILINE))
    failed_paths = set(re.findall(r"^[ \t]*--- FAIL: (Test\w+(?:/[^\s]+)*)[ \t]+\(", output, re.MULTILINE))
    failed = {path.split("/")[0] for path in failed_paths}
    skipped = set(re.findall(r"^\s*--- SKIP: ([^\s]+)", output, re.MULTILINE))
    passed = set(re.findall(r"^--- PASS: (Test\w+)\b", output, re.MULTILINE))
    ran_paths = set(re.findall(r"^=== RUN[ \t]+(Test\w+(?:/[^\s]+)*)[ \t]*$", output, re.MULTILINE))
    passed_paths = set(re.findall(r"^[ \t]*--- PASS: (Test\w+(?:/[^\s]+)*)[ \t]+\(", output, re.MULTILINE))
    assertion_seen = bool(re.search(r"^[ \t]+[^:\r\n]+\.go:\d+: " + re.escape(marker) + r"(?:[ \t]|$)", output, re.MULTILINE)) if marker else None
    crashed = bool(re.search(r"^(?:panic:|fatal error:|WARNING: DATA RACE|SIG[A-Z]+:)",
                             output, re.MULTILINE))
    observation = {"exit": status, "ran": sorted(ran), "failed": sorted(failed),
                   "passed": sorted(passed), "skipped": sorted(skipped),
                   "crashed": crashed, "target": target, "subtest": subtest,
                   "ran_paths": sorted(ran_paths), "failed_paths": sorted(failed_paths),
                   "passed_paths": sorted(passed_paths), "assertion": marker,
                   "assertion_seen": assertion_seen, "expected": sorted(expected),
                   "missing": sorted(expected - ran), "unexpected": sorted(ran - expected)}
    write_json(folder / "test-observation.json", observation)
    if marker is not None:
        expected_paths = target_paths if subtest else {test}
        reached = (ran == {test} and failed_paths == expected_paths and assertion_seen and
                   (not subtest or ran_paths == expected_paths) and not skipped and not crashed)
        if status != 1 or not reached:
            failure("red did not reach its intended failing assertion", output)
            raise CheckFailure("red did not reach its intended failing assertion")
        return {"verdict": "killed", "test": test, "exit": status,
                "reached": reached, "assertion": marker, "failed": sorted(failed),
                "target": target, "failed_paths": sorted(failed_paths)}
    selected_passed = not subtest or ran_paths == target_paths and passed_paths == target_paths
    if status != 0 or failed or skipped or crashed or ran != expected or passed != expected or not selected_passed:
        failure("candidate test failed or declared tests were not reached", output)
        raise CheckFailure("candidate test failed or declared tests were not reached")
    return {"verdict": "pass", "tests": sorted(ran), "exit": status}


def execute(source, evidence, report, selected, variants, focused):
    driver = evidence / "driver"
    driver.mkdir(mode=0o700)
    for name in ("mutations.py", "run-mutations.sh", "MATRIX.md", "MUTATIONS.md", "CONTRACT-GAPS.md"):
        path = Path(__file__).resolve().parent / name
        (driver / name).write_bytes(path.read_bytes())
    report["driver"] = inventory(driver)
    write_json(evidence / "driver-inputs.json", report["driver"])
    candidate = evidence / "candidate-source"
    dependencies = evidence / "dependencies"
    before = snapshot(source, candidate, dependencies)
    report["dependencies"] = inventory(dependencies)
    write_json(evidence / "dependency-inputs.json", report["dependencies"])
    write_json(evidence / "candidate-inputs.json", before)
    report["input_sha256"] = before["sha256"]
    report["anchor_preflight"] = preflight_mutations(candidate, selected)
    write_json(evidence / "anchor-preflight.json", report["anchor_preflight"])
    step(variant="setup", mutation="none", stage="go-toolchain", exit=None)
    status, _ = command(["go", "version"], candidate, evidence / "go-version.log")
    if status != 0:
        raise CheckFailure("Go toolchain metadata check failed")
    native_input = None
    if not focused or any(case["test"] == "TestStateFDExec" for case in selected):
        native = Path("/usr/bin/readlink").resolve(strict=True)
        data = native.read_bytes()
        (evidence / "readlink.bin").write_bytes(data)
        native_input = {"sha256": sha(data), "bytes": len(data)}
        report["native_readlink"] = native_input
        write_json(evidence / "native-input.json", native_input)
        status, _ = command(["/usr/bin/readlink", "--version"], candidate,
                            evidence / "readlink-version.log")
        if status != 0:
            raise CheckFailure("native readlink metadata check failed")
    printf_input = None
    if not focused or any(case["test"] == "TestPinnedWriterCredentials" for case in selected):
        native = Path("/usr/bin/printf").resolve(strict=True)
        data = native.read_bytes()
        (evidence / "printf.bin").write_bytes(data)
        printf_input = {"sha256": sha(data), "bytes": len(data)}
        report["native_printf"] = printf_input
        write_json(evidence / "printf-input.json", printf_input)
        status, _ = command(["/usr/bin/printf", "--version"], candidate, evidence / "printf-version.log")
        if status != 0:
            raise CheckFailure("native printf metadata check failed")
    # Focused source snapshots are retained as evidence. No credentials, Git
    # metadata, private denylist or other working copy is copied or modified.
    packages = sorted({case["package"] for case in selected}) if focused else list(PACKAGES)
    for variant, flags in variants:
        step(variant=variant, mutation="candidate", stage="build", exit=None)
        variant_root = evidence / variant
        variant_root.mkdir(mode=0o700)
        candidates = {}
        for package in packages:
            folder = variant_root / package
            folder.mkdir(mode=0o700)
            candidates[package] = (folder, *build(candidate, folder, package, flags))
        for case in selected:
            step(variant=variant, mutation=case["id"], stage="mutation-anchor", exit=None)
            folder = variant_root / case["id"]
            folder.mkdir(mode=0o700)
            mutant = folder / "source"
            shutil.copytree(candidate, mutant)
            path = mutant / case["file"]
            original = path.read_text()
            changed = original
            for old, new in case["edits"]:
                if changed.count(old) != 1:
                    raise CheckFailure("mutation source anchor count=" + str(changed.count(old)) + ": " + case["id"])
                changed = changed.replace(old, new, 1)
            path.write_text(changed)
            inputs = inventory(mutant)
            base_files = {row["path"]: row["sha256"] for row in before["files"]}
            red_files = {row["path"]: row["sha256"] for row in inputs["files"]}
            changed_files = sorted(name for name in base_files.keys() | red_files.keys()
                                   if base_files.get(name) != red_files.get(name))
            if changed_files != [case["file"]] or case["file"].endswith("_test.go"):
                raise CheckFailure("mutation changed an unexpected source or test file")
            write_json(folder / "inputs.json", inputs)
            row = {"mutation": case["id"], "variant": variant, "target": case["test"],
                   "subtest": case["subtest"],
                   "red": {"verdict": "not_run"}, "candidate": {"verdict": "not_run"}}
            report["mutations"].append(row)
            write_json(folder / "result.json", row)
            binary, metadata = build(mutant, folder, case["package"], flags)
            red = run_test(binary, metadata, mutant, folder,
                           case["test"], case["message"], case["subtest"])
            row["red"] = red
            write_json(folder / "result.json", row)
            if inventory(mutant) != inputs:
                raise CheckFailure("red source changed during execution")
            _, control_binary, control_metadata = candidates[case["package"]]
            control = folder / "candidate-control"
            control.mkdir(mode=0o700)
            green = run_test(control_binary, control_metadata, candidate,
                             control, test=case["test"], subtest=case["subtest"])
            row["candidate"] = green
            write_json(folder / "result.json", row)
            print(case["id"] + " " + variant + ": killed; candidate passed", flush=True)
        if not focused:
            for package, (folder, binary, metadata) in candidates.items():
                step(mutation="suite", package=package, stage="candidate-suite", exit=None)
                outcome = run_test(binary, metadata, candidate, folder)
                report["suites"].append({"package": package, "variant": variant,
                                         **outcome})
    if inventory(candidate) != before:
        raise CheckFailure("candidate source changed during execution")
    if native_input is not None:
        if sha(Path("/usr/bin/readlink").read_bytes()) != native_input["sha256"]:
            raise CheckFailure("native descriptor probe binary changed")
    if printf_input is not None and sha(Path("/usr/bin/printf").read_bytes()) != printf_input["sha256"]:
        raise CheckFailure("native writer probe binary changed")
    expected = len(selected) * len(variants)
    expected_suites = 0 if focused else len(PACKAGES) * len(variants)
    report["ok"] = (len(report["mutations"]) == expected and
                    all(row["red"]["verdict"] == "killed" and
                        row["candidate"]["verdict"] == "pass"
                        for row in report["mutations"]) and
                    len(report["suites"]) == expected_suites and
                    all(row["verdict"] == "pass" for row in report["suites"]))
    report["complete_inventory"] = (report["ok"] and not focused and
                                    len(variants) == len(VARIANTS) and
                                    len(selected) == len(MUTATIONS))
    if not report["ok"]:
        raise CheckFailure("mutation or candidate inventory is incomplete")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path,
                        default=Path(__file__).resolve().parents[4])
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--mutation", choices=[case["id"] for case in MUTATIONS])
    parser.add_argument("--variant", choices=["normal", "faults", "both"], default="both")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() == 0:
        parser.error("run only as an unprivileged UID on the authorized Linux box")
    if args.list:
        print(json.dumps([{key: case[key] for key in ("id", "file", "package", "test", "subtest", "message")}
                          for case in MUTATIONS], indent=2))
        return 0
    if args.evidence is None:
        parser.error("--evidence is required for a test run")
    selected = [case for case in MUTATIONS if args.mutation is None or case["id"] == args.mutation]
    variants = [item for item in VARIANTS if args.variant == "both" or item[0] == args.variant]
    if len({case["id"] for case in MUTATIONS}) != len(MUTATIONS):
        parser.error("mutation IDs must be unique")
    source = args.source.resolve(strict=True)
    evidence = args.evidence.resolve()
    if not args.evidence.is_absolute() or evidence == source or source in evidence.parents:
        parser.error("use a fresh absolute evidence directory outside the source")
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"schema": "laneboss.component-mutations.v1", "ok": False,
              "scope": "focused unit components; not installed SERVE-STATE",
              "selection": {"mutations": [case["id"] for case in selected],
                            "variants": [name for name, _ in variants],
                            "focused": args.mutation is not None},
              "mutations": [], "suites": [], "error": ""}
    try:
        execute(source, evidence, report, selected, variants, args.mutation is not None)
    except (CheckFailure, OSError, ValueError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        report["failed_step"] = dict(STEP)
        report["failure"] = failure(error)
        print("component mutation checks failed; retain evidence", file=sys.stderr)
        return 1
    finally:
        write_json(evidence / "result.json", report)
    if args.mutation or args.variant != "both":
        print("PASS: selected service mutation control")
    else:
        print("PASS: service component mutation controls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
