"""Supervisor-only Linux regression controls. Never execute on the authoring Mac.

Run on an extracted draft.4 source tree, with evidence outside that tree. Every
mutant is a new retained disposable copy; this script never changes its input,
the product Git index, tests, credentials or a running installation. It requires
the named reached test failure before checking the same candidate test.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


class MutationAnchorError(RuntimeError):
    """A control cannot be constructed; never a reached runtime red."""


def replace(text, before, after):
    if text.count(before) != 1:
        raise MutationAnchorError("mutation anchor is missing or ambiguous")
    return text.replace(before, after, 1)


def remove_block(text, start):
    if text.count(start) != 1:
        raise MutationAnchorError("mutation block is missing or ambiguous")
    begin = text.index(start)
    end = text.find("\n\t}", begin)
    if end < 0:
        raise MutationAnchorError("mutation block has no closing delimiter")
    end += len("\n\t}")
    return text[:begin] + text[end:]


# Tuples name real source mutations, targeted tests, and their reached diagnostic.
# Product/test sources contain no branch for these control names.
GO_CONTROLS = [
    ("cleanup-unbound-readiness", "assembly", "TestCleanupNativeUnbound", "unbound cleanup forwarding capability advertised readiness", "store/owned_fail.go",
     [("return port.CleanupNativeReady()", "_ = port\n\t\treturn true")]),
    ("helper-release-kind", "api", "TestHelperEffectCause", "release accepted an unrelated kind", "api/validation.go",
     [("kind == InternalHelperRelease &&", "(kind == InternalHelperRelease || kind == InternalHelperAbort) &&")]),
    ("public-policy-write", "api", "TestPublicWriteAuthority" "/policy_injection", "method wrote outside its contract row", "api/write_catalog.go",
     [('{events: "record.appended"}', '{fields: "Policy", events: "record.appended"}')]),
    ("mutation-without-reply", "api", "TestPublicWriteAuthority/missing_reply", "method wrote outside its contract row", "api/validation.go",
     [("if !exists || spec.Mutation && transaction.Reply == nil && transaction.Deferred == nil {", "if !exists {")]),
    ("release-live-resource", "api", "TestReleaseMeasuredQuiescence/survivor", "unproved release was accepted", "api/validation.go",
     [("if count == nil || *count != 0 {", "if count == nil {")]),
    ("helper-ipc-case", "api", "TestHelperIPCTags", "untagged helper IPC field", "api/bindings.go",
     [('`json:"spec_id"`', '')]),
    ("clef-zero-context", "api", "TestJudgeSelection/context_absent", "Clef accepted unproved", "api/policy.go",
     [("config.ContextTokens <= 0", "config.ContextTokens < 0")]),
    ("unapproved-provider", "api", "TestJudgePinsApprovedPolicy", "request selected an unapproved provider", "api/policy.go",
     [("if resolved != approved {", "if resolved.Provider == approved.Provider && resolved != approved {")]),
    ("fresh-mutation-key", "client", "TestMutationRetainsCallerKey", "mutation silently minted", "client/prepare.go",
     [("REMOVE_BLOCK", '\tif spec.Mutation && request.IdempotencyKey == "" {')]),
    ("missing-decision-projection", "records", "TestDecisionStructuredSupersession", "structured decision projection lost", "records/service.go",
     [("api.StateWrites{Decisions: decisions}", "api.StateWrites{}")]),
    ("decision-schema-unchecked", "records", "TestDecisionDocumentValidation" "/wrong_schema", "expected typed code invalid_request", "records/service.go",
     [('document.Schema != "laneboss.decision.v2"', 'document.Schema == "laneboss.decision.v2"')]),
    ("decision-history-overwrite", "records", "TestDecisionStructuredSupersession", "supersession overwrote canonical history", "records/service.go",
     [("record.RelatedIDs = []api.ID{prior.ID}", "record.ID = prior.ID\n\t\t\trecord.RelatedIDs = []api.ID{prior.ID}"),
      ('\t\tif request.Action == "supersede" {\n\t\t\tcompares = append(compares, api.Compare{Kind: api.CompareRecord, ID: record.ID, Generation: 0})\n\t\t}', '')]),
    ("late-decision-replay", "records", "TestDecisionMetadataBoundaryReplay", "200th metadata retry was rejected", "records/service.go",
     [("REMOVE_BLOCK", "\tif retained, found, err := s.replayDecision(ctx, scope, request); found || err != nil {")]),
    ("proof-input-upload", "cli", "TestProofBoundContentReference", "committed reference required an unknowable upload ID", "cli/commands_integrate.go",
     [('if reference != "" {', 'if reference == "" {')]),
    ("read-socket-closed", "cli", "TestInvokeReusesHumanReadConnection", "forbidden", "cli/cli.go",
     [("response, err := connection.Call(ctx, *sessionRequest)", "response, err := connection.Call(ctx, *sessionRequest)\n\t\tif err == nil { err = connection.Close() }")]),
    ("upload-key-alias", "cli", "TestUploadRetainsCallerKey", "different caller intents share an upload identity", "cli/commands_integrate.go",
     [('string(key) + "\\x00" + string(method)', 'string(method)')]),
    ("judge-boot-precedence", "assembly", "TestJudgePolicySelectsEnrolledProvider", "boot ordering overrode the policy", "assembly/judges.go",
     [("if approved.Provider == pins.Provider && approved.Model == pins.Model &&", "if approved.Provider != pins.Provider || approved.Provider == pins.Provider && approved.Model == pins.Model &&")]),
    ("content-read-session", "cli", "TestContentReadSession", "content read did not establish its session", "cli/cli.go",
     [('if !spec.Mutation || api.HumanSessionMethod(call.Method) {', 'if api.HumanSessionMethod(call.Method) {')]),
    ("lifecycle-worker-lease", "api", "TestLifecycleWorkerWrites/lane.start", "required lifecycle worker/cancellation writes were refused", "api/write_catalog.go",
     [('fields: "Lanes Grants Turns WorkerLeases", events: "lane.created grants.issued"', 'fields: "Lanes Grants Turns", events: "lane.created grants.issued"')]),
    ("internal-policy-write", "api", "TestInternalWriteAuthority/policy", "internal job wrote outside its authority", "api/validation.go",
     [('!validInternalWrites(transaction)', '!validInternalKind(transaction.Internal.Kind)')]),
    ("root-ticket-required", "api", "TestPublicGuardAuthority" "/root_ticket_missing", "human root spawn lacked its ticket", "api/write_catalog.go",
     [("REMOVE_BLOCK", '\tif transaction.Scope.Actor.Kind == "human" && spec.Access == "spawn" && !ticket {')]),
    ("public-lane-proof", "api", "TestPublicGuardAuthority/lane_proof", "lane borrowed a human proof", "api/write_catalog.go",
     [('\t\tif (guard.Proof != nil || guard.Ticket != nil) && transaction.Scope.Actor.Kind != "human" {\n\t\t\treturn false\n\t\t}', '')]),
    ("apply-approval-required", "api", "TestPublicGuardAuthority" "/approval_missing", "D6 apply lacked its approval", "api/write_catalog.go",
     [("REMOVE_BLOCK", '\tif transaction.Scope.Request.Method == "org.change.apply" && !approval {')]),
    ("ticket-provenance", "api", "TestTicketProvenance", "ticket write accepted unrelated provenance", "api/write_catalog.go",
     [('issued.PrincipalID != transaction.Scope.Actor.ID || ', '')]),
    ("ticket-wire-provenance", "api", "TestTicketProvenance", "ticket wire lost its provenance", "api/identity.go",
     [('`json:"principal_id"`', '`json:"issuer"`')]),
    ("decision-proof-binding", "records", "TestDecisionProofReplay/wrong_digest", "invalid proof replay was accepted", "records/service.go",
     [("REMOVE_BLOCK", '\tif request.Proof != nil && (!validID(request.Proof.ID) || request.Proof.RequestSHA256 != digest) {')]),
    ("lane-proof-refused", "records", "TestDecisionProofReplay/lane_proof", "lane record accepted a human proof", "records/service.go",
     [("REMOVE_BLOCK", '\tif scope.Actor.Kind != "human" && request.Proof != nil {')]),
    ("receipt-principal", "records", "TestReplayReceiptBinding/principal", "foreign receipt was replayed", "records/service.go",
     [('receipt.Actor.ID == scope.Actor.ID && ', '')]),
    ("receipt-config-domain", "records", "TestReceiptDomains/config", "foreign receipt domain was visible", "records/service_test.go",
     [('return receiptDomain{Config: scope.Config,', 'return receiptDomain{Config: "",')]),
    ("decision-note-time", "records", "TestDecisionNotesAndCAS", "decision metadata retained a stale time", "records/service.go",
     [('\t\t\trecord.RecordedAt = api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))\n', '')]),
    ("judge-default-resolution", "api", "TestJudgePinsApprovedPolicy", "R108 equivalent defaults were rejected", "api/policy.go",
     [('resolved, err := ResolveJudgeConfig(request.Config)', 'resolved, err := request.Config, error(nil)')]),
    ("release-event-payload", "api", "TestHelperReleaseEvent", "release event lost helper measurements", "api/events.go",
     [('"helper.released":     reflect.TypeFor[ReleaseReceipt](),', '"helper.released":     reflect.TypeFor[HelperLease](),')]),
    ("human-staging-proof", "records", "TestHumanStagingAndAppend", "verified human staging required an operation proof", "api/write_catalog.go",
     [('&& !row.session &&', '&&')]),
    ("lane-staging-session", "records", "TestStagingSessionBinding/lane", "staging borrowed unrelated human authority", "api/write_catalog.go",
     [("REMOVE_BLOCK", '\tif transaction.Scope.ReadAuthority != nil && !boundReadAuthority(transaction.Scope) {')]),
    ("human-preview-proof", "records", "TestHumanPreviewSession/judge.ask", "verified human preview required a mutation proof", "api/write_catalog.go",
     [('&& !row.session &&', '&&')]),
    ("staging-cli-session", "cli", "TestBlobStagingSession", "blob staging did not establish its session", "cli/cli.go",
     [('if !spec.Mutation || api.HumanSessionMethod(call.Method) {', 'if !spec.Mutation || spec.Access == "human-read" {')]),
    ("root-ticket-transfer", "api", "TestRootTicketBoundScope" "/other_principal", "root ticket transferred across its issuing scope", "api/write_catalog.go",
     [('use.PrincipalID != transaction.Scope.Actor.ID || ', '')]),
    ("file-guidance-validator", "cli", "TestFileInputHook/guidance", "owned guidance validation did not precede transport", "cli/cli.go",
     [("REMOVE_BLOCK", '\tif err := integrateValidateInput(call.Method, raw, requireValidator); err != nil {')]),
    ("file-record-validator", "cli", "TestFileInputHook/records", "owned record validation did not precede transport", "cli/cli.go",
     [("REMOVE_BLOCK", '\tif err := integrateValidateInput(call.Method, raw, requireValidator); err != nil {')]),
    ("deferred-without-effect", "api", "TestDeferredMutation/missing_effect", "unguarded or competing deferred reply was accepted", "api/write_catalog.go",
     [("REMOVE_BLOCK", '\tif !validDeferredMutation(transaction, row) {')]),
    ("deferred-second-reply", "api", "TestDeferredCompletion/second_reply", "second or unrelated final reply was accepted", "api/deferred.go",
     [('receipt.Deferred == nil || receipt.Reply != nil || outcome.Reply == nil', 'receipt.Deferred == nil || outcome.Reply == nil')]),
    ("assertion-reference", "api", "TestConfirmEvidence/unreferenced", "unbound or exposed assertion evidence was accepted", "api/assertion.go",
     [('object.ObjectKey != ref.ID || ', '')]),
    ("assertion-private-owner", "api", "TestConfirmEvidence/foreign_owner", "unbound or exposed assertion evidence was accepted", "api/assertion.go",
     [('acl.Owner != tx.Scope.Actor || ', '')]),
    ("file-catalog-gap", "cli", "TestFileInputCatalog/records.append", "catalog file input lacks its validator", "cli/cli.go",
     [('\t"records.append":   integrateInputCheck(records.ValidateAppendInput),\n', '')]),
    ("owned-input-noop", "cli", "TestOwnedFileInputs", "owned file input accepted invalid semantic data", "cli/cli.go",
     [('return validate(request)', 'return nil')]),
    ("append-file-registration", "cli", "TestFileInputHook/append", "owned append validation did not precede transport", "cli/cli.go",
     [('\t"records.append":   integrateInputCheck(records.ValidateAppendInput),\n', '')]),
    ("append-file-forward", "cli", "TestFileInputHook/append_forward", "valid file append did not reach the shared socket", "cli/cli.go",
     [('\t"records.append":   integrateInputCheck(records.ValidateAppendInput),\n', '')]),
    ("decision-file-registration", "cli", "TestFileInputHook/decision", "owned decision validation did not precede transport", "cli/cli.go",
     [('\t"decisions.mutate": integrateInputCheck(records.ValidateDecisionInput),\n', '')]),
    ("unregistered-file-open", "cli", "TestFileInputHook/unregistered", "unregistered file input reached transport", "cli/cli.go",
     [('if required {', 'if false {')]),
    ("validator-nil", "cli", "TestFileInputHook/registration" "/nil", "invalid validator registration was accepted", "cli/cli.go",
     [(' || validate == nil', '')]),
    ("validator-foreign-owner", "cli", "TestFileInputHook/registration" "/foreign_owner", "invalid validator registration was accepted", "cli/cli.go",
     # Keep spec used while admitting a nonempty foreign owner.
     [('owner != spec.Owner || ', 'owner != spec.Owner && owner == "" || ')]),
    ("validator-duplicate", "cli", "TestFileInputHook/registration" "/duplicate", "invalid validator registration was accepted", "cli/cli.go",
     [("REMOVE_BLOCK", '\tif integrateInputChecks.methods[method] != nil {')]),
    ("internal-public-reply", "api", "TestInternalWriteAuthority" "/internal_reply", "internal job wrote outside its authority", "api/validation.go",
     [('if transaction.Deferred != nil || transaction.Reply != nil {', 'if transaction.Deferred != nil {')]),
    ("publish-approval-again", "api", "TestCompletionApprovalGuard" "/org_publish", "completion accepted a second approval consumption", "api/write_catalog.go",
     [('effects: "ApplyChange Worker", guards: "Cancellation"', 'effects: "ApplyChange Worker", guards: "Approval Cancellation"')]),
    ("upgrade-approval-again", "api", "TestCompletionApprovalGuard" "/upgrade_apply", "completion accepted a second approval consumption", "api/write_catalog.go",
     [('effects: "Upgrade Worker", guards: "Cancellation"', 'effects: "Upgrade Worker", guards: "Approval Cancellation"')]),
    ("migration-approval-again", "api", "TestCompletionApprovalGuard" "/migration_apply", "completion accepted a second approval consumption", "api/write_catalog.go",
     [('effects: "Migration Rebuild Worker", guards: "Cancellation"', 'effects: "Migration Rebuild Worker", guards: "Approval Cancellation"')]),
    ("deferred-byte-identity", "api", "TestDeferredRequestEncoding/equivalent", "equivalent deferred request was refused", "api/deferred.go",
     [('if err != nil || !bytes.Equal(originalParams, params) {', 'if err != nil || !bytes.Equal(originalParams, params) || !bytes.Equal(original.Params, request.Params) {')]),
    ("deferred-unbound-params", "api", "TestDeferredRequestEncoding/changed", "changed deferred params matched the original frame", "api/deferred.go",
     # Keep bytes used; an object prefix cannot establish semantic equality.
     [('if err != nil || !bytes.Equal(originalParams, params) {', 'if err != nil || !bytes.Equal(originalParams[:1], params[:1]) {'),
      ('return err == nil && digest == key.RequestSHA256', 'return err == nil && digest != ""')]),
    ("lane-human-read", "records", "TestStagingAuthority/lane_secret", "foreign staging authority or guard was accepted", "api/write_catalog.go",
     [('spec.Access == "human-read" || ', '')]),
    ("lane-human-endpoint", "records", "TestStagingAuthority/lane_challenge", "foreign staging authority or guard was accepted", "api/write_catalog.go",
     [("REMOVE_BLOCK", '\tif spec.Access == "human-endpoint" && (transaction.Scope.Actor.Kind != "human" || transaction.Scope.Actor.ID == "" || transaction.Scope.EndpointGeneration == 0) {')]),
    ("session-proof-use", "records", "TestStagingAuthority/session_proof", "foreign staging authority or guard was accepted", "api/write_catalog.go",
     [("REMOVE_BLOCK", '\tif row.session && (proof || ticket || approval) {')]),
    ("session-ticket-use", "records", "TestStagingAuthority/session_ticket", "foreign staging authority or guard was accepted", "api/write_catalog.go",
     [("REMOVE_BLOCK", '\tif row.session && (proof || ticket || approval) {')]),
    ("session-approval-use", "records", "TestStagingAuthority/session_approval", "foreign staging authority or guard was accepted", "api/write_catalog.go",
     [("REMOVE_BLOCK", '\tif row.session && (proof || ticket || approval) {')]),
    ("begin-foreign-owner", "records", "TestStagingAuthority/begin_owner", "foreign staging authority or guard was accepted", "api/write_catalog.go",
     [(' || lease.ACL.Owner != transaction.Scope.Actor', '')]),
    ("begin-foreign-config", "records", "TestStagingAuthority/begin_config", "foreign staging authority or guard was accepted", "api/write_catalog.go",
     [('lease.ACL.Config != transaction.Scope.Config || ', '')]),
    ("commit-foreign-owner", "records", "TestStagingAuthority/commit_owner", "foreign staging authority or guard was accepted", "api/write_catalog.go",
     [(' || object.ACL.Owner != transaction.Scope.Actor', '')]),
    ("commit-foreign-config", "records", "TestStagingAuthority/commit_config", "foreign staging authority or guard was accepted", "api/write_catalog.go",
     [('object.ACL.Config != transaction.Scope.Config || ', '')]),
    ("decision-service-add-record", "records", "TestDecisionInputBoundary/add_record", "expected typed code invalid_request", "records/service.go",
     [("REMOVE_BLOCK", '\tif err := ValidateDecisionInput(request); err != nil {'),
      ('\t\tif request.RecordID != "" || request.ExpectedGeneration != 0 {\n\t\t\treturn api.Record{}, invalid("new decision requires an absent base")\n\t\t}\n', '')]),
    ("decision-service-add-base", "records", "TestDecisionInputBoundary" "/add_generation", "expected typed code invalid_request", "records/service.go",
     [("REMOVE_BLOCK", '\tif err := ValidateDecisionInput(request); err != nil {'),
      ('\t\tif request.RecordID != "" || request.ExpectedGeneration != 0 {\n\t\t\treturn api.Record{}, invalid("new decision requires an absent base")\n\t\t}\n', '')]),
    ("decision-service-zero-base", "records", "TestDecisionInputBoundary/change_zero", "expected typed code invalid_request", "records/service.go",
     [("REMOVE_BLOCK", '\tif err := ValidateDecisionInput(request); err != nil {'),
      (' || request.ExpectedGeneration == 0 || request.ExpectedGeneration >= 1<<53-1', '')]),
    # Annotation also rejects the incremented generation at the JSON boundary.
    # Embed reaches its not-implemented branch before arithmetic/store checks,
    # so its invalid upper bound must be rejected by the service preflight.
    ("decision-service-limit", "records", "TestDecisionInputBoundary/embed_limit", "expected typed code invalid_request", "records/input.go",
     [(' || request.ExpectedGeneration >= 1<<53-1', '')]),
]


def launch_plan_controls(path):
    data = json.loads(path.read_bytes())
    if not isinstance(data, dict) or set(data) != {"status", "controls"} or not isinstance(data["status"], str):
        raise RuntimeError("invalid launch control manifest")
    rows = data["controls"]
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("empty launch control manifest")
    controls, names = [], set()
    fields = {"id", "package", "test", "diagnostic", "file", "edits"}
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields or any(not isinstance(row[key], str) or not row[key] for key in fields - {"edits"}):
            raise RuntimeError("invalid launch control row")
        edits = row["edits"]
        if row["id"] in names or not isinstance(edits, list) or not edits or any(
                not isinstance(edit, list) or len(edit) != 2 or any(not isinstance(part, str) for part in edit) or not edit[0] for edit in edits):
            raise RuntimeError("duplicate or malformed launch control")
        names.add(row["id"])
        controls.append(tuple(row[key] for key in ("id", "package", "test", "diagnostic", "file", "edits")))
    return controls


GO_CONTROLS.extend(launch_plan_controls(Path(__file__).with_name("launch-plan-controls.json")))
GO_CONTROLS.extend(launch_plan_controls(Path(__file__).with_name("consumer-controls.json")))
GO_CONTROLS.extend(launch_plan_controls(Path(__file__).with_name("credential-controls.json")))
GO_CONTROLS.extend(launch_plan_controls(Path(__file__).with_name("contract-controls.json")))
GO_CONTROLS.extend(launch_plan_controls(Path(__file__).with_name("cleanup-controls.json")))
GO_CONTROLS.extend(launch_plan_controls(Path(__file__).with_name("store-controls.json")))
GO_CONTROLS.extend(launch_plan_controls(Path(__file__).with_name("store-r2-controls.json")))
if len({row[0] for row in GO_CONTROLS}) != len(GO_CONTROLS):
    raise RuntimeError("duplicate regression control ID")


def run(command, source, evidence):
    evidence.mkdir(parents=True)
    (evidence / "argv.json").write_text(json.dumps(command, indent=2) + "\n")
    result = subprocess.run(command, cwd=source, capture_output=True, timeout=600, check=False)
    (evidence / "stdout").write_bytes(result.stdout)
    (evidence / "stderr").write_bytes(result.stderr)
    (evidence / "exit.json").write_text(json.dumps(result.returncode) + "\n")
    return result


def go_command(package, test):
    expression = "/".join("^" + part + "$" for part in test.split("/"))
    return ["go", "test", "-count=1", "-json", "-run", expression, "./internal/v2/" + package]


def go_verdict(result, test, expected, diagnostic=""):
    events, plain = [], []
    malformed = False
    for line in result.stdout.splitlines():
        if line.startswith(b"{"):
            try:
                events.append(json.loads(line))
            except (json.JSONDecodeError, UnicodeDecodeError):
                malformed = True
                plain.append(line.decode("utf-8", "replace"))
        else:
            plain.append(line.decode("utf-8", "replace"))
    target = [row for row in events if row.get("Test") == test]
    # Parent controls may fail in a subtest. Keep diagnostics in that named
    # tree while requiring the exact nominated test's own run/final verdict.
    tree = [row for row in events if row.get("Test") == test or row.get("Test", "").startswith(test + "/")]
    output = "".join(row.get("Output", "") for row in tree)
    fallback = "".join(row.get("Output", "") for row in events if row not in tree)
    fallback += "\n".join(plain)
    verdicts = [row.get("Action") for row in target if row.get("Action") in {"run", "pass", "fail", "skip"}]

    def reject(label, reason):
        details = [f"{label}: {test}: {reason}; exit={result.returncode}; named actions={verdicts}"]
        for name, content in (("named test", output), ("compiler/setup", fallback),
                              ("stderr", result.stderr.decode("utf-8", "replace"))):
            lines = content.splitlines()[-12:]
            if lines:
                details.append(name + " output (last 12 lines):\n" + "\n".join(lines))
        if len(details) == 1:
            details.append("(no captured output)")
        raise RuntimeError("\n".join(details))

    if malformed:
        reject("NOT REACHED", "malformed go test JSON; no trustworthy named verdict")
    if verdicts not in (["run", "pass"], ["run", "fail"]):
        reject("NOT REACHED", "no single completed named test verdict; setup, compile, skip or crash does not count")
    if expected == 1 and verdicts[-1] == "pass":
        reject("SURVIVED", "mutated named test ran and passed")
    action = "pass" if expected == 0 else "fail"
    if result.returncode != expected or verdicts[-1] != action:
        reject("CANDIDATE FAILED" if expected == 0 else "INVALID VERDICT",
               f"expected exit {expected} and named {action}")
    if diagnostic and diagnostic not in output:
        reject("WRONG FAILURE", "test failed without its intended assertion diagnostic")


def scanner_verdict(result, evidence, case, red):
    """Require the actual wrong scanner pass, never a broken scanner/setup."""
    verdict = "FAIL" if red else "PASS"
    expected_lines = {f"{verdict} {case}/{mode}" for mode in ("working", "staged")}
    if result.returncode != (1 if red else 0) or result.stderr or set(result.stdout.decode("utf-8").splitlines()) != expected_lines:
        raise RuntimeError("scanner workload did not reach both targeted modes")
    roots = list(evidence.glob("lb-v2-integrate-scan-*/results.json"))
    if len(roots) != 1:
        raise RuntimeError("scanner workload has no unique retained result")
    rows = json.loads(roots[0].read_bytes())
    if not isinstance(rows, list) or len(rows) != 2 or {(row["id"], row["mode"]) for row in rows} != {(case, "working"), (case, "staged")}:
        raise RuntimeError("scanner result rows do not identify both modes")
    for row in rows:
        if type(row["exit"]) is not int or row["exit"] != (0 if red else 1) or row["passed"] is not (not red):
            raise RuntimeError("scanner exited with a setup/error result instead of the intended verdict")
        stem = roots[0].parent / f"{case}-{row['mode']}"
        output = stem.with_suffix(".stdout").read_text()
        errors = stem.with_suffix(".stderr").read_bytes()
        if errors or "SCAN ERROR" in output:
            raise RuntimeError("scanner error cannot count as red evidence")
        if red:
            if "SCAN PASS:" not in output or "SCAN FAIL" in output:
                raise RuntimeError("mutant did not wrongly pass the scanner")
        elif "SCAN FAIL" not in output or "long-secret-like-token" not in output or "SCAN PASS:" in output:
            raise RuntimeError("candidate did not detect the targeted token")


def prepare_go_controls(source, evidence, rows):
    """Inspect every edit before execution and retain every construction error."""
    prepared, failures = [], []
    for row in rows:
        name, package, test, diagnostic, relative, edits = row
        directory = evidence / name
        directory.mkdir(parents=True)
        before, after, issues = None, None, []
        try:
            before = (source / "internal/v2" / relative).read_text()
        except (OSError, UnicodeError) as err:
            issues.append({"edit": 0, "operation": "read", "occurrences": None,
                           "error": "source unavailable: " + type(err).__name__})
        if before is not None:
            after = before
            for index, (old, new) in enumerate(edits, 1):
                anchor = new if old == "REMOVE_BLOCK" else old
                try:
                    after = remove_block(after, new) if old == "REMOVE_BLOCK" else replace(after, old, new)
                except MutationAnchorError as err:
                    issues.append({"edit": index, "operation": "remove_block" if old == "REMOVE_BLOCK" else "replace",
                                   "occurrences": after.count(anchor), "error": str(err)})
        manifest = {"file": "internal/v2/" + relative, "test": test, "edits": edits,
                    "before_sha256": hashlib.sha256(before.encode()).hexdigest() if before is not None else None,
                    "after_sha256": hashlib.sha256(after.encode()).hexdigest() if after is not None else None,
                    "anchor_errors": issues}
        (directory / "mutation.json").write_text(json.dumps(manifest, indent=2) + "\n")
        if issues:
            if before is not None:
                (directory / "source-before.go").write_text(before)
            failure = {"id": name, "status": "broken_anchor", "file": manifest["file"], "test": test,
                       "red_exit": None, "candidate_exit": None, "anchor_errors": issues}
            failures.append(failure)
            for issue in issues:
                print(f"BROKEN ANCHOR {name}: {relative}: edit {issue['edit']}: "
                      f"{issue['error']}; occurrences={issue['occurrences']}", flush=True)
        else:
            prepared.append((row, after))
    (evidence / "anchor-results.json").write_text(json.dumps(failures, indent=2) + "\n")
    return prepared, failures


def run_go_controls(source, evidence, rows):
    prepared, results = prepare_go_controls(source, evidence, rows)
    # Broken rows remain failures while independent constructible rows execute.
    (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    for row, after in prepared:
        name, package, test, diagnostic, relative, edits = row
        mutant = evidence / name / "source"
        shutil.copytree(source, mutant, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        (mutant / "internal/v2" / relative).write_text(after)
        command = go_command(package, test)
        red = run(command, mutant, mutant.parent / "red")
        go_verdict(red, test, 1, diagnostic)
        candidate = run(command, source, mutant.parent / "candidate")
        go_verdict(candidate, test, 0)
        results.append({"id": name, "status": "passed", "red_exit": red.returncode, "candidate_exit": candidate.returncode})
        (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print("PASS red/candidate " + name, flush=True)
    return results


def finish_results(evidence, results):
    (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    broken = [row for row in results if row.get("status") == "broken_anchor"]
    if broken:
        count = sum(len(row["anchor_errors"]) for row in broken)
        print(f"FAIL: draft.4 regression controls: {len(broken)} broken controls, {count} anchor errors", flush=True)
        return 1
    print("PASS: draft.4 regression controls", flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("run only on the authorized disposable Linux machine")
    source = args.source.resolve(strict=True)
    evidence = args.evidence.resolve()
    if evidence.is_relative_to(source) or source.is_relative_to(evidence):
        parser.error("source and evidence must be disjoint")
    evidence.mkdir(parents=True)
    results = run_go_controls(source, evidence, GO_CONTROLS)
    wiring = evidence / "launch-controls-loader"
    mutant = wiring / "source"
    shutil.copytree(source, mutant, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
    verifier = mutant / "e2e/v2/cases/integrate/red-controls.py"
    before = verifier.read_text()
    anchor = ('GO_CONTROLS.extend(launch_plan_controls('
              'Path(__file__).with_name("launch-plan-controls.json")))')
    after = replace(before, anchor, "")
    verifier.write_text(after)
    (wiring / "mutation.json").write_text(json.dumps({
        "file": "e2e/v2/cases/integrate/red-controls.py", "removed": anchor,
        "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
        "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
    }, indent=2) + "\n")
    command = [sys.executable, "-m", "unittest", "discover", "-s", "e2e/v2/cases/integrate", "-p", "test_red_controls.py"]
    red = run(command, mutant, wiring / "red")
    errors = red.stderr.decode("utf-8", "replace")
    if red.returncode != 1 or "FAIL: test_loaded" not in errors or "launch controls are absent from runner" not in errors:
        raise RuntimeError("launch control loading mutation did not reach its assertion")
    candidate = run(command, source, wiring / "candidate")
    if candidate.returncode != 0 or "OK" not in candidate.stderr.decode("utf-8", "replace"):
        raise RuntimeError("launch control loading candidate failed")
    results.append({"id": "launch-controls-loader", "red_exit": red.returncode, "candidate_exit": candidate.returncode})
    print("PASS red/candidate launch-controls-loader", flush=True)
    anchor_controls = [
        ("anchor-reporting", "if issues:\n            if before is not None:",
         "if issues and not issues:\n            if before is not None:",
         "test_reports_all", "broken anchors were not retained"),
        ("anchor-continuation", "for row, after in " "prepared:", "for row, after in prepared[:0]:",
         "test_continues", "constructible control was not executed"),
        ("anchor-verdict", 'anchor errors", flush=True)\n        return 1',
         'anchor errors", flush=True)\n        return 0',
         "test_continues", "broken anchors became a successful run"),
    ]
    for name, old, new, test, diagnostic in anchor_controls:
        directory = evidence / name
        mutant = directory / "source"
        shutil.copytree(source, mutant, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        verifier = mutant / "e2e/v2/cases/integrate/red-controls.py"
        before = verifier.read_text()
        after = replace(before, old, new)
        verifier.write_text(after)
        (directory / "mutation.json").write_text(json.dumps({
            "file": "e2e/v2/cases/integrate/red-controls.py", "test": test, "edits": [[old, new]],
            "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
            "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
        }, indent=2) + "\n")
        command = [sys.executable, "-m", "unittest", "discover", "-s", "e2e/v2/cases/integrate",
                   "-p", "test_red_controls.py", "-k", "AnchorControlTests." + test]
        red = run(command, mutant, directory / "red")
        errors = red.stderr.decode("utf-8", "replace")
        if (red.returncode != 1 or "FAIL: " + test not in errors or diagnostic not in errors or
                "ERROR:" in errors or "Ran 1 test in " not in errors):
            raise RuntimeError(name + " did not reach its intended assertion")
        candidate = run(command, source, directory / "candidate")
        errors = candidate.stderr.decode("utf-8", "replace")
        if candidate.returncode != 0 or "OK\n" not in errors or "skipped" in errors or "Ran 1 test in " not in errors:
            raise RuntimeError(name + " candidate failed")
        results.append({"id": name, "red_exit": red.returncode, "candidate_exit": candidate.returncode})
        print("PASS red/candidate " + name, flush=True)
    # Verify this verifier too: the legacy marker-only predicate must fail the
    # error fixtures before the real candidate verifier is accepted.
    meta = evidence / "scanner-verifier"
    mutant = meta / "source"
    shutil.copytree(source, mutant, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
    verifier = mutant / "e2e/v2/cases/integrate/red-controls.py"
    before = verifier.read_text()
    start, end = before.index("def scanner_verdict("), before.index("\ndef prepare_go_controls(")
    legacy = ('def scanner_verdict(result, evidence, case, red):\n'
              '    marker = ("FAIL " if red else "PASS ") + case + "/working"\n'
              '    if result.returncode != (1 if red else 0) or marker not in result.stdout.decode():\n'
              '        raise RuntimeError("scanner workload did not reach the row")\n\n')
    after = before[:start] + legacy + before[end:]
    verifier.write_text(after)
    (meta / "mutation.json").write_text(json.dumps({
        "file": "e2e/v2/cases/integrate/red-controls.py", "removed": before[start:end], "inserted": legacy,
        "before_sha256": hashlib.sha256(before.encode()).hexdigest(), "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
    }, indent=2) + "\n")
    command = [sys.executable, "-m", "unittest", "discover", "-s", "e2e/v2/cases/integrate", "-p", "test_red_controls.py"]
    red = run(command, mutant, meta / "red")
    errors = red.stderr.decode("utf-8", "replace")
    if red.returncode != 1 or "FAIL: test_rejects_errors" not in errors or "RuntimeError not raised" not in errors:
        raise RuntimeError("scanner verifier mutation did not fail its reached assertion")
    candidate = run(command, source, meta / "candidate")
    if candidate.returncode != 0 or "OK" not in candidate.stderr.decode():
        raise RuntimeError("scanner evidence verifier candidate failed")
    results.append({"id": "scanner-verifier", "red_exit": red.returncode, "candidate_exit": candidate.returncode})
    print("PASS red/candidate scanner-verifier", flush=True)
    scanner_controls = [
        ("nonexistent-own-path", ' and suffix_path in tracked_go_dirs', ''),
        ("import-block-escape", '\n                if stack != [ord("(")]:\n                    in_import = False\n            index += 1', '\n            index += 1'),
    ]
    for case, old, new in scanner_controls:
        directory = evidence / ("scanner-" + case)
        directory.mkdir()
        scanner = directory / "scan.sh"
        scanner.write_text(replace((source / "scripts/scan.sh").read_text(), old, new))
        base = [sys.executable, str(source / "scripts/scan_self_test.py"), "--case", case]
        red = run(base + ["--scanner", str(scanner), "--evidence", str(directory / "red-inputs")], source, directory / "red")
        scanner_verdict(red, directory / "red-inputs", case, True)
        candidate = run(base + ["--evidence", str(directory / "candidate-inputs")], source, directory / "candidate")
        scanner_verdict(candidate, directory / "candidate-inputs", case, False)
        results.append({"id": case, "red_exit": red.returncode, "candidate_exit": candidate.returncode})
        print("PASS red/candidate scanner-" + case, flush=True)
    return finish_results(evidence, results)


if __name__ == "__main__":
    raise SystemExit(main())
