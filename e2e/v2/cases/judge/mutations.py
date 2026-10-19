"""Linux-only unit mutation evidence; independent of the public CLI case."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tarfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def private_directory(path):
    if path.exists():
        raise RuntimeError("evidence directory already exists")
    missing = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise RuntimeError("evidence directory identity differs")


def mutations():
    wire = "./internal/v2/judge/wire"
    judge = "./internal/v2/judge"
    cases = [
        ("drop-signatures", "internal/v2/judge/wire/screen.go",
         "for _, rule := range credentialShapes {",
         "for _, rule := range credentialShapes[:0] {", wire,
         "^Test(ScreenDifferential|CredentialShapeBranches)$", "reference credential escaped"),
        ("assignment-cut", "internal/v2/judge/wire/screen.go",
         "region := assignmentRegion(text[match[1]:], w)",
         "tail := text[match[1]:]\n"
         "\t\tif next := assignment.FindStringIndex(tail); next != nil { tail = tail[:next[0]] }\n"
         "\t\tregion := assignmentRegion(tail, w)", wire,
         "^TestAssignmentValueNotTruncated$", "assignment value was truncated"),
        ("discard-view", "internal/v2/judge/wire/screen_bounds.go",
         "if len(text) > view.window-len(view.buffer) {\n\t\ts.exhausted = true\n\t\treturn true\n\t}",
         "if len(text) > view.window-len(view.buffer) { return false }", wire,
         "^TestScreenBudgetDifferential$", "view cap differential changed"),
        ("input-cap-pass", "internal/v2/judge/wire/adapter.go",
         "if len(body) > MaxScreenInputBytes {\n\t\treturn failure(api.CodeUnscored, ScreenCapReason)\n\t}",
         "if len(body) > MaxScreenInputBytes { return nil }", wire,
         "^TestScreenCapsBeforeEgress$", "cap leaked input past preflight"),
        ("drop-request-ref", "internal/v2/judge/wire/adapter.go",
         "reply.Request = &requestRef", "_ = requestRef", wire,
         "^TestWireBatchAndNamedState$", "incomplete wire observation"),
        ("alias-request-ref", "internal/v2/judge/cache.go",
         "if reply.Request != nil {\n\t\tref := *reply.Request\n\t\treply.Request = &ref\n\t}",
         "", judge, "^TestCacheKeysAndCopies$", "cache result aliases caller"),
        ("ignore-task-claim", "internal/v2/judge/contract_stubs.go",
         "if len(request.Task) != 0 && !bytes.Equal(request.Task, chunk.Data) {",
         "if false && len(request.Task) != 0 && !bytes.Equal(request.Task, chunk.Data) {", judge,
         "^TestScopedFitRejectsChangedFacts$/^task$", "expected typed forbidden"),
        ("ignore-frame", "internal/v2/judge/stub.go",
         "if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {",
         "if err := error(nil); err != nil {", judge,
         "^TestScopedFitRejectsChangedFacts$/^frame$", "expected typed forbidden"),
        ("drop-extra-tails", "internal/v2/judge/wire/screen.go",
         "return !textSpace(r)", "return false && !textSpace(r)", wire,
         "^Test(AssignmentExtensionControls|NamedExtraGrammar)$", "named assignment extra escaped"),
        ("unapproved-pins", "internal/v2/judge/stub.go",
         "approved, err := api.ResolveJudgeForScope(scope, pinRequest, policy)",
         "approved, err := api.ResolveJudgeConfig(policy.Judge)", judge,
         "^TestScopedProviderPins$/^unapproved$", "expected typed forbidden"),
        ("drop-audit-write", "internal/v2/judge/audit.go",
         "JudgeAudits: []api.JudgeAudit{audit}", "JudgeAudits: []api.JudgeAudit{}", judge,
         "^TestAuditWriteMatrix$", "audit completion write was lost"),
        ("ignore-audit-score", "internal/v2/judge/wire/reply.go",
         "if *result.Probability != decoded.answers[result.QuestionID] {",
         "if false && *result.Probability != decoded.answers[result.QuestionID] {", judge,
         "^TestAuditRejectsChangedEvidence$/^probability$", "expected typed integrity"),
        ("ignore-peer-life", "internal/v2/judge/stub.go",
         "if err := scope.Connection.Peer().Alive(ctx); err != nil {",
         "if err := error(nil); err != nil {", judge,
         "^TestScopedFitRejectsChangedFacts$/^lifetime$", "expected typed unauthenticated"),
        ("prefilter-fold", "internal/v2/judge/wire/screen.go",
         "folded, foldedReady = strings.ToLower(text), true",
         "folded, foldedReady = text, true", wire,
         "^TestScreenFoldedShapes$", "folded signature escaped"),
        ("assignment-ends", "internal/v2/judge/wire/screen.go",
         "var assignment = regexp.MustCompile(",
         "var assignment = regexp.MustCompile(`token=` + ", wire,
         "^TestAssignmentMatchEnds$", "assignment match count changed"),
        ("raw-pins", "internal/v2/judge/stub.go",
         "approved, err := api.ResolveJudgeForScope(scope, pinRequest, policy)",
         "if pinRequest.Config != policy.Judge { return api.JudgeRequest{}, "
         "problem(api.CodeForbidden, \"fixture raw pin comparison\") }\n\t"
         "approved, err := api.ResolveJudgeForScope(scope, pinRequest, policy)", judge,
         "^TestScopedProviderPins$/^default-request$", "approved provider selection changed"),
        ("provider-fallback", "internal/v2/judge/contract_stubs.go",
         "return provider.Fit(ctx, resolved)",
         "fit, err := provider.Fit(ctx, resolved)\n\t"
         "if err != nil { return s.deps.TypeSafe.Fit(ctx, resolved) }\n\treturn fit, err", judge,
         "^TestScopedProviderNeverFallsBack$", "expected typed unavailable"),
        ("keep-audit-view", "internal/v2/judge/audit.go",
         "scope.ReadView = nil", "", judge,
         "^TestAuditWriteMatrix$", "audit completion write was lost"),
        ("allow-unknown-root", "internal/v2/judge/wire/response.go",
         "!fields(root, \"model answers usage request metadata \"+flags)",
         "false && !fields(root, \"model answers usage request metadata \"+flags)", wire,
         "^TestResponseFailuresAreUnscored$/^top-note$", "failure became scored"),
        ("drop-completion-screen", "internal/v2/judge/audit.go",
         "if err != nil || wire.SensitiveStrings(decoded, \"\") {",
         "if err != nil || false && wire.SensitiveStrings(decoded, \"\") {", judge,
         "^TestAuditUnscreenedMetadata$/^(reason|literal-id)$", "metadata escaped completion screen"),
        ("whole-request-joins", "internal/v2/judge/wire/adapter.go",
         "hit, capped := requestScreenResult(decoded, key)",
         "hit, capped := screenResult(decoded, key)", wire,
         "^TestBenignStructuredRequestsScore$", "benign structured input withheld"),
        ("whole-metadata-joins", "internal/v2/judge/audit.go",
         "if err != nil || wire.SensitiveStrings(decoded, \"\") {",
         "if err != nil || wire.Sensitive(decoded, \"\") {", judge,
         "^TestAuditUnscreenedMetadata$/^joined-id$", "benign metadata join withheld"),
        ("per-ask-cache-key", "internal/v2/judge/cache.go",
         "semantic.ID, semantic.DeadlineMS, semantic.MaxCostMicros = \"\", 0, 0",
         "", judge, "^TestCacheAcrossAsks$", "per-ask fields split cache"),
        ("zero-reservation", "internal/v2/judge/wire/adapter.go",
         "if o.ReserveMicros < 1 || o.ReserveMicros > maxInteger {",
         "if o.ReserveMicros < 0 || o.ReserveMicros > maxInteger {", wire,
         "^TestPositiveReservationRequired$", "nonpositive reservation accepted"),
        ("withheld-is-scored", "internal/v2/judge/wire/adapter.go",
         "reply.UnavailableReason = typed.Message",
         "reply.Status = \"scored\"\n\t\t\treply.UnavailableReason = typed.Message", wire,
         "^TestStructuredFragmentsStillWithhold$", "structured credential escaped preflight"),
        ("drop-scoped-joins", "internal/v2/judge/wire/screen_bounds.go",
         "s.execution, s.decodedOnly = true, true",
         "s.execution, s.decodedOnly = false, false", wire,
         "^TestCallerJoins$/^cwd-command$", "caller split reached retention or HTTP"),
        ("drop-split-key-echo", "internal/v2/judge/wire/screen_bounds.go",
         "s.joins, s.keyOnly = key != \"\", true",
         "s.joins, s.keyOnly = false, true", wire,
         "^TestSplitResponseKeyEcho$", "split response key reached retention"),
        ("widen-omission", "internal/v2/judge/wire/screen_diff_test.go",
         "|| caller ||", "|| false && caller ||", wire,
         "^TestOmissionCallerJoins$", "caller-only split was excused"),
        ("drop-judge-ask-input", "internal/v2/cli/commands_judge.go",
         'if err := RegisterInputValidator("judge.ask", "lb-v2-judge", func(raw json.RawMessage) error {\n'
         '\t\t_, err := judge.DecodeAskInput(raw)\n\t\treturn err\n\t}); err != nil {\n\t\tpanic(err)\n\t}',
         "", judge, "^TestJudgeInputFiles$/^ask$", "judge input validation was bypassed"),
        ("drop-judge-list-input", "internal/v2/cli/commands_judge.go",
         'if err := RegisterInputValidator("judge.list", "lb-v2-judge", func(raw json.RawMessage) error {\n'
         '\t\t_, err := judge.DecodeListInput(raw)\n\t\treturn err\n\t}); err != nil {\n\t\tpanic(err)\n\t}',
         "", judge, "^TestJudgeInputFiles$/^list$", "valid judge file missed transport"),
        ("decision-metadata-joins", "internal/v2/judge/wire/screen_fields.go",
         'case "decisions":\n\t\t\treturn decisionsPath, true, false',
         'case "decisions":\n\t\t\treturn dataPath, true, false', wire,
         "^TestBenignStructuredRequestsScore$/^guidance-task-7$", "benign structured input withheld"),
        ("drop-node-reset", "internal/v2/judge/wire/screen_bounds.go",
         "\t\ts.nodes = 0\n", "", wire,
         "^TestConformingRequestNodeBoundary$", "conforming request lost per-pass node allowance"),
        ("reset-shared-work", "internal/v2/judge/wire/screen_bounds.go",
         "\t\ts.nodes = 0\n", "\t\ts.nodes = 0\n\t\ts.left = MaxScreenWorkBytes\n", wire,
         "^TestRequestPassesShareWork$", "request passes reset the shared work budget"),
        ("isolate-decision-text", "internal/v2/judge/wire/screen_fields.go",
         'case "text", "binding":\n\t\t\treturn dataPath, true, false',
         'case "text", "binding":\n\t\t\treturn dataPath, true, true', wire,
         "^TestCallerJoins$/^decision-(task|document|texts)$", "caller split reached retention or HTTP"),
        ("exempt-list-containers", "internal/v2/judge/wire/screen_bounds.go",
         "if _, scalar := child.(string); scalar && at == metadataListPath {",
         "if at == metadataListPath {", wire,
         "^TestUnknownCallerJoins$", "unknown caller field escaped"),
        ("drop-excluded-string-screen", "internal/v2/judge/wire/screen_bounds.go",
         "case string:\n\t\tif s.text(value) {",
         "case string:\n\t\tif !s.joins { return false }\n\t\tif s.text(value) {", wire,
         "^TestDecisionServiceBoundary$", "decision metadata escaped complete-field screening"),
    ]
    # Each mutant detaches only the selected field from caller joins while
    # retaining individual-string/embedded-document checks. HTTP bytes stay
    # unchanged: this recreates the fix-8 authorship error, not a fixture flag.
    for name, detach, subtest in [
        ("isolate-cwd", 'take(command, "cwd"); take(state["context"].(map[string]any), "cwd")', "cwd-command"),
        ("isolate-command", 'take(command, "command")', "command-argv"),
        ("isolate-argv", 'take(command, "argv")', "argv-paths"),
        ("isolate-paths", 'take(command, "declared_paths")', "argv-paths"),
        ("isolate-task", 'take(state, "task")', "caller-document"),
        ("isolate-tool", 'take(command, "tool")', "tool-cwd"),
        ("isolate-unknown", 'take(state, "x")', ""),
    ]:
        changed = ('state := decoded["state"].(map[string]any)\n'
                   '\tcommand := state["commands"].([]any)[0].(map[string]any)\n'
                   '\t_ = command\n\tisolated := []any{}\n'
                   '\ttake := func(object map[string]any, name string) { '
                   'isolated = append(isolated, object[name]); delete(object, name) }\n'
                   '\t' + detach + '\n\thit, capped := requestScreenResult(decoded, key)\n'
                   '\thit = hit || SensitiveStrings(isolated, key)')
        pattern = "^TestCallerJoins$/^" + subtest + "$" if subtest else "^TestUnknownCallerJoins$"
        assertion = "caller split reached retention or HTTP" if subtest else "unknown caller field escaped"
        cases.append((name, "internal/v2/judge/wire/adapter.go",
                      "hit, capped := requestScreenResult(decoded, key)",
                      changed, wire, pattern, assertion))
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--only", choices=["judge-inputs"], help="run only the two CLI registration controls")
    args = parser.parse_args()

    if not args.source.is_absolute() or not args.evidence.is_absolute():
        raise RuntimeError("absolute test paths are required")
    if sys.platform != "linux":
        raise RuntimeError("mutation execution requires Linux")
    source = args.source.resolve(strict=True)
    evidence = args.evidence.absolute()
    if evidence.is_relative_to(source):
        raise RuntimeError("evidence must be outside source")
    private_directory(evidence)
    # External judge CLI tests compile the real shared adapter and its imports.
    inputs = ["go.mod", "go.sum", "internal", "e2e/v2/cases/judge"]
    original = {}
    for name in inputs:
        path = source / name
        paths = sorted(path.rglob("*")) if path.is_dir() else [path]
        for item in paths:
            if item.is_symlink():
                raise RuntimeError("source input is a symlink")
            if item.is_file():
                original[item.relative_to(source).as_posix()] = item.read_bytes()
    (evidence / "source-hashes.json").write_text(json.dumps(
        {name: sha(data) for name, data in original.items()}, sort_keys=True))
    # Keep the exact source/test/corpus bytes consumed by these two packages.
    with tarfile.open(evidence / "candidate-source.tar", "w") as archive:
        for name in original:
            archive.add(source / name, arcname=name, recursive=False)

    observations = []
    result = {"schema": "laneboss.judge-unit-mutations.v1", "verdict": "fail",
              "mutations": [], "commands": observations}

    def command(argv, directory, stem):
        call = subprocess.Popen(argv, cwd=directory, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        expired = False
        try:
            out, err = call.communicate(timeout=600)
        except subprocess.TimeoutExpired:
            expired = True
            os.killpg(call.pid, signal.SIGKILL)
            out, err = call.communicate(timeout=10)
        (evidence / (stem + ".stdout")).write_bytes(out)
        (evidence / (stem + ".stderr")).write_bytes(err)
        (evidence / (stem + ".exit")).write_text(str(call.returncode) + "\n")
        try:
            os.killpg(call.pid, 0)
            quiet = False
        except ProcessLookupError:
            quiet = True
        observations.append({"argv": argv, "cwd": str(directory), "pid": call.pid,
                             "exit": call.returncode, "quiescent": quiet,
                             "timed_out": expired})
        if expired or not quiet:
            raise RuntimeError("test command did not quiesce")
        return call.returncode, out + err

    def build(package, stem):
        binary = evidence / (stem + ".test")
        code, _ = command(["go", "test", "-c", "-o", str(binary), package],
                          source, stem + "-build")
        if code != 0 or not binary.is_file():
            raise RuntimeError("test binary build failed")
        data = binary.read_bytes()
        (evidence / (stem + ".sha256")).write_text(sha(data) + "\n")
        return binary

    def execute(binary, package, pattern, stem):
        argv = [str(binary), "-test.v", "-test.count=1", "-test.timeout=8m", "-test.run", pattern]
        if package == "./internal/v2/judge/wire":
            argv += ["-judge-screen-evidence", str(evidence / (stem + "-cases"))]
        return command(argv, source / package.removeprefix("./"), stem)

    try:
        version_code, _ = command(["go", "version"], source, "go-version")
        if version_code != 0:
            raise RuntimeError("Go version lookup failed")
        candidates = {}
        for label, package in [("judge", "./internal/v2/judge"),
                               ("wire", "./internal/v2/judge/wire")]:
            binary = build(package, "candidate-" + label)
            code, _ = execute(binary, package, ".", "candidate-" + label + "-before")
            if code != 0:
                raise RuntimeError("candidate baseline test failed")
            candidates[package] = binary
        selected = mutations()
        if args.only == "judge-inputs":
            selected = [row for row in selected if row[0] in {"drop-judge-ask-input", "drop-judge-list-input"}]
            if len(selected) != 2:
                raise RuntimeError("judge registration controls are incomplete")
        for name, filename, before, after, package, pattern, assertion in selected:
            path = source / filename
            pristine = original[filename]
            old, new = before.encode(), after.encode()
            if pristine.count(old) != 1:
                raise RuntimeError("mutation target is not unique: " + name)
            changed = pristine.replace(old, new, 1)
            (evidence / (name + ".source")).write_bytes(changed)
            row = {"id": name, "source": filename, "before": sha(pristine),
                   "after": sha(changed), "reached": False, "verdict": "fail"}
            result["mutations"].append(row)
            applied = False
            try:
                if path.read_bytes() != pristine:
                    raise RuntimeError("mutation source changed")
                path.write_bytes(changed)
                applied = True
                binary = build(package, name)
                code, output = execute(binary, package, pattern, name + "-red")
                reached = b"--- FAIL: Test" in output and assertion.encode() in output
                row["reached"] = reached
                if code != 1 or not reached:
                    raise RuntimeError("mutation lacked reached failure: " + name)
                row["verdict"] = "killed"
            finally:
                if applied:
                    path.write_bytes(pristine)
                    if path.read_bytes() != pristine:
                        raise RuntimeError("source restoration failed")
        for name, data in original.items():
            if (source / name).read_bytes() != data:
                raise RuntimeError("candidate source changed")
        for package, binary in candidates.items():
            label = package.rsplit("/", 1)[-1]
            code, _ = execute(binary, package, ".", "candidate-" + label + "-after")
            if code != 0:
                raise RuntimeError("restored candidate test failed")
        result["verdict"] = "pass"
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        result["failure"] = str(error)
    finally:
        retained = {}
        for path in sorted(evidence.rglob("*")):
            if path.is_file():
                retained[path.relative_to(evidence).as_posix()] = {
                    "bytes": path.stat().st_size, "sha256": sha(path.read_bytes())}
        result["evidence"] = retained
        (evidence / "result.json").write_text(json.dumps(result, sort_keys=True))
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
