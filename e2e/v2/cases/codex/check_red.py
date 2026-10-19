"""Linux-only unit regression mutations; never a substitute for the live case."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


PACKAGE = Path("internal") / "v2" / "runner" / "codex"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def replace_once(text, before, after):
    require(text.count(before) == 1, "mutation anchor absent or ambiguous")
    return text.replace(before, after, 1)


LAUNCH_ROWS = json.loads(Path(__file__).with_name("launch_red.json").read_text())
LAUNCH_CASES = {}
require(isinstance(LAUNCH_ROWS, list) and LAUNCH_ROWS, "launch controls are absent")
for row in LAUNCH_ROWS:
    require(set(row) == {"id", "file", "test", "reason", "edits"} and
            row["id"].startswith("lp-") and row["id"] not in LAUNCH_CASES and
            row["file"] in {"launch.go", "capture_binding.go", "runner.go", "home.go", "capture.go", "materialization.go", "usage.go", "slot.go", "refresh.go", "environment.go"} and
            row["test"].startswith("Test") and row["reason"] and row["edits"],
            "launch control has invalid metadata")
    require(all(isinstance(edit, list) and len(edit) == 2 and
                all(isinstance(value, str) for value in edit) and
                edit[0] and edit[0] != edit[1] for edit in row["edits"]),
            "launch control has invalid literal edits: " + row["id"])
    LAUNCH_CASES[row["id"]] = row


def mutation(name, source):
    """Deliberately broken artifacts exist only in the disposable test scope."""
    if name in LAUNCH_CASES:
        row = LAUNCH_CASES[name]
        for before, after in row["edits"]:
            source = replace_once(source, before, after)
        return row["file"], source
    if name == "h1-ordinary":
        before = ('\t\tif kind != "" {\n'
                  '\t\t\treport.Observations = append(report.Observations, '
                  'Observation{Path: name, Kind: kind})\n\t\t}\n')
        after = ('\t\tif kind != "" {\n'
                 '\t\t\tif kind == "symlink" || kind == "hardlink" || kind == "special" {\n'
                 '\t\t\t\treturn problem(api.CodeIntegrity, "red ordinary audit")\n'
                 '\t\t\t}\n'
                 '\t\t\treport.Observations = append(report.Observations, '
                 'Observation{Path: name, Kind: kind})\n'
                 '\t\t}\n')
        return "home.go", replace_once(source, before, after)
    if name == "h2-digest":
        before = ('\t\tif api.Digest(hex.EncodeToString(hash[:])) '
                  '!= asset.SHA256 {\n\t\t\treturn report, problem('
                  'api.CodeIntegrity, "Codex generated asset differs '
                  'from its protected digest")\n\t\t}\n')
        return "home.go", replace_once(source, before,
            '\t\t_ = hash // deliberately omit the digest gate in RED\n')
    if name == "h3-revoke":
        anchor = 'func (s *Slot) revoke() (Revocation, error) {\n'
        injection = ('\tif _, err := s.root.Lstat('
                     '".runnerhome-runtime/.runnerhome-directory"); '
                     'err == nil {\n\t\treturn Revocation{}, '
                     'problem(api.CodeIntegrity, "red runtime refusal")\n\t}\n')
        return "slot.go", replace_once(source, anchor, anchor + injection)
    if name == "h4-root":
        marker = "func sameRoot(path string, root *os.Root) error {"
        prefix, body = source.split(marker, 1)
        body = replace_once(body, "if err != nil || !os.SameFile(before, after) {",
                            "if err != nil {")
        # Keep the now-uncompared stat observation used; the mutation removes
        # only identity comparison, not the real filesystem read.
        body = replace_once(body, 'after, err := root.Stat(".")',
                            '_, err = root.Stat(".")')
        return "private.go", prefix + marker + body
    if name in ("h4-parent", "h4-parent-type"):
        marker = "func openControlDirectory("
        require(source.count(marker) == 1, "control directory function changed")
        prefix, body = source.split(marker, 1)
        require(body.count("\nfunc wrap(") == 1, "control directory end changed")
        function, rest = body.split("\nfunc wrap(", 1)
        before = ("if err != nil || !before.IsDir() || "
                  "before.Mode().Perm()&0077 != 0 {")
        if name == "h4-parent":
            after = "if err != nil || !before.IsDir() {"
        else:
            after = "if err != nil || before.Mode().Perm()&0077 != 0 {"
        function = replace_once(function, before, after)
        return "private.go", prefix + marker + function + "\nfunc wrap(" + rest
    if name == "h5-reason":
        return "private.go", replace_once(source,
            'return fmt.Errorf("%s: %w", operation, err)',
            'return fmt.Errorf("%s", operation)')
    if name == "h6-partial":
        anchor = '\t\treturn wrap("install Codex native auth slot", err)\n'
        injection = ('\t\tfor _, claim := range s.logins {\n'
                     '\t\t\tif closeErr := claim.close(); closeErr != nil '
                     '{ return closeErr }\n\t\t}\n')
        return "slot.go", replace_once(source, anchor, injection + anchor)
    if name == "c1-rebind":
        before = 'if s.closed || s.home.record.Session.ID == "" {'
        after = ('if s.closed || !s.home.record.Slot.Active || '
                 's.home.record.Session.ID == "" {')
        return "slot.go", replace_once(source, before, after)
    if name == "artifact-digest":
        before = ('\tif err != nil || final.Size() != after.Size() || '
                  'final.ModTime() != after.ModTime() ||\n'
                  '\t\tapi.Digest(hex.EncodeToString(hash.Sum(nil))) '
                  '!= pin.SHA256 {')
        after = ('\t_ = api.Digest(hex.EncodeToString(hash.Sum(nil))) '
                 '// RED: compute but omit the digest comparison\n'
                 '\tif err != nil || final.Size() != after.Size() || '
                 'final.ModTime() != after.ModTime() {')
        return "validate.go", replace_once(source, before, after)
    if name == "session-history":
        before = ('\tif request.Session.HistoryID != request.Home.HistoryID {\n'
                  '\t\treturn problem(api.CodeIntegrity, "Codex session history '
                  'differs from its private home")\n\t}\n')
        return "validate.go", replace_once(source, before, "")
    if name == "capture-history":
        before = ' || lane.Session.HistoryID != home.HistoryID'
        return "capture.go", replace_once(source, before, "")
    if name == "record-history":
        before = ' || session.HistoryID != h.record.Home.HistoryID'
        return "home.go", replace_once(source, before, "")
    if name == "blob-metadata":
        before = ('\tif metadata.Ref != reference || metadata.ACL.Config '
                  '!= s.deps.ReadScope.Config {\n\t\treturn problem('
                  'api.CodeIntegrity, "Codex blob reference differs from its '
                  'committed metadata")\n\t}\n')
        return "capture.go", replace_once(source, before,
            '\t_ = metadata // RED: omit committed object comparison\n')
    if name == "account-pin":
        return "credential.go", replace_once(source,
            'if account != enrolledAccount {', 'if account == "" {')
    if name == "auth-alias":
        return "credential.go", replace_once(source,
            'key != "last_refresh" {', 'key != "last_refresh" && key != "openai_api_key" {')
    if name == "required-fields":
        return "validate.go", replace_once(source,
            'if err := api.DecodeObject(data, destination); err != nil {',
            'if err := decodeJSON(data, destination, true); err != nil {')
    if name == "json-surrogate":
        return "validate.go", replace_once(source, ' || !validSurrogates(data)', '')
    if name == "json-finite":
        return "validate.go", replace_once(source,
            '\t\t\tif err != nil || math.IsInf(f, 0) || math.IsNaN(f) {',
            '\t\t\t_ = err\n\t\t\tif math.IsNaN(f) {')
    if name == "json-integer":
        return "validate.go", replace_once(source,
            '\t\t\t\tif err != nil || integer > 1<<53-1 || integer < -(1<<53-1) {',
            '\t\t\t\t_ = integer\n\t\t\t\tif err != nil {')
    if name == "event-origin":
        return "capture.go", replace_once(source, 'event.Origin != "service" || ', '')
    if name == "object-origin":
        before = ('\tif reference.Class == "capture" && metadata.Origin != "service" {\n'
                  '\t\treturn problem(api.CodeIntegrity, "Codex capture object has no outside service provenance")\n\t}\n')
        return "capture.go", replace_once(source, before, '')
    if name == "capture-class":
        source = replace_once(source, '\t\trecord.Data.Class != "capture" ||\n', '')
        return "capture.go", replace_once(source, 'candidate.Data.Class != "capture" || ', '')
    if name == "prompt-metadata":
        return "runner.go", replace_once(source,
            'if err := s.blobMetadata(ctx, request.Prompt); err != nil {',
            'if err := cancelled(ctx); err != nil {')
    if name == "message-limit":
        return "capture.go", replace_once(source,
            'if textField(fields, "code") == "" && textField(fields, "message") == "" {',
            'if textField(fields, "code") == "" {')
    if name == "limit-grant":
        return "capture.go", replace_once(source,
            'if slot.ProfileGrantID != capture.lane.ProfileGrantID || grants.ID != capture.lane.GrantSetID || grants.LifeID != capture.lane.LifeID {',
            'if slot.ProfileGrantID == "" {')
    if name == "startup-retry":
        return "runner.go", replace_once(source,
            'if !ended {\n\t\treturn problem(api.CodeContainmentUnknown, "Codex startup retry has no quiescent preceding run")',
            'if !ended || request.Target.Run > 1 {\n\t\treturn problem(api.CodeContainmentUnknown, "Codex startup retry has no quiescent preceding run")')
    if name == "startup-mapped":
        marker = 'func (s *Service) startupRetry('
        require(source.count(marker) == 1, "startup retry function changed")
        prefix, body = source.split(marker, 1)
        body = replace_once(body, 'if event.Kind == "runner.session" {',
                            'if event.Kind == "red.session" {')
        return "runner.go", prefix + marker + body
    if name == "startup-quiescence":
        marker = 'func (s *Service) startupRetry('
        require(source.count(marker) == 1, "startup retry function changed")
        prefix, body = source.split(marker, 1)
        before = ('if decode(event.Payload, &end) != nil || !quiescent(end.Observation, '
                  'api.LifeRef{LifeID: request.Target.LifeID, Run: event.Run}) {')
        body = replace_once(body, before, 'if decode(event.Payload, &end) != nil {')
        return "runner.go", prefix + marker + body
    if name == "project-hooks":
        return "config.go", replace_once(source,
            '[]string{"config.toml", "hooks.json"}', '[]string{"config.toml"}')
    if name == "records-root":
        before = ('\tif err := h.records.check(); err != nil {\n'
                  '\t\treturn report, wrap("audit Codex records", err)\n\t}\n')
        return "home.go", replace_once(source, before, '')
    if name == "leases-root":
        marker = 'func (s *Slot) Matches('
        require(source.count(marker) == 1, "slot verification function changed")
        prefix, body = source.split(marker, 1)
        before = ('\tif err := sameRoot(s.locks.path, s.locks.root); err != nil {\n'
                  '\t\treturn err\n\t}\n')
        return "slot.go", prefix + marker + replace_once(body, before, '')
    if name == "quiesce-save":
        return "slot.go", replace_once(source,
            '\t\tstate.Active, state.LastQuiesced = priorActive, priorQuiesced\n',
            '\t\t_ = priorActive\n\t\t_ = priorQuiesced\n')
    if name == "bind-save":
        return "slot.go", replace_once(source,
            '\t\ts.home.record.Session = prior\n', '\t\t_ = prior\n')
    if name == "revoke-close":
        before = ('\t\tif err := claim.close(); err != nil {\n'
                  '\t\t\tstate.Poisoned = true\n\t\t\treturn report, err\n\t\t}\n')
        after = ('\t\tif err := claim.close(); err != nil {\n'
                 '\t\t\treturn report, err\n\t\t}\n')
        return "slot.go", replace_once(source, before, after)
    if name == "bind-source":
        before = ('\tif !found {\n\t\treturn empty, problem(api.CodeIntegrity, '
                  '"Codex record has no outside capture event")\n\t}\n')
        return "capture.go", replace_once(source, before, '')
    if name == "partial-tail":
        return "capture.go", replace_once(source,
            'if inProgress && mapped {', 'if inProgress && mapped && terminated {')
    if name == "large-line":
        return "capture.go", replace_once(source,
            'const maxCaptureLineBytes = api.MaxObjectBytes',
            'const maxCaptureLineBytes = maxRecordBytes')
    if name == "inner-approval":
        return "runner.go", replace_once(source,
            '`approval_policy="never"`', '`approval_policy="on-request"`')
    if name == "inner-sandbox":
        return "runner.go", replace_once(source,
            '`sandbox_mode="danger-full-access"`', '`sandbox_mode="workspace-write"`')
    if name == "home-approval":
        return "home.go", replace_once(source, r'approval_policy = \"never\"\n', '')
    if name == "home-sandbox":
        return "home.go", replace_once(source, r'sandbox_mode = \"danger-full-access\"\n', '')
    raise AssertionError("unknown mutation")


CASES = {
    "h1-ordinary": ("home.go", "TestAuditOrdinaryArtifacts",
                    "ordinary tool artifact blocked future turns"),
    "h2-digest": ("home.go", "TestProtectedRecordsAndDigests",
                  "wanted typed integrity, got <nil>"),
    "h3-revoke": ("slot.go", "TestRevokeRemovesAuthFirst",
                  "native auth name remains after revocation"),
    "h4-root": ("private.go", "TestAuditOpenRootIdentity",
                "wanted typed integrity, got <nil>"),
    "h4-parent": ("private.go", "TestCreatePrivateParent",
                  "accessible parent was accepted"),
    "h4-parent-type": ("private.go", "TestCreateRejectsOddParent",
                       "Codex control directory cannot be opened"),
    "h5-reason": ("private.go", "TestSeedAndErrorReasons",
                  "wanted typed forbidden"),
    "h6-partial": ("slot.go", "TestPartialSwapRetainsBothLeases",
                   "partial swap released a login lease"),
    "c1-rebind": ("slot.go", "TestBindAfterInactiveRestart",
                  "inactive recovered binding could not complete"),
    "artifact-digest": ("validate.go", "TestArtifactPins/changed-bytes",
                        "wanted typed integrity, got <nil>"),
    "session-history": ("validate.go", "TestSessionHistoryBinding",
                        "wanted typed integrity, got <nil>"),
    "capture-history": ("capture.go", "TestCaptureHistoryBinding/history",
                        "wanted typed integrity, got <nil>"),
    "record-history": ("home.go", "TestReopenHistoryBinding",
                       "wanted typed integrity, got <nil>"),
    "blob-metadata": ("capture.go", "TestBlobMetadata/prefix",
                      "wanted typed integrity, got <nil>"),
    "account-pin": ("credential.go", "TestRefreshAccountPin", "wanted typed forbidden, got <nil>"),
    "auth-alias": ("credential.go", "TestAuthExactKeys", "wanted typed integrity, got <nil>"),
    "required-fields": ("validate.go", "TestRequiredRecordFields", "wanted typed integrity, got <nil>"),
    "json-surrogate": ("validate.go", "TestVendorJSONScalars/surrogate", "wanted typed integrity, got <nil>"),
    "json-finite": ("validate.go", "TestVendorJSONScalars/nonfinite", "wanted typed integrity, got <nil>"),
    "json-integer": ("validate.go", "TestVendorJSONScalars/integer", "wanted typed integrity, got <nil>"),
    "event-origin": ("capture.go", "TestCaptureOrigin/event", "wanted typed integrity, got <nil>"),
    "object-origin": ("capture.go", "TestCaptureOrigin/object", "wanted typed integrity, got <nil>"),
    "capture-class": ("capture.go", "TestCaptureClass", "wanted typed integrity, got <nil>"),
    "prompt-metadata": ("runner.go", "TestPromptMetadata", "wanted typed integrity, got <nil>"),
    "message-limit": ("capture.go", "TestMessageLimit", "message-only retained source was not matched"),
    "limit-grant": ("capture.go", "TestLimitGrantBinding", "wanted typed integrity, got <nil>"),
    "startup-retry": ("runner.go", "TestStartupRetry/unmapped", "quiescent unmapped startup retry was stranded"),
    "startup-mapped": ("runner.go", "TestStartupRetry/mapped", "wanted typed conflict, got <nil>"),
    "startup-quiescence": ("runner.go", "TestStartupQuiescence", "wanted typed containment_unknown, got <nil>"),
    "project-hooks": ("config.go", "TestProjectHooks", "wanted typed forbidden, got <nil>"),
    "records-root": ("home.go", "TestControlRoots/records", "wanted typed integrity, got <nil>"),
    "leases-root": ("slot.go", "TestControlRoots/leases", "wanted typed integrity, got <nil>"),
    "quiesce-save": ("slot.go", "TestQuiesceSaveFail", "failed save published quiescence"),
    "bind-save": ("slot.go", "TestBindSaveFail", "failed save published session binding"),
    "revoke-close": ("slot.go", "TestRevokeCloseFail", "failed lease close left the slot usable"),
    "bind-source": ("capture.go", "TestBindCaptureOnly", "wanted typed integrity, got <nil>"),
    "partial-tail": ("capture.go", "TestSessionPartialTail", "complete session prefix was lost at a later split line"),
    "large-line": ("capture.go", "TestSessionLargeLine", "large ordinary capture line blocked session extraction"),
    "inner-approval": ("runner.go", "TestInnerToolModes", "plan did not pin noninteractive approval mode"),
    "inner-sandbox": ("runner.go", "TestInnerToolModes", "plan did not leave isolation to the outer boundary"),
    "home-approval": ("home.go", "TestInnerToolModes", "generated home did not pin approval mode"),
    "home-sandbox": ("home.go", "TestInnerToolModes", "generated home did not pin sandbox mode"),
}


for name, row in LAUNCH_CASES.items():
    require(name not in CASES, "duplicate Go mutation: " + name)
    CASES[name] = (row["file"], row["test"], row["reason"])


def manifest(root):
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            rows.append({"path": str(path.relative_to(root)),
                         "sha256": hashlib.sha256(data).hexdigest(),
                         "bytes": len(data)})
    return rows


def keep_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def snapshot(source, target):
    target.mkdir(mode=0o700)
    for name in ("go.mod", "go.sum"):
        shutil.copyfile(source / name, target / name)
    for relative in (Path("internal") / "identity",
                     Path("internal") / "v2" / "api",
                     Path("internal") / "v2" / "admin",
                     Path("internal") / "v2" / "store",
                     Path("internal") / "v2" / "secrets", PACKAGE):
        shutil.copytree(source / relative, target / relative,
                        symlinks=True)
    # Refuse unexpected source links rather than following one outside the
    # explicitly selected package/API snapshot.
    require(not any(path.is_symlink() for path in target.rglob("*")),
            "source snapshot contains links")


def run_test(root, evidence, stem, selected, tags):
    # Go treats each slash-separated component as its own regexp. Anchor each
    # component so /history cannot also select /missing-history.
    pattern = "/".join("^" + part + "$" for part in selected.split("/"))
    args = ["go", "test", "-json", "-count=1", "-timeout=180s",
            "-run", pattern,
            "./" + PACKAGE.as_posix()]
    if tags:
        args[2:2] = ["-tags", tags]
    keep_json(evidence / (stem + "-command.json"), args)
    result = subprocess.run(args, cwd=root, capture_output=True, timeout=300)
    (evidence / (stem + "-stdout.txt")).write_bytes(result.stdout)
    (evidence / (stem + "-stderr.txt")).write_bytes(result.stderr)
    keep_json(evidence / (stem + "-exit.json"), {"exit": result.returncode})
    return result


def test_observations(result, selected):
    events = [json.loads(line) for line in result.stdout.splitlines()
              if line.strip()]
    selected_events = [event for event in events
                       if event.get("Test") == selected or
                       event.get("Test", "").startswith(selected + "/")]
    output = "".join(event.get("Output", "") for event in selected_events)
    reached = any(event.get("Test") == selected and
                  event.get("Action") == "run" for event in selected_events)
    failed = any(event.get("Test") == selected and
                 event.get("Action") == "fail" for event in selected_events)
    passed = any(event.get("Test") == selected and
                 event.get("Action") == "pass" for event in selected_events)
    skipped = any(event.get("Action") == "skip" for event in selected_events)
    build_failed = any(event.get("Action") == "build-fail" for event in events)
    return {"reached": reached, "failed": failed, "passed": passed,
            "skipped": skipped, "build_failed": build_failed,
            "output": output}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == "linux", "regression execution requires Linux")
    source = args.source.resolve(strict=True)
    evidence = args.evidence.resolve()
    require(not evidence.exists() and evidence.is_absolute(),
            "evidence scope must be new")
    require(not evidence.is_relative_to(source), "keep evidence outside source")
    evidence.mkdir(parents=True, mode=0o700)
    shutil.copyfile(Path(__file__), evidence / "check_red.py")
    shutil.copyfile(Path(__file__).with_name("launch_red.json"), evidence / "launch_red.json")
    keep_json(evidence / "driver-inputs.json", [{
        "path": name, "sha256": hashlib.sha256((evidence / name).read_bytes()).hexdigest(),
        "bytes": len((evidence / name).read_bytes())
    } for name in ("check_red.py", "launch_red.json")])
    candidate = evidence / "candidate"
    snapshot(source, candidate)
    keep_json(evidence / "candidate-inputs.json", manifest(candidate))
    rows = []
    for name, (filename, selected, reason) in CASES.items():
        print("Go mutation: " + name, flush=True)
        red = evidence / ("red-" + name)
        shutil.copytree(candidate, red)
        path = red / PACKAGE / filename
        try:
            actual_filename, changed = mutation(name, path.read_text())
        except AssertionError as error:
            raise AssertionError("Go mutation " + name + ": " + str(error)) from error
        require(actual_filename == filename, "mutation changed the wrong file")
        path.write_text(changed)
        keep_json(evidence / (name + "-red-inputs.json"), manifest(red))
        for tags in ("", "laneboss_faults"):
            stem = name + ("-faults" if tags else "-default")
            broken = run_test(red, evidence, stem + "-red", selected, tags)
            observed = test_observations(broken, selected)
            require(broken.returncode == 1 and observed["reached"] and
                    observed["failed"] and not observed["skipped"] and
                    not observed["build_failed"] and
                    reason in observed["output"] and
                    b"[build failed]" not in broken.stdout + broken.stderr,
                    "red did not reach the intended regression assertion")
            fixed = run_test(candidate, evidence, stem + "-candidate",
                             selected, tags)
            actual = test_observations(fixed, selected)
            require(fixed.returncode == 0 and actual["reached"] and
                    actual["passed"] and not actual["failed"] and
                    not actual["skipped"] and not actual["build_failed"],
                    "candidate regression failed or did not execute")
            rows.append({"id": name, "tags": tags, "test": selected,
                         "red_exit": broken.returncode,
                         "candidate_exit": fixed.returncode})
            keep_json(evidence / "results.json", rows)
    print("PASS: Codex unit red/candidate checks")


if __name__ == "__main__":
    main()
