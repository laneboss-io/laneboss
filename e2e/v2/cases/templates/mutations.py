#!/usr/bin/env python3
"""Linux red-before-green proofs, or explicitly selected static-only vet checks."""

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time


PACKAGE = "laneboss.io/laneboss/internal/v2/templates"
CLI_PACKAGE = "laneboss.io/laneboss/internal/v2/cli"
STORE_PACKAGE = "laneboss.io/laneboss/internal/v2/store"
PACKAGE_PATH = Path("internal", "v2", "templates")
SOURCES = str(PACKAGE_PATH / "sources.go")
RENDER = str(PACKAGE_PATH / "render.go")
WORKFLOW = str(PACKAGE_PATH / "workflow.go")
INPUTS = str(PACKAGE_PATH / "service_inputs.go")
BLOBS = str(PACKAGE_PATH / "blob.go")
VERIFY = str(PACKAGE_PATH / "verify.go")
SERVICE = str(PACKAGE_PATH / "stub.go")
APPROVED = str(PACKAGE_PATH / "approved.go")
PREPARATION = str(PACKAGE_PATH / "launch_render.go")
BOOTSTRAP = str(PACKAGE_PATH / "bootstrap.go")
ORG = str(PACKAGE_PATH / "org.go")
INVENTORY = str(PACKAGE_PATH / "inventory.go")
DECODE = str(PACKAGE_PATH / "input.go")
CLI = "internal/v2/cli/commands_templates.go"
STORE_SOURCES = "internal/v2/store/sources.go"
STORE_TEST = "internal/v2/store/source_test.go"
CASE_PATH = Path("e2e", "v2", "cases", "templates")
SCHEMA = "laneboss.templates-mutation.v1"
VET_SCHEMA = "laneboss.templates-mutation-vet.v1"


class MutationFailure(Exception):
    """A screened failure; never a killed mutation without operation evidence."""


@dataclass(frozen=True)
class Mutation:
    id: str
    assertion: str
    boundary: str
    file: str
    before: str
    after: str
    test: tuple
    failure_contains: str
    package: str = PACKAGE


def block(*lines, depth=1):
    return "".join("\t" * depth + line + "\n" for line in lines)


def catalog():
    def tpl(name, boundary, file, before, after, test, reason, package=PACKAGE):
        return Mutation(name, "TPL-SCOPE", boundary, file, before, after,
                        tuple(test), reason, package)

    def first(name, boundary, file, before, after, test, reason):
        return Mutation(name, "LB-FIRST", boundary, file, before, after,
                        tuple(test), reason)

    kinds_check = block(
        "if api.ValidateOrgKinds(snapshot) != nil {",
        '\treturn integrity("approved org snapshot has invalid semantic source or derived kinds")', "}")
    inventory_loop = block(
        "refs := make([]api.SourceRef, 0, len(snapshot.Sources)+len(snapshot.Derived))",
        "for group, files := range [][]api.ResourceFile{snapshot.Sources, snapshot.Derived} {",
        "\tfor _, file := range files {")
    file_check = "\t\t\tif !snapshotKind(file.Kind, group == 0) || file.Mode == 0 || file.Mode&^uint32(0777) != 0 ||\n"

    return [
        tpl("selected-level", "Print the selected level", RENDER,
            "r.context.Level, r.context.Role)",
            "input.Lane.Run, r.context.Role)",
            ["TestTplSelectedContext"], "selected level or role changed in prompt"),
        tpl("selected-role", "Print the selected role", RENDER,
            "r.context.Level, r.context.Role)",
            "r.context.Level, input.Config)",
            ["TestTplSelectedContext"], "selected level or role changed in prompt"),
        tpl("drop-task", "Preserve every assigned task byte", RENDER,
            "output.Write(input.TaskBytes)",
            "output.Write(input.TaskBytes[:len(input.TaskBytes)-1])",
            ["TestTplExactTask"], "assigned task bytes changed in rendered prompt"),
        tpl("template-hash", "Bind the selected template source hash", RENDER,
            "SourceSHA256: r.selected.SHA256,", "SourceSHA256: input.Policy.SHA256,",
            ["TestTplTemplateBinding"], "template reference lost source identity or generation"),
        tpl("template-generation", "Bind the approved template generation", RENDER,
            "Generation: r.generation, RenderedSHA256:",
            "Generation: input.Policy.Generation, RenderedSHA256:",
            ["TestTplTemplateBinding"], "template reference lost source identity or generation"),
        tpl("printed-hash", "Print the bound source hash", RENDER,
            "r.selected.ID, r.generation, r.selected.SHA256)",
            "r.selected.ID, r.generation, input.Policy.SHA256)",
            ["TestTplTemplateBinding"], "printed template provenance differs from selected source"),
        tpl("printed-generation", "Print the bound generation", RENDER,
            "r.selected.ID, r.generation, r.selected.SHA256)",
            "r.selected.ID, input.Policy.Generation, r.selected.SHA256)",
            ["TestTplTemplateBinding"], "printed template provenance differs from selected source"),
        tpl("rendered-hash", "Hash the actual rendered bytes", RENDER,
            "RenderedSHA256: hash(markdown)", "RenderedSHA256: input.Task.SHA256",
            ["TestTplRenderedHash"], "rendered hash does not bind actual prompt bytes"),
        tpl("drop-grants", "Print all delegated scopes and ceilings", RENDER,
            "appendJSON(&output, grantProjection(input.Grants))",
            "appendJSON(&output, grantProjection(api.GrantSet{}))",
            ["TestTplGrantProjection"], "printed grants dropped or widened a delegated scope"),
        tpl("grant-copy", "Rendering does not mutate service grants", RENDER,
            block("grants.Secrets = slices.Clone(grants.Secrets)"), "",
            ["TestTplGrantProjection"], "render modified the authoritative input grants"),
        tpl("report-parent", "Use the direct parent, including a non-root parent", RENDER,
            'input.Lane.LifeID, input.Lane.ParentLifeID)\n',
            'input.Lane.LifeID, input.Lane.RootLifeID)\n',
            ["TestTplReportLine"], "report line did not name the authentic direct parent"),
        tpl("drop-workspace", "Keep the selected workspace projection", RENDER,
            "appendJSON(&output, input.Lane.Workspace)",
            "appendJSON(&output, api.Workspace{})",
            ["TestTplWorkspace"], "selected workspace or worktree changed in prompt"),
        tpl("worktree-path", "Print the selected logical worktree", RENDER,
            "input.Lane.Workspace.LogicalCWD)", "input.Lane.Workspace.Branch)",
            ["TestTplWorkspace"], "selected workspace or worktree changed in prompt"),
        tpl("drop-rule-source", "Retain each consumed rule source", RENDER,
            block("policySources := slices.Clone(input.Policy.Sources)",
                  "for _, rule := range input.Policy.Rules {",
                  "\tpolicySources = append(policySources, rule.Source)", "}"),
            block("policySources := slices.Clone(input.Policy.Sources)"),
            ["TestTplSourceRefs"], "consumed rule source disappeared from provenance"),
        tpl("source-alias", "Archive independent source byte copies", SOURCES,
            "return Source{Ref: source.Ref, Bytes: bytes.Clone(source.Bytes)}",
            "return Source{Ref: source.Ref, Bytes: source.Bytes}",
            ["TestResolveOrgFallbackAndCopies"], "archive view exposed mutable internal bytes"),
        tpl("org-fallback", "A wholly absent local pair inherits org", SOURCES,
            "if (layers.Local == nil) != (layers.Drivers == nil) {",
            "if layers.Local == nil || (layers.Local == nil) != (layers.Drivers == nil) {",
            ["TestTplOrgFallback"], "missing local layer rejected the org default"),
        tpl("partial-local", "A partial local pair is an error", SOURCES,
            block("if (layers.Local == nil) != (layers.Drivers == nil) {",
                  '\treturn nil, invalid("local role source and driver source must be a complete pair")', "}"),
            "", ["TestTplPartialLocal"], "orphan local driver source was silently inherited"),
        tpl("malformed-source", "Malformed local text cannot fall back", SOURCES,
            "\t\tif err := checkBody(layers.Local.Bytes); err != nil {\n"
            "\t\t\treturn nil, err\n\t\t}\n", "",
            ["TestResolveRejectsBadSources", "malformed"],
            "wanted typed invalid_request with recovery"),
        tpl("wrong-role", "Resolve the exact level and role source path", SOURCES,
            "if source.Ref.Path != expectedPath || path.Clean(source.Ref.Path) != source.Ref.Path {",
            "if path.Clean(source.Ref.Path) != source.Ref.Path {",
            ["TestResolveRejectsBadSources", "wrong-role"],
            "wanted typed forbidden with recovery"),
        tpl("wrong-hash", "Reject retained source byte/hash mismatch", SOURCES,
            block("if hash(source.Bytes) != source.Ref.SHA256 {",
                  '\treturn integrity("template source bytes differ from their retained digest")', "}"),
            "", ["TestResolveRejectsBadSources", "hash"],
            "wanted typed integrity with recovery"),
        tpl("wrong-generation", "Reject source generation outside snapshot", SOURCES,
            "source.Ref.Generation == 0 || source.Ref.Generation > maxGeneration ||\n"
            "\t\tsource.Ref.Generation != generation",
            "source.Ref.Generation == 0 || source.Ref.Generation > maxGeneration",
            ["TestResolveRejectsBadSources", "generation"],
            "wanted typed conflict with recovery"),
        tpl("widen-drivers", "Local driver selection is bounded by org", SOURCES,
            "\t\tfor _, driver := range localDrivers {\n"
            "\t\t\tif !slices.Contains(drivers, driver) {\n"
            '\t\t\t\treturn nil, problem(api.CodeForbidden, "local primary drivers exceed the org catalog",\n'
            '\t\t\t\t\t"Propose an exact org change through L6 and direct human approval.")\n'
            "\t\t\t}\n\t\t}\n", "",
            ["TestResolveRejectsBadSources", "widen"],
            "wanted typed forbidden with recovery"),
        tpl("scope-role", "Lane, template and policy contexts agree", RENDER,
            block("if input.Lane.Level != context.Level || input.Lane.Role != context.Role ||",
                  "\tinput.Policy.Context.Level != context.Level || input.Policy.Context.Role != context.Role ||",
                  "\tinput.Policy.Context.InstanceID != context.InstanceID {",
                  '\treturn problem(api.CodeForbidden, "lane, template and effective policy role differ",',
                  '\t\t"Use the authenticated lane\'s exact level and role; text cannot change its scope.")', "}"),
            "", ["TestRenderRejectsScopeDrift", "wrong-role"],
            "wanted typed forbidden with recovery"),
        tpl("grant-life", "Grants belong to the authentic lane life", RENDER,
            "input.Grants.LifeID != input.Lane.LifeID ||", "",
            ["TestRenderRejectsScopeDrift", "grant-life"],
            "wanted typed integrity with recovery"),
        tpl("grant-revoked", "Revoked grants cannot render", RENDER,
            "input.Grants.Revoked ||", "",
            ["TestRenderRejectsScopeDrift", "revoked"],
            "wanted typed integrity with recovery"),
        tpl("policy-generation", "Historical grant generations cannot exceed the live lane", RENDER,
            block("if err := checkPolicyGeneration(input.Lane, input.Grants, input.Policy, input.NewLaunch); err != nil {",
                  "\treturn err", "}"),
            "", ["TestRenderRejectsScopeDrift", "policy-gen"],
            "wanted typed conflict with recovery"),
        tpl("lineage-check", "Reject an inconsistent starter chain", RENDER,
            block("if err := checkLineage(input.Lane); err != nil {", "\treturn err", "}"),
            "", ["TestRenderRejectsScopeDrift", "lineage"],
            "wanted typed integrity with recovery"),
        tpl("task-length", "Validate committed task byte count", RENDER,
            "if int64(len(data)) != ref.Bytes || hash(data) != ref.SHA256 {",
            "if hash(data) != ref.SHA256 {",
            ["TestTplTaskLength"], "task byte count mismatch was accepted"),
        tpl("task-hash", "Validate committed task digest", RENDER,
            "if int64(len(data)) != ref.Bytes || hash(data) != ref.SHA256 {",
            "if int64(len(data)) != ref.Bytes {",
            ["TestRenderRejectsScopeDrift", "task-hash"],
            "wanted typed integrity with recovery"),
        tpl("chunk-hash", "Validate retained task chunk digests", BLOBS,
            " || hash(chunk.Data) != chunk.SHA256", "",
            ["TestBlobIntegrityAndNoFakePrompt", "hash"],
            "wanted typed integrity with recovery"),
        tpl("brief-state-write", "Briefing performs no state mutation", SERVICE,
            block("// No launch, registration, worker, transaction or ambient-shell binding is"),
            block("if _, err := s.deps.Store.Transact(ctx, api.Transaction{Scope: scope}); err != nil {",
                  "\treturn api.Briefing{}, err", "}",
                  "// No launch, registration, worker, transaction or ambient-shell binding is"),
            ["TestTplBriefingReadOnly"], "briefing changed state before input resolution"),
        tpl("duplicate-json", "Malformed request fields cannot reach resolution", DECODE,
            "if !ok || seen[name] {", "if !ok {",
            ["TestDecodeStrictRequestBodies", "duplicate"],
            "wanted typed invalid_request with recovery"),
        tpl("duplicate-cli", "Ambiguous CLI flags cannot select a new role", CLI,
            "if seen[name] || flags.Lookup(name) == nil {",
            "if flags.Lookup(name) == nil {",
            ["TestCLIRejectsAmbiguousInputs"], "invalid CLI input returned"),
        tpl("cli-namespace", "CLI helpers carry the lane prefix", CLI,
            "type templatesFlags struct {",
            "type orphanTplFlags = templatesFlags\n\ntype templatesFlags struct {",
            ["TestTemplatesCLINamespace"], "CLI helper lacks templates prefix"),
        tpl("brief-source-hash", "Response template binds its source", VERIFY,
            "selected.SHA256 != briefing.Template.SourceSHA256 ||\n\t\t",
            "", ["TestTplBriefMetadata", "hash"],
            "inconsistent briefing metadata was accepted"),
        tpl("brief-source-gen", "Response source generation agrees", VERIFY,
            " ||\n\t\tselected.Generation != briefing.Template.Generation", "",
            ["TestTplBriefMetadata", "generation"],
            "inconsistent briefing metadata was accepted"),
        tpl("brief-role-path", "Response source belongs to requested role", VERIFY,
            block("if selected.Path != OrgTemplatePath && selected.Path != expected {",
                  '\treturn problem(api.CodeForbidden, "briefing template belongs to another level or role",',
                  '\t\t"Use the authenticated lane\'s exact role or its approved org default.")', "}"),
            block("_ = expected"), ["TestTplBriefMetadata", "wrong-role"],
            "inconsistent briefing metadata was accepted"),
        tpl("brief-source-duplicate", "Response sources are unique", VERIFY,
            block("if len(refs) != len(briefing.Sources) {",
                  '\treturn integrity("briefing repeats a consumed source reference")', "}"),
            "", ["TestTplBriefMetadata", "source-duplicate"],
            "inconsistent briefing metadata was accepted"),
        tpl("brief-life-duplicate", "Lane groups do not repeat a life", VERIFY,
            " || seen[life]", "", ["TestTplBriefMetadata", "repeated-life"],
            "inconsistent briefing metadata was accepted"),
        tpl("brief-check-unavailable", "Unavailable checks cannot pass", VERIFY,
            block("for _, check := range briefing.Checks {", "\tif !check.Available {",
                  '\t\treturn problem(api.CodePrerequisite, "briefing contains an unavailable capability",',
                  '\t\t\t"Inspect the briefing checks and repair the prerequisite before launching.")',
                  "\t}", "}"), "",
            ["TestTplBriefMetadata", "check-unavailable"],
            "inconsistent briefing metadata was accepted"),
        tpl("brief-checks-empty", "A successful briefing has real checks", VERIFY,
            " || len(briefing.Checks) == 0", "",
            ["TestTplBriefMetadata", "checks-empty"],
            "inconsistent briefing metadata was accepted"),
        tpl("verify-prompt-hash", "Consumer checks actual prompt hash", VERIFY,
            " || hash(prompt) != briefing.Markdown.SHA256", "",
            ["TestTplVerifyPromptBytes", "hash"], "prompt digest mismatch was accepted"),
        tpl("verify-prompt-size", "Consumer checks actual prompt size", VERIFY,
            "int64(len(prompt)) != briefing.Markdown.Bytes || ", "",
            ["TestTplVerifyPromptBytes", "length"], "prompt length mismatch was accepted"),
        tpl("verify-prompt-text", "Prompt bytes must be text", VERIFY,
            block("if !utf8.Valid(prompt) || bytes.ContainsRune(prompt, 0) {",
                  '\treturn integrity("briefing prompt is not UTF-8 text without NUL bytes")', "}"),
            block("_ = utf8.Valid(prompt)"),
            ["TestTplVerifyPromptBytes", "text"], "non-text prompt bytes were accepted"),
        tpl("verify-task-bytes", "Consumer checks the actual task bytes", VERIFY,
            " || !bytes.Equal(prompt[start:], taskBytes)", "",
            ["TestTplVerifyTaskBinding", "different-task"],
            "prompt was accepted for another assigned task"),
        tpl("verify-task-frame", "Task bytes retain their framing", VERIFY,
            " ||\n\t\t!bytes.HasSuffix(prompt[:start], heading)", "",
            ["TestTplVerifyTaskBinding", "missing-frame"], "unframed task bytes were accepted"),
        tpl("blob-full-hash", "Reader verifies the complete blob", BLOBS,
            block("if hash(data) != ref.SHA256 {",
                  '\treturn nil, integrity("retained blob differs from its committed digest")', "}"),
            "", ["TestTplVerifiedBlobRead", "whole-hash"],
            "whole-object digest mismatch returned usable bytes"),
        tpl("blob-class", "Unknown blob enum values are invalid", INPUTS,
            block("switch ref.Class {",
                  'case "task", "prompt", "report", "artifact", "capture", "transcript", "policy", "manifest",',
                  '\t"judge_request", "judge_raw", "archive", "record":',
                  "default:", '\treturn invalid("unknown committed blob class")', "}"),
            "", ["TestTplVerifiedBlobRead", "class"], "unknown blob class was accepted"),
        tpl("blob-cancel-before", "Cancelled reads do not call storage", BLOBS,
            block("if err := readContext(ctx); err != nil {", "\treturn nil, err", "}",
                  "limit := min(api.MaxChunkBytes, int(ref.Bytes)-len(data))", depth=2),
            block("limit := min(api.MaxChunkBytes, int(ref.Bytes)-len(data))", depth=2),
            ["TestTplBlobCancellation", "before-read"],
            "cancelled read reached the blob callback"),
        tpl("blob-cancel-during", "In-flight cancellation returns no bytes", BLOBS,
            block("if err := readContext(ctx); err != nil {", "\treturn nil, err", "}",
                  "if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) == 0 || len(chunk.Data) > limit || hash(chunk.Data) != chunk.SHA256 {", depth=2),
            block("if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) == 0 || len(chunk.Data) > limit || hash(chunk.Data) != chunk.SHA256 {", depth=2),
            ["TestTplBlobCancellation", "during-read"],
            "cancelled in-flight read interpreted returned chunk bytes"),
        first("drop-list-route", "Every briefing names blacklist discovery", RENDER,
              'Read `laneboss org blacklist list --config %s --life-id %s` before acting.',
              'Read the approved workflow sources for %s and %s before acting.',
              ["TestTplRuleListRoute"], "briefing lost its scoped blacklist discovery route"),
        first("seed-count", "Exactly twelve initial workflow entries", WORKFLOW,
              " || len(document.Blacklist) != len(workflowRoutes)", "",
              ["TestTplSeedCount"], "seed count guard accepted a missing workflow entry"),
        first("seed-route", "Every seed retains its Instead route", WORKFLOW,
              block("if entry.Instead != route {",
                    '\treturn nil, invalid("initial workflow entry lost its authentic Instead route")', "}", depth=2),
              "", ["TestTplSeedRoutes"], "seed parser accepted a changed Instead route"),
        first("tmux-agent-scope", "Private build tmux is ordinary work", WORKFLOW,
              block('if strings.HasPrefix(entry.ID, "raw-tmux-") &&',
                    '\t(!strings.Contains(strings.ToLower(entry.Text), "agent session") ||',
                    '\t\t!strings.Contains(strings.ToLower(entry.Text), "private build or test")) {',
                    '\treturn nil, invalid("tmux workflow entries must distinguish agent sessions from private build or test sessions")', "}", depth=2),
              "", ["TestTplTmuxScope"], "tmux seed accepted a ban on ordinary private sessions"),
        first("bare-claude", "Only the two primary managed drivers", SOURCES,
              "if driver != api.DriverClaudock && driver != api.DriverCodex {",
              'if driver != api.DriverClaudock && driver != api.DriverCodex && driver != api.Driver("claude") {',
              ["TestTplPrimaryCatalog"], "primary catalog accepted bare Claude"),
        first("unknown-tool", "An empty blacklist adds no implicit denial", RENDER,
              "if !safeID.MatchString(input.Config) || input.Role == nil || len(input.Role.body) == 0 {",
              "if !safeID.MatchString(input.Config) || input.Role == nil || len(input.Role.body) == 0 || len(input.Policy.Rules) == 0 {",
              ["TestTplOrdinaryWork"], "ordinary work was blocked by empty rules"),
        first("task-route-mask", "Task text cannot supply launcher policy", VERIFY,
              'bytes.Contains(prompt[:start], []byte("laneboss org blacklist list"))',
              'bytes.Contains(prompt, []byte("laneboss org blacklist list"))',
              ["TestTplTaskCannotSupplyRoute"],
              "task text masked a missing launcher rule-list route"),
        tpl("original-task", "Start uses the life’s retained original task", SERVICE,
            " || input.Lane.Task != *input.Task", "",
            ["TestOriginalTaskBinding"],
            "start accepted a task outside the retained life assignment"),
        tpl("snapshot-current", "Render uses the current approved org snapshot", APPROVED,
            "provided.Snapshot != snapshot.Ref || ", "",
            ["TestApprovedSnapshotGuards", "stale"],
            "inconsistent approved snapshot produced a usable prompt"),
        tpl("source-content-map", "Approved source IDs resolve to exact content", APPROVED,
            "retained.Content != source.Content || ", "",
            ["TestApprovedSnapshotGuards", "source-map"],
            "inconsistent approved snapshot produced a usable prompt"),
        tpl("hidden-local-pair", "Absence cannot hide an installed local pair", APPROVED,
            "provided.Local != nil || localFiles != 0", "provided.Local != nil",
            ["TestApprovedSnapshotGuards", "hidden-local"],
            "inconsistent approved snapshot produced a usable prompt"),
        tpl("source-revision", "File revision cannot exceed snapshot generation", APPROVED,
            " || file.RevisionGeneration > ref.Generation", "",
            ["TestApprovedSnapshotGuards", "revision"],
            "inconsistent approved snapshot produced a usable prompt"),
        tpl("metadata-authority", "Caller labels cannot override committed metadata", INPUTS,
            "metadata.Ref != ref || ", "",
            ["TestCommittedMetadataGuards", "class"],
            "caller blob labels overrode committed metadata"),
        tpl("org-full-sources", "Validation checks unselected role sources too", SERVICE,
            block("if err := s.validateOrg(ctx, scope, snapshot); err != nil {",
                  "\treturn api.OrgValidation{}, err", "}"), "",
            ["TestOrgChecksUnselectedRole"],
            "org validation ignored an invalid unselected role pair"),
        tpl("blob-exact-end", "A prefix digest cannot hide extra bytes", BLOBS,
            "len(end.Data) != 0 || end.SHA256 != hash(nil)", "len(end.Data) < 0",
            ["TestBlobExactEnd"], "valid prefix hash hid undeclared object bytes"),
        tpl("retain-error", "Retention errors propagate without a usable briefing", APPROVED,
            block("})", "if err != nil {", "\treturn api.Briefing{}, err", "}",
                  "if err := checkBlobRef(ref); err != nil {"),
            block("})", "if err := checkBlobRef(ref); err != nil {"),
            ["TestPromptRetentionFailure"],
            "retention failure became success or a different error"),
        tpl("input-provenance", "Retained prompts keep their actual input refs", APPROVED,
            "InputRefs: refs", "InputRefs: nil",
            ["TestApprovedPromptRetention"],
            "prompt retention lost its authentic scope or input provenance"),
        tpl("authorized-groups", "Briefing keeps the service-authorized lane groups", APPROVED,
            "LaneGroups: input.Groups", "LaneGroups: api.LaneGroups{}",
            ["TestApprovedPromptRetention"],
            "briefing dropped authorized groups or changed lifecycle state"),
        tpl("service-no-fallback", "Approved absent pairs inherit in the service", APPROVED,
            'case "absent":\n\t\tif provided.Local != nil || localFiles != 0 {',
            'case "absent":\n\t\tif provided.Local == nil || localFiles != 0 {',
            ["TestServiceOrgFallback"], "service fallback rejected the approved org pair"),
        tpl("overview-task", "Human overview invents no assigned task", APPROVED,
            'output.WriteString("## Retained source references\\n\\n")',
            'output.WriteString("## Assigned task\\n\\n## Retained source references\\n\\n")',
            ["TestHumanOverviewIsReadOnly"],
            "human overview invented an assignment or started lifecycle work"),
        tpl("bootstrap-absence", "Bootstrap reserves only an absent org", BOOTSTRAP,
            "ID: target.TargetID, Generation: 0}", "ID: target.TargetID, Generation: 1}",
            ["TestBootstrapAtomicIntent"], "bootstrap omitted its absent-org comparison"),
        tpl("bootstrap-proof-use", "Proof use and bootstrap intent share one commit", BOOTSTRAP,
            block("Guards:  []api.TransactionGuard{{Proof: &api.ProofUse{Proof: proof.Ref, Target: target}}},", depth=2),
            "", ["TestBootstrapAtomicIntent"], "bootstrap proof use was not atomic with the effect"),
        tpl("bootstrap-renderer-pin", "Bootstrap effect uses its protected renderer", BOOTSTRAP,
            "Renderer: s.deps.BootstrapRenderer,", "Renderer: api.Executable{},",
            ["TestBootstrapAtomicIntent"], "bootstrap effect lost its protected pins or actual requester"),
        tpl("bootstrap-proof-expiry", "Expired proof facts cannot reach a transaction", BOOTSTRAP,
            "!s.deps.Clock.Now().Before(expires)", "expires.IsZero()",
            ["TestBootstrapProofGuards", "expired"],
            "invalid human proof reached the bootstrap transaction"),
        tpl("bootstrap-frame-hash", "Bootstrap binds the exact framed intent", BOOTSTRAP,
            "err != nil || exactDigest != digest", 'err != nil || exactDigest == ""',
            ["TestBootstrapFrameBinding"], "bootstrap accepted a frame with different exact intent"),
        tpl("bootstrap-replay", "Durable reply replays before proof and base preflight", BOOTSTRAP,
            block("if reservation.Reply != nil {",
                  "\texpected := reservation.SimulatedPresence || reservation.Operation.SimulatedPresence",
                  "\treturn bootstrapReply(reservation.Reply, reservation.Operation.ID, expected)", "}"),
            "", ["TestBootstrapAtomicIntent"], "bootstrap replay repeated proof use or publication intent"),
        tpl("bootstrap-existing-org", "Existing orgs use D6 instead of bootstrap", BOOTSTRAP,
            block("if target.BaseGeneration != 0 {",
                  '\treturn api.Operation{}, problem(api.CodeConflict, "org already exists; bootstrap cannot replace it",',
                  '\t\t"Use an authenticated L6 exact-change proposal and direct human D6 approval.")', "}"),
            "", ["TestBootstrapExistingOrg"], "bootstrap replaced an existing org or returned success"),
        tpl("lifecycle-life-binding", "Only the reserved operation may render a child", APPROVED,
            block("\treceipt.Operation.LifeID != lane.LifeID ||"), "",
            ["TestLifecycleRenderReservation"],
            "unbound lifecycle operation rendered another life’s prompt"),
        tpl("lifecycle-cause", "Prompt retention keeps its parent operation", APPROVED,
            "CauseOperationID: causeID,", 'CauseOperationID: api.ID(string(causeID) + "-wrong"),',
            ["TestLifecycleRenderReservation"],
            "lifecycle render lost its original operation or requester"),
        tpl("bootstrap-commit-error", "Failed atomic commit is not a pending success", BOOTSTRAP,
            block("})", "if err != nil {", "\treturn api.Operation{}, err", "}",
                  "result, err := bootstrapReply(commit.Reply, operation.ID, operation.SimulatedPresence)"),
            block("})", "result, err := bootstrapReply(commit.Reply, operation.ID, operation.SimulatedPresence)"),
            ["TestBootstrapCommitFailure", "transaction"],
            "bootstrap transaction failure was swallowed"),
        tpl("bootstrap-reply-shape", "The exact durable reply must contain one result", BOOTSTRAP,
            block("if reply == nil || (reply.Error == nil) == (len(reply.Result) == 0) {",
                  '\treturn api.Operation{}, integrity("bootstrap commit omitted its typed durable reply")', "}"),
            "", ["TestBootstrapCommitFailure", "empty-reply"],
            "wanted typed integrity with recovery"),
        tpl("bootstrap-proof-principal", "Proof belongs to the resolved human principal", BOOTSTRAP,
            "proof.PrincipalID != scope.Actor.ID || ", "",
            ["TestBootstrapProofGuards", "principal"],
            "invalid human proof reached the bootstrap transaction"),
        tpl("bootstrap-proof-endpoint", "Proof uses the current endpoint generation", BOOTSTRAP,
            " || proof.EndpointGeneration != scope.EndpointGeneration", "",
            ["TestBootstrapProofGuards", "endpoint"],
            "invalid human proof reached the bootstrap transaction"),
        tpl("bootstrap-proof-class", "A lane proof is not human mutation authority", BOOTSTRAP,
            "proof.EndpointClass != api.EndpointHuman || ", "",
            ["TestBootstrapProofGuards", "lane-proof"],
            "invalid human proof reached the bootstrap transaction"),
        tpl("bootstrap-proof-consumed", "A consumed proof cannot reserve another effect", BOOTSTRAP,
            'proof.ConsumedBy != "" || ', "",
            ["TestBootstrapProofGuards", "consumed"],
            "invalid human proof reached the bootstrap transaction"),
        tpl("bootstrap-proof-target", "Proof binds the actual authorization target", BOOTSTRAP,
            " || proof.Target != target", "",
            ["TestBootstrapProofGuards", "target"],
            "invalid human proof reached the bootstrap transaction"),
        tpl("snapshot-config", "Approved snapshot belongs to the bound configuration", APPROVED,
            "snapshot.Config != scope.Config || ", "",
            ["TestApprovedSnapshotGuards", "config"],
            "inconsistent approved snapshot produced a usable prompt"),
        tpl("local-status-error", "Unreadable local status never becomes absence", APPROVED,
            block('\treturn nil, api.OrgSnapshot{}, integrity("approved local template status is neither absent nor present")'),
            "", ["TestApprovedSnapshotGuards", "local-error"],
            "inconsistent approved snapshot produced a usable prompt"),
        tpl("metadata-config", "Committed object metadata stays configuration scoped", INPUTS,
            "metadata.ACL.Config != scope.Config || ", "",
            ["TestCommittedMetadataGuards", "config"],
            "caller blob labels overrode committed metadata"),
        tpl("metadata-origin", "Prompt inputs have committed provenance", INPUTS,
            'metadata.Origin == "" || ', "",
            ["TestCommittedMetadataGuards", "origin"],
            "caller blob labels overrode committed metadata"),
        tpl("unrelated-role-data", "Plugin data is not a level/role prompt layer", ORG,
            "return roleSourceRoot.MatchString(name)", 'return strings.Contains(name, "/roles/")',
            ["TestOrgValidationNeedsSources"],
            "complete approved source validation failed or changed state"),
        tpl("own-grant-before-read", "Foreign grant claims refuse before selected reads", INPUTS,
            ' || grantID != "" && grantID != lane.GrantSetID', "",
            ["TestOwnLifeClaimsBeforeSelectedReads", "lane", "brief-render"],
            "foreign grant claim reached selected briefing inputs or objects"),
        tpl("worker-own-life", "Worker endpoints obey the own-life claim rule", INPUTS,
            'return scope.Actor.Kind == "lane" || scope.Actor.Kind == "worker"',
            'return scope.Actor.Kind == "lane"',
            ["TestOwnLifeClaimsBeforeSelectedReads", "worker", "brief-render"],
            "foreign grant claim reached selected briefing inputs or objects"),
        tpl("worker-own-role", "Worker role claims agree with the authentic life", INPUTS,
            " || lane.Role != role.Role", "",
            ["TestWorkerRoleClaimsBeforeSelectedReads", "role"],
            "worker role claim reached selected briefing inputs or objects"),
        tpl("worker-own-level", "Worker level claims agree with the authentic life", INPUTS,
            "lane.Level != role.Level || ", "",
            ["TestWorkerRoleClaimsBeforeSelectedReads", "level"],
            "worker role claim reached selected briefing inputs or objects"),
        tpl("own-life-before-read", "Foreign life claims cannot be silently rewritten", SERVICE,
            block('if request.LifeID != "" && request.LifeID != scope.Actor.LifeID {',
                  '\treturn api.Briefing{}, problem(api.CodeForbidden, "brief.start cannot impersonate another lane life",',
                  '\t\t"Use the authenticated life or omit --life-id.")', "}", depth=2),
            "", ["TestOwnLifeClaimsBeforeSelectedReads", "lane", "start"],
            "foreign life claim reached selected briefing inputs or objects"),
        tpl("own-context-before-life", "A lifecycle label cannot bypass the caller role", SERVICE,
            "if err := selfContext(scope, request.Context); err != nil {",
            "if err := selfContext(scope, request.Context); err != nil && !lifecycleRender(scope.Request.Method) {",
            ["TestLifecycleLabelCannotBypassOwnLife"],
            "lifecycle method label bypassed the authenticated parent’s own life"),
        tpl("own-input-selector", "Briefing inputs use the resolved authentic life", SERVICE,
            "inputRequest.LifeID, inputRequest.GrantSetID = current.LifeID, current.GrantSetID",
            "inputRequest.GrantSetID = current.GrantSetID",
            ["TestOwnLifeBriefings", "lane"],
            "own-life render lost its authentic selector, output or read-only behavior"),
        tpl("render-current-run", "Render input matches the current run", SERVICE,
            "lane.Generation != current.Generation || lane.Run != current.Run || lane.Task != current.Task",
            "lane.Generation != current.Generation || lane.Task != current.Task",
            ["TestCurrentLifeInputBinding", "render", "run"],
            "changed current-life input reached retained source or prompt bytes"),
        tpl("start-current-run", "Start input matches the current run", SERVICE,
            "input.Lane.Generation != current.Generation || input.Lane.Run != current.Run ||",
            "input.Lane.Generation != current.Generation ||",
            ["TestCurrentLifeInputBinding", "start", "run"],
            "changed current-life input reached retained source or prompt bytes"),
        tpl("render-current-generation", "Render input matches the current generation", SERVICE,
            "lane.Generation != current.Generation || lane.Run != current.Run || lane.Task != current.Task",
            "lane.Run != current.Run || lane.Task != current.Task",
            ["TestCurrentLifeInputBinding", "render", "generation"],
            "changed current-life input reached retained source or prompt bytes"),
        tpl("start-current-generation", "Start input matches the current generation", SERVICE,
            "input.Lane.Generation != current.Generation || input.Lane.Run != current.Run ||",
            "input.Lane.Run != current.Run ||",
            ["TestCurrentLifeInputBinding", "start", "generation"],
            "changed current-life input reached retained source or prompt bytes"),
        tpl("bootstrap-receipt-config", "Bootstrap retries retain their configuration domain", BOOTSTRAP,
            "reservation.Config != scope.Config || ", "",
            ["TestBootstrapReplayReceiptDomain", "config"],
            "foreign bootstrap receipt replayed or repeated proof use"),
        tpl("bootstrap-receipt-key", "Bootstrap retries retain their exact request key", BOOTSTRAP,
            "reservation.Key != key || ", "",
            ["TestBootstrapReplayReceiptDomain", "key"],
            "foreign bootstrap receipt replayed or repeated proof use"),
        tpl("bootstrap-receipt-actor", "Bootstrap retries retain their original principal", BOOTSTRAP,
            "reservation.Actor != scope.Actor || ", "",
            ["TestBootstrapReplayReceiptDomain", "principal"],
            "foreign bootstrap receipt replayed or repeated proof use"),
        tpl("lifecycle-receipt-config", "Lifecycle render receipts retain their configuration", APPROVED,
            "receipt.Config != scope.Config || ", "",
            ["TestLifecycleRenderReservation", "receipt-config"],
            "foreign lifecycle receipt retained a child prompt"),
        tpl("lifecycle-receipt-key", "Lifecycle render receipts retain their request key", APPROVED,
            "receipt.Key != key || ", "",
            ["TestLifecycleRenderReservation", "receipt-key"],
            "foreign lifecycle receipt retained a child prompt"),
        tpl("lifecycle-receipt-actor", "Lifecycle render receipts retain their principal", APPROVED,
            " || receipt.Actor != scope.Actor", "",
            ["TestLifecycleRenderReservation", "receipt-principal"],
            "foreign lifecycle receipt retained a child prompt"),
        tpl("bootstrap-replay-proof-id", "Proof ID shape is checked before replay", BOOTSTRAP,
            "!safeID.MatchString(string(scope.Request.Proof.ID)) || ", "",
            ["TestBootstrapProofBeforeReplay", "unsafe-id"],
            "invalid replay proof reached a durable receipt or repeated proof use"),
        tpl("bootstrap-replay-proof-digest", "Proof digest is checked before replay", BOOTSTRAP,
            " || scope.Request.Proof.RequestSHA256 != digest", "",
            ["TestBootstrapProofBeforeReplay", "digest"],
            "invalid replay proof reached a durable receipt or repeated proof use"),
        tpl("bootstrap-replay-lane-proof", "Lane proofs refuse before receipt lookup", BOOTSTRAP,
            'scope.Actor.Kind != "human" || scope.Request.Proof == nil',
            "scope.Request.Proof == nil",
            ["TestBootstrapProofBeforeReplay", "lane"],
            "invalid replay proof reached a durable receipt or repeated proof use"),
        tpl("file-render-validator", "Render file requests use their owned validator", CLI,
            block('{"brief.render", templatesInputCheck(templatesValidateRenderRequest)},', depth=2), "",
            ["TestCLIFileSemantics", "render"], "template file input missed its owned semantic validator"),
        tpl("file-start-validator", "Start file requests use their owned validator", CLI,
            block('{"brief.start", templatesInputCheck(templatesValidateStartRequest)},', depth=2), "",
            ["TestCLIFileSemantics", "start"], "template file input missed its owned semantic validator"),
        tpl("file-org-validator", "Org file requests use their owned validator", CLI,
            block('{"org.validate", templatesInputCheck(templatesValidateOrgRequest)},', depth=2), "",
            ["TestCLIFileSemantics", "validate"], "template file input missed its owned semantic validator"),
        tpl("file-bootstrap-validator", "Bootstrap file requests use their owned validator", CLI,
            block('{"org.bootstrap", templatesInputCheck(templatesValidateBootstrapRequest)},', depth=2), "",
            ["TestCLIFileSemantics", "bootstrap"], "template file input missed its owned semantic validator"),
        tpl("file-render-semantics", "Render validates its committed task class", CLI,
            'templatesBlob(request.Task, "task")', 'templatesBlob(request.Task, request.Task.Class)',
            ["TestCLIFileSemantics", "render"], "template file input missed its owned semantic validator"),
        tpl("file-start-semantics", "Start refuses reserved levels before transport", CLI,
            "value.Level < 3", "value.Level < 2",
            ["TestCLIFileSemantics", "start"], "template file input missed its owned semantic validator"),
        tpl("file-org-semantics", "Org validation needs a positive generation", CLI,
            "request.Generation == 0 || ", "",
            ["TestCLIFileSemantics", "validate"], "template file input missed its owned semantic validator"),
        tpl("file-bootstrap-semantics", "Bootstrap needs a committed manifest class", CLI,
            'templatesBlob(request.SourceManifest, "manifest")', 'templatesBlob(request.SourceManifest, request.SourceManifest.Class)',
            ["TestCLIFileSemantics", "bootstrap"], "template file input missed its owned semantic validator"),
        tpl("service-render-label", "Service rendering needs a lifecycle reservation", APPROVED,
            block('if scope.Actor.Kind == "service" {',
                  '\treturn "", api.Actor{}, problem(api.CodeForbidden, "service rendering requires a reserved lifecycle cause",',
                  '\t\t"Render through the original reserved lifecycle request; a service read label supplies no cause.")', "}", depth=2), "",
            ["TestServiceRenderGuards", "label"], "unlabelled service render retained a prompt"),
        tpl("service-render-life", "Service receipts bind the actual reserved life", APPROVED,
            block("\treceipt.Operation.LifeID != lane.LifeID ||"), "",
            ["TestServiceRenderGuards", "foreign-life"], "unbound service render retained a prompt"),
        tpl("service-render-actor", "Service rendering preserves an authentic requester", APPROVED,
            block('if scope.Actor.Kind == "service" &&',
                  '\t(receipt.Actor.Kind != "lane" && receipt.Actor.Kind != "human" || !safeID.MatchString(string(receipt.Actor.ID)) ||',
                  '\t\treceipt.Actor.Kind == "lane" && !safeID.MatchString(string(receipt.Actor.LifeID)) ||',
                  '\t\treceipt.Actor.Kind == "human" && receipt.Actor.LifeID != "") {',
                  '\treturn "", api.Actor{}, problem(api.CodeForbidden, "service render receipt has no authentic lane or human requester",',
                  '\t\t"Use the original lane/human lifecycle reservation and its actual requester.")', "}"), "",
            ["TestServiceRenderGuards", "actor"], "unbound service render retained a prompt"),
        tpl("service-original-requester", "Retained prompts name the original requester", APPROVED,
            "RequestedBy: requester,", "RequestedBy: scope.Actor,",
            ["TestLifecycleRenderReservation"], "lifecycle render lost its original operation or requester"),
        tpl("service-reply-binding", "Queued lifecycle replies bind their active operation", APPROVED,
            block("if err := renderReceiptReply(receipt); err != nil {", '\treturn "", api.Actor{}, err', "}"), "",
            ["TestServiceReply", "operation"], "foreign lifecycle reply retained a prompt"),
        tpl("service-human-requester", "Human lifecycle reservations retain their original actor", APPROVED,
            'receipt.Actor.Kind != "lane" && receipt.Actor.Kind != "human"', 'receipt.Actor.Kind != "lane"',
            ["TestServiceHuman"], "human lifecycle requester lost its retained cause"),
        tpl("seed-required-production", "Bootstrap requires its workflow pack", ORG,
            block("workflow, present := files[WorkflowPath]", "if !present {",
                  '\treturn invalid("org workflow source is required")', "}",
                  "if _, err := parseSeed(workflow); err != nil {", "\treturn err", "}"), "",
            ["TestBootstrapWorkflow", "missing"], "bootstrap accepted a missing or invalid workflow seed"),
        tpl("seed-parse-production", "Bootstrap validates actual workflow routes", ORG,
            block("if _, err := parseSeed(workflow); err != nil {", "\treturn err", "}"),
            block("if len(workflow) == 0 {", '\treturn invalid("org workflow source is empty")', "}"),
            ["TestBootstrapWorkflow", "route"], "bootstrap accepted a missing or invalid workflow seed"),
        tpl("seed-org-production", "Org validation checks actual workflow routes", ORG,
            block("if _, err := parseSeed(workflow); err != nil {", "\treturn err", "}"),
            block("if len(workflow) == 0 {", '\treturn invalid("org workflow source is empty")', "}"),
            ["TestOrgWorkflow", "route"], "org validation accepted a missing or invalid workflow seed"),
        tpl("seed-source-discovery", "Workflow source participates in full org validation", ORG,
            " || name == WorkflowPath", "",
            ["TestOrgValidationNeedsSources"], "complete approved source validation failed or changed state"),
        tpl("prompt-stable-key", "Identical renders reuse an immutable object", APPROVED,
            "promptObjectKey(scope, input, snapshot, document, acl, refs, requester, causeID)", "newID()",
            ["TestPromptObjectKey"], "identical render inputs allocated multiple prompt objects"),
        tpl("cli-typed-subcalls", "Typed feature subcalls need no foreign file hook", CLI,
            "err = rpc.Invoke(ctx, params)", "err = rpc.InvokeRaw(ctx, data)",
            ["TestTemplatesCLI"], "template CLI failed its typed transport path", CLI_PACKAGE),
        tpl("cli-file-exact-bytes", "Feature file requests retain their original bytes", CLI,
            "err = rpc.InvokeRaw(ctx, data)", "err = rpc.Invoke(ctx, json.RawMessage(data))",
            ["TestTemplatesFileBytes"], "template file input lost its exact bytes or shared read session", CLI_PACKAGE),
        tpl("cli-session-staging", "Blob staging uses the existing human read session", CLI,
            "spec.Mutation && !api.HumanSessionMethod(method)", "spec.Mutation",
            ["TestTemplatesStage"], "session staging lost its connection-scoped proof", CLI_PACKAGE),
        tpl("cli-start-identity", "Start verifies its returned identity before task access", CLI,
            block("if self.Config != call.Config ||",
                  '\t!((self.Actor.Kind == "human" && self.Actor.LifeID == "") ||',
                  '\t\t(self.Actor.Kind == "lane" || self.Actor.Kind == "worker") && templatesID.MatchString(string(self.Actor.LifeID))) {',
                  '\treturn templatesIntegrity("briefing identity response is missing its bound configuration or life")', "}", depth=2), "",
            ["TestTemplatesIdentity"], "start skipped its authenticated identity and task boundary", CLI_PACKAGE),
        tpl("cli-file-nonblocking", "A FIFO cannot block the bounded file reader", CLI,
            "os.O_RDONLY|syscall.O_NONBLOCK", "os.O_RDONLY|syscall.O_RDONLY",
            ["TestTemplatesFIFO"], "template file reader blocked on a FIFO", CLI_PACKAGE),
        tpl("live-policy-order", "Live policy drift preserves historical grants", RENDER,
            "grants.PolicyGeneration > lane.PolicyGeneration || lane.PolicyGeneration > policy.Generation ||",
            "grants.PolicyGeneration != policy.Generation || lane.PolicyGeneration != policy.Generation ||",
            ["TestPolicyLive"], "live policy drift refused or rewrote historical grants"),
        tpl("new-launch-current", "New lives require current policy equality", RENDER,
            '(newLaunch || lane.Run == 1 && lane.State == "preparing")',
            '(newLaunch && lane.Run == 0)',
            ["TestPolicyLaunch"], "new launch accepted historical policy generations"),
        tpl("plan-continue-route", "Internal continuations use retained planning causes", PREPARATION,
            '} else if scope.Request.Method != "" {', '} else if !lifecycleRender(scope.Request.Method) {',
            ["TestPlanRender", "continue"], "reserved launch could not render its active task"),
        tpl("plan-phase", "Failed plans cannot prepare another prompt", PREPARATION,
            block('if record.Phase != "reserved" && record.Phase != "sourced" {',
                  '\treturn nil, problem(api.CodeConflict, "briefing launch plan is past prompt preparation",',
                  '\t\t"Reconcile the retained plan; never prepare a replacement from a completed or failed phase.")', "}", depth=2), "",
            ["TestPlanGuards", "phase"], "invalid planning authority reached briefing inputs or retained a prompt"),
        tpl("plan-claim", "A planning claim must still be held", PREPARATION,
            "!s.deps.Clock.Now().Before(expires)", "expires.IsZero()",
            ["TestPlanGuards", "claim"], "invalid planning authority reached briefing inputs or retained a prompt"),
        tpl("plan-original-cause", "Planned prompts retain the exact original requester", PREPARATION,
            "cause.RequestedBy != r.RequestedBy ||", "cause.RequestedBy.Kind != r.RequestedBy.Kind ||",
            ["TestPlanGuards", "requester"], "invalid planning authority reached briefing inputs or retained a prompt"),
        tpl("plan-input-fence", "The reserved run binds briefing inputs", PREPARATION,
            "lane.Run != r.Target.Run ||", "",
            ["TestPlanGuards", "input"], "invalid planning authority reached briefing inputs or retained a prompt"),
        tpl("turn-task-assignment", "Render uses the active turn task", SERVICE,
            "if *input.Task != request.Task {", "if lane.Task != request.Task || *input.Task != request.Task {",
            ["TestTurnTask"], "active turn task was confused with original life task"),
        tpl("cli-turn-task", "CLI renders a committed active turn task", CLI,
            'if options.taskRef != "" {', 'if options.taskRef == "" {',
            ["TestTemplatesTurn"], "CLI refused the committed active turn task", CLI_PACKAGE),
        tpl("boot-presence-proof", "Verified proof and reference presence marks agree", BOOTSTRAP,
            "proof.SimulatedPresence != proof.Ref.SimulatedPresence || ", "",
            ["TestBootPresenceGuard", "verified"], "bootstrap accepted changed presence provenance"),
        tpl("boot-presence-receipt", "A simulated reservation cannot become hardware", BOOTSTRAP,
            "(reservation.SimulatedPresence && !proof.SimulatedPresence) ||", "",
            ["TestBootPresenceGuard", "receipt"], "bootstrap accepted changed presence provenance"),
        tpl("boot-presence-stamp", "Queued bootstrap operations preserve verified presence", BOOTSTRAP,
            block("operation.SimulatedPresence = reservation.Operation.SimulatedPresence || proof.SimulatedPresence"), "",
            ["TestBootPresence"], "bootstrap lost verified presence provenance"),
        tpl("boot-presence-reply", "Replay cannot change the durable presence mark", BOOTSTRAP,
            block("if operation.SimulatedPresence != expectedPresence {",
                  '\treturn api.Operation{}, integrity("bootstrap reply lost verified presence provenance")', "}"), "",
            ["TestBootPresenceGuard", "replay"], "bootstrap accepted changed presence provenance"),
        tpl("boot-presence-commit", "The committed operation agrees with its reply", BOOTSTRAP,
            block("if !commit.Replayed && commit.Operation.SimulatedPresence != result.SimulatedPresence {",
                  '\treturn api.Operation{}, integrity("bootstrap reply lost verified presence provenance")', "}"), "",
            ["TestBootPresenceGuard", "commit"], "bootstrap accepted changed presence provenance"),
        tpl("service-before-input", "Service causality is checked before input selection", SERVICE,
            block("preparation, err := s.renderPreflight(ctx, scope, request)", "if err != nil {",
                  "\treturn api.Briefing{}, err", "}"), block("var preparation *renderPreparation"),
            ["TestServicePreflight", "label"], "service causal preconditions ran after briefing input selection"),
        tpl("plan-start-flow", "A valid start reaches reserved and sourced rendering", PREPARATION,
            "selector.PlanLaunch == nil ||", "selector.PlanLaunch != nil ||",
            ["TestPlanRender", "start"], "reserved launch could not render its active task"),
        tpl("plan-turn-flow", "A valid turn reaches reserved and sourced rendering", PREPARATION,
            "selector.PlanLaunch == nil ||", "selector.PlanLaunch != nil ||",
            ["TestPlanRender", "turn"], "reserved launch could not render its active task"),
        tpl("plan-public-grants", "Matched public plan grant mismatches refuse", PREPARATION,
            'if scope.Request.Method == "" && r.GrantSetID != request.GrantSetID {',
            'if r.GrantSetID != request.GrantSetID {',
            ["TestPlanMatch", "grants"], "matched plan mismatch did not fail before fallback"),
        tpl("plan-public-launch", "Matched public launch mismatches cannot fall back", PREPARATION,
            block("r := record.Reservation", 'if scope.Request.Method == "" && r.GrantSetID != request.GrantSetID {', depth=2),
            block("r := record.Reservation", 'if scope.LaunchID != "" && scope.LaunchID != r.LaunchID {',
                  "\tcontinue", "}", 'if scope.Request.Method == "" && r.GrantSetID != request.GrantSetID {', depth=2),
            ["TestPlanMatch", "launch"], "matched plan mismatch did not fail before fallback"),
        tpl("plan-continue-launch", "Matched continuation launch mismatches refuse integrity", PREPARATION,
            block("r := record.Reservation", 'if scope.Request.Method == "" && r.GrantSetID != request.GrantSetID {', depth=2),
            block("r := record.Reservation", 'if scope.LaunchID != "" && scope.LaunchID != r.LaunchID {',
                  "\tcontinue", "}", 'if scope.Request.Method == "" && r.GrantSetID != request.GrantSetID {', depth=2),
            ["TestPlanMatch", "continue"], "matched plan mismatch did not fail before fallback"),
        tpl("exact-render-snapshot", "Render passes the exact source publication", APPROVED,
            "Generation: provided.Snapshot.Generation", "Generation: 0",
            ["TestExactSnapshots"], "render omitted its exact source snapshot selector"),
        tpl("exact-org-snapshot", "Org validation passes its exact publication", SERVICE,
            "Generation: request.Generation", "Generation: 0",
            ["TestExactSnapshots"], "org validation omitted its exact source snapshot selector"),
        tpl("semantic-source-kind", "Sources cannot masquerade as structural files", APPROVED,
            kinds_check + inventory_loop + file_check,
            inventory_loop + file_check.replace("!snapshotKind", "group != 0 && !snapshotKind"),
            ["TestInventoryKinds", "source-file"], "full source gate accepted invalid kinds or retained content"),
        tpl("structural-derived-kind", "Derived inventory uses structural file kinds", APPROVED,
            kinds_check + inventory_loop + file_check,
            inventory_loop + file_check.replace("!snapshotKind", "group == 0 && !snapshotKind"),
            ["TestInventoryKinds", "derived-kind"], "full source gate accepted invalid kinds or retained content"),
        tpl("derived-inventory-required", "Full validation needs actual derived inventory", APPROVED,
            kinds_check, "",
            ["TestInventoryKinds", "no-derived"], "full source gate accepted invalid kinds or retained content"),
        tpl("source-callback-content", "The acyclic callback checks retained source bytes", ORG,
            block("if err := s.validateOrg(ctx, scope, snapshot); err != nil {", "\treturn api.OrgValidation{}, err", "}"), "",
            ["TestSourceCallback"], "complete source callback recursed or skipped retained content"),
        tpl("exact-inventory-source", "A source ID alone cannot select other source bytes", INVENTORY,
            "if file.Source == ref {", "if file.Source.ID == ref.ID {",
            ["TestInventorySource", "hash"], "source lookup accepted a nonmatching retained source reference"),
        tpl("inventory-local-pair", "Partial local pairs cannot become fallback", INVENTORY,
            block('if !hasPrompt || !hasDrivers || prompt.Kind != "prompt" || catalog.Kind != "drivers" {',
                  '\treturn api.RoleTemplateSources{}, false, invalid("template prompt and driver sources must be a complete semantic pair")', "}", depth=2), "",
            ["TestInventorySelect"], "inventory selection treated a partial local pair as absent"),
        tpl("org-kind-path", "Full validation checks every template path's semantic kind", ORG,
            block("if isTemplateSource(file.Source.Path) && file.Kind != templateSourceKind(file.Source.Path) {",
                  '\treturn invalid("template source kind differs from its prompt, drivers or workflow path")', "}", depth=2), "",
            ["TestOrgKinds", "callback", "unselected"], "org validation accepted a template kind that disagrees with its path"),
        tpl("org-bound-snapshot", "Inventory org ID belongs to its configuration", APPROVED,
            " || ref.OrgID != api.ID(scope.Config)", "",
            ["TestOrgBoundary", "selection"], "inventory accepted an org outside its configuration"),
        tpl("org-bound-validate", "Org ID refuses before policy validation", SERVICE,
            " || snapshot.Ref.OrgID != api.ID(scope.Config)", "",
            ["TestOrgBoundary", "org"], "foreign org snapshot reached policy or content validation"),
        tpl("org-bound-render", "Provided org ID refuses before snapshot lookup", APPROVED,
            block("if provided.Snapshot.OrgID != api.ID(scope.Config) {",
                  '\treturn nil, api.OrgSnapshot{}, problem(api.CodeConflict, "template snapshot belongs to another configuration",',
                  '\t\t"Resolve the configuration\'s exact approved org generation.")', "}"), "",
            ["TestOrgBoundary", "render"], "foreign template selection reached snapshot lookup"),
        tpl("store-view-config", "Borrowed views must carry the bound configuration", STORE_SOURCES,
            block("if scope.ReadView != nil && scope.ReadView.Snapshot().Config != scope.Config {",
                  '\treturn sourceFault(api.CodeIntegrity, "source read view omits its bound configuration")', "}"), "",
            ["TestSourceView", "foreign"], "source adapter accepted an unbound or foreign read view", STORE_PACKAGE),
        tpl("store-empty-config", "Empty store and scope configs refuse", STORE_SOURCES,
            'scope.Config == "" || s.deps.Config == "" || ', "",
            ["TestSourceView", "empty"], "source adapter accepted an unbound or foreign read view", STORE_PACKAGE),
        tpl("store-acl-generation", "Source object ACLs have a committed generation", STORE_SOURCES,
            " || metadata.ACL.Generation == 0", "",
            ["TestSourceMetadata", "generation"], "source adapter accepted uncommitted object metadata", STORE_PACKAGE),
        tpl("store-source-order", "Source binding takes precedence over malformed claims", STORE_SOURCES,
            block("if err := s.sourceScope(scope); err != nil {", "\treturn result, err", "}",
                  "if err := templates.ValidateSourceRef(request); err != nil {", "\treturn result, err", "}"),
            block("if err := templates.ValidateSourceRef(request); err != nil {", "\treturn result, err", "}",
                  "if err := s.sourceScope(scope); err != nil {", "\treturn result, err", "}"),
            ["TestSourceRequests", "cross-zero"], "source request crossed its configuration or preflight boundary", STORE_PACKAGE),
        tpl("store-template-order", "Template binding precedes generation validation", STORE_SOURCES,
            block("if err := s.sourceScope(scope); err != nil {", "\treturn result, err", "}",
                  "if api.ValidateOrgSnapshotRequest(scope, api.OrgSnapshotRequest{OrgID: request.OrgID, Generation: request.Generation}) != nil {",
                  '\treturn result, sourceFault(api.CodeInvalid, "template sources require this org and an exact generation")', "}"),
            block("if api.ValidateOrgSnapshotRequest(scope, api.OrgSnapshotRequest{OrgID: request.OrgID, Generation: request.Generation}) != nil {",
                  '\treturn result, sourceFault(api.CodeInvalid, "template sources require this org and an exact generation")', "}",
                  "if err := s.sourceScope(scope); err != nil {", "\treturn result, err", "}"),
            ["TestSourceRequests", "cross-zero"], "template request crossed its configuration or generation boundary", STORE_PACKAGE),
        tpl("store-template-range", "Template generations stay in the supported integer range", STORE_SOURCES,
            "api.ValidateOrgSnapshotRequest(scope, api.OrgSnapshotRequest{OrgID: request.OrgID, Generation: request.Generation}) != nil",
            "request.OrgID != api.ID(scope.Config) || request.Generation == 0",
            ["TestSourceRequests", "range"], "template request crossed its configuration or generation boundary", STORE_PACKAGE),
        tpl("store-source-claim", "Malformed source claims refuse before opening a view", STORE_SOURCES,
            block("if err := templates.ValidateSourceRef(request); err != nil {", "\treturn result, err", "}"), "",
            ["TestSourceRequests", "id"], "source request crossed its configuration or preflight boundary", STORE_PACKAGE),
        tpl("source-ref-claim", "Pure source lookup validates claims before inventory scan", INVENTORY,
            block("if err := ValidateSourceRef(ref); err != nil {", "\treturn api.RetainedSource{}, err", "}"), "",
            ["TestSourceClaim", "id"], "malformed source claim reached inventory lookup"),
        tpl("initial-source-shape", "Generation one has an explicit empty derived inventory", APPROVED,
            " || len(snapshot.Sources) == 0 {", " || len(snapshot.Sources) == 0 || len(snapshot.Derived) == 0 {",
            ["TestInitialShape"], "explicit initial empty derived inventory was refused"),
        tpl("initial-nil-shape", "Generation one rejects null derived inventory", APPROVED,
            "if api.ValidateOrgKinds(snapshot) != nil {", "if api.ValidateOrgKinds(snapshot) != nil && snapshot.Derived != nil {",
            ["TestInitialGuards", "nil"], "initial shape repair bypassed an inventory integrity gate"),
        tpl("initial-extra-shape", "Generation one rejects generated entries", APPROVED,
            "if api.ValidateOrgKinds(snapshot) != nil {", "if api.ValidateOrgKinds(snapshot) != nil && snapshot.Ref.Generation != 1 {",
            ["TestInitialGuards", "unexpected"], "initial shape repair bypassed an inventory integrity gate"),
        tpl("callback-org-code", "Foreign returned orgs are integrity violations", ORG,
            'integrity("source validation snapshot differs from its configuration")',
            'problem(api.CodeConflict, "source validation snapshot differs from its configuration", "Use the exact configuration.")',
            ["TestOrgRead", "callback", "org"], "org read confused a foreign projection with a stale generation"),
        tpl("store-org-code", "Both store source adapters share the projection fence", STORE_SOURCES,
            block("return api.ValidateOrgSnapshotSelection(scope, api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: generation}, snapshot)"),
            block("if snapshot.Ref.OrgID != api.ID(scope.Config) {",
                  '\treturn sourceFault(api.CodeConflict, "source snapshot belongs to another org")', "}",
                  "return api.ValidateOrgSnapshotSelection(scope, api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: generation}, snapshot)"),
            ["TestSourceSnapshot", "org"], "source projection confused a foreign publication with a stale generation", STORE_PACKAGE),
        tpl("store-context-preflight", "Invalid role contexts refuse before view acquisition", STORE_SOURCES,
            block("if err := templates.ValidateTemplateContext(request.Context); err != nil {", "\treturn result, err", "}"), "",
            ["TestSourceContext", "new", "level"], "invalid source context reached view or snapshot lookup before preflight", STORE_PACKAGE),
    ]


def require(condition, reason):
    if not condition:
        raise MutationFailure(reason)


def require_compiled(mutation, phase, code, stdout, stderr):
    if code == 0:
        return
    label = mutation.id + "/" + phase
    print(label + ": compiler exited " + str(code), file=sys.stderr)
    for channel, path in (("stdout", stdout), ("stderr", stderr)):
        diagnostic = path.read_bytes().decode("utf-8", errors="replace")
        if diagnostic:
            print(label + ": compiler " + channel + ":", file=sys.stderr)
            print(diagnostic, end="" if diagnostic.endswith("\n") else "\n", file=sys.stderr)
    raise MutationFailure(label + ": a compile failure cannot kill a mutation")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            value.update(chunk)
    return value.hexdigest()


def exact_replacement(data, mutation):
    before, after = mutation.before.encode(), mutation.after.encode()
    require(bool(before) and data.count(before) == 1,
            "mutation anchor must occur exactly once")
    require(before != after, "mutation cannot be a no-op")
    changed = data.replace(before, after, 1)
    require(changed != data, "mutation did not change source bytes")
    return changed


def checked_catalog():
    entries = catalog()
    seen = set()
    for item in entries:
        require(re.fullmatch(r"[a-z][a-z0-9-]{0,38}", item.id) is not None,
                "invalid mutation identifier")
        require(item.id not in seen, "duplicate mutation identifier")
        seen.add(item.id)
        target = PurePosixPath(item.file)
        require(target.suffix == ".go" and not target.name.endswith("_test.go"),
                "mutations may not edit or weaken tests")
        require(item.file in (CLI, STORE_SOURCES) or target.parent == PurePosixPath(PACKAGE_PATH),
                "mutation is outside this lane's source ownership")
        require(item.assertion in ("TPL-SCOPE", "LB-FIRST") and item.failure_contains,
                "mutation must name an assertion and failure reason")
        require(item.package in (PACKAGE, CLI_PACKAGE, STORE_PACKAGE), "mutation has a foreign test package")
        require((item.file == STORE_SOURCES) == (item.package == STORE_PACKAGE),
                "store controls must select the authorized store source and package together")
        require(item.test and re.fullmatch(r"Test[A-Za-z0-9_]+", item.test[0]),
                "mutation must select an actual Go test")
        require(all(re.fullmatch(r"[A-Za-z0-9_-]+", word) for word in item.test),
                "mutation test selector is not a literal name")
    return entries


def analyze(records, exit_code, mutation, phase):
    """Classify actual test2json records; setup failures never kill a mutant."""
    require(phase in ("red", "green"), "unknown mutation phase")
    target = "/".join(mutation.test)
    ancestors = {"/".join(mutation.test[:index])
                 for index in range(1, len(mutation.test))}
    runs, failures, passes, skipped = set(), set(), set(), set()
    output = []
    package_terminal = []
    terminals = set()
    for row in records:
        require(not package_terminal, "test records continue after the package terminal")
        require(isinstance(row, dict) and row.get("Package") == mutation.package,
                "test records have the wrong package or shape")
        action = row.get("Action")
        require(action in ("start", "run", "pause", "cont", "output",
                           "pass", "fail", "skip", "bench"),
                "test records contain an unknown action")
        name = row.get("Test", "")
        require(isinstance(name, str), "invalid test name in records")
        related = name == target or name.startswith(target + "/")
        allowed = related or name in ancestors
        if name and action == "run":
            require(allowed, "an unrelated test ran")
            require(name not in runs, "a focused test ran more than once")
            runs.add(name)
        if name and action in ("pass", "fail", "skip"):
            require(name not in terminals, "a test has duplicate terminal records")
            require(allowed and name in runs, "test terminal has no matching focused run")
            terminals.add(name)
        if action == "fail" and name:
            failures.add(name)
        if action == "pass" and name:
            passes.add(name)
        if action == "skip":
            skipped.add(name)
        if action in ("pass", "fail", "skip") and not name:
            package_terminal.append(action)
        if action == "output":
            text = row.get("Output")
            require(isinstance(text, str), "test output is not text")
            require("panic:" not in text and "runtime error:" not in text,
                    "a panic or runtime fault is not an assertion failure")
            if related:
                require(name in runs and name not in terminals,
                        "assertion output is outside the focused test run")
                output.append(text)
    require(not skipped, "skipped tests cannot prove a mutation")
    require(target in runs and runs <= terminals,
            "the focused test did not run to a terminal observation")
    require(len(package_terminal) == 1, "missing or ambiguous package terminal")
    if phase == "red":
        require(exit_code == 1 and package_terminal == ["fail"],
                "the mutated test did not fail normally")
        require(target in failures, "the intended test did not fail")
        require(mutation.failure_contains in "".join(output),
                "the intended assertion failure was not observed")
    else:
        require(exit_code == 0 and package_terminal == ["pass"]
                and target in passes and not failures,
                "restored source did not pass the same focused test")
    return {"target": target, "reached": sorted(runs),
            "failed": sorted(failures), "passed": sorted(passes),
            "observed_exit": exit_code}


def read_records(path):
    records = []
    with path.open("rb") as stream:
        for line in stream:
            require(len(line) <= 1048576, "test record exceeds its bound")
            try:
                row = json.loads(line)
            except (ValueError, UnicodeError) as error:
                raise MutationFailure("test output is not complete JSONL") from error
            records.append(row)
    require(records, "test output contains no observations")
    return records


def relative_name(value):
    name = PurePosixPath(value)
    require(not name.is_absolute() and str(name) == value and
            value not in ("", ".") and ".." not in name.parts,
            "source inventory has a path outside its root")
    require(name.parts[0] not in (".git", ".aws", ".ssh", ".codex",
                                 ".claude", ".config", ".env"),
            "source inventory includes a private runtime directory")
    return Path(*name.parts)


def own_source(value):
    private = {".git", ".aws", ".ssh", ".codex", ".claude", ".config", ".env"}
    parts = PurePosixPath(value).parts
    if any(part in private for part in parts):
        return False
    if PurePosixPath(value).suffix not in (".go", ".py", ".sh", ".json", ".md", ".toml"):
        return False
    return (value in (CLI, STORE_SOURCES, STORE_TEST) or any(value.startswith(prefix + "/") for prefix in (
        "internal/v2/templates", "templates/v2", "examples/v2",
        str(CASE_PATH))))


class Proof:
    def __init__(self, source, root, entries, tags, deadline, max_seconds,
                 file_list=None, revision_file=None, vet_only=False):
        self.source, self.root = source, root
        self.copy = root / "source"
        self.entries, self.tags, self.deadline = entries, tags, deadline
        self.ends_at = time.monotonic() + max_seconds
        self.file_list, self.revision_file = file_list, revision_file
        self.vet_only = vet_only
        self.active = set()
        self.evidence = set()
        self.inventory = []
        self.cli_overlay = None
        self.results = [{"id": item.id, "assertion": item.assertion,
                         "scope": "component", "boundary": item.boundary,
                         "status": "not_reached"} for item in entries]

    def keep_json(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
        os.replace(temporary, path)
        self.evidence.add(relative)
        return path

    def keep_bytes(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(value)
        self.evidence.add(relative)
        return path

    def command(self, relative, argv, cwd):
        remaining = int(self.ends_at - time.monotonic())
        require(remaining > 0, "overall mutation deadline expired")
        limit = min(self.deadline, remaining)
        directory = self.root / relative
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.keep_json(relative + "/command.json", {"argv": argv,
                       "cwd": str(cwd), "timeout_seconds": limit})
        stdout, stderr = directory / "stdout", directory / "stderr"
        start = time.monotonic()
        timed_out = False
        with stdout.open("wb") as out, stderr.open("wb") as err:
            process = subprocess.Popen(argv, cwd=cwd, stdout=out, stderr=err,
                                       start_new_session=True)
            self.active.add(process.pid)
            self.keep_json(relative + "/process.json", {"pid": process.pid,
                           "process_group": process.pid})
            try:
                process.wait(timeout=limit)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait(timeout=10)
        self.evidence.update((relative + "/stdout", relative + "/stderr"))
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            self.active.discard(process.pid)
        self.keep_json(relative + "/exit.json", {
            "exit": process.returncode, "timed_out": timed_out,
            "elapsed_seconds": time.monotonic() - start,
            "process_group_quiescent": process.pid not in self.active,
        })
        require(not timed_out, "command deadline expired")
        require(process.pid not in self.active, "owned process group still survives")
        return process.returncode, stdout, stderr

    def prepare(self):
        if self.vet_only:
            self.keep_json("inputs/platform.json", {
                "system": sys.platform, "machine": platform.machine(),
                "kernel": os.uname().release, "mode": "static-only",
            })
        else:
            release = platform.freedesktop_os_release()
            require(release.get("ID") == "ubuntu" and release.get("VERSION_ID") == "24.04",
                    "mutation execution requires Ubuntu 24.04")
            self.keep_json("inputs/platform.json", {
                "system": sys.platform, "distribution": release["ID"],
                "version": release["VERSION_ID"], "machine": platform.machine(),
                "kernel": os.uname().release,
            })
        if self.file_list is not None:
            data = self.file_list.read_bytes()
            require(data.endswith(b"\0"), "source file list must be NUL-terminated")
            revision_bytes = self.revision_file.read_bytes()
            require(re.fullmatch(rb"[a-f0-9]{7,40}\n?", revision_bytes) is not None,
                    "supplied revision file is not a source revision")
            listing = self.keep_bytes("inputs/file-list", data)
            revision = self.keep_bytes("inputs/revision", revision_bytes)
            tracked = {name.decode("utf-8") for name in data.split(b"\0") if name}
            revision_source = "supplied-file"
        else:
            exit_code, listing, _ = self.command(
                "inputs/tracked", ["git", "ls-files", "-z"], self.source)
            require(exit_code == 0, "could not obtain the tracked source inventory")
            tracked = {name.decode("utf-8") for name in listing.read_bytes().split(b"\0") if name}
            exit_code, listing, _ = self.command(
                "inputs/untracked", ["git", "ls-files", "--others",
                                     "--exclude-standard", "-z"], self.source)
            require(exit_code == 0, "could not obtain this lane's new source inventory")
            tracked.update(name.decode("utf-8") for name in listing.read_bytes().split(b"\0")
                           if name and own_source(name.decode("utf-8")))
            exit_code, revision, _ = self.command(
                "inputs/revision", ["git", "rev-parse", "HEAD"], self.source)
            require(exit_code == 0, "source revision could not be retained")
            revision_source = "git"
        require(tracked, "source inventory is empty")
        for name in sorted(tracked):
            relative = relative_name(name)
            original = self.source / relative
            require(original.parent.resolve().is_relative_to(self.source),
                    "source parent escapes through a link")
            metadata = original.lstat()
            row = {"path": name, "mode": stat.S_IMODE(metadata.st_mode)}
            require(not row["mode"] & ~0o777, "source file has a special mode")
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(original)
                require(not Path(target).is_absolute() and
                        original.resolve(strict=True).is_relative_to(self.source),
                        "source link escapes or has no retained target")
                row.update(kind="symlink", target=target)
            else:
                require(stat.S_ISREG(metadata.st_mode), "source contains a special file")
                row.update(kind="file", bytes=metadata.st_size, sha256=file_sha(original))
            self.inventory.append(row)
        require(any(row["path"] == "go.mod" for row in self.inventory),
                "source root does not contain the module")
        self.copy.mkdir(mode=0o700)
        for row in self.inventory:
            original, target = self.source / row["path"], self.copy / row["path"]
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if row["kind"] == "symlink":
                target.symlink_to(row["target"])
            else:
                shutil.copyfile(original, target, follow_symlinks=False)
                target.chmod(row["mode"])
        self.verify_tree(self.copy)
        self.verify_tree(self.source)
        inventory = self.keep_json("inputs/source-manifest.json", self.inventory)
        self.keep_json("inputs/source-digest.json", {"sha256": file_sha(inventory)})
        exit_code, version, _ = self.command("inputs/go", ["go", "version"], self.copy)
        require(exit_code == 0, "Go toolchain is unavailable")
        archive = self.root / "inputs/source.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            for row in self.inventory:
                path = self.copy / row["path"]
                info = bundle.gettarinfo(str(path), arcname=row["path"])
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                if row["kind"] == "file":
                    with path.open("rb") as stream:
                        bundle.addfile(info, stream)
                else:
                    bundle.addfile(info)
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            require(len(members) == len(self.inventory), "source archive inventory differs")
            for row, member in zip(self.inventory, members):
                require(member.name == row["path"] and member.mode == row["mode"],
                        "source archive changed a path or mode")
                if row["kind"] == "file":
                    stream = bundle.extractfile(member)
                    require(stream is not None, "source archive omitted file bytes")
                    with stream:
                        require(sha(stream.read()) == row["sha256"],
                                "source archive read-back hash differs")
                else:
                    require(member.issym() and member.linkname == row["target"],
                            "source archive changed a link")
        self.evidence.add("inputs/source.tar.gz")
        self.keep_json("inputs/identity.json", {
            "revision": revision.read_text().strip(),
            "revision_source": revision_source,
            "go_version": version.read_text().strip(), "tags": self.tags,
            "mode": "static-only" if self.vet_only else "red-green",
            "source_archive_sha256": file_sha(archive),
            "manifest_sha256": file_sha(inventory),
            "catalog": [asdict(item) for item in self.entries],
        })
        if self.vet_only or any(item.package == CLI_PACKAGE for item in self.entries):
            fixture = self.copy / PACKAGE_PATH / "_cli_test.go"
            require(fixture.is_file() and not fixture.is_symlink(), "owned CLI fixture source is absent")
            self.cli_overlay = self.keep_json("inputs/cli-overlay.json", {"Replace": {
                str(self.copy / "internal/v2/cli/templates_fixture_test.go"): str(fixture),
            }})

    def verify_tree(self, directory):
        if directory == self.copy:
            observed = set()
            for parent, directories, files in os.walk(directory, followlinks=False):
                for name in directories[:]:
                    child = Path(parent) / name
                    if child.is_symlink():
                        observed.add(child.relative_to(directory).as_posix())
                        directories.remove(name)
                observed.update((Path(parent) / name).relative_to(directory).as_posix()
                                for name in files)
            require(observed == {row["path"] for row in self.inventory},
                    "source copy gained or lost an input outside the selected mutation")
        for row in self.inventory:
            path = directory / row["path"]
            if row["kind"] == "symlink":
                require(path.is_symlink() and os.readlink(path) == row["target"],
                        "retained source link changed")
            else:
                require(not path.is_symlink() and path.is_file() and
                        path.stat().st_size == row["bytes"] and file_sha(path) == row["sha256"],
                        "retained source bytes changed outside the selected mutation")
            require(stat.S_IMODE(path.lstat().st_mode) == row["mode"],
                    "retained source mode changed")

    def test_phase(self, mutation, phase):
        require(not self.vet_only, "static vet mode cannot compile or execute tests")
        relative = mutation.id + "/" + phase
        binary = self.root / relative / "templates.test"
        compile_args = ["go", "test", "-c", "-mod=readonly", "-trimpath",
                        "-o", str(binary)]
        if self.tags:
            compile_args += ["-tags", self.tags]
        package_path = Path(mutation.package.removeprefix("laneboss.io/laneboss/"))
        if mutation.package == CLI_PACKAGE:
            require(self.cli_overlay is not None, "CLI test fixture overlay is absent")
            compile_args += ["-overlay", str(self.cli_overlay)]
        compile_args += ["./" + package_path.as_posix()]
        code, stdout, stderr = self.command(relative + "/compile", compile_args, self.copy)
        require_compiled(mutation, phase, code, stdout, stderr)
        require(binary.is_file() and not binary.is_symlink(), "compiled test binary is absent")
        with binary.open("rb") as stream:
            require(stream.read(4) == b"\x7fELF", "test binary is not a native Linux artifact")
        self.evidence.add(relative + "/templates.test")
        binary_sha = file_sha(binary)
        selector = "/".join("^" + re.escape(name) + "$" for name in mutation.test)
        args = ["go", "tool", "test2json", "-t", "-p", mutation.package, str(binary),
                "-test.v=test2json", "-test.run=" + selector, "-test.count=1",
                "-test.timeout=" + str(self.deadline) + "s"]
        code, stdout, _ = self.command(relative + "/test", args, self.copy / package_path)
        require(file_sha(binary) == binary_sha, "tested binary changed during execution")
        records = read_records(stdout)
        facts = {
            "observed_exit": code, "binary_sha256": binary_sha,
            "failed": sorted({row["Test"] for row in records if isinstance(row, dict)
                              and row.get("Action") == "fail" and isinstance(row.get("Test"), str)}),
            "ran": sorted({row["Test"] for row in records if isinstance(row, dict)
                           and row.get("Action") == "run" and isinstance(row.get("Test"), str)}),
        }
        self.keep_json(relative + "/observed-tests.json", facts)
        current = next(row for row in self.results if row["id"] == mutation.id)
        current[phase + "_observed"] = facts
        observed = analyze(records, code, mutation, phase)
        observed["binary_sha256"] = binary_sha
        self.keep_json(relative + "/observation.json", observed)
        return observed

    def vet_phase(self, label):
        argv = ["go", "vet", "-mod=readonly"]
        if self.cli_overlay is not None:
            argv += ["-overlay", str(self.cli_overlay)]
        if self.tags:
            argv += ["-tags", self.tags]
        argv += ["./..."]
        code, stdout, stderr = self.command(label + "/vet", argv, self.copy)
        if code != 0:
            for channel, path in (("stdout", stdout), ("stderr", stderr)):
                diagnostic = path.read_bytes().decode("utf-8", errors="replace")
                if diagnostic:
                    print(label + ": vet " + channel + ":", file=sys.stderr)
                    print(diagnostic, end="" if diagnostic.endswith("\n") else "\n", file=sys.stderr)
            raise MutationFailure(label + ": static vet failed; no mutation kill was observed")
        return {"observed_exit": code, "tests_executed": False}

    def run(self):
        self.prepare()
        if self.vet_only:
            self.vet_phase("baseline")
        for mutation, result in zip(self.entries, self.results):
            result["status"] = "running"
            path = self.copy / mutation.file
            require(path.is_file() and not path.is_symlink(), "mutation target is not an ordinary source file")
            before = path.read_bytes()
            after = exact_replacement(before, mutation)
            self.keep_bytes(mutation.id + "/before.go", before)
            self.keep_bytes(mutation.id + "/after.go", after)
            self.keep_json(mutation.id + "/change.json", {
                "file": mutation.file, "before_sha256": sha(before),
                "after_sha256": sha(after), "replacements": 1,
                "test": list(mutation.test), "failure_contains": mutation.failure_contains,
            })
            path.write_bytes(after)
            if self.vet_only:
                result["vet"] = self.vet_phase(mutation.id)
                path.write_bytes(before)
                self.verify_tree(self.copy)
                self.verify_tree(self.source)
                result["status"] = "vetted"
                print(mutation.id + ": static vet passed; no tests executed", flush=True)
                continue
            result["red"] = self.test_phase(mutation, "red")
            result["status"] = "red_observed"
            print(mutation.id + ": red failed " + ", ".join(result["red"]["failed"]), flush=True)
            # Restore only after the intended red assertion was observed. An
            # unexpected red failure retains the changed copy for inspection.
            path.write_bytes(before)
            self.verify_tree(self.copy)
            self.verify_tree(self.source)
            result["green"] = self.test_phase(mutation, "green")
            require(result["red"]["binary_sha256"] != result["green"]["binary_sha256"],
                    "red and green did not use distinct tested artifacts")
            self.verify_tree(self.copy)
            self.verify_tree(self.source)
            result["status"] = "proved"
            print(mutation.id + ": restored source passed the same test", flush=True)

    def finish(self, reason):
        if reason:
            for row in self.results:
                if row["status"] in ("running", "red_observed"):
                    row["status"], row["failure_reason"] = "failed", reason
        unchanged = False
        try:
            self.verify_tree(self.source)
            unchanged = bool(self.inventory)
        except (MutationFailure, OSError):
            unchanged = False
        references = []
        missing = []
        for relative in sorted(self.evidence):
            path = self.root / relative
            if not path.is_file() or path.is_symlink():
                missing.append(relative)
                continue
            try:
                references.append({"path": relative, "sha256": file_sha(path),
                                   "bytes": path.stat().st_size})
            except OSError:
                missing.append(relative)
        required_status = "vetted" if self.vet_only else "proved"
        ok = (bool(self.results) and all(row["status"] == required_status for row in self.results)
              and not self.active and unchanged and not reason and not missing)
        self.keep_json("result.json", {
            "schema": VET_SCHEMA if self.vet_only else SCHEMA, "ok": ok,
            "scope": "static-only" if self.vet_only else "component",
            "reason": reason, "mutations": self.results, "evidence": references,
            "missing_evidence": missing,
            "collection": {"processes_quiescent": not self.active,
                           "source_inputs_unchanged": unchanged,
                           "retained_source_copy": "source",
                           "observed_process_groups": sorted(self.active)},
        })
        return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--mutation")
    selection.add_argument("--all", action="store_true")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--file-list", type=Path)
    parser.add_argument("--revision-file", type=Path)
    parser.add_argument("--tags", choices=("", "laneboss_faults"), default="")
    parser.add_argument("--vet-only", action="store_true",
                        help="materialise every selected edit and run whole-tree go vet; execute no tests")
    parser.add_argument("--timeout-seconds", type=int, default=240)
    parser.add_argument("--max-seconds", type=int, default=1800)
    args = parser.parse_args()
    proof = None
    try:
        require(sys.platform == "linux" or args.vet_only,
                "mutation execution requires the disposable Linux box; only --vet-only is static")
        require(1 <= args.timeout_seconds <= 1800, "mutation deadline is outside its bound")
        require(1 <= args.max_seconds <= 7200, "overall mutation deadline is outside its bound")
        require(args.source.is_absolute() and args.work_root.is_absolute(), "use absolute source and evidence paths")
        require((args.file_list is None) == (args.revision_file is None),
                "archive input needs both file list and revision file")
        if args.file_list is not None:
            require(args.file_list.is_absolute() and args.revision_file.is_absolute(),
                    "use absolute source inventory paths")
        source = args.source.resolve(strict=True)
        require((source / "go.mod").is_file(), "source root does not contain the module")
        root = args.work_root.parent.resolve(strict=True) / args.work_root.name
        require(not root.exists() and not root.is_symlink(), "mutation evidence root must be new")
        require(not root.is_relative_to(source), "mutation copy must be outside the checkout")
        require(any("lb-v2-templates" in part for part in root.parts), "mutation evidence root must carry the lane name")
        entries = checked_catalog()
        if not args.all:
            entries = [entry for entry in entries if entry.id == args.mutation]
            require(len(entries) == 1, "unknown mutation identifier")
        root.mkdir(mode=0o700)
        proof = Proof(source, root, entries, args.tags, args.timeout_seconds, args.max_seconds,
                      args.file_list, args.revision_file, args.vet_only)
        proof.run()
        return proof.finish("")
    except (MutationFailure, OSError, ValueError, UnicodeError,
            subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, MutationFailure) else type(error).__name__
        print("Mutation proof failed: " + reason, file=sys.stderr)
        if proof is not None:
            return proof.finish(reason)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
