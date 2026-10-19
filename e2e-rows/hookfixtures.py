"""Owner-authored legacy policy for rows that exercise it, never init output.

Keep the former rule and refusal text here so assertions continue to check the
same policy through the real hook after org init stops seeding sample rules.
"""

import json
from pathlib import Path

from orgsupport import write_rule_source


RULES = {
    "declared-writes": (
        {"kind": "write-scope", "paths": ["{writable_repos}"], "deny_paths": ["{hook_paths}"]},
        "Writes outside declared repositories, writes to hook policy and settings, and uninspectable commands.",
        "An agent's writes must stay in its scope and cannot change the guard that enforces it.",
        "Write in a declared repository with a supported file tool; leave policy changes to the supervisor.",
        ["Edit a source file inside a declared writable repository."],
        ["Write in another identity's repository.", "Replace shared/hooks/rules.toml."]),
    "secret-files": (
        {"kind": "secret-read", "names": ["{secret_names}", ".env", ".env.*", "*.key", "*.pem"]},
        "Reading or printing a file whose name is protected as a secret.",
        "Secret values must remain outside agent output at every level.",
        "Refer to secrets by name only; read a permitted non-secret source or ask the supervisor to supply a public or redacted input.",
        ["Read README.md.", "Print the literal name of a secret without reading its file."],
        ["Read .env.", "Print a file listed in secret_names."]),
    "runner-launches": (
        {"kind": "command-pattern", "patterns": [["claude"], ["codex"]]},
        "Starting an agent runner directly from an agent tool call.",
        "The launcher must check and pass the org's mandatory hook settings before a runner starts.",
        "Have the supervisor start the instance through the checked launcher command.",
        ["Run git status."], ["Start claude directly.", "Start codex directly."]),
    "worktree-writes": (
        {"kind": "write-scope", "paths": ["{worktree}"]},
        "Writing outside the executor's own worktree.",
        "Executor work must stay isolated from other lanes and repositories.",
        "Make the change in this instance's worktree and report it for review.",
        ["Write a source file in this instance's worktree."], ["Write to a sibling worktree."]),
    "no-push": (
        {"kind": "command-pattern", "patterns": [["git", "push"]]},
        "Pushing repository changes from an executor or mini-supervisor.",
        "Publishing changes belongs to the supervising level.",
        "Leave the changes for review and ask the supervisor to publish them.",
        ["git status", "printf '%s' 'git push'"], ["git push", "git -C repository push origin topic"]),
    "supervisor-writes": (
        {"kind": "write-scope", "paths": ["{writable_repos}"]},
        "Writing outside the supervisor identity's declared repositories.",
        "A supervising level does not grant access to another identity's repositories.",
        "Use a declared repository or ask for a policy change before writing elsewhere.",
        ["Edit a file in a repository listed in writable_repos."],
        ["Edit a file in an undeclared repository."]),
}


def install_hook_refusals(test, org, layer, *identifiers):
    levels = [3, 4, 5, 6] if layer == "shared" else [int(layer[1:])]
    for identifier in identifiers:
        _, refuses, why, instead, allowed, refused = RULES[identifier]
        fields = {"id": identifier, "refuses": refuses, "why": why, "instead": instead,
                  "examples_allowed": allowed, "examples_refused": refused}
        text = "".join(key + " = " + json.dumps(value) + "\n" for key, value in fields.items())
        text += '\n[applies_to]\nlevels = ' + json.dumps(levels) + '\nidentities = ["*"]\n'
        write_rule_source(test, Path(org) / ".laneboss" / layer / "refusals" / (identifier + ".toml"), text)


def install_hook_rules(test, org, layer, *identifiers):
    install_hook_refusals(test, org, layer, *identifiers)
    lines = ["schema_version = 1"]
    if not identifiers:
        lines.append("rules = []")
    for identifier in identifiers:
        fields = {"id": identifier, **RULES[identifier][0]}
        lines.append("\n[[rules]]")
        lines.extend(key + " = " + json.dumps(value) for key, value in fields.items())
    write_rule_source(test, Path(org) / ".laneboss" / layer / "hooks" / "rules.toml",
                      "\n".join(lines) + "\n")
