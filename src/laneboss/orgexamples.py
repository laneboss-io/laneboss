"""Generic init policy. Rules and TypeSafe descriptions share one source of data."""

import json

from .errors import Refused


ALL_LEVELS = [3, 4, 5, 6]
SHARED = [
    {"id": "instance-tools", "kind": "tool-allowlist", "tools": ["{allowed_tools}"],
     "refuses": "Tools outside the instance's declared allowlist.",
     "why": "Each identity receives only the tools its role needs.",
     "instead": "Use an allowed tool or ask the supervisor to change the instance policy.",
     "examples_allowed": ["Use Read when Read is listed in allowed_tools."],
     "examples_refused": ["Use an unlisted tool."]},
    {"id": "declared-writes", "kind": "write-scope", "paths": ["{writable_repos}"],
     "deny_paths": ["{hook_paths}"],
     "refuses": "Writes outside declared repositories, writes to hook policy and settings, and uninspectable commands.",
     "why": "An agent's writes must stay in its scope and cannot change the guard that enforces it.",
     "instead": "Write in a declared repository with a supported file tool; leave policy changes to the supervisor.",
     "examples_allowed": ["Edit a source file inside a declared writable repository."],
     "examples_refused": ["Write in another identity's repository.", "Replace shared/hooks/rules.toml."]},
    {"id": "secret-files", "kind": "secret-read", "names": ["{secret_names}", ".env", ".env.*", "*.key", "*.pem"],
     "refuses": "Reading or printing a file whose name is protected as a secret.",
     "why": "Secret values must remain outside agent output at every level.",
     "instead": "Refer to a secret by name and use the configured credential service without printing its value.",
     "examples_allowed": ["Read README.md.", "Print the literal name of a secret without reading its file."],
     "examples_refused": ["Read .env.", "Print a file listed in secret_names."]},
    {"id": "runner-launches", "kind": "command-pattern", "patterns": [["claude"], ["codex"]],
     "refuses": "Starting an agent runner directly from an agent tool call.",
     "why": "The launcher must check and pass the org's mandatory hook settings before a runner starts.",
     "instead": "Have the supervisor start the instance through the checked launcher command.",
     "examples_allowed": ["Run git status."],
     "examples_refused": ["Start claude directly.", "Start codex directly."]},
]

WORKTREE = {
    "id": "worktree-writes", "kind": "write-scope", "paths": ["{worktree}"],
    "refuses": "Writing outside the executor's own worktree.",
    "why": "Executor work must stay isolated from other lanes and repositories.",
    "instead": "Make the change in this instance's worktree and report it for review.",
    "examples_allowed": ["Write a source file in this instance's worktree."],
    "examples_refused": ["Write to a sibling worktree."]}

NO_PUSH = {
    "id": "no-push", "kind": "command-pattern", "patterns": [["git", "push"]],
    "refuses": "Pushing repository changes from an executor or mini-supervisor.",
    "why": "Publishing changes belongs to the supervising level.",
    "instead": "Leave the changes for review and ask the supervisor to publish them.",
    "examples_allowed": ["git status", "printf '%s' 'git push'"],
    "examples_refused": ["git push", "git -C repository push origin topic"]}

SUPERVISOR_SCOPE = {
    "id": "supervisor-writes", "kind": "write-scope", "paths": ["{writable_repos}"],
    "refuses": "Writing outside the supervisor identity's declared repositories.",
    "why": "A supervising level does not grant access to another identity's repositories.",
    "instead": "Use a declared repository or ask for a policy change before writing elsewhere.",
    "examples_allowed": ["Edit a file in a repository listed in writable_repos."],
    "examples_refused": ["Edit a file in an undeclared repository."]}

LEVEL_RULES = {3: [WORKTREE, NO_PUSH], 4: [NO_PUSH], 5: [SUPERVISOR_SCOPE], 6: [SUPERVISOR_SCOPE]}
DESCRIPTION_KEYS = ("id", "refuses", "why", "instead", "examples_allowed", "examples_refused")


def _value(value):
    # All seed values are strings or arrays of strings/integers; JSON is a
    # valid TOML representation for these values. No code is put in the data.
    return json.dumps(value, ensure_ascii=True)


def example_files(levels=ALL_LEVELS):
    levels = tuple(levels)
    if not levels or len(set(levels)) != len(levels) or any(type(n) is not int or n not in ALL_LEVELS for n in levels):
        raise Refused("example hook levels must be distinct integers from 3 to 6")
    files = {}
    layers = [("shared", SHARED, list(levels))] + [("L" + str(n), LEVEL_RULES[n], [n]) for n in levels]
    for layer, entries, applicable in layers:
        rules = ["schema_version = 1\n"]
        for entry in entries:
            rules.append("\n[[rules]]\n")
            for key, value in entry.items():
                if key not in DESCRIPTION_KEYS or key == "id":
                    rules.append(key + " = " + _value(value) + "\n")
            description = "".join(key + " = " + _value(entry[key]) + "\n" for key in DESCRIPTION_KEYS)
            description += "\n[applies_to]\nlevels = " + _value(applicable) + "\nidentities = [\"*\"]\n"
            files[layer + "/refusals/" + entry["id"] + ".toml"] = description
        files[layer + "/hooks/rules.toml"] = "".join(rules)
    return files
