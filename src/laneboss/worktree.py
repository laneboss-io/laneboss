"""Git operations for lanes: a lane's worktree and branch are created from a project's local repository and, when
the lane is cleaned, removed only the way Git allows without force.

Git is always called with an argument vector and `-C`, never through a shell, and without any GIT_ variable of the
caller's environment (GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, GIT_COMMON_DIR, GIT_CONFIG and the like would send
it to another repository, work tree, index or configuration). Nothing here touches the repository's main working
copy: `git worktree add` writes the new directory and the repository's own records, and the branch. Messages from
Git are passed on only when they do not look like a credential.
"""

import os
import re
import shutil
import subprocess

from . import credentials
from .errors import Refused

TIMEOUT = 120
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def environment():
    """The caller's environment without any GIT_ variable, in the C locale so Git's messages can be recognised."""
    found = {key: value for key, value in os.environ.items() if not key.startswith("GIT_") and key != "LANGUAGE"}
    found.update(LC_ALL="C", LANG="C")
    return found


def git(directory, *arguments):
    if shutil.which("git") is None:
        raise Refused("git is not on PATH; lanes of a project with a local repository need it")
    try:
        result = subprocess.run(["git", "-C", str(directory), *arguments], stdin=subprocess.DEVNULL,
                                env=environment(), capture_output=True, text=True, encoding="utf-8", errors="replace",
                                timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        raise Refused("git did not finish within {} seconds".format(TIMEOUT)) from None
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def dot_git_above(directory):
    """True when the directory or one above it has a .git entry."""
    current = os.path.realpath(directory)
    while True:
        if os.path.lexists(os.path.join(current, ".git")):
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def kind_of(directory):
    """("none", None) outside any Git work tree, ("main", top) inside a repository's main working copy, and
    ("linked", git directory) inside a linked worktree, whose own administrative directory is returned. Refused
    when Git cannot be asked: no git on PATH, a git that fails for another reason than "not a git repository", an
    answer of an unexpected form, or a .git entry in or above the directory that Git did not recognise."""
    if shutil.which("git") is None:
        raise Refused("git is not on PATH, so it cannot be told whether {} lies inside a Git repository".format(
            directory))
    status, output, errors = git(directory, "rev-parse", "--path-format=absolute", "--show-toplevel", "--git-dir",
                                 "--git-common-dir")
    lines = output.splitlines()
    if status == 0 and len(lines) == 3 and all(line.startswith("/") for line in lines):
        top, git_dir, common = (os.path.realpath(line) for line in lines)
        if git_dir == common:
            return "main", top
        return "linked", git_dir
    if status != 0 and "not a git repository" in errors and not dot_git_above(directory):
        return "none", None
    raise Refused("Git cannot be asked whether {} lies inside a repository ({}); a lane's working directory is a "
                  "linked worktree or lies outside every repository".format(
                      directory, said(errors) if errors else "an answer of an unexpected form"))


def head_branch(directory):
    """The branch checked out in a work tree, or None (detached, or not a work tree)."""
    status, output, _ = git(directory, "symbolic-ref", "--quiet", "--short", "HEAD")
    return output if status == 0 and output else None


def said(message):
    """Git's first line, for an error message, unless it looks like a credential."""
    line = message.splitlines()[0] if message else ""
    if credentials.find_in_text(line):
        return "(Git's message is withheld: it looks like a credential)"
    return line[:300]


def repository_root(path):
    """The top of the work tree at path, or None when path is not a Git work tree."""
    if not os.path.isdir(path):
        return None
    status, output, _ = git(path, "rev-parse", "--show-toplevel")
    return os.path.realpath(output) if status == 0 and output else None


def resolve_base(repository, ref):
    """The commit a new lane branch starts from: --base REF, else the repository's current HEAD."""
    if ref is not None and (not ref or ref.startswith("-") or any(ord(character) <= 32 for character in ref)):
        raise Refused("--base must name a commit, branch or tag")
    status, output, errors = git(repository, "rev-parse", "--verify", "--quiet", (ref or "HEAD") + "^{commit}")
    if status != 0 or COMMIT.fullmatch(output) is None:
        raise Refused("--base: {} does not name a commit in the project's repository".format(
            "the given reference" if ref else "HEAD"))
    return output


def check_branch(repository, branch):
    status, _, _ = git(repository, "check-ref-format", "--branch", branch)
    if status != 0:
        raise Refused("the lane name {} is not a valid Git branch name".format(branch))
    status, _, _ = git(repository, "rev-parse", "--verify", "--quiet", "refs/heads/" + branch)
    if status == 0:
        raise Refused("the project's repository already has a branch {}; a lane's branch is new".format(branch))


def create_branch(repository, branch, base):
    """Create the lane's branch at base. Refused when Git does not create it (for example because a branch of that
    name exists by now), so a caller knows exactly whether the branch is its own."""
    status, _, errors = git(repository, "branch", branch, base)
    if status != 0:
        raise Refused("git could not create the lane's branch {}: {}".format(branch, said(errors)))


def add(repository, path, branch):
    """Create the lane's worktree on its existing branch."""
    status, _, errors = git(repository, "worktree", "add", path, branch)
    if status != 0:
        raise Refused("git could not create the lane's worktree: " + said(errors))


def remove(repository, path):
    """Remove a worktree without force: (True, None), or (False, Git's reason) when Git refuses."""
    status, _, errors = git(repository, "worktree", "remove", path)
    return (True, None) if status == 0 else (False, said(errors))


def delete_merged_branch(repository, branch):
    """Delete a branch only when Git agrees it is merged (git branch -d): True when deleted."""
    status, _, _ = git(repository, "branch", "-d", branch)
    return status == 0


def branch_exists(repository, branch):
    status, _, _ = git(repository, "rev-parse", "--verify", "--quiet", "refs/heads/" + branch)
    return status == 0
