"""Claims on working directories: one lane of one configuration works in a directory at a time.

Starting a lane in a directory writes a claim naming the configuration (with its state directory), the lane, the
launch and the directory. It is created atomically (written under a temporary name and linked into place, which
fails when a claim exists) and nothing of it is written into the working directory itself:

- inside a linked Git worktree it is `laneboss-claim` in that worktree's own administrative directory
  (`.git/worktrees/NAME` of its repository);
- for any other directory it lives in the account's claims registry (mode 0700, this user's alone), under the
  directory's identity (device and inode), where every configuration of the user finds it and the executor's own Git
  never sees it, even when the executor makes the directory a repository later.

There is one registry per account, whatever the environment says: HOME/.local/state/laneboss/.lane-claims, with HOME
the account's home directory as the user database gives it, never LANEBOSS_HOME, LANEBOSS_STATE_HOME or the HOME
variable. Only LANEBOSS_TEST_CLAIMS_DIR moves it; it is for tests. lane.started records the registry that holds a
plain directory's claim (`claims`), and a later command for that lane that would look in another registry refuses.

A repository's main working copy, or a directory inside it, is never a new lane's working directory, and a directory
Git cannot be asked about is refused rather than taken for a plain one. Start, resume and clean read the claim:
another lane's or another configuration's claim refuses them before any runner starts or anything is removed.
"""

import json
import os
import pwd
import stat

from . import fsguard, worktree
from .errors import Refused
from .identity import env_name

LINKED = "laneboss-claim"
REGISTRY = ".lane-claims"
MAX_BYTES = 64 * 1024


class Claim:
    def __init__(self, holder, name):
        self.holder = holder
        self.name = name

    @property
    def path(self):
        return os.path.join(self.holder, self.name)


def registry_path():
    """The account's claims registry: from the user database's home directory, or LANEBOSS_TEST_CLAIMS_DIR (tests)."""
    moved = os.environ.get(env_name("TEST_CLAIMS_DIR"))
    if moved:
        if not moved.startswith("/"):
            raise Refused(env_name("TEST_CLAIMS_DIR") + " must be an absolute path")
        return os.path.normpath(moved)
    try:
        home = pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        raise Refused("the account has no entry in the user database, so its claims registry cannot be found") from None
    if not home or not home.startswith("/"):
        raise Refused("the account's home directory in the user database is not an absolute path")
    return os.path.join(home, ".local", "state", "laneboss", REGISTRY)


def registry(path=None):
    """The claims registry, created when missing; refused unless it is this user's alone."""
    path = path or registry_path()
    for attempt in range(3):
        try:
            os.makedirs(path, mode=0o700, exist_ok=True)
        except OSError as error:
            raise Refused("cannot create the claims registry {}: {}".format(path, error.strerror or "error")) from None
        try:
            info = os.lstat(path)
            break
        except FileNotFoundError:
            continue
    else:
        raise Refused("the claims registry {} keeps disappearing".format(path))
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Refused("{} must be a directory of this user's alone (mode 0700, not a link); it holds the claims of "
                      "lanes' working directories".format(path))
    return path


def key(directory):
    """The registry name of a directory's claim: its identity."""
    info = os.stat(directory)
    return "{}-{}.json".format(info.st_dev, info.st_ino)


def registered(directory, path=None):
    return Claim(registry(path), key(directory))


def same_registry(recorded):
    """Refuse a command that would look in another registry than the one the lane's claim was recorded in."""
    current = registry_path()
    if recorded is not None and recorded != current:
        raise Refused("the lane's claim was recorded in the claims registry {}, but this command would look in {}; "
                      "nothing was done (LANEBOSS_TEST_CLAIMS_DIR differs)".format(recorded, current))
    return current


def locate(directory, option="--worktree", starting=False, recorded=None):
    """Where a directory's claim lives. A new lane (starting) is refused a repository's main working copy and anything
    inside it; an existing lane's claim in the registry `recorded` (its lane.started's `claims`) is found whatever the
    directory has become since."""
    if not starting:
        same_registry(recorded)
        if recorded is not None:
            claim = registered(directory, recorded)
            if read(claim) is not None:
                return claim
    kind, place = worktree.kind_of(directory)
    if kind == "main" and starting:
        raise Refused("{} {} is inside the main working copy of the repository at {}; a lane works in its own "
                      "worktree, never in a repository's main working copy".format(option, directory, place))
    if kind == "linked":
        return Claim(place, LINKED)
    return registered(directory, recorded)


def owner(configuration, state_real, lane, launch, directory=None):
    value = {"config": configuration.name, "state": state_real, "lane": lane, "launch": launch}
    if directory is not None:
        value["path"] = directory
    return value


def read(claim):
    """The claim's content; None when there is none; {} when it is unreadable (nobody's we know)."""
    try:
        descriptor = fsguard.open_directory(claim.holder, "the claim's directory")
    except Refused:
        return None
    try:
        if fsguard.file_info(descriptor, claim.name) is None:
            return None
        try:
            data = fsguard.read_descriptor(fsguard.open_child(descriptor, claim.name, "the claim"), MAX_BYTES,
                                           "the claim")
            value = json.loads(data.decode("utf-8"))
        except (Refused, UnicodeDecodeError, ValueError):
            return {}
    finally:
        os.close(descriptor)
    return value if isinstance(value, dict) else {}


def same_lane(value, mine):
    return bool(value) and all(value.get(key) == mine[key] for key in ("config", "state", "lane"))


def describe(value):
    if value and isinstance(value.get("config"), str) and isinstance(value.get("lane"), str):
        return "lane {} of configuration {}".format(value["lane"], value["config"])
    return "another lane"


def take(claim, mine):
    """Claim the directory for this lane: create the claim atomically, or replace this lane's own earlier claim.
    Refused when another lane or configuration holds it. True when the claim was new."""
    descriptor = fsguard.open_directory(claim.holder, "the claim's directory")
    data = (json.dumps(mine, sort_keys=True) + "\n").encode("utf-8")
    try:
        try:
            fsguard.write_new(descriptor, claim.name, data, mode=0o600)
            return True
        except FileExistsError:
            pass
        value = read(claim)
        if not same_lane(value, mine):
            raise Refused("the working directory is claimed by {}; one lane works in a directory at a time".format(
                describe(value)))
        fsguard.write_new(descriptor, claim.name, data, replace=True, mode=0o600)
        return False
    finally:
        os.close(descriptor)


def check(claim, mine):
    """Refuse unless the directory carries this lane's claim."""
    value = read(claim)
    if value is None:
        raise Refused("the working directory no longer carries lane {}'s claim".format(mine["lane"]))
    if not same_lane(value, mine):
        raise Refused("the working directory is claimed by {}".format(describe(value)))


def release(claim, mine):
    """Remove this lane's claim; another lane's claim is left alone. True when removed."""
    if not same_lane(read(claim), mine):
        return False
    descriptor = fsguard.open_directory(claim.holder, "the claim's directory")
    try:
        os.unlink(claim.name, dir_fd=descriptor)
        return True
    except FileNotFoundError:
        return False
    finally:
        os.close(descriptor)


def release_stale(path, mine, directory, keep=None):
    """Remove this lane's registry claims on `directory` made under another identity than `keep` (the directory's
    current one): the directory no longer exists, or was removed and made again. Another lane's claim, and the claim
    named `keep`, are left alone."""
    try:
        names = sorted(os.listdir(path))
    except FileNotFoundError:
        return 0
    removed = 0
    for name in names:
        if name == keep:
            continue
        claim = Claim(registry(path), name)
        value = read(claim)
        if same_lane(value, mine) and value.get("path") == directory and release(claim, mine):
            removed += 1
    return removed
