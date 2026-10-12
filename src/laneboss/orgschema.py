"""Versioned org and instance data, shared with the future identity-aware hook.

These checks inspect shape and references, never grant access or load secrets.
Diagnostics use known field names and never echo a rejected value.
"""

from pathlib import Path
import re


SCHEMA_VERSION = 1
LEVELS = (3, 4, 5, 6)
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SECRET_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
TOOL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
CHANNEL_ID = re.compile(r"[0-9]{1,20}")
INSTANCE_FIELDS = {"schema_version", "name", "level", "role", "discord_channel_id", "services", "secrets",
                   "writable_repos", "allowed_tools"}
INSTANCE_REQUIRED = INSTANCE_FIELDS - {"discord_channel_id"}
DEFAULT_FIELDS = INSTANCE_FIELDS - {"schema_version", "name"}


class Checks:
    def __init__(self, label):
        self.label = label
        self.problems = []

    def fail(self, field, message):
        self.problems.append({"path": self.label, "message": "{}: {}".format(field, message)})

    def table(self, value, field, allowed, required):
        if not isinstance(value, dict):
            self.fail(field, "must be a table")
            return {}
        if set(value) - set(allowed):
            self.fail(field, "contains an unknown field")
        for key in sorted(set(required) - set(value)):
            self.fail(key if field == "document" else field + "." + key, "is required")
        return value

    def text(self, value, field, pattern=None, maximum=128):
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            self.fail(field, "must be a nonempty string of at most {} characters".format(maximum))
            return False
        if any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value):
            self.fail(field, "must not contain control characters or Unicode surrogates")
            return False
        if pattern is not None and pattern.fullmatch(value) is None:
            self.fail(field, "must match " + pattern.pattern)
            return False
        return True

    def level(self, value, field):
        if type(value) is not int or value not in LEVELS:
            self.fail(field, "must be an integer from 3 to 6")
            return False
        return True

    def version(self, value):
        if type(value) is not int or value != SCHEMA_VERSION:
            self.fail("schema_version", "must be 1")

    def repos(self, value, field):
        if self.text(value, field, maximum=1024):
            if "\\" in value or any(part in ("", ".", "..") for part in value.split("/")):
                self.fail(field, "must be an org-relative path without empty, '.' or '..' parts")

    def array(self, value, field, item_check):
        if not isinstance(value, list):
            self.fail(field, "must be an array")
            return
        seen = set()
        for index, item in enumerate(value):
            item_check(item, "{}[{}]".format(field, index))
            if isinstance(item, (str, int)):
                if item in seen:
                    self.fail(field, "must not repeat an item")
                    break
                seen.add(item)

    def instance_fields(self, value, prefix=""):
        def field(key):
            return prefix + key

        if "level" in value:
            self.level(value["level"], field("level"))
        if "role" in value:
            self.text(value["role"], field("role"))
        if "discord_channel_id" in value:
            self.text(value["discord_channel_id"], field("discord_channel_id"), CHANNEL_ID)
        for key, pattern in (("services", NAME), ("secrets", SECRET_NAME), ("allowed_tools", TOOL_NAME)):
            if key in value:
                self.array(value[key], field(key), lambda item, name, pattern=pattern: self.text(item, name, pattern))
        if "writable_repos" in value:
            self.array(value["writable_repos"], field("writable_repos"), self.repos)


def check_org(value, label, root):
    checks = Checks(label)
    data = checks.table(value, "document",
                        {"schema_version", "name", "company", "levels", "owner_channel", "secret_store", "defaults"},
                        {"schema_version", "name", "company", "levels", "owner_channel", "secret_store", "defaults"})
    if "schema_version" in data:
        checks.version(data["schema_version"])
    for key in ("name", "company", "owner_channel"):
        if key in data:
            checks.text(data[key], key, NAME)
    levels = data.get("levels")
    if "levels" in data:
        checks.array(levels, "levels", checks.level)
        if isinstance(levels, list) and not levels:
            checks.fail("levels", "must enable at least one level")
    if "secret_store" in data:
        store = checks.table(data["secret_store"], "secret_store", {"kind", "path"}, {"kind", "path"})
        kind = store.get("kind")
        if "kind" in store and kind not in ("keychain", "file"):
            checks.fail("secret_store.kind", "must be keychain or file")
        if "path" in store and checks.text(store["path"], "secret_store.path", maximum=4096):
            if kind == "keychain":
                if any(NAME.fullmatch(part) is None for part in store["path"].split("/")):
                    checks.fail("secret_store.path", "must be a keychain namespace of simple names separated by '/'")
            elif kind == "file":
                path = Path(store["path"])
                if not path.is_absolute() or any(part in (".", "..", "") for part in store["path"].split("/")[1:]):
                    checks.fail("secret_store.path", "must be an absolute external file path without '.' or '..'")
                else:
                    try:
                        inside = path.resolve().is_relative_to(root)
                    except (OSError, RuntimeError):
                        checks.fail("secret_store.path", "cannot resolve the external file path")
                    else:
                        if inside:
                            checks.fail("secret_store.path", "secret values must live outside the org folder")
    if "defaults" in data:
        defaults = checks.table(data["defaults"], "defaults", DEFAULT_FIELDS, {"level", "role"})
        checks.instance_fields(defaults, "defaults.")
        if type(defaults.get("level")) is int and isinstance(levels, list) and defaults["level"] not in levels:
            checks.fail("defaults.level", "must be an enabled level")
    return checks.problems


def check_instance(value, label, directory_name, levels):
    checks = Checks(label)
    data = checks.table(value, "document", INSTANCE_FIELDS, INSTANCE_REQUIRED)
    if "schema_version" in data:
        checks.version(data["schema_version"])
    if "name" in data:
        checks.text(data["name"], "name", NAME)
        if data["name"] != directory_name:
            checks.fail("name", "must match the instance directory name")
    checks.instance_fields(data)
    if type(data.get("level")) is int and data["level"] not in levels:
        checks.fail("level", "the instance level is not enabled in org.toml")
    return checks.problems
