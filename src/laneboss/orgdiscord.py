"""Org owner channels, their shared roles file, and channel-aware gateway events.

No gateway is started here. read_roles and message_to_event are the contract for
the next shared gateway; validate_org_channels is called by org validation.
"""

from contextlib import contextmanager
from dataclasses import dataclass, replace
import http.client
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request

from . import fsguard
from .errors import Refused
from .jsonutil import output, parse

ROLES_PATH = Path(".laneboss/shared/services/discord-roles.toml")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}")
SECRET_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
DISCORD_ID = re.compile(r"[1-9][0-9]{0,19}")
API_BASE = "https://discord.com/api/v10"
TEST_BASE_ENV = "LANEBOSS_TEST_DISCORD_BASE_URL"
MAX_BYTES = 1024 * 1024
LOGGER = logging.getLogger(__name__)


def _id(value, label):
    if not isinstance(value, str) or DISCORD_ID.fullmatch(value) is None:
        raise Refused(label + " must be a positive Discord id written as a string")
    return value


def _name(value, label, pattern=NAME):
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise Refused(label + " must be a plain name without path separators")
    return value


def _channel_name(value):
    if (not isinstance(value, str) or not value or len(value) > 100
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise Refused("Discord channel name is missing or invalid")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise Refused("Discord channel name must be valid Unicode") from None
    return value


def _org_root(org_dir):
    root = Path(org_dir).expanduser().resolve()
    if not root.is_dir() or not (root / ".laneboss").is_dir():
        raise Refused("org-dir must contain an existing .laneboss directory")
    _inside(root, Path(".laneboss"))
    return root


def _inside(root, relative):
    path = root / relative
    if not path.resolve().is_relative_to(root) or path.is_symlink():
        raise Refused("org configuration paths must stay inside the org and must not be symbolic links")
    return path


def _read_bytes(path, label, private=False):
    try:
        descriptor = os.open(path, os.O_RDONLY | fsguard.NOFOLLOW | os.O_NONBLOCK | fsguard.CLOEXEC)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise Refused(label + " must be a regular file")
            if private and (info.st_mode & 0o077 or info.st_uid != os.getuid()):
                raise Refused("the org secret store must be owned by this user and have mode 600 or stricter")
            data = handle.read(MAX_BYTES + 1)
    except OSError:
        raise Refused("cannot read " + label) from None
    if len(data) > MAX_BYTES:
        raise Refused(label + " exceeds 1 MiB")
    return data


def _toml(data, label):
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError):
        # Parser diagnostics can contain the input, including a misfiled secret.
        raise Refused(label + " must be valid UTF-8 TOML") from None


def _instance(root, name):
    _name(name, "instance")
    relative = Path(".laneboss/instances") / name / "instance.toml"
    path = _inside(root, relative)
    raw = _read_bytes(path, "instance.toml")
    value = _toml(raw, "instance.toml")
    if type(value.get("level")) is not int or value["level"] not in (3, 4, 5, 6):
        raise Refused("instance.toml level must be an integer from 3 to 6")
    if "name" in value and value["name"] != name:
        raise Refused("instance.toml name must match its instance directory")
    if "discord_channel_id" in value:
        _id(value["discord_channel_id"], "instance.toml discord_channel_id")
    return relative, raw, value


@dataclass(frozen=True)
class DiscordMember:
    kind: str
    id: str
    authority: str

    def as_dict(self):
        return {"user_id" if self.kind == "user" else "role_id": self.id,
                "authority": self.authority}


@dataclass(frozen=True)
class DiscordRole:
    name: str
    instance: str
    channel_id: str
    channel_name: str
    members: tuple[DiscordMember, ...]
    state_file: str
    events_file: str
    form_doorbell: str
    hello_message_id: str | None = None

    def as_dict(self):
        value = {"instance": self.instance, "channel_id": self.channel_id,
                 "channel_name": self.channel_name, "state_file": self.state_file,
                 "events_file": self.events_file, "form_doorbell": self.form_doorbell,
                 "members": [member.as_dict() for member in self.members]}
        if self.hello_message_id is not None:
            value["hello_message_id"] = self.hello_message_id
        return value


def read_roles(org_dir, *, allow_missing=False):
    """Return name -> immutable DiscordRole, validating each binding and member.

    Partial registration is allowed: use validate_org_channels for full L5/L6
    coverage. A missing file is accepted only when allow_missing is explicit.
    """
    root = _org_root(org_dir)
    path = _inside(root, ROLES_PATH)
    if allow_missing and not path.exists():
        return {}
    value = _toml(_read_bytes(path, "discord-roles.toml"), "discord-roles.toml")
    if (set(value) != {"schema_version", "roles"} or type(value["schema_version"]) is not int
            or value["schema_version"] != 1 or not isinstance(value["roles"], dict)):
        raise Refused("discord-roles.toml requires schema_version = 1 and a roles table")
    roles = {}
    instances, channels = set(), set()
    fields = {"instance", "channel_id", "channel_name", "members", "state_file", "events_file", "form_doorbell"}
    for name, entry in value["roles"].items():
        _name(name, "Discord role")
        if (not isinstance(entry, dict) or not fields <= set(entry)
                or set(entry) - fields - {"hello_message_id"}):
            raise Refused("each Discord role must have exactly the documented role fields")
        instance = _name(entry["instance"], "role instance")
        _, _, agent = _instance(root, instance)
        if agent["level"] not in (5, 6):
            raise Refused("Discord roles may belong only to L5 or L6 instances; L3/L4 are refused")
        channel = _id(entry["channel_id"], "role channel_id")
        if instance in instances or channel in channels:
            raise Refused("each instance and each channel may occur in exactly one Discord role")
        instances.add(instance)
        channels.add(channel)
        _channel_name(entry["channel_name"])
        for field in ("state_file", "events_file", "form_doorbell"):
            _name(entry[field], "role " + field, FILE_NAME)
        if entry["state_file"] == entry["events_file"]:
            raise Refused("state_file and events_file must be different file names")
        members, seen = [], set()
        if not isinstance(entry["members"], list) or not entry["members"]:
            raise Refused("each Discord role requires at least one member with an authority")
        for member in entry["members"]:
            if not isinstance(member, dict) or set(member) not in (
                    {"user_id", "authority"}, {"role_id", "authority"}):
                raise Refused("each member requires one user_id or role_id and an authority")
            kind = "user" if "user_id" in member else "role"
            identifier = _id(member[kind + "_id"], "member id")
            if member["authority"] not in ("decide", "inform"):
                raise Refused("every member authority must be decide or inform")
            if (kind, identifier) in seen:
                raise Refused("a Discord role must not repeat a member")
            seen.add((kind, identifier))
            members.append(DiscordMember(kind, identifier, member["authority"]))
        hello = entry.get("hello_message_id")
        if hello is not None:
            _id(hello, "role hello_message_id")
        roles[name] = DiscordRole(name, instance, channel, entry["channel_name"], tuple(members),
                                  entry["state_file"], entry["events_file"], entry["form_doorbell"], hello)
    return roles


def render_roles(roles):
    """Serialize the validated role objects into the one shared TOML file."""
    lines = ["schema_version = 1", ""]
    if not roles:
        lines.append("roles = {}")
    for name, role in sorted(roles.items()):
        lines.append("[roles.{}]".format(json.dumps(name)))
        for key, value in role.as_dict().items():
            if key != "members":
                lines.append("{} = {}".format(key, json.dumps(value, ensure_ascii=False)))
        lines.append("members = [")
        for member in role.members:
            fields = ", ".join("{} = {}".format(key, json.dumps(value))
                               for key, value in member.as_dict().items())
            lines.append("  { " + fields + " },")
        lines.extend(["]", ""])
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


def validate_org_channels(org_dir):
    """Return failures for phase A's org validate; [] means all channel rules pass.

    This performs no network requests and never opens the secret store.
    """
    try:
        root = _org_root(org_dir)
        roles = read_roles(root, allow_missing=True)
        directory = _inside(root, Path(".laneboss/instances"))
        if not directory.is_dir():
            return ["Discord validation requires the instances directory"]
        org = _toml(_read_bytes(_inside(root, Path(".laneboss/org.toml")), "org.toml"), "org.toml")
        services = org.get("services", {})
        # The org uses Discord once org.toml configures services.discord or a role is registered.
        uses_discord = bool(roles) or (isinstance(services, dict) and "discord" in services)
        failures = []
        for path in sorted(directory.iterdir()):
            if not path.is_dir():
                continue
            _, _, agent = _instance(root, path.name)
            matches = [role for role in roles.values() if role.instance == path.name]
            channel = agent.get("discord_channel_id")
            if agent["level"] in (5, 6):
                if not uses_discord:
                    continue   # no Discord yet: a recorded L5/L6 channel binds once services.discord is configured
                if len(matches) != 1 or channel is None:
                    failures.append(path.name + ": every L5/L6 instance requires exactly one role and channel")
                elif matches[0].channel_id != channel:
                    failures.append(path.name + ": instance channel and Discord role channel disagree")
            elif matches or channel is not None:
                failures.append(path.name + ": L3/L4 instances must not have a Discord role or channel")
        return failures
    except Refused as error:
        return [str(error)]
    except OSError:
        return ["cannot read org instances for Discord validation"]


def message_to_event(message, roles, *, channel_names=None, logger=LOGGER):
    """Convert an authenticated Discord MESSAGE_CREATE payload, or log and return 'drop'.

    Explicit user authority wins over group membership. Among matching server
    roles decide wins. The caller supplies actual Discord member roles, never
    role ids claimed in message text. channel_names is the gateway's channel cache.
    """
    def drop(reason):
        logger.warning("drop Discord message: %s", reason)
        return "drop"

    if not isinstance(message, dict):
        return drop("message is not an object")
    role = next((role for role in roles.values() if role.channel_id == message.get("channel_id")), None)
    if role is None:
        return drop("channel is not registered")
    author = message.get("author")
    if not isinstance(author, dict) or author.get("bot") or message.get("webhook_id"):
        return drop("sender is not a human member")
    try:
        _id(author.get("id"), "author id")
        _id(message.get("id"), "message id")
    except Refused:
        return drop("author or message id is invalid")
    member = message.get("member", {})
    if not isinstance(member, dict):
        return drop("Discord member metadata is invalid")
    authority = next((entry.authority for entry in role.members
                      if entry.kind == "user" and entry.id == author["id"]), None)
    if authority is None:
        group_ids = member.get("roles", [])
        if not isinstance(group_ids, list) or any(
                not isinstance(identifier, str) or DISCORD_ID.fullmatch(identifier) is None
                for identifier in group_ids):
            return drop("Discord server role metadata is invalid")
        matches = [entry.authority for entry in role.members if entry.kind == "role" and entry.id in group_ids]
        authority = "decide" if "decide" in matches else ("inform" if "inform" in matches else None)
    if authority is None:
        return drop("sender is not listed for this channel")
    display = next((value for value in (member.get("nick"), author.get("global_name"), author.get("username"))
                    if isinstance(value, str) and value), None)
    text = message.get("content")
    reference = message.get("message_reference")
    if reference is None:
        reference = {}
    if display is None or not isinstance(text, str) or not isinstance(reference, dict):
        return drop("message text, display name or reply metadata is invalid")
    reply_to = reference.get("message_id")
    if reply_to is not None and (not isinstance(reply_to, str) or DISCORD_ID.fullmatch(reply_to) is None):
        return drop("reply message id is invalid")
    name = (channel_names or {}).get(role.channel_id, role.channel_name)
    try:
        _channel_name(name)
    except Refused:
        return drop("channel name is unavailable")
    return {"role": role.name, "instance": role.instance,
            "channel": {"id": role.channel_id, "name": name},
            "author": {"id": author["id"], "display_name": display, "authority": authority},
            "message_id": message["id"], "text": text, "reply_to": reply_to}


def event_json_line(message, roles, **options):
    """The exact single JSON line a gateway appends, or 'drop' (never appended)."""
    event = message_to_event(message, roles, **options)
    return "drop" if event == "drop" else output(event) + "\n"


def _settings(root):
    org = _toml(_read_bytes(_inside(root, Path(".laneboss/org.toml")), "org.toml"), "org.toml")
    services = org.get("services", {})
    discord = services.get("discord", {}) if isinstance(services, dict) else {}
    if not isinstance(discord, dict):
        raise Refused("org.toml requires a services.discord table")
    _id(discord.get("guild_id"), "services.discord.guild_id")
    name = discord.get("token_secret")
    if not isinstance(name, str) or SECRET_NAME.fullmatch(name) is None:
        raise Refused("services.discord.token_secret must name a secret, never contain its value")
    if "owner_id" in discord:
        _id(discord["owner_id"], "services.discord.owner_id")
    store = org.get("secret_store")
    if not isinstance(store, dict) or store.get("kind") not in ("file", "keychain"):
        raise Refused("org.toml secret_store.kind must be file or keychain")
    if store["kind"] == "file":
        location = store.get("path")
        if not isinstance(location, str) or not Path(location).expanduser().is_absolute():
            raise Refused("secret_store.path must be an absolute path outside the org")
        path = Path(location).expanduser()
        if path.resolve().is_relative_to(root) or path.is_symlink():
            raise Refused("the org secret store must be outside the org and must not be a symbolic link")
        if any((parent / ".git").exists() for parent in path.resolve().parents):
            raise Refused("the org secret store must be outside every repository")
    else:
        _name(store.get("service"), "secret_store.service")
    return discord, store


def _load_token(root, discord, store):
    name = discord["token_secret"]
    if store["kind"] == "file":
        data = _read_bytes(Path(store["path"]).expanduser(), "org secret store", private=True)
        token = _toml(data, "org secret store").get(name)
    else:
        if sys.platform != "darwin":
            raise Refused("the keychain secret store requires macOS; use a private file store on this platform")
        try:
            result = subprocess.run(["/usr/bin/security", "find-generic-password", "-s", store["service"],
                                     "-a", name, "-w"], capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Refused("cannot resolve the named bot secret from the org keychain") from None
        if result.returncode:
            raise Refused("cannot resolve the named bot secret from the org keychain")
        try:
            token = result.stdout.decode("utf-8").strip()
        except UnicodeDecodeError:
            raise Refused("the named bot secret must be UTF-8 text") from None
    if (not isinstance(token, str) or not 20 <= len(token) <= 512
            or re.fullmatch(r"[A-Za-z0-9._-]+", token) is None):
        raise Refused("the named bot secret is missing or is not a valid bot token")
    return token


def _api_base():
    base = os.environ.get(TEST_BASE_ENV)
    if base is None:
        return API_BASE
    try:
        url = urllib.parse.urlsplit(base)
        host = ipaddress.ip_address(url.hostname or "")
        valid = (url.scheme == "http" and host.is_loopback and url.port is not None
                 and not url.username and not url.password and not url.query and not url.fragment
                 and url.path.rstrip("/") == "/api/v10")
    except ValueError:
        valid = False
    if not valid:
        raise Refused(TEST_BASE_ENV + " is for a localhost HTTP test stub at /api/v10 only")
    return base.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise Refused("Discord REST redirects are refused; no bot credential was forwarded")


class DiscordREST:
    def __init__(self, token):
        self._token = token
        self._base = _api_base()
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def request(self, method, path, body=None, *, creating=False):
        request = urllib.request.Request(self._base + path, method=method,
            data=None if body is None else output(body).encode("utf-8"),
            headers={"Authorization": "Bot " + self._token, "Content-Type": "application/json",
                     "User-Agent": "DiscordBot (laneboss, 1.0)"})
        try:
            with self._opener.open(request, timeout=20) as response:
                raw = response.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as error:
            if creating and error.code == 403:
                raise Refused("Discord refused channel creation (HTTP 403): the bot needs Manage Channels. "
                              "Owner step: in Discord, Server Settings > Roles > the bot's role, enable Manage "
                              "Channels (only that permission). Or create the channel yourself and rerun with "
                              "--channel-id") from None
            raise Refused("Discord REST request failed (HTTP {})".format(error.code)) from None
        except (OSError, urllib.error.URLError, http.client.HTTPException, ValueError):
            raise Refused("Discord REST request could not be completed") from None
        if len(raw) > MAX_BYTES:
            raise Refused("Discord REST response exceeds 1 MiB")
        try:
            reply = parse(raw.decode("utf-8"), "Discord REST response")
        except UnicodeDecodeError:
            raise Refused("Discord REST response is not UTF-8 JSON") from None
        if not isinstance(reply, dict):
            raise Refused("Discord REST response must be an object")
        return reply


def _member_arguments(values, kind):
    members = {}
    for value in values:
        parts = value.split(":")
        if len(parts) != 2 or parts[1] not in ("decide", "inform"):
            raise Refused("--member and --role-id require ID:decide or ID:inform")
        identifier = _id(parts[0], "member id")
        if identifier in members and members[identifier].authority != parts[1]:
            raise Refused("a member must not be given conflicting authorities in one command")
        members[identifier] = DiscordMember(kind, identifier, parts[1])
    return list(members.values())


def _binding(root, arguments):
    relative, raw, agent = _instance(root, arguments.instance)
    if agent["level"] not in (5, 6):
        raise Refused("owner Discord channels are for L5 or L6 instances only; L3/L4 are refused")
    discord, store = _settings(root)
    roles = read_roles(root, allow_missing=True)
    existing = next((role for role in roles.values() if role.instance == arguments.instance), None)
    channel = existing.channel_id if existing else agent.get("discord_channel_id")
    if existing and agent.get("discord_channel_id") not in (None, channel):
        raise Refused("instance channel and Discord role channel disagree; resolve the binding before adding")
    if arguments.channel_id is not None:
        requested = _id(arguments.channel_id, "--channel-id")
        if channel is not None and requested != channel:
            raise Refused("this instance already has another channel; channel add will not rebind it")
        channel = requested
    if channel and any(role.channel_id == channel and role != existing for role in roles.values()):
        raise Refused("this channel is already registered to another instance")
    members = {(entry.kind, entry.id): entry for entry in (existing.members if existing else ())}
    for entry in (_member_arguments(arguments.member, "user") + _member_arguments(arguments.role_id, "role")):
        if entry.kind == "user" and entry.id == discord.get("owner_id") and entry.authority != "decide":
            raise Refused("the configured owner must keep decide authority in every channel")
        members[(entry.kind, entry.id)] = entry
    if "owner_id" in discord:
        members[("user", discord["owner_id"])] = DiscordMember("user", discord["owner_id"], "decide")
    if not members:
        raise Refused("add at least one --member or --role-id, or configure services.discord.owner_id")
    name = existing.name if existing else arguments.instance
    if not existing and name in roles:
        raise Refused("the default role name is already used by another instance")
    role = (replace(existing, members=tuple(members.values())) if existing else
            DiscordRole(name, arguments.instance, channel or "<created-channel-id>",
                        re.sub(r"[^a-z0-9_-]", "-", arguments.instance.lower()), tuple(members.values()),
                        "owner-discord." + name + ".state.json", "owner-discord.events." + name + ".jsonl",
                        "owner-form." + name))
    return relative, raw, agent, discord, store, roles, existing, role, channel


def _changes(relative, agent, existing, role):
    changes = []
    before = existing.as_dict() if existing else None
    if before != role.as_dict():
        changes.append({"file": str(ROLES_PATH), "role": role.name, "before": before, "after": role.as_dict()})
    if agent.get("discord_channel_id") != role.channel_id:
        changes.append({"file": str(relative), "field": "discord_channel_id",
                        "before": agent.get("discord_channel_id"), "after": role.channel_id})
    return changes


def _write(root, relative, data):
    path = _inside(root, relative)
    if path.exists() and _read_bytes(path, "org channel configuration") == data:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path.parent, fsguard.DIRECTORY)
    try:
        fsguard.write_new(descriptor, path.name, data, replace=True)
    finally:
        os.close(descriptor)


@contextmanager
def _locked(root):
    descriptor = os.open(_inside(root, Path(".laneboss")), fsguard.DIRECTORY)
    try:
        with fsguard.Lock(descriptor):
            yield
    finally:
        os.close(descriptor)


def _hello(instance, level):
    return "laneboss: owner channel ready for {} (L{}).".format(instance, level)


def _verify_message(reply, role, hello, message_id=None):
    identifier = _id(reply.get("id"), "hello message id")
    author = reply.get("author")
    if (reply.get("channel_id") != role.channel_id or reply.get("content") != hello
            or (message_id is not None and identifier != message_id)
            or not isinstance(author, dict) or author.get("bot") is not True):
        raise Refused("Discord hello verification failed: message id, channel, text or bot author did not match")
    return identifier


def add_channel(arguments):
    """Implement channel add. Dry-run does not open secrets, lock, write or call REST."""
    try:
        root = _org_root(arguments.org_dir)
        if arguments.dry_run:
            relative, _, agent, discord, _, _, existing, role, channel = _binding(root, arguments)
            requests = [{"method": "GET", "path": "/channels/" + channel}] if channel else [
                {"method": "POST", "path": "/guilds/" + discord["guild_id"] + "/channels",
                 "body": {"name": role.channel_name, "type": 0}}]
            if role.hello_message_id is None:
                role = replace(role, hello_message_id="<posted-message-id>")
                requests.append({"method": "POST", "path": "/channels/" + role.channel_id + "/messages",
                                 "body": {"content": _hello(role.instance, agent["level"]),
                                          "allowed_mentions": {"parse": []}}})
            requests.append({"method": "GET", "path": "/channels/" + role.channel_id +
                             "/messages/" + role.hello_message_id})
            return {"dry_run": True, "instance": role.instance, "reused": channel is not None,
                    "changes": _changes(relative, agent, existing, role), "requests": requests,
                    "note": "channel name and new ids are resolved by REST during the real run"}
        with _locked(root):
            relative, raw, agent, discord, store, roles, existing, role, channel = _binding(root, arguments)
            api = DiscordREST(_load_token(root, discord, store))
            reused = channel is not None
            if channel:
                metadata = api.request("GET", "/channels/" + channel)
            else:
                metadata = api.request("POST", "/guilds/" + discord["guild_id"] + "/channels",
                                       {"name": role.channel_name, "type": 0}, creating=True)
            identifier = _id(metadata.get("id"), "Discord channel id")
            if (metadata.get("guild_id") != discord["guild_id"] or type(metadata.get("type")) is not int
                    or metadata["type"] not in (0, 5)
                    or (channel is not None and identifier != channel)):
                raise Refused("Discord channel is not a text channel in the configured org server")
            if any(entry.channel_id == identifier and entry != existing for entry in roles.values()):
                raise Refused("Discord returned a channel already registered to another instance")
            channel_name = _channel_name(metadata.get("name"))
            if api._token in channel_name:
                raise Refused("Discord channel metadata contains credential material; registration refused")
            role = replace(role, channel_id=identifier, channel_name=channel_name)
            roles[role.name] = role
            # Save the binding before posting. A failed self-test stays visible and
            # can be retried using the same channel instead of creating another.
            if role != existing:
                _write(root, ROLES_PATH, render_roles(roles))
            if "discord_channel_id" not in agent:
                _write(root, relative, ('discord_channel_id = ' + json.dumps(identifier) + '\n').encode() + raw)
            hello = _hello(role.instance, agent["level"])
            if role.hello_message_id is None:
                posted = api.request("POST", "/channels/" + identifier + "/messages",
                                     {"content": hello, "allowed_mentions": {"parse": []}})
                role = replace(role, hello_message_id=_verify_message(posted, role, hello))
                roles[role.name] = role
                # Save the posted id before read-back, so a failed GET can be
                # retried without sending the hello twice.
                _write(root, ROLES_PATH, render_roles(roles))
            read_back = api.request("GET", "/channels/" + identifier + "/messages/" + role.hello_message_id)
            _verify_message(read_back, role, hello, role.hello_message_id)
            result = {"dry_run": False, "instance": role.instance, "role": role.name,
                      "channel_id": identifier, "channel_name": role.channel_name,
                      "hello_message_id": role.hello_message_id, "verified": True, "reused": reused,
                      "changes": _changes(relative, agent, existing, role)}
            # Even a malicious REST reply cannot echo the token via channel names.
            return parse(output(result).replace(api._token, "[hidden]"), "channel result")
    except OSError:
        raise Refused("org channel registration could not read or write its configuration files") from None
