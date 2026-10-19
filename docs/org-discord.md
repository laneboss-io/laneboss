## Owner Discord channels for L5 and L6

Once an org uses Discord (its `org.toml` has a `services.discord` table, or a
role is registered), every L5 and L6 instance has one owner channel. L3 and L4
instances never have one: `org instance add` refuses `--discord-channel` for
them, and the org's default channel is inherited by L5 and L6 only. Before an
org uses Discord, a channel recorded on an L5 or L6 instance is kept and is
checked once `services.discord` is configured. Register an owner-created channel with mode A, or ask the bot to create a
channel with mode B:

```sh
laneboss org channel add ./example-org L5-topic \
  --channel-id 123456789012345678 \
  --member 234567890123456789:decide \
  --member 345678901234567890:inform \
  --role-id 456789012345678901:inform

laneboss org channel add ./example-org L6-root --create

laneboss org channel add ./example-org L5-topic \
  --channel-id 123456789012345678 --dry-run
```

`--channel-id` and `--create` are mutually exclusive and one is required.
`--member` names a Discord user; `--role-id` names a Discord server role. Both
options may be repeated. Every entry must have `decide` or `inform` authority.
The instance argument is its directory name below `.laneboss/instances/`.
The command reads the integer `level` from that instance's `instance.toml`,
before resolving credentials or calling Discord, and refuses levels 3 and 4.

Mode A uses the channel the owner already made. The bot needs permission to
view the channel, send messages, and read message history. Mode B requires
Manage Channels in the configured Discord server as well. An HTTP 403 on channel
creation explains that requirement and offers `--channel-id`. Only the owner
can grant the bot new server permissions. The channel must be a guild text or
announcement channel in the configured org server.

### Org configuration and named secrets

The Go org validator accepts the `[services.discord]` table below and checks its
required guild id and secret name and optional owner id. Like the Python Discord
reader, it leaves other services and extra Discord settings alone. The
legacy Python org validator still lacks the service-table schema; select the
Go org binary when running the combined init/render/channel/validate workflow.

The existing top-level org fields and `secret_store` schema still match
`src/laneboss/orgschema.py`: the original seven top-level fields are required,
and `secret_store.kind` and `secret_store.path` are required with no extra store
fields. The Go fix adds only the optional top-level `services` table. Within
`services.discord`, required `guild_id` and `token_secret`, optional `owner_id`,
positive string ids of 1–20 digits and uppercase secret-name syntax match
`src/laneboss/orgdiscord.py::_settings`.

There are pre-existing Python inconsistencies that exact equivalence cannot
preserve while fixing this bug. Its org schema rejects `services` entirely;
its `validate_org_channels` checks channel/instance coverage without validating
service credentials/settings; and its keychain Discord reader requires
`secret_store.service`, while its org schema requires `secret_store.path` and
rejects `service`. This change does not alter the secret-store schema or channel
coverage rules. The Go schema now validates the added service table during
render/validate; the Python reader performs those field checks during channel
registration. A malformed non-table `services` is also rejected by the Go schema,
whereas Python's channel-coverage helper alone ignores it when no role exists.

Add the Discord service and a reference to the org secret store in
`.laneboss/org.toml`. All Discord ids are strings. These fields contain public
ids and secret names, never credentials:

```toml
[services.discord]
guild_id = "567890123456789012"
token_secret = "ORG_DISCORD_BOT_TOKEN"
owner_id = "234567890123456789"

[secret_store]
kind = "file"
path = "/srv/private/example-org/secrets.toml"
```

The file store is a flat TOML mapping from secret names to values. Provision the
named bot token there through the org's private secret-management procedure.
The file must be outside the org and every Git repository, owned by the user
running the command, a regular file with mode 600 or stricter, and not a symbolic
link. The command reads only the named entry into the REST client's memory. It
does not put the token in argv, stdout, stderr, instance files, or the roles file.
Discord error bodies and keychain diagnostics are never echoed.

On macOS the same service can instead use an OS keychain entry:

```toml
[secret_store]
kind = "keychain"
service = "example-org"
```

The keychain service is the configured `service` and its account is the
`token_secret` name. The command captures the secret from
`security find-generic-password`; its argument vector holds only that service
and account name. Keychain resolution is refused on other platforms.

`owner_id` is optional. When configured, it is included as an explicit `decide`
member in every registration, including an idempotent repeat. The command
refuses an attempt to give that owner `inform` authority. Without `owner_id`,
provide at least one member or server role when first registering the channel.
An existing registration can be reused without supplying its members again.

### One roles file

The command registers each instance in
`.laneboss/shared/services/discord-roles.toml`. This file replaces separate
gateway, messaging-tool, and form-tool role lists. A role name defaults to the
instance name. For example:

```toml
schema_version = 1

[roles."L5-topic"]
instance = "L5-topic"
channel_id = "123456789012345678"
channel_name = "owner-topic"
state_file = "owner-discord.L5-topic.state.json"
events_file = "owner-discord.events.L5-topic.jsonl"
form_doorbell = "owner-form.L5-topic"
hello_message_id = "678901234567890123"
members = [
  { user_id = "234567890123456789", authority = "decide" },
  { user_id = "345678901234567890", authority = "inform" },
  { role_id = "456789012345678901", authority = "inform" },
]
```

`state_file` and `events_file` are file names relative to that instance's
`state/` directory. `form_doorbell` is the form notification name; it is not a
webhook URL or credential. This phase records the names; the gateway and form
service create or use their own state, events and notification resources later.

`laneboss.orgdiscord.read_roles(org_dir)` returns a mapping from role names to
immutable `DiscordRole` objects. Each object has immutable `DiscordMember`
entries (`kind`, `id`, `authority`) and `as_dict()` for the TOML-shaped data.
The reader checks the schema, instance existence and L5/L6 level, unique
instance and channel bindings, nonempty member lists, ids, authorities, safe
file names, and optional hello message id. It rejects duplicate or unknown
fields and duplicate members. A missing file is refused unless the caller
explicitly passes `allow_missing=True`; that option supports incremental org
setup. Full org coverage is checked by the validator below.

The command adds the top-level `discord_channel_id` string to the instance's
`instance.toml`. It preserves the original file bytes after that added line,
including comments and unrelated service settings. It resolves the channel's
actual name through REST instead of guessing the name of an owner-created
channel. Unicode channel names are preserved in TOML and event data.

### Verification, dry-run and repeat runs

Registration writes the roles file and instance channel, posts one hello line,
and reads that message back through REST. Success requires the returned message
id, channel id, text and bot author to match; a successful POST alone is not
verification. The hello disables all allowed mentions.

A repeat reuses the role and channel and reads the saved hello message again.
It does not create another channel or post another hello. An unchanged roles
file and instance file are left untouched. Explicit member options add members
or update their authority while retaining other members. A conflicting channel
id or a channel already belonging to another instance is refused. `--create`
also reuses a channel already present in the instance or roles file.

`--dry-run` returns one JSON object listing every proposed field change and
REST request. Newly created channel and message ids appear as placeholders.
For an owner-created channel the actual channel name remains to be resolved
by the real run. Dry-run does not read secret values, acquire a write lock,
create directories, write files, or make REST requests.

Real runs hold an org lock and replace individual configuration files
atomically. The two configuration files and Discord are separate resources;
registration cannot provide an atomic transaction across them. A failure after
channel creation or a local write can leave a partial registration. Validation
reports missing or inconsistent bindings; repeating the command repairs a
missing instance channel when the role is present. The posted hello id is saved
before its read-back, so a read failure can be retried without posting twice.
If a create or message POST reaches Discord but its response is lost before the
id is saved, inspect the channel before retrying; that transport ambiguity
cannot be resolved from local files alone. All failures exit nonzero.

The normal REST base is Discord API v10. Only tests may set
`LANEBOSS_TEST_DISCORD_BASE_URL`, which accepts an HTTP URL on a literal loopback
address with an explicit port and `/api/v10` path. Other endpoints, credentials
in the URL, queries and fragments are refused. REST redirects are refused and
proxy environment settings are ignored so authorization cannot be forwarded to
another endpoint.

### Channel-aware, multi-member events

The org's **shared Discord gateway**, `integrations/discord/gateway.mjs`, reads
these bindings through `laneboss org channel read ORG --json`. That read-only
command validates the Discord service, members and instance/channel coverage,
returns the token's environment-variable name and absolute event/state paths,
and neither opens the secret store nor contacts Discord. The messaging and form
tools must use the same role bindings and `form_doorbell` names when they are
packaged as shared org services.

For each authenticated Discord `MESSAGE_CREATE`, the gateway calls
`message_to_event(message, roles, channel_names=channel_cache)`. The optional
cache maps channel ids to their current names; otherwise the registered channel
name is used. It returns an event such as:

```json
{"role":"L5-topic","instance":"L5-topic","channel":{"id":"123456789012345678","name":"owner-topic"},"author":{"id":"234567890123456789","display_name":"Owner","authority":"decide"},"message_id":"789012345678901234","text":"Use the revised plan.","reply_to":"678901234567890123"}
```

`reply_to` is the referenced message id, or JSON `null`. Display-name precedence
is the guild nickname, global display name, then username. Text is preserved,
including Unicode and line breaks. `event_json_line(message, roles, **options)`
returns the same event serialized as exactly one JSON line with a final newline.
The gateway appends that line to the role's `events_file` and updates its
`state_file` with `last_message_id`. Each line is one UTF-8 `O_APPEND` write;
state updates use a temporary file and atomic rename. Files are created with
mode 0600. Duplicate message ids already in the event log are not appended
again, including after a process restart; an incomplete log line stops startup.

An explicit user entry controls that user's authority even if their Discord
server roles also match. If only server roles match, `decide` takes precedence
among those roles, followed by `inform`. Server role ids come from Discord's
authenticated `member.roles` metadata. Text that claims a role grants nothing.
The gateway must enable the message-content intent and provide member metadata
from Discord rather than from user-supplied input.

Unknown channels, unlisted senders, bots, webhooks and malformed messages return
the literal string `"drop"` and log a reason. Neither converter delivers a
stranger's message or echoes its text into the drop log. The gateway must not
append `"drop"` as an event. Form doorbells need their own authenticated,
informational handling in a later phase. Downstream decision capture
may treat only `decide` events as authoritative decisions; `inform` events
remain questions or information.

### Run the gateway

Use **Node 22 or newer**, the Go launcher from this release, and an org with
registered L5/L6 channels. No Node packages are needed. In the Discord developer
portal, enable **Message Content Intent** and **Server Members Intent** under
Bot → Privileged Gateway Intents; the bot must be able to view the registered
channels. Enable those privileged intents before starting the gateway.

Provision the bot token in the gateway's process environment using the name in
`services.discord.token_secret` (for example `ORG_DISCORD_BOT_TOKEN`), or the
fallback `DISCORD_BOT_TOKEN`. The gateway checks it silently and reads no secret
store. Keep the token out of commands and public configuration.

```sh
node integrations/discord/gateway.mjs --org ./example-org --launcher /usr/local/bin/laneboss
```

Release and source installers also retain the script and this guide under
`PREFIX/share/laneboss/versions/0.7.0/`. Use that script's absolute path when
running an installed service; installing Laneboss does not install Node.

Run that foreground command under your existing process supervisor. For a
systemd service, use the absolute paths to Node, this script, the org and the
launcher in `ExecStart`, provide the token through a private `EnvironmentFile`
owned by the service account with mode 0600, and use `Restart=on-failure` and
`RestartSec=5`. A launchd job can use the same arguments in `ProgramArguments`
and its private environment provisioner; keep credentials out of its arguments.
Run as the account that owns the org. This guide starts no service.

The gateway holds `.laneboss/shared/state/discord-gateway.lock` beside its
sequence state, so a second process for the org refuses before contacting
Discord. SIGTERM/SIGINT releases the lock. After a crash, verify the recorded
PID is no longer the gateway before removing a stale lock; it is never stolen
automatically. Role event/state files remain under each instance's `state/`
directory at the names in the configuration. Config changes require a restart.

Reconnects use bounded exponential backoff and Discord's resume URL, session
id and last processed sequence, with heartbeats and acknowledgment checks.
Missed dispatches replayed before `RESUMED` are delivered. Session credentials
stay in memory; a process restart identifies anew and does not fetch channel
history. A session Discord can no longer resume may therefore have a gap.
The shared state stores only `last_sequence`. Logs contain status and fixed
drop reasons, never message text. Slash commands, interactions, form doorbells
and automatic decision capture are outside this receive-only service.

For the loopback fake only, `LANEBOSS_TEST_DISCORD_BASE_URL` accepts exactly
`http://127.0.0.1:PORT` or `ws://127.0.0.1:PORT` (an optional final slash is
allowed). It uses `/api/v10/gateway/bot` on that HTTP origin, and accepts
gateway/resume WebSockets only on the same origin. Other hosts, schemes, paths,
credentials, queries and fragments are refused before any request. Production
uses Discord API v10 and secure Discord gateway URLs; redirects are refused.
`e2e-rows/test_discord_gateway.py` exercises that fake on a disposable Linux box
and includes a bot-filter mutant. It cannot establish live Discord authentication.

### Validation and acceptance

`org validate` calls `laneboss.orgdiscord.validate_org_channels(org_dir)` and
adds the returned failure strings to its other failures. An empty list means the
channel rules pass. Once the org uses Discord, it checks every L5/L6 instance has
exactly one role and the matching instance channel; L3/L4 instances never have
either; and every member has a valid authority. Duplicate instance or channel bindings and invalid role schemas
also fail. Validation reads configuration only; it never calls REST or opens
the secret store. `org channel add` is part of the one `laneboss org` command
group.

`laneboss-e2e:tests/e2e/test_org_discord.py` installs the checkout with the normal installer
and drives the installed CLI against a localhost `http.server`. The server
checks the exact bot authorization, guild, channel, JSON payload, and stored
message id. Its negative controls reject incorrect authorization, payloads and
unknown messages. Discord ids, secret names and token canaries vary on every
run. Event and validator probes use the same installed library and roles file
written by the CLI.

The acceptance checks fail if lower levels register, either file or hello
read-back is missing, mode B never creates, a 403 lacks the permission message,
dry-run writes or calls REST, repeats create or post again, allowed member
authority or channel context is lost, strangers are delivered, invalid roles
validate, or a token appears in output, live CLI argv, or public configuration.
Additional checks cover group precedence, Unicode names, retained instance
bytes, partial read-back retries, reflected secrets, and refused redirects.
Run this module and its RED/GREEN checks in the designated disposable test
environment. Compile and help checks alone do not establish runtime acceptance.

The referenced black-box files live in the separate `laneboss-e2e` repository. Run its commands there with `LANEBOSS_SRC` set to an absolute laneboss checkout. Go unit tests remain `go test ./...` in this repository.
