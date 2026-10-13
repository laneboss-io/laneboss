"""The credential detector as one table, applied to events, briefs, rules files and configuration values,
and the rule that no message repeats a refused value, not even through a field path."""

import hashlib
import json
import uuid

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


DIGEST = hashlib.sha256(b"an invented key").hexdigest()
UUID = str(uuid.UUID(int=0x1234567812345678123456781234ABCD))

# (label, line of text, the refused value that must never be echoed)
REFUSED = [
    ("short value", "password = aB3!xY7", "aB3!xY7"),
    ("upper-case literal", "password = HUNTER2LETMEIN", "HUNTER2LETMEIN"),
    ("slash prefix", "password = /x9Fq2LmP", "/x9Fq2LmP"),
    ("dollar prefix", "password = $ecretP4ss", "$ecretP4ss"),
    ("percent prefix", "password = %tY7xQ2", "%tY7xQ2"),
    ("name with space", "API key: K9m2rX6vC8", "K9m2rX6vC8"),
    ("name with hyphen", "API-key: K9m2rX6vC8", "K9m2rX6vC8"),
    ("name with underscore", "API_key: K9m2rX6vC8", "K9m2rX6vC8"),
    ("digest under a credential name", "token = " + DIGEST, DIGEST),
    ("uuid under a credential name", "token: " + UUID, UUID),
    ("second assignment on a line", "token = $DEPLOY_TOKEN; password = S3cretAbc", "S3cretAbc"),
    ("quoted passphrase", 'password = "correct horse battery staple"', "correct horse battery staple"),
]
ACCEPTED = [
    ("prose", "Token: identifies a parser symbol."),
    ("code", "password = read_password()"),
    ("secret name", "api_key = E2E_DEPLOY_KEY"),
    ("dollar reference", "token = $DEPLOY_TOKEN"),
    ("braced reference", "token = ${DEPLOY_TOKEN}"),
    ("angle placeholder", "token = <placeholder>"),
    ("brace placeholder", "token = {placeholder}"),
    ("one-letter word", "Token: a parser symbol."),
    ("comparison", "if token == expected:"),
    ("other comparisons", "while token != previous and password >= limit and secret <= other:"),
]
# The same values as JSON fields: (label, key, value, refused). A JSON string is quoted by nature, so
# several words under a credential name are a literal passphrase, not prose.
FIELDS = [
    ("short value", "password", "aB3!xY7", True),
    ("upper-case literal", "password", "HUNTER2LETMEIN", True),
    ("slash prefix", "password", "/x9Fq2LmP", True),
    ("name with space", "API key", "K9m2rX6vC8", True),
    ("digest", "token", DIGEST, True),
    ("several words", "token", "identifies a parser symbol.", True),
    ("quoted passphrase", "password", "correct horse battery staple", True),
    ("code", "password", "read_password()", False),
    ("secret name", "api_key", "E2E_DEPLOY_KEY", False),
    ("dollar reference", "token", "$DEPLOY_TOKEN", False),
    ("braced reference", "token", "${DEPLOY_TOKEN}", False),
    ("angle placeholder", "token", "<placeholder>", False),
    ("brace placeholder", "token", "{placeholder}", False),
]
# Addresses that carry a secret in the URL itself: (label, the rule that must report it, line of text, the
# secret that must never be echoed). Every sample is invented and built here from short pieces, so no long
# run of characters sits in the file and no rule can be keyed to one sample's exact length.
DISCORD_ID = "1" * 18                              # 18 digits
DISCORD_TOKEN = "A1b2C3" * 11 + "-_"               # 68 characters of [A-Za-z0-9_-]
SLACK_T = "T" + "1" * 10                           # 11 characters
SLACK_B = "B" + "2" * 8                            # 9 characters
SLACK_A = "A" + "4" * 10                           # 11 characters
SLACK_NUM = "3" * 13                               # the digits Slack puts in a trigger path
SLACK_SECRET = "aB3xY7" * 4                        # 24 characters
APPS_ID = "AKfycb" + "Q7wE" * 16 + "Rt"            # a bare deployment id: AKfycb and 66 more


def _address_rows():
    """Every address form, built here: (label, rule, line, the secret that must never be echoed)."""
    discord_path = "api/webhooks/{}/{}".format(DISCORD_ID, DISCORD_TOKEN)
    escaped = lambda value: value.replace("/", "\\/")     # noqa: E731  the \/ a JSON encoder writes
    encoded = lambda value: value.replace("/", "%2F")     # noqa: E731  a percent-encoded slash
    discord = [
        ("discord no scheme", "discord.com/" + discord_path),
        ("discord capitalised scheme", "Https://discord.com/" + discord_path),
        ("discord upper-case host", "https://DISCORD.COM/" + discord_path),
        ("discord old host", "https://discordapp.com/" + discord_path),
        ("discord versioned path", "https://discord.com/api/v10/webhooks/{}/{}".format(DISCORD_ID, DISCORD_TOKEN)),
        ("discord ptb subdomain", "https://ptb.discord.com/" + discord_path),
        ("discord canary subdomain", "https://canary.discord.com/" + discord_path),
        ("discord escaped slashes", "discord.com/" + escaped(discord_path)),
        ("discord percent-encoded slashes", "discord.com/" + encoded(discord_path)),
    ]
    slack_path = "services/{}/{}/{}".format(SLACK_T, SLACK_B, SLACK_SECRET)
    slack = [
        ("slack no scheme", "hooks.slack.com/" + slack_path),
        ("slack capitalised scheme", "Https://hooks.slack.com/" + slack_path),
        ("slack upper-case host", "https://HOOKS.SLACK.COM/" + slack_path),
        ("slack escaped slashes", "hooks.slack.com/" + escaped(slack_path)),
        ("slack percent-encoded slashes", "hooks.slack.com/" + encoded(slack_path)),
        ("slack trigger", "https://hooks.slack.com/triggers/{}/{}/{}".format(SLACK_T, SLACK_NUM, SLACK_SECRET)),
        ("slack workflow", "https://hooks.slack.com/workflows/{}/{}/{}/{}".format(
            SLACK_T, SLACK_A, SLACK_NUM, SLACK_SECRET)),
    ]
    apps_path = "macros/s/{}/exec".format(APPS_ID)
    apps = [
        ("apps script no scheme", "script.google.com/" + apps_path),
        ("apps script capitalised scheme", "Https://script.google.com/" + apps_path),
        ("apps script upper-case host", "https://SCRIPT.GOOGLE.COM/" + apps_path),
        ("apps script workspace /a/macros/", "script.google.com/a/macros/example.org/s/{}/exec".format(APPS_ID)),
        ("apps script workspace /a/domain/macros/", "script.google.com/a/example.org/macros/s/{}/exec".format(APPS_ID)),
        ("apps script account index", "script.google.com/macros/u/1/s/{}/exec".format(APPS_ID)),
        ("apps script cut before the suffix", "script.google.com/macros/s/{}".format(APPS_ID)),
        ("apps script escaped slashes", "script.google.com/" + escaped(apps_path)),
        ("apps script percent-encoded slashes", "script.google.com/" + encoded(apps_path)),
        ("apps script bare deployment id", "deployment: " + APPS_ID),
    ]
    return ([(label, "chat-webhook-url", line, DISCORD_TOKEN) for label, line in discord]
            + [(label, "chat-webhook-url", line, SLACK_SECRET) for label, line in slack]
            + [(label, "script-web-app-url", line, APPS_ID) for label, line in apps])


ADDRESSES = _address_rows()
# Prose that names one of those hosts without a real token: not an address, so not refused.
ADDRESS_PROSE = [
    ("discord webhook path", "Discord's hooks live under discord.com/api/webhooks when you make one."),
    ("apps script host", "Deployments run on script.google.com."),
    ("slack webhook host", "Create the app at hooks.slack.com first."),
    ("discord documentation page", "The fields are listed on discord.com/developers/docs/resources/webhook."),
    ("apps script home page", "Open script.google.com/home to deploy a new version."),
    ("discord placeholders", "A hook looks like https://discord.com/api/webhooks/<id>/{token}."),
    ("apps script placeholder", "Deploy at https://script.google.com/macros/s/<id>/exec first."),
]


class DetectorTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.write_config("alpha")

    def test_bearer_after_unicode_space(self):
        """Fails if a Unicode separator lets the credential reach any public input surface."""
        for whitespace in ("\u00a0", "\u0085", "\u2003", "\u202f", "\u001c", "\v"):
            for prefix in ("Bearer", "Authorization:" + whitespace + "Bearer"):
                secret = uuid.uuid4().hex
                line = prefix + whitespace + secret
                for surface, check in (("event", self.check_event), ("brief", self.check_brief),
                                       ("rules", self.check_rules), ("config", self.check_value)):
                    with self.subTest(separator=hex(ord(whitespace)), surface=surface):
                        check({"log": line} if surface == "event" else line, True, secret)

    def check_event(self, payload, refused, secret=None):
        self.fresh_config("alpha")
        result = self.append(self.event(id="detect-" + uuid.uuid4().hex[:8], payload=payload),
                             code=2 if refused else 0)
        if secret:
            self.assertNotIn(secret, result.stdout + result.stderr)
        return result

    def check_brief(self, line, refused, secret=None):
        self.fresh_config("alpha")
        source = self.directory / "brief.md"
        source.write_text("# Brief\n\nAn invented task.\n\n" + line + "\n", encoding="utf-8")
        target = self.directory / "rendered-{}.md".format(uuid.uuid4().hex[:8])
        result = self.run_laneboss("brief", "render", "--config", "alpha", "--lane", "alpha-lane-1", "--in", source,
                              "--out", target, code=2 if refused else 0)
        if secret:
            self.assertNotIn(secret, result.stdout + result.stderr)
            self.assertFalse(target.exists())
        return result

    def check_rules(self, line, refused, secret=None):
        directory = self.fresh_config("alpha")
        (directory / "rules" / "standing.md").write_text("# Rules\n\n" + line + "\n", encoding="utf-8")
        result = self.run_laneboss("config", "validate", "alpha", code=2 if refused else 0)
        if secret:
            self.assertNotIn(secret, result.stdout + result.stderr)
        return result

    def check_value(self, line, refused, secret=None):
        self.fresh_config("alpha", replace=[(
            'description = "Invented configuration for the launcher\'s black-box tests."',
            "description = {}".format(json.dumps(line)))])
        result = self.run_laneboss("config", "validate", "alpha", code=2 if refused else 0)
        if secret:
            self.assertNotIn(secret, result.stdout + result.stderr)
        return result

    def test_refused_table(self):
        for label, line, secret in REFUSED:
            for surface, check in (("event", lambda: self.check_event({"log": line}, True, secret)),
                                   ("brief", lambda: self.check_brief(line, True, secret)),
                                   ("rules", lambda: self.check_rules(line, True, secret)),
                                   ("configuration value", lambda: self.check_value(line, True, secret))):
                with self.subTest(label=label, surface=surface):
                    check()
        self.fresh_config("alpha")
        self.assertEqual(self.events(), [])

    def test_accepted_table(self):
        for label, line in ACCEPTED:
            for surface, check in (("event", lambda: self.check_event({"log": line}, False)),
                                   ("brief", lambda: self.check_brief(line, False)),
                                   ("rules", lambda: self.check_rules(line, False)),
                                   ("configuration value", lambda: self.check_value(line, False))):
                with self.subTest(label=label, surface=surface):
                    check()

    def test_field_table(self):
        for label, key, value, refused in FIELDS:
            with self.subTest(label=label, key=key):
                self.check_event({key: value}, refused, value if refused else None)

    def test_no_echo_through_path(self):
        secret = "S3cretAbc"
        result = self.check_event({secret: {"password": secret}}, True, secret)
        self.assertIn("payload", result.stderr)
        self.assertNotIn("password", result.stderr, "no key below the top level is printed")
        self.check_event({"outer": {secret + "-x": [{"password": secret}]}}, True, secret)
        self.fresh_config("alpha", tail='\n[{0}]\npassword = "{0}"\n'.format(secret))
        result = self.run_laneboss("config", "validate", "alpha", code=2)
        self.assertNotIn(secret, result.stdout + result.stderr)
        result = self.run_laneboss("doctor", "--config", "alpha", code=1)
        self.assertNotIn(secret, result.stdout + result.stderr)
        self.fresh_config("alpha")
        self.assertEqual(self.events(), [])

    def test_value_from_short_keys(self):
        secret = "12.34.56"
        result = self.check_event({"12": {"34": {"56": {"password": secret}}}}, True, secret)
        self.assertIn("payload", result.stderr)
        for inner in ("zqkouter", "zqkinner"):
            result = self.check_event({"zqkouter": {"zqkinner": [{"password": "Zq9x" + "Wv7y"}]}}, True,
                                      "Zq9xWv7y")
            self.assertNotIn(inner, result.stderr)
        self.fresh_config("alpha", tail='\n[12.34.56]\npassword = "12.34.56"\n')
        for arguments, code in ((("config", "validate", "alpha"), 2), (("doctor", "--config", "alpha"), 1)):
            result = self.run_laneboss(*arguments, code=code)
            self.assertNotIn(secret, result.stdout + result.stderr)
            self.assertNotIn("34.56", result.stdout + result.stderr)
        self.fresh_config("alpha", tail='\n[zqktop.zqkinner]\npassword = "Zq9xWv7y"\n')
        result = self.run_laneboss("config", "validate", "alpha", code=2)
        self.assertNotIn("zqkinner", result.stdout + result.stderr)
        self.assertNotIn("Zq9xWv7y", result.stdout + result.stderr)

    def test_parse_error_position_only(self):
        token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6Q7r8"
        self.fresh_config("alpha", tail='\n["{0}"]\nfirst = 1\n\n["{0}"]\nsecond = 2\n'.format(token))
        for arguments, code in ((("config", "validate", "alpha"), 2), (("doctor", "--config", "alpha"), 1),
                                (("config", "show", "alpha"), 2)):
            result = self.run_laneboss(*arguments, code=code)
            self.assertNotIn(token, result.stdout + result.stderr)
            self.assertIn("line", result.stdout + result.stderr)
        project = self.home / "configs" / "alpha" / "projects" / "web.toml"
        self.fresh_config("alpha")
        project.write_text(project.read_text(encoding="utf-8") + '\n["{0}"]\nx = 1\n["{0}"]\ny = 2\n'.format(token),
                           encoding="utf-8")
        result = self.run_laneboss("config", "validate", "alpha", code=2)
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertIn("projects/web.toml", result.stderr)

    def test_address_table(self):
        for label, rule, line, secret in ADDRESSES:
            for surface, check in (("event", lambda: self.check_event({"log": line}, True, secret)),
                                   ("brief", lambda: self.check_brief(line, True, secret)),
                                   ("rules", lambda: self.check_rules(line, True, secret)),
                                   ("configuration value", lambda: self.check_value(line, True, secret))):
                with self.subTest(label=label, surface=surface):
                    result = check()
                    self.assertIn(rule, result.stdout + result.stderr,
                                  "the refusal names the rule {}".format(rule))

    def test_address_prose_table(self):
        for label, line in ADDRESS_PROSE:
            for surface, check in (("event", lambda: self.check_event({"log": line}, False)),
                                   ("brief", lambda: self.check_brief(line, False)),
                                   ("rules", lambda: self.check_rules(line, False)),
                                   ("configuration value", lambda: self.check_value(line, False))):
                with self.subTest(label=label, surface=surface):
                    check()
