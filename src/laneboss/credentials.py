"""Detect values that look like credentials, from known credential shapes.

Two kinds of rule. Shapes: private-key headers, well-known token prefixes, authorization headers and
URLs that carry a password; they never match a hex digest, a commit id or a UUID. Assignments: a value
given to a name such as token, secret, password or api key (also written "API key" or "api-key"), after
`:`, `=`, `:=` or `=>` but not a comparison such as `==`, `!=`, `<=` or `>=`. Every assignment on a line
is examined, not only the first. An assigned value is a credential unless it is a reference or plain
language: a secret name in capitals with underscores (DEPLOY_TOKEN), $NAME, ${name}, <placeholder>,
{placeholder}, a placeholder word, a type name, a mask such as ****, a code expression (read_password(),
settings.password, new_password), or unquoted prose (a word followed by more words). A quoted value, and
every string value of a JSON or TOML field with a credential name, is the value itself: several words in
quotes are a passphrase. Any other literal is refused, however short, also when it is a hex digest or a
UUID: real keys have those shapes.

Callers never print a refused value: text findings name the line, structured findings name the top-level
field and the depth (never a key below the top level), and a top-level key that holds or is part of the
refused value is not printed either.
"""

import re

_WORDS = (r"(?:api[ _-]?key|apikey|access[ _-]?key|secret[ _-]?key|private[ _-]?key|client[ _-]?secret"
          r"|auth[ _-]?token|secret|token|passw(?:or)?d|passphrase|credentials?)")
_PREFIX = r"(?:[A-Za-z0-9]+[_.-])*?"
SENSITIVE_NAME = re.compile(_PREFIX + _WORDS, re.IGNORECASE)
# A path separator in an address rule: a slash, the \/ a JSON encoder may write, or a percent-encoded slash.
_SEP = r"(?:\\?/|%2[Ff])"

SHAPES = (
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("authorization-header", re.compile(
        r"\b(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic|token|digest)\s+[A-Za-z0-9._~+/=-]{8,}",
        re.IGNORECASE)),
    ("bearer-token", re.compile(r"\bbearer\s+[A-Za-z0-9._~+/-]{16,}", re.IGNORECASE)),
    ("code-host-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})")),
    ("chat-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("chat-bot-token", re.compile(r"\b[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}(?![A-Za-z0-9_-])")),
    ("messenger-bot-token", re.compile(r"\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])")),
    ("cloud-access-key-id", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("cloud-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("oauth-access-token", re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}")),
    ("prefixed-secret-key", re.compile(r"(?<![A-Za-z0-9])sk-(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{20,}")),
    ("payment-secret-key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("package-registry-token", re.compile(r"\b(?:npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,})")),
    ("model-hub-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("embedding-api-key", re.compile(r"(?<![A-Za-z0-9])pa-(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{40,}")),
    ("json-web-token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("url-credentials", re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@")),
    # An address whose path holds the secret: the token part is required, so prose that names the host is not
    # refused. Each rule starts at the host, so a missing scheme, a capitalised scheme and any subdomain of the
    # host are covered; the separator is a slash, the \/ a JSON encoder writes, or a percent-encoded %2F.
    ("chat-webhook-url", re.compile(
        r"(?i:discord(?:app)?\.com)" + _SEP + r"api" + _SEP + r"(?:v[0-9]+" + _SEP + r")?webhooks"
        + _SEP + r"[0-9]{5,}" + _SEP + r"[A-Za-z0-9_-]{6,}")),
    ("chat-webhook-url", re.compile(
        r"(?i:hooks\.slack\.com)" + _SEP + r"(?:services" + _SEP + r"T[A-Z0-9]{5,}" + _SEP + r"B[A-Z0-9]{5,}"
        r"|workflows" + _SEP + r"T[A-Z0-9]{5,}" + _SEP + r"A[A-Z0-9]{5,}" + _SEP + r"[0-9]{5,}"
        r"|triggers" + _SEP + r"T[A-Z0-9]{5,}" + _SEP + r"[0-9]{5,})"
        + _SEP + r"[A-Za-z0-9_-]{6,}")),
    ("script-web-app-url", re.compile(
        r"(?i:script\.google\.com)" + _SEP + r"(?:a" + _SEP + r"(?:macros" + _SEP + r")?[A-Za-z0-9.-]+" + _SEP
        + r")?(?:macros" + _SEP + r")?(?:u" + _SEP + r"[0-9]+" + _SEP + r")?s" + _SEP + r"[A-Za-z0-9_-]{10,}")),
    ("script-web-app-url", re.compile(r"(?<![A-Za-z0-9_-])AKfycb[A-Za-z0-9_-]{40,}")),
)

# The name and its separator only, so the next assignment on the same line is found as well.
ASSIGNMENT = re.compile(r"(?<![A-Za-z0-9_])" + _PREFIX + _WORDS + r"[\"'*_]*[ \t]*(?::=|=>|=(?!=)|:(?![:=]))",
                        re.IGNORECASE)
REFERENCE = re.compile(r"\$[A-Z_][A-Z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_ .-]*>"
                       r"|\{\{?[ ]*[A-Za-z_][A-Za-z0-9_. -]*[ ]*\}?\}")
SECRET_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
CODE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*"
                  r"|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+"
                  r"|[A-Za-z_][A-Za-z0-9_.]*\[.*"
                  r"|[a-z][a-z0-9]*(?:_[a-z0-9]+)+"
                  r"|[a-z]+(?:[A-Z][a-z]+)+")
PROSE_WORD = re.compile(r"[A-Za-z][a-z]*")
MASK = re.compile(r"[xX*.-]+")
PLACEHOLDERS = {
    "none", "null", "nil", "empty", "required", "optional", "provided", "redacted", "omitted", "unset",
    "unchanged", "unknown", "missing", "hidden", "masked", "rotated", "revoked", "expired", "n/a", "tbd",
    "true", "false", "yes", "no",
    "str", "string", "bytes", "int", "integer", "bool", "boolean", "number", "float", "any", "object",
    "dict", "list",
}


def literal_token(value, more_words):
    value = value.strip("*_").rstrip(",;.")
    if not value:
        return False
    if REFERENCE.fullmatch(value) or SECRET_NAME.fullmatch(value) or CODE.fullmatch(value):
        return False
    if value.lower() in PLACEHOLDERS or MASK.fullmatch(value):
        return False
    if more_words and PROSE_WORD.fullmatch(value):
        return False
    return True


def literal_quoted(value):
    """(True, value) when a quoted value, or a field's string value, is a literal. Several words are one."""
    value = value.strip()
    if not value:
        return False, ""
    if REFERENCE.fullmatch(value):
        return False, value
    if len(value.split()) > 1:
        return True, value
    return literal_token(value, False), value


def literal_value(text):
    """(True, value) when the text after an assignment to a credential name holds a literal."""
    text = text.strip()
    if text[:1] in ("\"", "'", "`"):
        end = text.find(text[0], 1)
        return literal_quoted(text[1:end] if end > 0 else text[1:])
    if not text:
        return False, ""
    if text[0] in "<{":
        end = text.find(">" if text[0] == "<" else "}")
        if end >= 0:
            candidate = text[:end + 2] if text[end + 1:end + 2] == "}" else text[:end + 1]
            if REFERENCE.fullmatch(candidate):
                return False, candidate
    words = text.split()
    return literal_token(words[0], len(words) > 1), words[0]


def find_in_text(text):
    """Return (rule, line, matched text) of the first credential in text, or None."""
    for rule, pattern in SHAPES:
        match = pattern.search(text)
        if match:
            return rule, text.count("\n", 0, match.start()) + 1, match.group(0)
    for match in ASSIGNMENT.finditer(text):
        end = text.find("\n", match.end())
        literal, value = literal_value(text[match.end():] if end < 0 else text[match.end():end])
        if literal:
            return "secret-assignment", text.count("\n", 0, match.start()) + 1, value
    return None


def begins_before(text, limit):
    """True when a credential that the detector finds anywhere in the text begins before position `limit`: an excerpt
    of the text's first `limit` characters would show part of it."""
    for _, pattern in SHAPES:
        match = pattern.search(text)
        if match and match.start() < limit:
            return True
    for match in ASSIGNMENT.finditer(text):
        if match.start() >= limit:
            break
        end = text.find("\n", match.end())
        if literal_value(text[match.end():] if end < 0 else text[match.end():end])[0]:
            return True
    return False


def find_in_value(value):
    """Walk a JSON or TOML value. Returns (where, rule) of the first credential, or None.

    `where` names the top-level field and the depth below it, never a key below the top level; a top-level
    key that holds the refused value, or is part of it, is described instead of printed."""
    found = _walk(value, None, 0)
    if found is None:
        return None
    top, depth, kind, rule, secret = found
    if top is None or kind == "top-level field name" or _overlaps(top, secret):
        name = "a top-level field"
    else:
        name = top
    if kind == "top-level field name":
        return "a top-level field name", rule
    if depth == 0 and kind == "value":
        return name, rule
    return "{} (a {} at depth {})".format(name, "field name" if kind == "field name" else "value", depth), rule


def _overlaps(key, secret):
    key, secret = key.casefold(), secret.casefold()
    return bool(secret) and (secret in key or (len(key) >= 3 and key in secret))


def _walk(value, top, depth):
    """(top-level key, depth, kind, rule, secret) of the first credential below value, or None."""
    if isinstance(value, str):
        found = find_in_text(value)
        return (top, depth, "value", found[0], found[2]) if found else None
    if isinstance(value, dict):
        child = depth + 1 if top is not None else 0
        for key, item in value.items():
            key_text = str(key)
            here = key_text if top is None else top
            found = find_in_text(key_text)
            if found:
                return (here, child, "top-level field name" if top is None else "field name", found[0], key_text)
            if isinstance(item, str) and SENSITIVE_NAME.fullmatch(key_text):
                literal, _ = literal_quoted(item)
                if literal:
                    return (here, child, "value", "secret-assignment", item)
            found = _walk(item, here, child)
            if found:
                return found
        return None
    if isinstance(value, list):
        for item in value:
            found = _walk(item, top, depth + 1)
            if found:
                return found
    return None
