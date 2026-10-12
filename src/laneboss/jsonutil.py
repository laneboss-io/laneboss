"""Strict JSON reading, canonical JSON for hashing and ASCII-safe JSON for output."""

from decimal import Decimal
import hashlib
import json
import math
import sys

from .errors import Refused


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refused("JSON contains a duplicate field")
        value[key] = item
    return value


def _reject_constant(name):
    raise Refused("JSON must contain finite numbers")


def _exact_float(literal):
    """A number with a fraction or an exponent must survive storage unchanged; integers are always exact."""
    value = float(literal)
    if not math.isfinite(value) or Decimal(repr(value)) != Decimal(literal):
        raise Refused("a JSON number with a fraction or an exponent cannot be stored exactly (it is beyond double "
                      "precision); write it as an integer or a string")
    return value


def _bounded_int(literal):
    """Integers are kept exactly up to the interpreter's limit for converting integers to and from text
    (4300 digits by default; the installed command runs with -I, so no environment changes it)."""
    limit = sys.get_int_max_str_digits()
    if limit and len(literal.lstrip("-")) > limit:
        raise Refused("a JSON integer has more than {} digits, the most this launcher stores exactly; write it as "
                      "a string".format(limit))
    return int(literal)


def parse(text, what):
    """Parse JSON text, refusing duplicate fields, non-finite and inexact numbers, and integers beyond the
    digit limit. Never echoes the text."""
    try:
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant,
                          parse_float=_exact_float, parse_int=_bounded_int)
    except json.JSONDecodeError as error:
        raise Refused("{} is not valid JSON (line {}, column {})".format(what, error.lineno, error.colno)) from None
    except (ValueError, RecursionError):
        raise Refused(what + " is not valid JSON") from None


def canonical(value):
    """Sorted keys, no whitespace, non-ASCII kept as UTF-8: the form every stored hash covers."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def canonical_bytes(value):
    try:
        return canonical(value).encode("utf-8")
    except UnicodeEncodeError:
        raise Refused("text must be valid Unicode without unpaired surrogates") from None


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def output(value):
    """The one JSON value a command prints on stdout."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False)
