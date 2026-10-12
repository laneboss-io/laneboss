"""A judge for the laneboss launcher that asks TypeSafe's Jev model one yes/no question.

The launcher runs a judge as a command: it writes one JSON object to standard input and reads one JSON object from
standard output. This program is the adapter for Jev. It reads the request

    {"laneboss_judge": 1, "question": "...", "kind": "noul", "prompt": "...", "subject": {"name": "text", ...}}

asks the service one Noul question (a yes/no judgment returned as the probability of yes) and prints

    {"probability": 0.93, "model": "jev-1.13.0", "request": "req_..."}

The request to the service is the one on https://docs.typesafe.ai/api.md: POST <base URL>/v1/systemone with the
bearer key and the body {"state": <the subject>, "model": <model>, "questions": {"answer": {"type": "noul",
"instructions": <the prompt>}}}; the probability is answers.answer.noul, read as the exact number the service wrote,
the model is the top-level model, and the request identifier is the response header x-typesafe-request-id. A repeated
member anywhere in the answer, and an identifier or a model that is not [A-Za-z0-9][A-Za-z0-9._:-]{0,127}, make it
no answer (an identifier alone becomes null).

Anything else is no answer: a non-zero exit status, one line on standard error and nothing on standard output.

    2  a bad request or bad options (the line names an option at most, never what was typed)
    3  a refused or unreadable key file
    4  an HTTP error, a connection that failed, an answer that cannot be read, or text that held the key
    5  a time-out
    1  a bug in this program

Nothing that holds the key's exact text is ever printed: ONE function writes to standard output and standard error, and
once the key has been read it refuses every text in which the key's value occurs (an encoded or split echo is not
seen). A key must have at least 16 characters, so that a value which could occur in an ordinary answer or in this
program's own fixed lines is never accepted as a key. A request goes over HTTPS, or over plain HTTP only to the
literal address 127.0.0.1: no name is resolved for a plain-HTTP request. The program retries nothing, writes no file
and needs only the standard library (Python 3.9 or newer). The key is read from a file of NAME=value lines that group
and others cannot access.
"""

import argparse
import decimal
import http.client
import json
import math
import os
import re
import socket
import stat
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE_URL = "https://api.typesafe.ai"
DEFAULT_MODEL = "jev-latest"
DEFAULT_KEY_NAME = "TYPESAFE_API_KEY"
DEFAULT_TIMEOUT = 8.0
MAX_TIMEOUT = 3600.0
ENDPOINT = "/v1/systemone"
REQUEST_ID_HEADER = "x-typesafe-request-id"
ANSWER_ID = "answer"
USER_AGENT = "laneboss-judge-typesafe-jev/1"
LOOPBACK = "127.0.0.1"
MIN_KEY_CHARACTERS = 16
MAX_REQUEST_BYTES = 1 << 20
MAX_RESPONSE_BYTES = 1 << 20
MAX_KEY_FILE_BYTES = 1 << 16
MAX_TEXTS = 8
MAX_TEXT_CHARACTERS = 4000
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
KEY_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,99}")
MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")
HELD = "the answer held the key and was not printed"

# What a usage error may say about a value: these fixed texts and nothing that was typed.
SECONDS = "must be a number of seconds"
RANGE = "must be above 0 and at most {:g} seconds".format(MAX_TIMEOUT)
NAME = "must be a variable name such as " + DEFAULT_KEY_NAME
MODEL = "must be a model name such as " + DEFAULT_MODEL
SPACES = "must not hold spaces or control characters"
URL = "is not a valid URL"
HTTPS = "must be an https:// URL with a host"
CREDENTIALS = "must not carry credentials, a query or a fragment"
LOCAL = "must be https:// unless the host is " + LOOPBACK
ONE = "expected one argument"
REASONS = frozenset((SECONDS, RANGE, NAME, MODEL, SPACES, URL, HTTPS, CREDENTIALS, LOCAL, ONE))


class Failure(Exception):
    """No answer: the exit status and the one line for standard error."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class Secret:
    """The key's value, once it has been read."""

    value = None


def write(descriptor, text):
    """The ONE place that writes to standard output (1) or standard error (2). A text in which the key's value occurs
    is never written: the fixed line goes to standard error instead, and True is returned. Standard error gets one
    line of at most 290 characters."""
    held = Secret.value is not None and Secret.value in text
    if held:
        descriptor, text = 2, "typesafe_jev: " + HELD
    if descriptor == 2:
        data = (" ".join(text.split())[:290] + "\n").encode("ascii", "replace")
    else:
        data = (text + "\n").encode("utf-8", "replace")
    while data:
        data = data[os.write(descriptor, data):]
    return held


def fail(code, message):
    """The failure line on standard error; returns the exit status: `code`, or 4 when the line held the key."""
    try:
        held = write(2, "typesafe_jev: " + message)
    except OSError:
        held = False
    return 4 if held else code


def reject_constant(name):
    raise ValueError("not a JSON number: " + name)


def whole_object(pairs):
    """A JSON object in which no member is repeated."""
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise ValueError("a repeated member")
    return dict(pairs)


class Parser(argparse.ArgumentParser):
    """An argument error names an option at most and never repeats what was typed."""

    def error(self, message):
        found = re.match(r"argument ([-A-Za-z0-9/]+): (.*)", message, re.DOTALL)
        if found is None:
            raise Failure(2, "usage error (see --help)")
        option, reason = found.groups()
        if reason in REASONS:
            raise Failure(2, "usage error: {} {}".format(option, reason))
        raise Failure(2, "usage error with {} (see --help)".format(option))


def timeout_value(text):
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(SECONDS)
    if not math.isfinite(value) or not 0 < value <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(RANGE)
    return value


def key_name_value(text):
    if not KEY_NAME.fullmatch(text):
        raise argparse.ArgumentTypeError(NAME)
    return text


def model_value(text):
    if not MODEL_NAME.fullmatch(text):
        raise argparse.ArgumentTypeError(MODEL)
    return text


def base_url_value(text):
    """https for any host, or http for the literal address 127.0.0.1 only (a name could resolve to another machine);
    no credentials, query or fragment."""
    if re.search(r"[\s\x00-\x1f\x7f]", text):
        raise argparse.ArgumentTypeError(SPACES)
    try:
        parts = urllib.parse.urlsplit(text)
        host = parts.hostname
        port = parts.port  # a port that is not a number or out of range raises ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(URL)
    if port == 0:
        raise argparse.ArgumentTypeError(URL)
    if parts.scheme not in ("http", "https") or not host:
        raise argparse.ArgumentTypeError(HTTPS)
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise argparse.ArgumentTypeError(CREDENTIALS)
    if parts.scheme == "http" and host != LOOPBACK:
        raise argparse.ArgumentTypeError(LOCAL)
    return text.rstrip("/")


def build_parser():
    parser = Parser(prog="typesafe_jev.py", add_help=False, allow_abbrev=False, description=(
        "Judge for the laneboss launcher: asks TypeSafe's Jev one yes/no question about the request on standard "
        "input and prints the probability of yes. Exit 2: bad request or options; 3: key file; 4: HTTP error, an "
        "answer that cannot be read, or text that held the key; 5: time-out."))
    parser.add_argument("-h", "--help", action="store_true", help="show this help and exit")
    parser.add_argument("--env-file", metavar="PATH",
                        help="required: file of NAME=value lines that holds the key; group and others must have no access")
    parser.add_argument("--key-name", default=DEFAULT_KEY_NAME, type=key_name_value, metavar="NAME",
                        help="the name of the key's line (default: %(default)s)")
    parser.add_argument("--model", default=DEFAULT_MODEL, type=model_value, metavar="MODEL",
                        help="the model or alias to ask (default: %(default)s)")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, type=base_url_value, metavar="URL",
                        help="the service's address; https unless 127.0.0.1 (default: %(default)s)")
    parser.add_argument("--timeout", default=DEFAULT_TIMEOUT, type=timeout_value, metavar="SECONDS",
                        help="seconds to wait for the service in all (default: %(default)g)")
    return parser


def parse_options(parser, arguments):
    options, unknown = parser.parse_known_args(arguments)
    if unknown:
        raise Failure(2, "unrecognized arguments (see --help)")  # not echoed: a stray argument could be the key
    return options


def bad_request(message):
    raise Failure(2, message)


def read_request():
    """The contract's request from standard input: the prompt and the named texts."""
    stream = getattr(sys.stdin, "buffer", None)
    if stream is None:
        bad_request("there is no standard input")
    data = stream.read(MAX_REQUEST_BYTES + 1)
    if len(data) > MAX_REQUEST_BYTES:
        bad_request("the request is larger than 1 MiB")
    try:
        request = json.loads(data.decode("utf-8"), parse_constant=reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        bad_request("the request is not one JSON object in UTF-8")
    if not isinstance(request, dict):
        bad_request("the request is not one JSON object")
    version = request.get("laneboss_judge")
    if type(version) is not int or version != 1:
        bad_request("laneboss_judge must be 1")
    if request.get("kind") != "noul":
        bad_request("kind must be noul")
    question = request.get("question")
    if not isinstance(question, str) or not question:
        bad_request("question must be a non-empty string")
    prompt = request.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        bad_request("prompt must be a non-empty string")
    subject = request.get("subject")
    if not isinstance(subject, dict) or not 1 <= len(subject) <= MAX_TEXTS:
        bad_request("subject must hold one to {} named texts".format(MAX_TEXTS))
    for name, text in subject.items():
        if not name:
            bad_request("a subject name is empty")
        if not isinstance(text, str):
            bad_request("every subject text must be a string")
        if len(text) > MAX_TEXT_CHARACTERS:
            bad_request("a subject text is longer than {} characters".format(MAX_TEXT_CHARACTERS))
    return prompt, subject


def read_key(path, name):
    """The key under `name` in the file at `path`. The file is opened (a link is followed) and the TARGET must be a
    regular file that group and others cannot access."""
    try:
        descriptor = os.open(os.path.expanduser(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise Failure(3, "cannot open the key file: " + (error.strerror or type(error).__name__))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise Failure(3, "the key file is not a regular file")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o077:
            raise Failure(3, "the key file has mode {:04o}: group and others must have no access (chmod 600)".format(mode))
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_KEY_FILE_BYTES:
                raise Failure(3, "the key file is larger than 64 KiB")
    except OSError as error:
        raise Failure(3, "cannot read the key file: " + (error.strerror or type(error).__name__))
    finally:
        os.close(descriptor)
    try:
        text = b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError:
        raise Failure(3, "the key file is not UTF-8 text")
    found = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export") and line[6:7].isspace():
            line = line[6:].lstrip()
        variable, separator, value = line.partition("=")
        if not separator or variable.strip() != name:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        found = value
    if found is None:
        raise Failure(3, "the key file has no line for the name given with --key-name")
    if not re.fullmatch(r"[\x21-\x7e]+", found):
        raise Failure(3, "the key's value is empty or has characters that cannot go in a header")
    if len(found) < MIN_KEY_CHARACTERS:
        raise Failure(3, "the key's value is too short to be a key")
    return found


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """The key goes to the address it was given and nowhere else: a redirect is an error."""

    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def clean_identifier(value):
    """The provider's request identifier if it is an identifier, else None."""
    if isinstance(value, str) and IDENTIFIER.fullmatch(value):
        return value
    return None


def timed_out(error):
    return isinstance(error, (socket.timeout, TimeoutError)) or "timed out" in str(error).lower()


def describe(error):
    detail = getattr(error, "strerror", None)
    return type(error).__name__ + (" ({})".format(detail) if detail else "")


def start_deadline(seconds):
    """A hard stop for the whole exchange: no single read may time out while a service sends a byte at a time, and
    a name lookup has no time-out of its own. Nothing has been written to standard output by then."""
    def expire():
        os._exit(fail(5, "timed out after {:g} seconds".format(seconds)))

    timer = threading.Timer(seconds + 0.25, expire)
    timer.daemon = True
    timer.start()
    return timer


def ask(base_url, model, key, prompt, subject, timeout):
    """One Noul question about the subject; returns the service's body and its request identifier."""
    body = {"state": subject, "model": model, "questions": {ANSWER_ID: {"type": "noul", "instructions": prompt}}}
    try:
        data = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (UnicodeEncodeError, ValueError):
        raise Failure(2, "the request holds text that cannot be sent as UTF-8")
    request = urllib.request.Request(base_url + ENDPOINT, data=data, method="POST", headers={
        "Authorization": "Bearer " + key, "Content-Type": "application/json", "Accept": "application/json",
        "User-Agent": USER_AGENT})
    handlers = [NoRedirect]
    if urllib.parse.urlsplit(base_url).hostname == LOOPBACK:
        # The loopback address is never reached through a proxy, whatever the environment says: over plain HTTP the
        # key travels in the clear and must not leave the machine. For any other host (https only) the
        # environment's proxy settings apply and the key travels inside TLS.
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    timer = start_deadline(timeout)
    try:
        with opener.open(request, timeout=timeout) as response:
            answer = response.read(MAX_RESPONSE_BYTES + 1)
            identifier = clean_identifier(response.headers.get(REQUEST_ID_HEADER))
    except urllib.error.HTTPError as error:
        identifier = clean_identifier(error.headers.get(REQUEST_ID_HEADER)) if error.headers is not None else None
        error.close()
        raise Failure(4, "the service answered HTTP {}{}".format(
            error.code, " (request {})".format(identifier) if identifier else ""))
    except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
        reason = error.reason if isinstance(error, urllib.error.URLError) else error
        if timed_out(reason) or timed_out(error):
            raise Failure(5, "the service did not answer within {:g} seconds".format(timeout))
        raise Failure(4, "cannot get an answer from the service: " + describe(reason))
    finally:
        timer.cancel()
    if len(answer) > MAX_RESPONSE_BYTES:
        raise Failure(4, "the service's answer is larger than 1 MiB")
    return answer, identifier


def read_answer(body, identifier):
    """The contract's answer from the service's body: answers.answer.noul as written (an exact decimal, checked
    against 0 and 1 before it becomes a float), the top-level model and the identifier."""
    unreadable = Failure(4, "the service's answer is not the documented one")
    try:
        value = json.loads(body.decode("utf-8"), parse_float=decimal.Decimal, parse_int=decimal.Decimal,
                           parse_constant=reject_constant, object_pairs_hook=whole_object)
    except (UnicodeDecodeError, ValueError, RecursionError, ArithmeticError):
        raise unreadable
    answers = value.get("answers") if isinstance(value, dict) else None
    answer = answers.get(ANSWER_ID) if isinstance(answers, dict) else None
    if not isinstance(answer, dict) or answer.get("type") != "noul":
        raise unreadable
    probability = answer.get("noul")
    if type(probability) is not decimal.Decimal or not 0 <= probability <= 1:
        raise unreadable
    model = value.get("model")
    if model is not None and (not isinstance(model, str) or not IDENTIFIER.fullmatch(model)):
        raise unreadable
    return {"probability": float(probability) + 0.0, "model": model, "request": identifier}


def main(arguments):
    try:
        parser = build_parser()
        options = parse_options(parser, arguments)
        if options.help:
            write(1, parser.format_help().rstrip("\n"))
            return 0
        if options.env_file is None:
            raise Failure(2, "--env-file is required (see --help)")
        prompt, subject = read_request()
        Secret.value = read_key(options.env_file, options.key_name)
        body, identifier = ask(options.base_url, options.model, Secret.value, prompt, subject, options.timeout)
        answer = read_answer(body, identifier)
    except Failure as failure:
        return fail(failure.code, failure.message)
    except Exception as error:
        return fail(1, "internal error: " + type(error).__name__)
    try:
        held = write(1, json.dumps(answer))
    except OSError:
        return fail(1, "cannot write the answer")
    return 4 if held else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
