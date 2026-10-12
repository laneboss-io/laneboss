"""The resource stand-in adapter: the program a resource test names as a configuration's `command`.

It stands in for a cloud that a test machine cannot reach, so that the launcher's own half of the resource model can
be driven end to end against a program that answers the adapter contract (docs/architecture.md, "The adapter
contract"). It is run as `python3 -I tests/e2e/resourcestandin.py --config <adapter-toml>`; it reads its configuration
from that file, one JSON request from its standard input to its end, and writes one JSON answer to its standard output
followed by one newline and nothing else. It serves the three operations, `acquire`, `describe` and `release`, and
exits 0 for every answer of the contract. It exits non-zero, with nothing on its standard output, for a request it
cannot serve at all (an unknown operation, a kind it does not serve, a contract version that is not the whole number 1,
an id that is not `rs-` and 24 lower-case hex digits, which it would use as a file name) and for a provider it cannot
look at (a file or a directory that cannot be read, other than one that is not there): it gives no answer then, and
never `absent`.

It keeps its "provider" in the directory its configuration names (`provider_dir`): one small file for each resource,
named by the request's id, holding the provider's id, the start time, the state, and the size and region it was asked
for (and the end time once it ends). Each file is written whole through a temporary name of its own in the same
directory (so that two writers of one id never share a name) and renamed into place, so a reader never sees a half
file; the temporary name is removed if its write fails.

In the file beside that directory that its configuration names (`record_file`) it appends one line for every request,
before the request is checked, so that a request it cannot serve is recorded too. The line is a JSON object with three
members. `request_text` is the text read from its standard input to its end, exactly as it was received: its member
order, its separators, its line framing, its final newline, its escapes and any repeated member are kept, so that a test
can see them. `request` is the value that this text parses to (a repeated member is kept once, as its last value).
`environment` holds the names and values of the variables in its own environment as its interpreter holds them once
started (so a variable that the interpreter adds, such as `LC_CTYPE`, is there too). Together they let a test read
what the program was given. It reads its identity only from the request's `profile` and its own configuration, never
from a default of the machine it runs on.
"""

import datetime
import json
import os
import re
import sys
import tempfile
import tomllib

OPERATIONS = ("acquire", "describe", "release")
KINDS = ("machine", "credential")
IDENTIFIER = re.compile(r"rs-[0-9a-f]{24}")


def option(arguments, name):
    """The argument after NAME, or None when it is absent."""
    return arguments[arguments.index(name) + 1] if name in arguments else None


def stamp(value):
    """VALUE as a timestamp in the grammar of the envelope's `occurred_at` (UTC, milliseconds, `Z`)."""
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + "{:03d}Z".format(value.microsecond // 1000)


def now():
    """The current time, in `stamp`'s grammar."""
    return stamp(datetime.datetime.now(datetime.timezone.utc))


def after(seconds):
    """`now`, SECONDS later, in `stamp`'s grammar."""
    return stamp(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=seconds))


def provider_path(config, identifier):
    return os.path.join(config["provider_dir"], identifier)


def read_provider(config, identifier):
    """The provider file for IDENTIFIER as a dict, or None when there is none (or the directory is not there). A
    provider that cannot be read for any other reason (a permission, a directory that is a file, an I/O error) is not
    "none": the error ends the program, which then gives no answer, because an adapter that cannot look never says that
    it looked and found nothing."""
    try:
        with open(provider_path(config, identifier), "rb") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None


def write_provider(config, identifier, resource):
    """Write RESOURCE whole through a temporary name of its own in the provider directory and rename it into place;
    the temporary name is removed if the write fails."""
    directory = config["provider_dir"]
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=identifier + ".", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(resource, handle, sort_keys=True)
        os.replace(temporary, provider_path(config, identifier))
    except BaseException:
        os.unlink(temporary)
        raise


def record(config, request, text):
    """Append one line to the record file: the request's TEXT as it was received, the REQUEST value that it parses to,
    and the names and values of this environment."""
    line = {"request_text": text, "request": request, "environment": dict(os.environ)}
    with open(config["record_file"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, sort_keys=True) + "\n")


def quote(config, request):
    """The quote: the size and region of the request, or the configuration's when they are null, and the price."""
    size = request["size"] if request["size"] is not None else config.get("size")
    region = request["region"] if request["region"] is not None else config.get("region")
    return {"state": "quoted", "size": size, "region": region,
            "price_per_hour_micros": config["price_per_hour_micros"], "currency": config["currency"],
            "price_source": config["price_source"]}


def acquire(config, request):
    """A quote when `dry_run` is true; otherwise the resource, created once and answered the same on a repeat."""
    if request["dry_run"]:
        return quote(config, request)
    identifier = request["id"]
    resource = read_provider(config, identifier)
    if resource is None:
        resource = {"provider_id": "provider-" + identifier[3:], "started_at": now(), "state": "running",
                    "ended_at": None,
                    "size": request["size"] if request["size"] is not None else config.get("size"),
                    "region": request["region"] if request["region"] is not None else config.get("region")}
        write_provider(config, identifier, resource)
    return {"state": "acquired", "provider_id": resource["provider_id"], "started_at": resource["started_at"]}


def describe(config, request):
    """What the provider shows for the id: `running`, `terminated` once it has ended, or `absent`."""
    resource = read_provider(config, request["id"])
    if resource is None:
        return {"state": "absent"}
    if resource["ended_at"] is not None and resource["ended_at"] <= now():
        return {"state": "terminated", "provider_id": resource["provider_id"], "provider_state": "terminated",
                "started_at": resource["started_at"], "ended_at": resource["ended_at"]}
    state = "ending" if resource["ended_at"] is not None else "running"
    return {"state": "running", "provider_id": resource["provider_id"], "provider_state": state,
            "started_at": resource["started_at"]}


def release(config, request):
    """Mark the resource as ending (at once, or `end_after_seconds` later) and answer `releasing`, always."""
    identifier = request["id"]
    resource = read_provider(config, identifier)
    if resource is not None and resource["ended_at"] is None:
        delay = config.get("end_after_seconds") or 0
        resource["ended_at"] = after(delay)
        resource["state"] = "ending" if delay > 0 else "ended"
        write_provider(config, identifier, resource)
    return {"state": "releasing"}


def answer(config, request):
    operation = request["operation"]
    if operation == "acquire":
        return acquire(config, request)
    if operation == "describe":
        return describe(config, request)
    return release(config, request)


def servable(request):
    """Whether this program serves REQUEST: the version of the contract is the whole number 1 (not true, and not 1.0,
    which Python treats as equal to 1), the operation and the kind are ones it has, and the id is of the contract's
    form, which matters because the id is used as a file name."""
    version = request.get("laneboss_resource")
    identifier = request.get("id")
    return (type(version) is int and version == 1
            and request.get("operation") in OPERATIONS and request.get("kind") in KINDS
            and isinstance(identifier, str) and IDENTIFIER.fullmatch(identifier) is not None)


def main(argv):
    path = option(argv, "--config")
    if path is None:
        sys.stderr.write("resourcestandin: --config is required\n")
        return 2
    with open(path, "rb") as handle:
        config = tomllib.load(handle)
    text = sys.stdin.buffer.read().decode("utf-8")
    request = json.loads(text)
    record(config, request, text)
    if not servable(request):
        sys.stderr.write("resourcestandin: cannot serve this request\n")
        return 2
    sys.stdout.write(json.dumps(answer(config, request)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
