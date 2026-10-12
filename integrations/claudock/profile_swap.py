#!/usr/bin/env python3
"""Select Claudock quota and resume the same Claude Code history on another profile.

Python 3.11 standard library only. No profile names or credentials are stored here.
See docs/claudock.md#profile-swap for the supervisor loop and message sources.
"""
import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


WRAPPER = "/Applications/Claudock.app/Contents/MacOS/claudock"
HEADER = ("PROFILE", "PLAN", "WINDOW", "USED_PERCENT", "RESETS_UTC")
DEFAULT_PROMPT = "Continue the same session from where it stopped."
SGR = re.compile(r"\x1b\[[0-9;]*m")
# Claude Code's own quota messages, matched as whole lines. Sources and supported
# suffixes are listed individually in docs/claudock.md, under Profile swap.
LIMIT_PATTERNS = (
    re.compile(r"You['’]ve hit your (?:limit|usage limit|session limit|weekly limit|Opus limit|Sonnet limit)"
               r"(?:[.!]| · (?:resets|limit resets) [^\r\n]+)?(?: · progress saved)?"),
    re.compile(r"Usage limit reached(?: · limit resets [^\r\n]+)?"),
)


class SwapError(Exception):
    """A local or vendor-input problem, reported with exit 2."""


class NoProfile(Exception):
    """Quota is unavailable under this policy, reported with exit 3."""


@dataclass(frozen=True)
class Settings:
    exclude: tuple[str, ...] = ()
    max_used_percent: float = 85
    prefer: tuple[str, ...] = ()
    include_console: bool = False


@dataclass(frozen=True)
class Window:
    used: float
    reset: datetime | None


@dataclass(frozen=True)
class Profile:
    name: str
    windows: tuple[Window, ...]
    plan: str

    @property
    def is_console(self):
        return self.plan == "Console API"

    @property
    def tightest(self):
        return max(window.used for window in self.windows)

    def free_at(self, threshold):
        # All windows at/above the threshold must reset before this profile qualifies.
        blocked = [window for window in self.windows if window.used >= threshold]
        if threshold == 0 or not blocked or any(window.reset is None for window in blocked):
            return None
        return max(window.reset for window in blocked)


def profile_name(value):
    if (not isinstance(value, str) or not value.strip() or value.startswith("-")
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)):
        raise ValueError("profile names must be nonempty, contain no controls, and not start with '-'")
    return value


def percentage(value):
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("percentage must be a finite number from 0 to 100") from None
    if isinstance(value, bool) or not math.isfinite(number) or not 0 <= number <= 100:
        raise ValueError("percentage must be a finite number from 0 to 100")
    return number


def max_age(value):
    try:
        number = float(value)
    except (ValueError, OverflowError):
        raise ValueError("max age must be a finite nonnegative number of seconds") from None
    if not math.isfinite(number) or number < 0:
        raise ValueError("max age must be a finite nonnegative number of seconds")
    return number


def names_setting(document, key):
    values = document.get(key, [])
    if not isinstance(values, list):
        raise SwapError(f"settings {key} must be an array of profile names")
    try:
        names = tuple(profile_name(value) for value in values)
    except ValueError as error:
        raise SwapError(f"settings {key}: {error}") from None
    if len(set(names)) != len(names):
        raise SwapError(f"settings {key} must not repeat a profile name")
    return names


def read_settings(filename, override, include_console):
    document = {}
    if filename is not None:
        try:
            with Path(filename).expanduser().open("rb") as handle:
                document = tomllib.load(handle)
        except (OSError, ValueError) as error:
            # Do not echo a TOML line, which could contain the user's private data.
            raise SwapError("cannot read settings as TOML") from error
    if set(document) - {"exclude", "max_used_percent", "prefer", "include_console"}:
        raise SwapError("settings contain an unknown key")
    configured = document.get("max_used_percent", 85)
    if isinstance(configured, bool) or not isinstance(configured, (int, float)):
        raise SwapError("settings max_used_percent must be a number from 0 to 100")
    try:
        threshold = percentage(configured)
    except ValueError as error:
        raise SwapError(f"settings max_used_percent: {error}") from None
    configured_console = document.get("include_console", False)
    if not isinstance(configured_console, bool):
        raise SwapError("settings include_console must be true or false")
    return Settings(names_setting(document, "exclude"), threshold if override is None else override,
                    names_setting(document, "prefer"), configured_console or include_console)


def wrapper_path():
    path = shutil.which("claudock")
    if path is not None:
        return str(Path(path).resolve())
    if os.path.isfile(WRAPPER) and os.access(WRAPPER, os.X_OK):
        return WRAPPER
    raise SwapError("claudock is not executable on PATH or at its macOS app path")


def reset_time(value):
    if value in ("", "-", "—", "unknown"):
        return None
    try:
        reset = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if reset.tzinfo is None or reset.utcoffset() is None:
            raise ValueError("missing time zone")
        return reset.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise SwapError("claudock usage has an invalid reset time; expected an ISO timestamp with a time zone") from None


def parse_usage(text):
    lines = text.splitlines()
    if not lines or tuple(lines[0].split("\t")) != HEADER:
        raise SwapError("claudock usage has an invalid TSV header")
    windows = {}
    plans = {}
    now = datetime.now(timezone.utc)
    for line_number, line in enumerate(lines[1:], 2):
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != len(HEADER):
            raise SwapError(f"claudock usage row {line_number} must have five TSV columns")
        name, plan, window, used_text, reset_text = fields
        try:
            profile_name(name)
            used = float(used_text.removesuffix("%"))
        except (ValueError, OverflowError):
            raise SwapError(f"claudock usage row {line_number} has an invalid profile or percentage") from None
        if not plan or not window or not math.isfinite(used) or used < 0:
            raise SwapError(f"claudock usage row {line_number} has an invalid window or percentage")
        if name in plans and plans[name] != plan:
            raise SwapError(f"claudock usage row {line_number} has inconsistent profile plan values")
        plans[name] = plan
        reset = reset_time(reset_text)
        effective = 0 if reset is not None and reset <= now else used
        windows.setdefault(name, []).append(Window(effective, reset))
    return [Profile(name, tuple(readings), plans[name]) for name, readings in windows.items()]


def read_usage(wrapper, age, directory):
    argv = [wrapper, "usage"]
    if age is not None:
        argv += ["--max-age", f"{age:g}"]
    try:
        done = subprocess.run(argv, cwd=directory, stdin=subprocess.DEVNULL, capture_output=True,
                              encoding="utf-8", timeout=60)
    except subprocess.TimeoutExpired:
        raise SwapError("claudock usage did not finish within 60 seconds") from None
    except (OSError, UnicodeError):
        raise SwapError("cannot run or decode claudock usage") from None
    if done.returncode != 0:
        raise SwapError(f"claudock usage failed (exit {done.returncode}); no profile selected")
    # Claudock may return cached data while cooling down; exit 0 is still a reading.
    return parse_usage(done.stdout)


def utc_text(value):
    return value.isoformat().replace("+00:00", "Z")


def choose(profiles, settings, excluded):
    eligible = [profile for profile in profiles if profile.name not in excluded]
    billing_note = ""
    if not settings.include_console:
        console_count = sum(profile.is_console for profile in eligible)
        eligible = [profile for profile in eligible if not profile.is_console]
        if console_count:
            billing_note = (f"; Console API profiles excluded: {console_count} (per-token billing; "
                            "opt in with --include-console or include_console = true)")
    preference = {name: index for index, name in enumerate(settings.prefer)}

    def rank(profile):
        # Vendor ordering: subscriptions before billed Console profiles. USED_PERCENT
        # on a Console row is spent credit share, so lower usage means more credit share left.
        return profile.is_console, profile.tightest, preference.get(profile.name, len(preference)), profile.name

    ready = [profile for profile in eligible if profile.tightest < settings.max_used_percent]
    if ready:
        return min(ready, key=rank)
    prefix = f"no profile under {settings.max_used_percent:g}%: next to free up is "
    if not eligible:
        raise NoProfile(prefix + "none at unknown (no eligible profiles)" + billing_note)
    # Known estimates sort first; unknown resets retain the reported usage and never
    # invent a time. The estimate assumes no further usage before the reset.
    estimates = [(profile.free_at(settings.max_used_percent), profile) for profile in eligible]
    reset, profile = min(estimates, key=lambda item: (
        item[0] is None, item[0] or datetime.max.replace(tzinfo=timezone.utc), rank(item[1])))
    raise NoProfile(prefix + profile.name + " at " + (utc_text(reset) if reset is not None else "unknown") + billing_note)


def message_texts(line):
    """Plain output, or message fields of a headless error record; never arbitrary JSON values."""
    clean = SGR.sub("", line).strip()
    if not clean.startswith("{"):
        return [clean]
    try:
        event = json.loads(clean)
    except (ValueError, RecursionError):
        return []
    if not isinstance(event, dict):
        return []
    if event.get("type") == "result" and event.get("is_error") is True:
        messages = [event["result"]] if isinstance(event.get("result"), str) else []
        errors = event.get("errors")
        if isinstance(errors, list):
            messages.extend(error for error in errors if isinstance(error, str))
        return messages
    if event.get("type") == "assistant" and event.get("error") == "rate_limit":
        message = event.get("message")
        blocks = message.get("content") if isinstance(message, dict) else None
        if isinstance(blocks, list):
            return [block["text"] for block in blocks if isinstance(block, dict)
                    and block.get("type") == "text" and isinstance(block.get("text"), str)]
    return []


def is_limit(line):
    return any(pattern.fullmatch(SGR.sub("", part).strip()) is not None
               for message in message_texts(line) for part in message.splitlines()
               for pattern in LIMIT_PATTERNS)


def limited(filename):
    found = False
    try:
        with Path(filename).expanduser().open(encoding="utf-8") as handle:
            for line in handle:
                if is_limit(line):
                    found = True
    except (OSError, UnicodeError):
        raise SwapError("cannot read log as UTF-8") from None
    return 0 if found else 1


def selection_options(parser):
    parser.add_argument("--exclude", metavar="NAME", type=profile_name, action="append", default=[],
                        help="Never use this profile; repeat to exclude more (also reads settings exclusions).")
    parser.add_argument("--settings", metavar="FILE",
                        help="User TOML with exclude, max_used_percent, prefer and include_console.")
    parser.add_argument("--max-used", metavar="PCT", type=percentage,
                        help="Require every active window to be strictly below PCT (settings, else 85).")
    parser.add_argument("--max-age", metavar="S", type=max_age,
                        help="Pass this cache age to claudock usage; otherwise use Claudock's default.")
    parser.add_argument("--include-console", action="store_true",
                        help="Opt in to per-token Console API billing; subscriptions still rank first.")


def parser():
    cli = argparse.ArgumentParser(description="Move the same Claude Code session between Claudock profiles.",
                                  epilog="Claudock profiles must share history. The cross-provider resume guard stays enabled.")
    commands = cli.add_subparsers(dest="command", required=True)
    pick = commands.add_parser("pick", help="Print the profile with the most quota headroom.")
    selection_options(pick)
    resume = commands.add_parser("resume", help="Resume the same session on a profile other than --from.",
                                 epilog="After --, CLAUDE_ARGS go unchanged to Claude Code. --continue resumes the newest "
                                        "session in --cwd and needs one session per directory. No cross-provider override is added.")
    identity = resume.add_mutually_exclusive_group(required=True)
    identity.add_argument("--session", metavar="ID", help="Resume this existing Claude Code session id.")
    identity.add_argument("--continue", dest="continue_session", action="store_true",
                          help="Resume the newest session; needs one session per directory.")
    resume.add_argument("--from", dest="from_profile", metavar="NAME", type=profile_name, required=True,
                        help="The profile used by the stopped request; always excluded.")
    resume.add_argument("--cwd", metavar="DIR", help="Session directory (default: current directory).")
    selection_options(resume)
    resume.add_argument("--prompt", metavar="TEXT", default=DEFAULT_PROMPT,
                        help=f"Continuation prompt (default: {DEFAULT_PROMPT})")
    resume.add_argument("--dry-run", action="store_true",
                        help="Read usage and print exact argv/cwd as JSON, without starting Claude.")
    detect = commands.add_parser("limited", help="Exit 0 for a recognized usage/session-limit log, 1 otherwise.")
    detect.add_argument("log", metavar="LOG", help="UTF-8 claude -p text or JSONL log; unreadable input exits 2.")
    return cli


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    cli = parser()
    # Split the explicit vendor-argument boundary ourselves, so wrapper options
    # remain parseable anywhere before it and unknown options cannot slip through.
    boundary = arguments.index("--") if "--" in arguments else len(arguments)
    args = cli.parse_args(arguments[:boundary])
    claude_args = arguments[boundary + 1:]
    if boundary < len(arguments) and args.command != "resume":
        cli.error("only resume accepts -- CLAUDE_ARGS")
    try:
        if args.command == "limited":
            return limited(args.log)
        settings = read_settings(args.settings, args.max_used, args.include_console)
        excluded = set(settings.exclude) | set(args.exclude)
        directory = Path.cwd()
        if args.command == "resume":
            excluded.add(args.from_profile)
            if args.session is not None and (not args.session.strip() or args.session.startswith("-")):
                raise SwapError("session id must be nonempty and must not start with '-'")
            try:
                directory = Path(args.cwd or directory).expanduser().resolve(strict=True)
            except (OSError, RuntimeError):
                raise SwapError("session directory cannot be resolved") from None
            if not directory.is_dir():
                raise SwapError("session directory is not a directory")
        wrapper = wrapper_path()
        profiles = read_usage(wrapper, getattr(args, "max_age", None), directory)
        chosen = choose(profiles, settings, excluded)
        if args.command == "pick":
            print(chosen.name)
            return 0
        reason = (f"Console API opt-in; {100 - chosen.tightest:g}% credit left; most credit share left"
                  if chosen.is_console else "most room left among subscription profiles")
        print(f"profile_swap: resuming from {args.from_profile} on {chosen.name}: "
              f"tightest window {chosen.tightest:g}% used (< {settings.max_used_percent:g}%); {reason}",
              file=sys.stderr, flush=True)
        run_argv = [wrapper, "run", chosen.name, "--", "-p"]
        run_argv += ["-c"] if args.continue_session else ["--resume", args.session]
        run_argv += [args.prompt, *claude_args]
        if args.dry_run:
            print(json.dumps({"argv": run_argv, "cwd": str(directory)}, ensure_ascii=False))
            return 0
        os.chdir(directory)
        # Replacing this process preserves the wrapper's exit status and signals.
        os.execv(wrapper, run_argv)
    except NoProfile as error:
        print(str(error), file=sys.stderr)
        return 3
    except SwapError as error:
        print(f"profile_swap: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("profile_swap: cannot access directory or start Claudock", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("profile_swap: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
