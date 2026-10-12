"""Split supervisors' curated markdown into verbatim, content-addressed cases. Never read session transcripts."""

from datetime import datetime, timezone
from pathlib import Path
import re

from .orgcontext import Org, read_regular, recent_injections
from .schema import InvalidInput, canonical, sha256, timestamp, utc_now, validate_record

CURATED_KINDS = ("ledger", "report", "board", "bulletin")
HEADING = re.compile(r"^(#{1,6})\s+\S")
BULLET = re.compile(r"^(?:[-*+] |\d+[.)] )")
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3}(?:\d{3})?)?(?:Z|[+-]\d{2}:\d{2})")


def entries(text, kind):
    """(first line, exact text) per board line, heading section, or ledger bullet/paragraph.

    Fenced blocks belong to their containing entry. The shallowest heading below the file title starts a ledger
    or bulletin entry; reports split at each section heading. Continuations and blank lines keep their bytes.
    """
    lines = text.splitlines(keepends=True)
    if kind == "board":
        return [(number, line) for number, line in enumerate(lines, 1)
                if line.strip() and not HEADING.match(line) and not re.fullmatch(r"[\s|:\-]+", line)]
    headings, fenced, plain = [], False, []
    for index, line in enumerate(lines):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        match = None if fenced else HEADING.match(line)
        if match and len(match[1]) > 1:
            headings.append((index, len(match[1])))
        if not fenced:
            plain.append(index)
    if headings:
        depth = min(depth for _, depth in headings)
        starts = [index for index, size in headings if kind == "report" or size == depth]
    else:
        starts = [index for index in plain if BULLET.match(lines[index])]
        if not starts:
            starts = [index for index, line in enumerate(lines)
                      if line.strip() and not HEADING.match(line) and (index == 0 or not lines[index - 1].strip())]
    if not starts:
        return []
    if any(line.strip() and not HEADING.match(line) for line in lines[:starts[0]]):
        starts.insert(0, 0)
    starts.append(len(lines))
    return [(start + 1, "".join(lines[start:end])) for start, end in zip(starts, starts[1:])
            if "".join(lines[start:end]).strip()]


def case(identifier, kind, text, source, created, identity, line=1):
    source_line = text.splitlines(keepends=True)[0]
    return validate_record({
        "id": identifier, "kind": kind, "asked_at": created, "answered_at": created,
        "project": "org-history", "area": kind, "topics": [kind],
        "question": {"text": next((line for line in text.splitlines() if line.strip()), kind),
                     "background": "Curated org history"},
        "answer": {"verbatim": text, "channel": source}, "scope": {"applies_to": "This org"},
        "status": "in_force", **identity,
        "provenance": {"recorded_by": identity["instance"], "recorded_at": utc_now(),
                       "sources": [{"path": source, "line": line, "sha256_of_line": sha256(source_line),
                                    "line_text": source_line}]},
    })


def citations(store, org, text, source, created, identity):
    receipts = recent_injections(org)
    cited = set()
    moment = timestamp(created, "citation time")
    for receipt in receipts:
        if receipt.get("instance") != identity["instance"] or timestamp(receipt["at"], "injection time") > moment:
            continue
        for identifier in receipt.get("ids", []):
            if identifier not in cited and re.search(r"(?<![\w./:-])" + re.escape(identifier) + r"(?![\w./:-])", text):
                store.append_feedback(identifier, "cited", source, created)
                cited.add(identifier)
    return sorted(cited)


def ingest_records(store, org_dir, instance, path, kind="ledger"):
    org = Org(org_dir)
    org.check_store(store.connection.execute("PRAGMA database_list").fetchone()[2])
    identity, _, _ = org.instance(instance)
    text = read_regular(path)
    pieces = entries(text, kind)
    if not pieces:
        raise InvalidInput("curated file has no entries")
    source = str(Path(path).resolve())
    fallback = datetime.fromtimestamp(Path(path).stat().st_mtime, timezone.utc).isoformat(timespec="microseconds")
    records = []
    for line, content in pieces:
        found = STAMP.search(content.splitlines()[0])
        created = found[0] if found else fallback
        identifier = "C-" + sha256(canonical({"kind": kind, "instance": instance, "content": content}))
        records.append(case(identifier, kind, content, source, created, identity, line))
    added, existing, ids = 0, 0, []
    with store.history_transaction():
        for record in records:
            row = store.connection.execute("SELECT * FROM records WHERE id = ?", (record["id"],)).fetchone()
            if row is not None:
                prior = store.checked_record(row)
                if (prior["answer"]["verbatim"] != record["answer"]["verbatim"]
                        or prior.get("instance") != instance or prior.get("level") != identity["level"]
                        or prior["kind"] != kind):
                    raise InvalidInput("curated content id conflicts with a stored case")
                existing += 1
            else:
                store._insert_record(record, sha256(canonical(record)))
                added += 1
            ids.append(record["id"])
        cited = citations(store, org, text, "curated:" + source + ":" + sha256(text), fallback, identity)
    return {"rows_added": added, "rows_existing": existing, "ids": ids, "cited": cited, **identity}
