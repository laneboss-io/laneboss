"""Independent checks shared by the real acceptance entry and its red controls.

Inputs are public CLI/dashboard events and independently observed sink rows.
These helpers do not create identities, change product state, or deliver mail.
"""

import hashlib


class CaseFailure(Exception):
    """An observed operation did not meet its declared acceptance rule."""


def require(condition, message):
    if not condition:
        raise CaseFailure(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_mail_copy(kept, original, content, recipient):
    fields = ("id", "sender", "recipient_life_id", "channel_grant_id",
              "content", "source", "queued_seq", "ask", "reply_to", "artifacts", "answer")
    require(all(kept.get(name) == original.get(name) for name in fields),
            "recipient changed immutable mail provenance")
    require(kept["recipient_life_id"] == recipient,
            "mail reached a different life")
    require(type(original.get("generation")) is int and original["generation"] > 0 and
            type(kept.get("generation")) is int and kept["generation"] >= original["generation"] and
            isinstance(original.get("artifacts"), list) and isinstance(kept.get("artifacts"), list),
            "mail has an invalid generation or artifact array")
    require(kept["content"]["sha256"] == digest(content) and
            kept["content"]["bytes"] == len(content),
            "recipient content differs from the original file bytes")


def verify_human_mail(mail, recipient, content):
    sender = mail["sender"]
    require(sender["kind"] == "human" and bool(sender["id"]) and
            not sender.get("life_id") and sender.get("level", 0) == 0 and
            not sender.get("role") and mail["source"] == "dashboard",
            "dashboard mail lacks its actual human sender/source")
    require(mail["recipient_life_id"] == recipient and not mail.get("channel_grant_id"),
            "human mail targets a different life or channel")
    require(mail["status"] == "queued" and type(mail["queued_seq"]) is int and
            mail["queued_seq"] > 0 and mail["content"]["sha256"] == digest(content) and
            mail["content"]["bytes"] == len(content),
            "human mail lacks the exact queued file content")
    require(type(mail.get("generation")) is int and mail["generation"] > 0 and
            isinstance(mail.get("artifacts"), list),
            "human mail lacks its committed generation or artifact array")


def verify_human_raw(raw, original):
    copies = [mail for mail in raw["messages"] if mail["id"] == original["id"]]
    require(len(copies) == 1, "human raw history omitted or duplicated the mail")
    for name in ("sender", "recipient_life_id", "content", "source", "queued_seq", "artifacts"):
        require(copies[0][name] == original[name],
                "human raw history changed mail provenance or bytes")


def matching_turns(events, mail, recipient):
    return [event for event in events
            if event["origin"] == "service" and event["kind"] == "lane.turn" and
            event["life_id"] == recipient and mail["id"] in event["payload"]["mail_ids"]]


def verify_manual_actor(events, mail, requester, recipient):
    turns = matching_turns(events, mail, recipient)
    require(bool(turns), "manual mail turn was not observed")
    for turn in turns:
        require(turn["actor"] == requester,
                "manual turn actor borrowed a carried sender")
        require(turn["requested_by"] == requester,
                "manual turn lost its original requester")
    return turns


def verify_scheduler_actor(events, mail, recipient):
    turns = matching_turns(events, mail, recipient)
    require(bool(turns), "automatic mail turn was not observed")
    for turn in turns:
        actor = turn["actor"]
        require(actor["kind"] == "scheduler" and bool(actor["id"]) and
                not actor.get("life_id") and actor.get("level", 0) == 0 and not actor.get("role"),
                "automatic turn actor borrowed a carried sender")
    return turns


def verify_delivery(events, mail, recipient):
    receipts = [event for event in events
                if event["origin"] == "service" and
                event["kind"] in ("mail.delivered", "mail.returned") and
                event["payload"]["mail_id"] == mail["id"]]
    require(len(receipts) == 1 and receipts[0]["kind"] == "mail.delivered",
            "mail lacks exactly one completed delivery receipt")
    event = receipts[0]
    receipt = event["payload"]
    target = receipt["target"]
    require(target["life_id"] == recipient and event["life_id"] == recipient and
            target["run"] == event["run"] and type(target["run"]) is int and target["run"] > 0,
            "delivery receipt targets a different life or run")
    logical = receipt["logical_turn_id"]
    require(bool(logical) and event["logical_turn_id"] == logical and
            receipt["status"] == "delivered" and receipt["prompt_status"] == "completed" and
            receipt["cause"] == "exit",
            "mail receipt does not describe completed logical delivery")
    ends = [item for item in events if item["origin"] == "service" and
            item["kind"] == "lane.ended" and item["life_id"] == recipient and
            item["run"] == target["run"] and item["logical_turn_id"] == logical]
    require(len(ends) == 1, "mail receipt lacks its exact authentic run end")
    end = ends[0]
    observed = end["payload"]["observation"]
    require(end["payload"]["reason"] == "exit" and
            end["payload"]["profile_continuation"] is False and
            observed["state"] == "exited" and observed["handle"]["target"] == target and
            type(observed.get("survivors")) is int and observed["survivors"] == 0 and
            type(observed.get("exit_code")) is int and observed["exit_code"] == 0 and
            observed.get("signal") is None and observed["prompt_status"] == "completed" and
            observed["observed_at"] == receipt["observed_at"],
            "mail receipt inferred completion from an uncertain or limited process")
    queues = [item for item in events if item["origin"] == "service" and
              item["kind"] == "mail.queued" and item["payload"]["id"] == mail["id"]]
    require(len(queues) == 1 and queues[0]["seq"] == mail["queued_seq"] and
            queues[0]["payload"]["content"] == mail["content"] and
            queues[0]["payload"]["sender"] == mail["sender"],
            "delivery lost its original immutable queue event")
    turns = [item for item in matching_turns(events, mail, recipient)
             if item["logical_turn_id"] == logical and
             mail["queued_seq"] in item["payload"]["trigger"]["causing_seqs"]]
    require(turns and all(mail["queued_seq"] < item["seq"] < end["seq"] < event["seq"] for item in turns),
            "mail receipt precedes its actual causal turn completion")
    return event


def sink_rows(rows, mail_id, content):
    result = [row for row in rows if row["mail_id"] == mail_id]
    for row in result:
        require(bool(row["channel_id"]) and bool(row["delivery_key"]) and bool(row["receipt_id"]) and
                row["content_sha256"] == digest(content),
                "channel sink lacks the actual immutable content or receipt")
    return result


def verify_channel(rows, mail_id, content, destinations):
    expected = set(destinations)
    require(expected and len(expected) == len(destinations),
            "fixture destination inventory is empty or duplicated")
    rows = sink_rows(rows, mail_id, content)
    channels = {row["channel_id"]: row for row in rows}
    require(len(rows) == len(channels), "duplicate confirmed channel delivery")
    require(set(channels) == expected, "confirmed channel destinations are missing or unexpected")
    require(len({row["delivery_key"] for row in rows}) == len(rows),
            "confirmed channel deliveries reused a delivery key")
    require(len({row["receipt_id"] for row in rows}) == len(rows),
            "confirmed channel deliveries reused a remote receipt")
    return channels


def verify_partial_retry(before, after, mail_id, content, destinations):
    expected = set(destinations)
    before = sink_rows(before, mail_id, content)
    prior = {row["channel_id"]: row for row in before}
    require(before and len(before) == len(prior) and set(prior) < expected,
            "retry control did not begin with an actual partial delivery")
    confirmed = verify_channel(after, mail_id, content, destinations)
    for channel, original in prior.items():
        require(confirmed[channel] == original,
                "retry changed an already confirmed external send")
    return confirmed
