"""Outside measurements for secrets; receipts alone never imply collection."""

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import time
import stat
import subprocess


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def variants(canaries):
    result = []
    for value in canaries.values():
        require(isinstance(value, bytes) and len(value) >= 32, "short secrecy canary")
        result.extend((value, base64.b64encode(value), value.hex().encode()))
    return result


def no_values(data, hidden):
    return not any(value in data for value in hidden)


def archive_values(raw, hidden):
    require(raw and no_values(raw, hidden), "archive discloses a canary")
    count, total = 0, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
        for member in archive:
            count += 1
            require(count <= 100000 and not member.name.startswith("/") and
                    ".." not in Path(member.name).parts, "invalid archive inventory")
            require(no_values(member.name.encode(), hidden), "archive name discloses a canary")
            if member.isfile():
                total += member.size
                require(member.size <= 67108864 and total <= 268435456, "archive exceeds its bound")
                with archive.extractfile(member) as stream:
                    require(no_values(stream.read(), hidden), "archive member discloses a canary")
    require(count > 0, "archive is empty")
    return count


def event_pages(read, target, config):
    """read is the installed human-authorized public RPC, not a store reader."""
    cursor, seen, by_id, by_seq, retained = "", set(), {}, {}, []
    deadline = time.monotonic() + 120
    while True:
        require(time.monotonic() < deadline, "event pagination deadline")
        request = dict(target, since=0, cursor=cursor, follow=False, until="", deadline_ms=1000)
        page = read("event.tail", request)
        require(isinstance(page.get("events"), list), "actual event page is missing")
        retained.append({"request": request, "response": page})
        for event in page["events"]:
            require(event.get("schema") == 2 and event.get("config") == config and
                    event.get("life_id") == target["life_id"] and event.get("run") == target["run"] and
                    type(event.get("seq")) is int and event["seq"] > 0 and event.get("id"),
                    "event page contains a foreign or uncorrelated record")
            identifier, sequence = event["id"], event["seq"]
            require(identifier not in by_id and sequence not in by_seq, "event page replays an identity or sequence")
            by_id[identifier], by_seq[sequence] = event, identifier
        if page.get("complete") is True:
            break
        following = page.get("cursor")
        require(isinstance(following, str) and following and following not in seen, "event cursor did not advance")
        seen.add(following)
        cursor = following
    events = sorted(by_id.values(), key=lambda event: event["seq"])
    require(events, "actual event inventory is empty")
    return events, retained


def blob(read, reference):
    require(type(reference.get("bytes")) is int and 0 < reference["bytes"] <= 67108864,
            "primary object has no bounded bytes")
    raw = bytearray()
    while len(raw) < reference["bytes"]:
        chunk = read("blob.read", {"object_id": reference["id"], "offset": len(raw),
                                  "limit": min(262144, reference["bytes"] - len(raw))})
        part = base64.b64decode(chunk["data"], validate=True)
        require(chunk.get("object_id") == reference["id"] and chunk.get("offset") == len(raw) and
                part and len(part) <= reference["bytes"] - len(raw) and sha(part) == chunk.get("sha256"),
                "primary blob chunk differs from its exact reference")
        raw.extend(part)
    require(sha(raw) == reference["sha256"], "primary object digest differs")
    end = read("blob.read", {"object_id": reference["id"], "offset": len(raw), "limit": 1})
    require(end.get("object_id") == reference["id"] and end.get("offset") == len(raw) and
            base64.b64decode(end["data"], validate=True) == b"" and end.get("sha256") == sha(b""),
            "primary object has no authentic exact end")
    return bytes(raw)


def primary(read, events, target, operation, stream="stdout"):
    launches = [event for event in events if event.get("kind") in {"lane.started", "lane.resumed"} and
                event.get("operation_id") == operation["id"] and
                event.get("life_id") == target["life_id"] and event.get("run") == target["run"]]
    require(len(launches) == 1, "primary capture has no exact actual launch")
    chunks = [event["payload"] for event in events if event.get("kind") == "capture.appended" and
              event.get("origin") == "service" and event.get("payload", {}).get("primary") is True and
              event["payload"].get("target") == target and event["payload"].get("stream") == stream]
    require(chunks, "outside primary capture is missing")
    chunks.sort(key=lambda chunk: chunk["offset"])
    binding, raw = chunks[0].get("binding_id"), bytearray()
    require(binding, "primary capture has no installed binding")
    for chunk in chunks:
        require(chunk.get("binding_id") == binding and chunk.get("offset") == len(raw),
                "primary capture is mixed, overlapping or incomplete")
        raw.extend(blob(read, chunk["data"]))
        require(len(raw) <= 16777216, "primary capture exceeds its bound")
    return bytes(raw), launches[0]["payload"]


def probe_verdicts(capture):
    rows = [json.loads(line) for line in capture.splitlines() if line.strip()]
    require(len(rows) == 4 and all(set(row) == {"name", "ok"} and type(row["ok"]) is bool for row in rows) and
            {row["name"] for row in rows} == {"env", "file", "undelegated", "reserved"},
            "actual probe output is not names-only")
    return {row["name"]: row["ok"] for row in rows}


def process(pid):
    try:
        raw = (Path("/proc") / str(pid) / "stat").read_bytes()
    except FileNotFoundError:
        return None
    fields = raw[raw.rfind(b")") + 2:].split()
    require(len(fields) > 19 and fields[19].isdigit(), "process generation is unknown")
    return {"pid": pid, "start_time": fields[19].decode()}


def uid_processes(uid):
    require(type(uid) is int and uid > 0, "owned lane UID is missing")
    found = []
    # Read kernel identity metadata only; never read cmdline or environ.
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            rows = (entry / "status").read_bytes().splitlines()
        except (FileNotFoundError, ProcessLookupError):
            continue
        selected = [row.split()[1:] for row in rows if row.startswith(b"Uid:")]
        require(len(selected) == 1 and len(selected[0]) == 4, "process UID inventory is unknown")
        if uid in [int(value) for value in selected[0]]:
            observed = process(int(entry.name))
            if observed is not None:
                found.append(observed)
    return found


def release(events, target):
    records = [event for event in events if event.get("kind") == "helper.released" and
               event.get("origin") == "service" and
               event.get("payload", {}).get("quiescence", {}).get("handle", {}).get("target") == target]
    require(records, "helper release measurement is missing")
    for event in records:
        payload = event["payload"]
        measured = payload["quiescence"]
        require(measured.get("state") == "exited" and type(measured.get("survivors")) is int and
                measured["survivors"] == 0 and all(type(payload.get(key)) is int and payload[key] == 0
                for key in ("live_connections", "queued_jobs", "writable_exports")),
                "helper release has unknown or surviving resources")
        require(payload.get("operation_id") == event.get("operation_id") and
                payload.get("containment_id") == measured.get("handle", {}).get("containment_id") and
                any(row.get("kind") == "helper.allocated" and row.get("origin") == "service" and
                    row.get("payload", {}).get("id") == payload.get("lease_id") and
                    row.get("payload", {}).get("containment_id") == payload.get("containment_id") for row in events),
                "helper release is not correlated with its allocated lease")
    return records


class Containment:
    """Take an initial inventory while the actual target is still running."""

    def __init__(self, root, target, uid, cgroup, paths):
        self.root, self.target, self.uid = Path(root), target, uid
        self.cgroup = Path(cgroup)
        require(self.cgroup.is_absolute() and self.cgroup.resolve() == self.cgroup,
                "noncanonical containment path")
        require(self.cgroup.is_relative_to(Path("/sys/fs/cgroup")) and any(
            " - cgroup2 " in line and line.split()[4] == "/sys/fs/cgroup"
            for line in Path("/proc/self/mountinfo").read_text().splitlines()),
            "containment is not on the actual cgroup-v2 filesystem")
        self.initial = uid_processes(uid)
        require(self.initial, "owned process inventory is empty")
        require(self.members(), "actual containment inventory is empty")
        self.paths = []
        for relative in paths:
            path = self.root / relative
            require(not Path(relative).is_absolute() and ".." not in Path(relative).parts and
                    path.resolve().is_relative_to(self.root.resolve()) and not path.is_symlink() and path.exists(),
                    "runtime resource was not independently present")
            self.paths.append(relative)
        require(self.paths, "runtime resource inventory is empty")

    def members(self):
        raw = (self.cgroup / "cgroup.procs").read_text(encoding="ascii")
        pids = raw.split()
        require(all(value.isdecimal() and int(value) > 1 for value in pids), "invalid native process inventory")
        return [int(value) for value in pids]

    def collect(self, events):
        release(events, self.target)
        require(not uid_processes(self.uid), "owned containment is not quiescent")
        if self.cgroup.exists():
            require(not self.members(), "owned containment is not quiescent")
            state = dict(line.split() for line in (self.cgroup / "cgroup.events").read_text(encoding="ascii").splitlines())
            require(state.get("populated") == "0", "kernel containment is still populated")
        for old in self.initial:
            now = process(old["pid"])
            require(now is None or now["start_time"] != old["start_time"], "an old process generation survived")
        for relative in self.paths:
            require(not os.path.lexists(self.root / relative), "runtime resource survived collection")
        return {"state": "exited", "survivors": 0, "processes": self.initial, "removed_paths": self.paths}


def protected(path, maximum=16777216, owner=0):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, "noncanonical native evidence path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_nlink == 1 and
                not before.st_mode & 0o022 and 0 < before.st_size <= maximum, "unprotected native evidence")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(raw) == before.st_size and before.st_size == after.st_size and
                before.st_mtime_ns == after.st_mtime_ns, "native evidence changed during read")
        return raw


def planned_child(context, target, facts, journal, task_sha256):
    """Reject host answers before inspecting the matching native generation."""
    lease = journal["lease"]
    require(facts.get("Schema") == "laneboss.secret-native.v1" and facts.get("Config") == context["config"] and
            facts.get("LifeID") == target["life_id"] and facts.get("Run") == target["run"] and
            facts.get("UID") == lease["uid"] and facts.get("GID") == lease["gid"] and
            facts.get("UID") != os.geteuid() and facts.get("UID") != 0,
            "probe was answered from the observer host identity")
    require(facts.get("MountNS") != os.readlink("/proc/self/ns/mnt") and
            facts.get("PIDNS") != os.readlink("/proc/self/ns/pid"), "probe was answered from the observer host namespaces")
    spec = journal["spec"]["handoff"]["spec"]
    require(spec["target"] == target and facts.get("ExecutableSHA") == spec["runner"]["executable"]["sha256"] and
            facts.get("TaskSHA") == task_sha256 and facts.get("PromptSHA") == spec["runner"]["prompt"]["sha256"],
            "probe differs from the actually planned confined runtime")
    return lease


def native_child(context, target, facts, journal, task_sha256):
    """Join child stdout/stderr to actual helper ownership and /proc facts."""
    lease = planned_child(context, target, facts, journal, task_sha256)
    matches = []
    for observed in uid_processes(lease["uid"]):
        path = Path("/proc") / str(observed["pid"])
        if observed["start_time"] != facts["StartTime"]:
            continue
        if (os.readlink(path / "ns/mnt") == facts["MountNS"] and os.readlink(path / "ns/pid") == facts["PIDNS"] and
                sha((path / "exe").read_bytes()) == facts["ExecutableSHA"]):
            matches.append(observed)
    require(len(matches) == 1, "actual probe process generation is absent or ambiguous")
    mountinfo = (Path("/proc") / str(matches[0]["pid"]) / "mountinfo").read_bytes()
    require(sha(mountinfo) == facts.get("MountInfoSHA"), "child mount inventory differs from the kernel observer")
    membership = (Path("/proc") / str(matches[0]["pid"]) / "cgroup").read_text()
    require(any(line == "0::/system.slice/laneboss-helper@" + context["config"] + ".service/lanes/" + lease["containment_id"]
                for line in membership.splitlines()), "probe escaped its actual helper containment")
    return matches[0]


def retained_binding(context, target, facts, journal, inventory, task_sha256):
    """Recheck the retained root journal after the physical runtime is gone."""
    lease = planned_child(context, target, facts, journal, task_sha256)
    expected = Path("/var/lib/laneboss-v2/lanes") / context["config"] / lease["id"]
    require(lease["id"] == inventory["lease_id"] and inventory["target"] == target and
            inventory["uid"] == lease["uid"], "retained probe belongs to another native lease")
    require(str(expected) == inventory["runtime_root"], "retained probe selected another runtime root")
    witness = inventory["witness"]
    require(witness in inventory["processes"] and witness["start_time"] == facts["StartTime"],
            "retained probe has no measured native process generation")
    return lease


def mount_excludes(pid, paths):
    expected = set()
    for path in paths:
        info = Path(path).stat()
        expected.add((info.st_dev, info.st_ino))
    root = Path("/proc") / str(pid) / "root"
    lines = (Path("/proc") / str(pid) / "mountinfo").read_text().splitlines()
    require(lines and len(lines) <= 10000, "actual child mount inventory is missing or oversized")
    for line in lines:
        fields = line.split()
        require(len(fields) >= 10, "actual child mount inventory is malformed")
        target = fields[4].replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
        require(target.startswith("/") and ".." not in Path(target).parts, "native mount target escapes its namespace")
        try:
            info = (root / target.lstrip("/")).stat()
        except FileNotFoundError:
            continue
        require((info.st_dev, info.st_ino) not in expected, "child mounted an undelegated native registry or key source")
    return {"mountinfo_sha256": sha((Path("/proc") / str(pid) / "mountinfo").read_bytes()), "outside_objects": len(expected)}


class NativeView:
    """Outside reader: all paths are derived from protected installation data."""

    def __init__(self, context, installation, reader, reader_sha256, retain):
        self.context, self.retain = context, retain
        self.installation = json.loads(protected(installation, 1048576))
        installed = self.installation
        require(installed["schema"] == "laneboss.service-install.v2" and installed["config"] == context["config"] and
                installed["artifact_sha256"] == context["binary_sha256"] and
                installed["binding_file"] == context["binding_file"], "native installation differs from the frozen context")
        self.reader = str(Path(reader).resolve(strict=True))
        require(sha(Path(self.reader).read_bytes()) == reader_sha256, "native reader pin differs")
        self.index, self.inventories = 0, {}

    def journal(self, target, events):
        planned = [event["payload"]["plan"]["lease"]["id"] for event in events if event.get("kind") == "launch.planned" and
                   event.get("life_id") == target["life_id"] and event.get("run") == target["run"]]
        require(planned and len(set(planned)) == 1, "actual planned agent lease is missing or ambiguous")
        allocated = [event["payload"] for event in events if event.get("kind") == "helper.allocated" and
                     event.get("origin") == "service" and event.get("life_id") == target["life_id"] and
                     event.get("run") == target["run"] and event["payload"].get("id") == planned[0]]
        require(allocated, "actual helper allocation is missing")
        ids = {row["id"] for row in allocated}
        require(len(ids) == 1, "actual agent helper lease is ambiguous")
        lease_id = next(iter(ids))
        path = Path("/var/lib/laneboss-v2/helper") / self.context["config"] / (lease_id + ".json")
        raw = protected(path)
        journal = json.loads(raw)
        require(journal["lease"]["id"] == lease_id and journal["lease"]["containment_id"] == allocated[0]["containment_id"] and
                journal["request"]["cause"]["config"] == self.context["config"], "native journal does not own this service allocation")
        self.index += 1
        self.retain("helper-%04d.json" % self.index, raw)
        return journal

    def home(self, journal):
        storage, lease = journal["launch_storage"], journal["lease"]
        home = storage["binding"]["home"]
        root_id = home["root_id"]
        selected = [row for row in storage["directories"] if row["id"] == root_id]
        require(len(selected) == 1, "native home root is not enrolled in its storage inventory")
        path = Path("/var/lib/laneboss-v2/lanes") / self.context["config"] / lease["id"] / root_id
        observed = path.lstat()
        require(str(observed.st_dev) == selected[0]["device"] and str(observed.st_ino) == selected[0]["inode"] and
                stat.S_ISDIR(observed.st_mode) and observed.st_uid == lease["uid"], "native home inode differs from its actual planned root")
        return path

    def measure(self, target, events, facts):
        journal = self.journal(target, events)
        tasks = [event["payload"]["lane"]["task"]["sha256"] for event in events if event.get("kind") == "lane.started" and
                 event.get("life_id") == target["life_id"] and event.get("run") == target["run"]]
        require(len(tasks) == 1, "native probe has no unique actual launch task")
        witness = native_child(self.context, target, facts, journal, tasks[0])
        lease = journal["lease"]
        cgroup = Path("/sys/fs/cgroup/system.slice") / ("laneboss-helper@" + self.context["config"] + ".service") / "lanes" / lease["containment_id"]
        members = [int(value) for value in (cgroup / "cgroup.procs").read_text().split()]
        require(witness["pid"] in members and members, "native probe is not a member of the measured cgroup")
        processes = uid_processes(lease["uid"])
        require(processes, "native process inventory is empty")
        root = Path("/var/lib/laneboss-v2/lanes") / self.context["config"] / lease["id"]
        require(root.is_dir(), "native runtime root was never created")
        self.inventories[(target["life_id"], target["run"])] = {
            "target": target, "lease_id": lease["id"], "uid": lease["uid"], "processes": processes, "witness": witness,
            "runtime_root": str(root), "cgroup": str(cgroup), "home": str(self.home(journal))}
        return journal

    def inspect(self, mode, grants=(), profiles=(), slots=(), recovery=None, backup=None):
        self.index += 1
        installed = self.installation
        uid = installed["service_uid"]
        records = Path(installed["secret_directory"]) / "records"
        key = Path(installed["secret_directory"]) / "keys" / (installed["secret_key_handle"] + ".key")
        descriptors, request = [], {"mode": mode, "config": self.context["config"], "directory": str(records),
            "key_handle": installed["secret_key_handle"], "grants": list(grants), "profiles": list(profiles), "slots": list(slots)}
        for field, path in (("key_fd", key if mode not in {"locked", "recover"} else None),
                            ("recovery_fd", recovery), ("backup_fd", backup)):
            if path is not None:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                descriptors.append(fd)
                request[field] = fd
        gid = records.stat().st_gid

        def identity():
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)

        try:
            completed = subprocess.run([self.reader], input=json.dumps(request).encode(), capture_output=True, timeout=60,
                check=False, pass_fds=tuple(descriptors), preexec_fn=identity if os.geteuid() == 0 else None,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        finally:
            for fd in descriptors:
                os.close(fd)
        stem = "native-%04d" % self.index
        self.retain(stem + ".request.json", json.dumps(request).encode())
        self.retain(stem + ".out", completed.stdout)
        self.retain(stem + ".err", completed.stderr)
        self.retain(stem + ".exit.json", json.dumps({"exit": completed.returncode}).encode())
        value = json.loads(completed.stdout)
        require(value.get("mode") == mode and value.get("config") == self.context["config"] and
                value.get("key_handle") == installed["secret_key_handle"], "native observer returned another installed enrollment")
        return completed.returncode, value

    def collected(self, events):
        result = []
        require(self.inventories, "whole-run native inventory is missing")
        for inventory in self.inventories.values():
            release(events, inventory["target"])
            require(not uid_processes(inventory["uid"]), "native UID retained a detached descendant")
            for old in inventory["processes"]:
                now = process(old["pid"])
                require(now is None or now["start_time"] != old["start_time"], "an inventoried native process survived")
            require(not os.path.lexists(inventory["runtime_root"]), "actual native runtime root survived collection")
            if Path(inventory["cgroup"]).exists():
                require(not (Path(inventory["cgroup"]) / "cgroup.procs").read_text().strip(), "native cgroup retained survivors")
            result.append(inventory)
        return result

    def all_quiet(self):
        parent = Path("/var/lib/laneboss-v2/helper") / self.context["config"]
        retained = []
        for path in sorted(parent.glob("*.json")):
            raw = protected(path)
            record = json.loads(raw)
            lease = record["lease"]
            require(record.get("phase") in {"released", "aborted"}, "an actual helper lease remains active or unknown")
            require(not uid_processes(lease["uid"]), "an actual helper UID still owns a detached process")
            runtime = Path("/var/lib/laneboss-v2/lanes") / self.context["config"] / lease["id"]
            require(not os.path.lexists(runtime), "a helper runtime root survived collection")
            receipt = record.get("receipt") if record["phase"] == "released" else record.get("abort_receipt")
            require(isinstance(receipt, dict) and receipt, "quiet helper lease has no measured native receipt")
            self.index += 1
            self.retain("quiet-helper-%04d.json" % self.index, raw)
            retained.append({"lease_id": lease["id"], "phase": record["phase"], "uid": lease["uid"], "runtime_root": str(runtime)})
        require(retained, "actual helper journal inventory is empty")
        return retained
