"""A real, unsandboxed DAC control under the exact leased UID and GID."""

import hashlib
import json
import os
import select
import signal


def probe(paths, uid, gid):
    if os.geteuid() != 0:
        raise RuntimeError("DAC observer requires authorized disposable root")
    if any(type(value) is not int or not 0 < value < 2**32
           for value in (uid, gid)):
        raise ValueError("DAC control needs a non-root leased UID and GID")
    reader, writer = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        os.close(reader)
        try:
            os.setgroups([])
            os.setresgid(gid, gid, gid)
            os.setresuid(uid, uid, uid)
            result = {"uid": os.geteuid(), "gid": os.getegid(),
                      "groups": os.getgroups(), "files": {}}
            for name, path in paths.items():
                observed = {}
                for operation, flags in (("read", os.O_RDONLY),
                                         ("write", os.O_WRONLY)):
                    try:
                        fd = os.open(path, flags | os.O_NOFOLLOW |
                                     os.O_NONBLOCK | os.O_CLOEXEC)
                    except OSError as failure:
                        observed[operation] = {"errno": failure.errno}
                    else:
                        try:
                            value = {"errno": 0}
                            if operation == "read":
                                raw = os.read(fd, 1024 * 1024 + 1)
                                if len(raw) > 1024 * 1024:
                                    raise ValueError("DAC control file is too large")
                                value["sha256"] = hashlib.sha256(raw).hexdigest()
                            observed[operation] = value
                        finally:
                            os.close(fd)
                result["files"][name] = observed
            os.write(writer, json.dumps(result, sort_keys=True).encode())
        except Exception as failure:
            os.write(writer, json.dumps({"error": type(failure).__name__}).encode())
            os._exit(1)
        os._exit(0)
    os.close(writer)
    waited = False
    try:
        ready, _, _ = select.select([reader], [], [], 5)
        if not ready:
            raise TimeoutError("DAC control child did not finish")
        raw = os.read(reader, 65537)
        got, status = os.waitpid(child, 0)
        waited = True
        if got != child or status != 0 or len(raw) > 65536:
            raise RuntimeError("DAC control child failed")
        result = json.loads(raw)
        if (result.get("uid") != uid or result.get("gid") != gid or
                result.get("groups") != [] or set(result["files"]) != set(paths)):
            raise RuntimeError("DAC control did not use the leased identity")
        return result
    finally:
        os.close(reader)
        if not waited:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)


def require_access(result, expected):
    if set(result["files"]) != set(expected):
        raise RuntimeError("DAC positive controls are incomplete")
    for name, digest in expected.items():
        observed = result["files"][name]
        if (observed["read"].get("errno") != 0 or
                observed["write"].get("errno") != 0 or
                observed["read"].get("sha256") != digest):
            raise RuntimeError("DAC masks the intended boundary: " + name)
