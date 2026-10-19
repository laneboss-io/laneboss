"""Narrow Linux handoff for a confined Python actor's child CLI.

The two projections retain their original FD numbers. Their native service
peer still authenticates every frame; these checks never create authority.
"""

import fcntl
import json
import os
import re
import stat

LANE_BINDING = "/run/laneboss/binding.json"
LANE_SOCKET = "/run/laneboss/service.sock"


class HandoffRefusal(RuntimeError):
    code = "prerequisite_missing"

    def projection(self):
        return {"code": self.code, "owner": "lb-v2-linux", "completed": False,
                "message": str(self),
                "instead": "Run this actor inside its original installed confinement with its unchanged fixed binding; retain the failed handoff."}


def _refuse():
    raise HandoffRefusal("lane child requires its two fixed sealed projections")


def _descriptor(path):
    target = os.readlink(path)
    match = re.fullmatch(r"/proc/self/fd/([1-9][0-9]*)", target)
    if match is None:
        _refuse()
    number = int(match[1])
    if number < 6 or number > 4096:
        _refuse()
    return number


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse()
        result[key] = value
    return result


def lane_descriptors(config, binding_file):
    """Return only pass_fds for the already confined, configuration-bound actor."""
    if binding_file != LANE_BINDING:
        _refuse()
    bound = os.environ.get("LANEBOSS_CONFIG", "")
    if bound and bound != config:
        raise HandoffRefusal("lane child conflicts with the active configuration")
    try:
        binding_fd, socket_fd = _descriptor(LANE_BINDING), _descriptor(LANE_SOCKET)
        if binding_fd == socket_fd:
            _refuse()
        info = os.fstat(binding_fd)
        required = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o444 or
                not 0 < info.st_size <= 1048576 or
                fcntl.fcntl(binding_fd, fcntl.F_GET_SEALS) & required != required):
            _refuse()
        raw = os.pread(binding_fd, info.st_size + 1, 0)
        if len(raw) != info.st_size:
            _refuse()
        binding = json.loads(raw, object_pairs_hook=_unique_object)
        if (not isinstance(binding, dict) or binding.get("class") != "lane" or
                binding.get("config") != config or binding.get("socket") != LANE_SOCKET or
                binding.get("contract_revision") != "v2.0-draft.4"):
            _refuse()
        endpoint = os.fstat(socket_fd)
        if (not stat.S_ISSOCK(endpoint.st_mode) or stat.S_IMODE(endpoint.st_mode) != 0o666 or
                endpoint.st_nlink != 1 or
                type(binding.get("mapped_service_uid")) is not int or
                type(binding.get("mapped_service_gid")) is not int or
                endpoint.st_uid != binding["mapped_service_uid"] or
                endpoint.st_gid != binding["mapped_service_gid"] or
                fcntl.fcntl(socket_fd, fcntl.F_GETFL) & os.O_PATH == 0):
            _refuse()
        if _descriptor(LANE_BINDING) != binding_fd or _descriptor(LANE_SOCKET) != socket_fd:
            _refuse()
        return binding_fd, socket_fd
    except (OSError, ValueError, KeyError, TypeError):
        _refuse()
