"""Kernel metadata for the explicitly authorized Darwin-only communication rows."""

import ctypes
import errno
import os
import sys


class BSDInfo(ctypes.Structure):
    # proc_bsdinfo from sys/proc_info.h; command/name bytes are never printed.
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid",
        "svuid", "svgid", "reserved")]
    _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in (
        "nfiles", "pgid", "jobc", "tty", "tty_pgid")]
    _fields_ += [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64),
                ("start_usec", ctypes.c_uint64)]


def kernel_process(pid):
    if sys.platform != "darwin":
        raise RuntimeError("Darwin kernel metadata is only available in the Darwin rows")
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    library.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                     ctypes.c_void_p, ctypes.c_int]
    library.proc_pidinfo.restype = ctypes.c_int
    info = BSDInfo()
    size = ctypes.sizeof(info)
    received = library.proc_pidinfo(pid, 3, 0, ctypes.byref(info), size)
    if received != size:
        error = ctypes.get_errno()
        if received == 0 and error in (errno.ESRCH, errno.ENOENT):
            return None
        raise OSError(error, "the Darwin fixture could not read complete kernel process metadata")
    if info.pid != pid or info.start_sec == 0:
        raise RuntimeError("the Darwin kernel returned a different or incomplete process identity")
    try:
        sid = os.getsid(pid)
    except ProcessLookupError:
        return None
    return {"pid": info.pid, "ppid": info.ppid, "pgid": info.pgid, "sid": sid,
            "start": "{}.{:06d}".format(info.start_sec, info.start_usec),
            "alive": info.status != 5, "state": info.status,
            "controlling_terminal": bool(info.flags & 0xC0)}


def require_headless_darwin():
    try:
        descriptor = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY)
    except OSError as error:
        if error.errno not in (errno.ENXIO, errno.ENODEV):
            raise
    else:
        os.close(descriptor)
        raise RuntimeError("the Darwin communication fixture acquired a controlling terminal")
    identity = kernel_process(os.getpid())
    if identity is None or not identity["alive"] or identity["controlling_terminal"]:
        raise RuntimeError("the kernel did not confirm a live headless Darwin caller")
    return identity
