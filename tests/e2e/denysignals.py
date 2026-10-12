"""Run a command with some of its process operations denied, for the lane tests.

    denysignals.py MODE COMMAND [ARGUMENT...]

runs COMMAND so that it and every process it starts cannot:

- pidfd: open a process file descriptor or signal through one (pidfd_open and pidfd_send_signal fail with EPERM), as
  on a kernel or under a policy without them;
- stop: send SIGTERM or SIGKILL to a process (kill, tkill, tgkill, rt_sigqueueinfo, rt_tgsigqueueinfo and
  pidfd_send_signal fail with EPERM for those two signals), so nothing it tries to stop can be stopped by it.

On Linux the denial is a seccomp filter, which every descendant inherits (a tmux server the command starts included).
On macOS `stop` runs the command under sandbox-exec with a profile that denies sending signals; macOS has no process
file descriptors, so `pidfd` changes nothing there. Nothing of the system under test is replaced: its own system calls
fail the way a restricted system makes them fail.
"""

import ctypes
import os
import platform
import struct
import sys

EPERM = 1
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
RET_ALLOW = 0x7FFF0000
RET_ERRNO = 0x00050000
LOAD = 0x20     # BPF_LD | BPF_W | BPF_ABS
JEQ = 0x15      # BPF_JMP | BPF_JEQ | BPF_K
RET = 0x06      # BPF_RET | BPF_K
SIGNALS = (9, 15)
SANDBOX = "(version 1)(allow default)(deny signal)"
# (audit architecture, {system call: index of its signal argument}, pidfd_open)
ARCHITECTURES = {
    "x86_64": (0xC000003E, {62: 1, 200: 1, 234: 2, 129: 1, 297: 2, 424: 1}, 434),
    "aarch64": (0xC00000B7, {129: 1, 130: 1, 131: 2, 138: 1, 240: 2, 424: 1}, 434),
}
PIDFD_SEND_SIGNAL = 424


class Program:
    """A classic BPF program with named jump targets."""

    def __init__(self):
        self.code = []
        self.labels = {}

    def label(self, name):
        self.labels[name] = len(self.code)

    def add(self, op, k, true=None, false=None):
        self.code.append((op, k, true, false))

    def assemble(self):
        def offset(index, target):
            return 0 if target is None else self.labels[target] - index - 1
        return b"".join(struct.pack("HBBI", op, offset(index, true), offset(index, false), k)
                        for index, (op, k, true, false) in enumerate(self.code))


def filter_for(mode):
    """The filter's instructions. BPF jumps only forward, so every target comes after the jumps to it."""
    architecture, signalling, pidfd_open = ARCHITECTURES[platform.machine()]
    program = Program()
    program.add(LOAD, 4)
    program.add(JEQ, architecture, None, "allow")
    program.add(LOAD, 0)
    if mode == "pidfd":
        program.add(JEQ, pidfd_open, "deny")
        program.add(JEQ, PIDFD_SEND_SIGNAL, "deny")
    else:
        for number, argument in sorted(signalling.items()):
            program.add(JEQ, number, "argument{}".format(argument))
    program.add(RET, RET_ALLOW)
    for argument in (1, 2):
        # The low 32 bits of the system call's argument (struct seccomp_data: nr, arch, ip, args[6]).
        program.label("argument{}".format(argument))
        program.add(LOAD, 16 + 8 * argument)
        program.add(JEQ, SIGNALS[0], "deny")
        program.add(JEQ, SIGNALS[1], "deny", "allow")
    program.label("allow")
    program.add(RET, RET_ALLOW)
    program.label("deny")
    program.add(RET, RET_ERRNO | EPERM)
    return program.assemble()


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def deny_on_linux(mode):
    code = filter_for(mode)
    buffer = ctypes.create_string_buffer(code, len(code))
    program = SockFprog(len(code) // 8, ctypes.cast(buffer, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_SECCOMP) failed")


def main():
    mode, command = sys.argv[1], sys.argv[2:]
    if mode not in ("pidfd", "stop") or not command:
        sys.exit("usage: denysignals.py pidfd|stop COMMAND [ARGUMENT...]")
    if sys.platform.startswith("linux"):
        deny_on_linux(mode)
    elif mode == "stop":
        command = ["/usr/bin/sandbox-exec", "-p", SANDBOX] + command
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
