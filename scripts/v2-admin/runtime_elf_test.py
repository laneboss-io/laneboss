"""ELF metadata checks with external inspection disabled."""

import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "runtime_deps", Path(__file__).with_name("runtime_deps.py"))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


# Exact uname output from loaderprobe1 on ARM64 Ubuntu 24.04.5.
# Decode sed's \t and end-of-line markers; those markers are not loader bytes.
UNAME_LINES = (
    "\t (0x0000efa778cc0000)\n"
    "\tlinux-vdso.so.1 (0x0000efa778d3d000)\n"
    "\tlibc.so.6 => /lib/aarch64-linux-gnu/libc.so.6 (0x0000efa778b00000)\n"
    "\t/lib/ld-linux-aarch64.so.1 (0x0000efa778cf0000)\n"
)


def image(machine=183, interp=b"/lib/ld-linux-aarch64.so.1\0",
          strings=b"\0libc.so.6\0libm.so.6\0libsample.so\0"):
    raw = bytearray(1024 + len(strings))
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", raw, 0, ident, 3, machine, 1,
                     0, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    program(raw, 0, 1, 0, 0x400000, len(raw))
    program(raw, 1, 3, 256, 0x400100, len(interp))
    program(raw, 2, 2, 512, 0x400200, 16 * 6)
    raw[256:256 + len(interp)] = interp
    raw[1024:] = strings
    dynamic(raw, 0, 5, 0x400400)
    dynamic(raw, 1, 10, len(strings))
    dynamic(raw, 2, 1, 1)
    dynamic(raw, 3, 1, 11)
    dynamic(raw, 4, 14, 21)
    dynamic(raw, 5, 0, 0)
    return raw


def program(raw, index, kind, offset, address, size):
    struct.pack_into("<IIQQQQQQ", raw, 64 + index * 56,
                     kind, 4, offset, address, address, size, size, 1)


def dynamic(raw, index, kind, value):
    struct.pack_into("<qQ", raw, 512 + index * 16, kind, value)


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "input"
        patch = mock.patch.object(runtime, "command", side_effect=AssertionError(
            "ELF metadata invoked an external tool"))
        patch.start()
        self.addCleanup(patch.stop)
        process = mock.patch.object(runtime.subprocess, "Popen", side_effect=AssertionError(
            "ELF metadata spawned an external process"))
        process.start()
        self.addCleanup(process.stop)

    def parse(self, raw):
        self.path.write_bytes(raw)
        return runtime.metadata(self.path)

    def refuse(self, raw, reason):
        with self.assertRaisesRegex(ValueError, reason):
            self.parse(raw)

    def test_elf64(self):
        expected = {"format": "ELF", "interpreter": "/lib/ld-linux-aarch64.so.1",
                    "soname": "libsample.so", "needed": ["libc.so.6", "libm.so.6"]}
        self.assertEqual(self.parse(image()), expected)
        expected["interpreter"] = "/lib64/ld-linux-x86-64.so.2"
        self.assertEqual(self.parse(image(62, expected["interpreter"].encode() + b"\0")), expected)

    def test_script(self):
        self.assertEqual(self.parse(b"#!/usr/bin/env -S sh\nprintf ok\n"), {
            "format": "script", "interpreter": "/usr/bin/env",
            "argument": "-S sh", "needed": []})

    def test_static(self):
        raw = image()
        struct.pack_into("<H", raw, 56, 1)
        self.assertEqual(self.parse(raw), {"format": "ELF", "interpreter": None,
                                         "soname": None, "needed": []})

    def test_elf32(self):
        raw = image()
        raw[4] = 1
        self.refuse(raw, "ELF64 little-endian")

    def test_big_endian(self):
        raw = image()
        raw[5] = 2
        self.refuse(raw, "ELF64 little-endian")

    def test_machine(self):
        raw = image(40)
        self.refuse(raw, "machine is unsupported")

    def test_multi_interp(self):
        raw = image()
        program(raw, 2, 3, 256, 0x400100, 27)
        self.refuse(raw, "ambiguous interpreters")

    def test_multi_dynamic(self):
        raw = image()
        program(raw, 1, 2, 512, 0x400200, 16 * 6)
        self.refuse(raw, "ambiguous dynamic tables")

    def test_header_offset(self):
        raw = image()
        struct.pack_into("<Q", raw, 32, len(raw))
        self.refuse(raw, "offset is outside file")

    def test_segment_offset(self):
        raw = image()
        program(raw, 1, 3, len(raw), 0x400100, 27)
        self.refuse(raw, "offset is outside file")

    def test_string_offset(self):
        raw = image()
        dynamic(raw, 2, 1, len(raw))
        self.refuse(raw, "string is outside table")

    def test_string_mapping(self):
        raw = image()
        dynamic(raw, 0, 5, 0x500000)
        self.refuse(raw, "string table is not file-backed")

    def test_string_bound(self):
        raw = image(strings=b"\0" + b"x" * 4097 + b"\0")
        self.refuse(raw, "string exceeds its bound")

    def test_interp_bound(self):
        raw = image()
        raw.extend(bytes(8192 - len(raw)))
        raw[2048:6148] = b"/x\0" + bytes(4097)
        program(raw, 0, 1, 0, 0x400000, len(raw))
        program(raw, 1, 3, 2048, 0x400800, 4100)
        self.refuse(raw, "interpreter exceeds its bound")

    def test_unterminated_interp(self):
        raw = image(interp=b"/lib/no-null")
        self.refuse(raw, "string is unterminated")

    def test_unterminated_string(self):
        raw = image(strings=b"\0" + b"x" * 32)
        self.refuse(raw, "string is unterminated")

    def test_dynamic_end(self):
        raw = image()
        dynamic(raw, 5, 1, 1)
        self.refuse(raw, "dynamic table is unterminated")

    def test_strtab_size(self):
        raw = image()
        dynamic(raw, 1, 10, len(raw))
        self.refuse(raw, "string table is not file-backed")

    def test_multi_soname(self):
        raw = image()
        dynamic(raw, 3, 14, 21)
        self.refuse(raw, "ambiguous SONAME aliases")

    def test_loader_names(self):
        with self.assertRaisesRegex(ValueError, re.escape(
                "executable='/runtime/claude' library='libabsent.so'")):
            runtime.loader_paths("libabsent.so => not found\n", "/runtime/claude")

    def test_loader_paths(self):
        self.assertEqual(runtime.loader_paths(
            "linux-vdso.so.1 (0x1234)\nlibc.so.6 => /lib/libc.so.6 (0x5678)\n"
            "/lib/ld-linux-aarch64.so.1 (0x9876)\n", "/runtime/claude"), {
                "libc.so.6": "/lib/libc.so.6",
                "ld-linux-aarch64.so.1": "/lib/ld-linux-aarch64.so.1"})

    def test_loader_relative(self):
        with self.assertRaisesRegex(ValueError, "unresolved library"):
            runtime.loader_paths("libabsent.so => relative/libabsent.so\n", "/runtime/claude")

    def test_loader_uname(self):
        self.assertEqual(runtime.loader_paths(UNAME_LINES, "/runtime/uname"), {
            "libc.so.6": "/lib/aarch64-linux-gnu/libc.so.6",
            "ld-linux-aarch64.so.1": "/lib/ld-linux-aarch64.so.1"})

    def loader_refused(self, listed, name, line):
        with self.assertRaises(ValueError) as caught:
            runtime.loader_paths(listed, "/runtime/uname")
        message = str(caught.exception)
        self.assertIn("executable='/runtime/uname'", message)
        self.assertIn("library=" + repr(name), message)
        self.assertIn("line=" + repr(line), message)

    def test_loader_missing_twin(self):
        line = "\tlibx.so.1 => not found"
        listed = UNAME_LINES.replace(UNAME_LINES.splitlines()[2], line)
        self.loader_refused(listed, "libx.so.1", line)

    def test_loader_pathless_twin(self):
        line = "\tlibx.so.1 (0x0000efa778cc0000)"
        listed = UNAME_LINES.replace(UNAME_LINES.splitlines()[0], line)
        self.loader_refused(listed, "libx.so.1", line)

    def test_loader_map_bounds(self):
        lines = (
            "\t (0x0000efa778cc0000) extra",
            "\t (0x0000efa778cc0000) (0x0000efa778cc0000)",
            "\t (0xZZ)",
            "\tlibx.so.1 => (0x0000efa778cc0000)",
            "\tlinux-vdso-unknown.so.1 (0x0000efa778cc0000)",
            "\tlinux-gate-unknown.so.1 (0x0000efa778cc0000)",
            "\tlinux-vdso.so.1 (0x0000efa778cc0000) extra",
        )
        for line in lines:
            with self.subTest(line=line):
                self.loader_refused(line, line.split()[0], line)


class ProcessTests(unittest.TestCase):
    def test_loader_failure_names(self):
        argv = ["/lib/loader", "--list", "/runtime/claude"]
        failures = (
            (b"", b"claude: error while loading shared libraries: libabsent.so: cannot open shared object file\n"),
            (b"libabsent.so => not found\n", b""),
        )
        for stdout, stderr in failures:
            with self.subTest(stderr=bool(stderr)):
                result = runtime.subprocess.CompletedProcess(argv, 127, stdout, stderr)
                with mock.patch.object(runtime.subprocess, "run", return_value=result):
                    with self.assertRaisesRegex(ValueError, re.escape(
                            "executable='/runtime/claude' library='libabsent.so'")):
                        runtime.command(argv)


class ClosureTests(unittest.TestCase):
    def test_programs(self):
        programs = {"uname": Path("/usr/bin/uname"), "git": Path("/usr/bin/git"),
                    "sh": Path("/bin/sh"), "bash": Path("/usr/bin/bash")}
        with tempfile.TemporaryDirectory(prefix="lb-loader-", dir="/opt") as directory:
            root = Path(directory)
            objects = runtime.enroll(root, "root", programs)
            graph = json.loads((root / "runtime-links.json").read_bytes())
            rows = {row["path"]: row for row in graph["files"]}
            pinned = {"/" + item["relative_path"] for item in objects}
            for name, path in programs.items():
                with self.subTest(program=name):
                    row = rows["/runtime/" + name]
                    self.assertTrue(row["executable"])
                    resolved = row["resolved"]
                    self.assertTrue(resolved)
                    self.assertIn(row["interpreter"], pinned)
                    self.assertIn(runtime.source_file(row["interpreter"]),
                                  {runtime.source_file(path) for path in resolved.values()})
                    for library, target in sorted(resolved.items()):
                        self.assertIn(target, pinned)
                        self.assertTrue((root / target[1:]).is_file())
                        print(f"closure {path}: {library} => {target}", flush=True)
                    for entry in [row, *[rows[path] for path in set(resolved.values())]]:
                        for needed in entry["needed"]:
                            self.assertIn(needed, resolved)

    def test_needed(self):
        # A real observed anonymous map must not satisfy a removed NEEDED name.
        needed = runtime.metadata(Path("/usr/bin/uname"))["needed"][0]
        native = runtime.command

        def omit_needed(argv, target=None):
            listed = native(argv, target)
            lines = listed.splitlines()
            kept = [line for line in lines if not line.split() or line.split()[0] != needed]
            self.assertEqual(len(lines) - len(kept), 1)
            return UNAME_LINES.splitlines()[0] + "\n" + "\n".join(kept) + "\n"

        with tempfile.TemporaryDirectory(prefix="lb-loader-", dir="/opt") as directory:
            with mock.patch.object(runtime, "command", side_effect=omit_needed):
                with self.assertRaisesRegex(ValueError, re.escape(
                        "runtime loader omitted a DT_NEEDED dependency: "
                        "executable='/runtime/uname' library=" + repr(needed))):
                    runtime.enroll(Path(directory), "root", {"uname": Path("/usr/bin/uname")})
        print(f"missing-edge control refused: /runtime/uname library={needed!r}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "real":
        with mock.patch.object(runtime, "command", side_effect=AssertionError(
                "ELF metadata invoked an external tool")):
            with mock.patch.object(runtime.subprocess, "Popen", side_effect=AssertionError(
                    "ELF metadata spawned an external process")):
                observed = runtime.metadata(Path(sys.argv[2]))
        if observed != json.loads(sys.argv[3]):
            raise AssertionError("real ELF metadata differs from independent expected records")
        print("real ELF metadata matched")
    elif sys.argv[1:] == ["closure"]:
        unittest.main(argv=[sys.argv[0]], defaultTest="ClosureTests", verbosity=2)
    else:
        unittest.main(defaultTest=["ReaderTests", "ProcessTests"], verbosity=2)
