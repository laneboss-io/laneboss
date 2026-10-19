"""Inert CLI-adapter controls; no fixture result is product acceptance."""

import base64
import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "e2e" / "v2"))

from ladder_box import bundle_file
from ladder_case import fixture
from ladder_live import CLI
from ladder_observer import Observer, RemoteFailure, receive
from support import Command, Failure, bytes_hash, load, save


class CLIControls(unittest.TestCase):
    def test_typed_failure_and_exact_cli_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = {"code": "not_implemented", "owner": "lb-v2-service",
                     "message": "serve is not implemented", "instead": "retain the failure",
                     "retryable": False}
            stdout, stderr, receipt = root / "stdout", root / "stderr", root / "receipt"
            save(stdout, {})
            save(stderr, value)
            command = Command(69, stdout, stderr, receipt)
            cli = object.__new__(CLI)
            cli.binary, cli.binding, cli.config = "installed-cli", "installed-binding", "tree-a"
            cli.root, cli.index = root, 0
            cli.bound = {"class": "human"}
            cli.invocations = []
            cli.recorder = Mock()
            cli.recorder.run.return_value = command
            body = {"client_version": "", "artifact_sha256": bytes_hash(os.urandom(8))}
            with self.assertRaises(RemoteFailure) as caught:
                cli.call(["health"], body)
            self.assertEqual(caught.exception.wire(), value)
            self.assertEqual(cli.last_exit, 69)
            argv = cli.recorder.run.call_args.args[0]
            self.assertEqual(argv[:6], ["installed-cli", "health", "--config", "tree-a",
                                       "--binding", "installed-binding"])
            self.assertEqual(argv[6], "--request")
            self.assertEqual(load(argv[7]), body)

    def test_ready_false_is_a_named_failure(self):
        cli = object.__new__(CLI)
        digest = bytes_hash(os.urandom(8))
        cli.call = Mock(return_value={"protocol": "laneboss.rpc.v2", "schema": 2,
                                      "ready": False, "artifact_sha256": digest})
        with self.assertRaises(Failure) as caught:
            cli.health(digest)
        self.assertEqual((caught.exception.code, caught.exception.owner),
                         ("unavailable", "lb-v2-service"))

    def test_cursor_keeps_exclusive_filter(self):
        cli = object.__new__(CLI)
        cli.config, cli.cursor, cli.seq, cli.events = "tree-a", "", 0, []
        cli.event_positions = {}
        cli.lanes = Mock(return_value=[{"life_id": "selected-life", "run": 1}])
        cli.call = Mock(side_effect=[
            {"events": [{"schema": 2, "config": "tree-a", "seq": 1,
                         "id": "one", "life_id": "selected-life", "run": 1}],
             "cursor": "cursor-one", "complete": False},
            {"events": [{"schema": 2, "config": "tree-a", "seq": 2,
                         "id": "two", "life_id": "selected-life", "run": 1}],
             "cursor": "cursor-two", "complete": True}])
        self.assertFalse(cli.events_page())
        self.assertTrue(cli.events_page())
        second = cli.call.call_args_list[1].args[1]
        self.assertEqual((second["since"], second["cursor"]), (0, "cursor-one"))
        self.assertEqual(cli.seq, 2)

    def test_blob_bytes_are_hashed_and_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cli = object.__new__(CLI)
            cli.root, cli.blobs = root, {}
            data = os.urandom(48)
            digest = bytes_hash(data)
            reference = {"id": "blob-id", "sha256": digest, "bytes": len(data), "class": "report"}
            chunk = {"object_id": "blob-id", "offset": 0,
                     "data": base64.b64encode(data).decode("ascii"), "sha256": digest}
            cli.call = Mock(return_value=chunk)
            cli.retain_blob(reference, root)
            self.assertEqual((root / cli.blobs["blob-id"]["path"]).read_bytes(), data)
            self.assertEqual(cli.blobs["blob-id"]["sha256"], digest)
            cli.blobs.clear()
            cli.call = Mock(return_value={**chunk, "sha256": bytes_hash(os.urandom(8))})
            with self.assertRaises(Failure) as caught:
                cli.retain_blob(reference, root)
            self.assertIn("chunk", str(caught.exception))


class MissingDependencyControls(unittest.TestCase):
    def test_dual_installation_is_named(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(Failure) as caught:
                fixture(SimpleNamespace(inputs=Path(temporary)))
            self.assertEqual((caught.exception.code, caught.exception.owner),
                             ("not_implemented", "lb-v2-admin"))

    def test_bundle_named_variable_only(self):
        with patch("ladder_box.os.environ.get", return_value=None) as getter:
            with self.assertRaises(Failure) as caught:
                bundle_file()
        getter.assert_called_once_with("LANEBOSS_LADDER_BUNDLE")
        self.assertEqual((caught.exception.code, caught.exception.owner),
                         ("prerequisite_missing", "lb-v2-secrets"))

    def test_observer_binding_absence_is_named(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(Failure) as caught:
                Observer(root / "absent.json", root / "out", "artifact", "draw")
            self.assertEqual((caught.exception.code, caught.exception.owner),
                             ("not_implemented", "lb-v2-integrate"))
            self.assertFalse((root / "out").exists())

    def test_incomplete_observer_frame_refuses(self):
        reader = SimpleNamespace(recv=io.BytesIO(b"abc").read)
        with self.assertRaises(Failure):
            receive(reader, 4)
        data = os.urandom(16)
        reader = SimpleNamespace(recv=io.BytesIO(data).read)
        self.assertEqual(receive(reader, len(data)), data)
