"""The real product smoke; missing serve is an ordinary red result."""

from pathlib import Path
import uuid

from box_support import BlackBoxCase


class ServiceSmoke(BlackBoxCase):
    def test_service_and_readback(self):
        # Invoke the public CLI even when the service implementation is absent.
        status = self.box.readiness()
        self.assertServiceLive()
        value = self.assertJSON(status)
        self.assertEqual(value.get("protocol"), "laneboss.rpc.v2")
        self.assertEqual(value.get("schema"), 2)
        self.assertIs(value.get("ready"), True)
        self.assertEqual(value.get("artifact_sha256"), self.box.data["binary_sha256"])
        page = self.assertJSON(self.box.operator_request(
            ["event", "tail"], {"life_id": "", "run": 0, "since": 0, "cursor": "",
                               "follow": False, "until": "service.started",
                               "deadline_ms": 1000}, proof=self.box.startup_proof()))
        events = page.get("events")
        self.assertIsInstance(events, list)
        starts = [event for event in events if event.get("kind") == "service.started"
                  and event.get("origin") == "service" and event.get("schema") == 2
                  and event.get("config") == self.box.data["lane"] and
                  event.get("seq", 0) > 0 and event.get("payload", {}).get(
                      "artifact_sha256") == self.box.data["binary_sha256"]]
        self.assertEqual(len(starts), 1, "authentic startup event is missing")
        # health is the v2 public readiness contract; an empty legacy store
        # verification object cannot satisfy it.
        nonce = ("ordinary work " + uuid.uuid4().hex[:16] + "\n").encode("ascii")
        target = Path(self.box.data["accounts"]["lane"]["home"]) / "ordinary.bin"
        written = self.box.as_user("lane", ["/usr/bin/tee", str(target)], input_bytes=nonce)
        self.assertExit(written)
        self.assertEqual(written.stdout, nonce)
        self.assertEqual(self.box.outside_read(target), nonce)
        denied = self.box.as_user("operator", ["/usr/bin/cat", str(target)])
        self.assertExit(denied, 1)
        self.assertEqual(denied.stdout, b"")
        self.assertServiceLive()
